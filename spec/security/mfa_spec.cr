require "../spec_helper"

# A second factor is only as good as the three things around the arithmetic: a rate limit, a
# code that cannot be used twice, and a factor that does not count until it has been proved.
# Every example here is named for what fails without one of them.

private alias TOTP = KemalIdentity::MFA::TOTP

private BOX_KEY = KemalIdentity::Secret.new("m" * 32)

private def mfa_harness(
  rate_limiter : KemalIdentity::RateLimiter = KemalIdentity::NullRateLimiter.new,
  drift : Int32 = 1,
  recovery_code_count : Int32 = 10,
  sessions : KemalIdentity::Sessions::Service? = nil,
)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  random = KemalIdentity::Testing::DeterministicRandom.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
  repo = KemalIdentity::Testing::MemoryMfaRepository.new

  service = KemalIdentity::MFA::Service.new(
    factors: repo,
    secret_box: KemalIdentity::MFA::AesSecretBox.new(BOX_KEY, random),
    clock: clock,
    random: random,
    issuer: "Acme",
    rate_limiter: rate_limiter,
    sessions: sessions,
    drift: drift,
    recovery_code_count: recovery_code_count,
  )

  {service, repo, accounts, clock}
end

# A harness whose MFA service can also end sessions, for the recovery-code case.
private def mfa_harness_with_sessions
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  random = KemalIdentity::Testing::DeterministicRandom.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
  session_repo = KemalIdentity::Testing::MemorySessionRepository.new(accounts)

  sessions = KemalIdentity::Sessions::Service.new(
    sessions: session_repo, clock: clock, random: random
  )

  mfa = KemalIdentity::MFA::Service.new(
    factors: KemalIdentity::Testing::MemoryMfaRepository.new,
    secret_box: KemalIdentity::MFA::AesSecretBox.new(BOX_KEY, random),
    clock: clock,
    random: random,
    issuer: "Acme",
    sessions: sessions,
  )

  {mfa, sessions, session_repo, accounts, clock}
end

private def account(accounts)
  accounts.find_by_id("a1").or_fail
end

# The secret is only ever handed out once, in the provisioning URI. Reading it back from there
# is exactly what an authenticator app does.
private def secret_of(pending : KemalIdentity::MFA::PendingEnrolment) : Bytes
  encoded = URI.parse(pending.provisioning_uri).query_params["secret"]

  KemalIdentity::MFA::Base32.decode?(encoded).or_fail
end

private def code_for(pending, clock, offset : Int32 = 0) : String
  TOTP.code(secret_of(pending), TOTP.counter(clock.now) + offset)
end

# Enrols, confirms, and hands back the recovery codes that came with turning MFA on.
private def enrolled_with_codes(service, accounts, clock, label : String = "phone")
  pending = service.enrol(account(accounts), label)
  service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes
end

# Enrols and confirms in one go, for the specs that are about what happens afterwards.
private def enrolled(service, accounts, clock, label : String = "phone")
  pending = service.enrol(account(accounts), label)
  service.confirm(pending.factor.id, code_for(pending, clock)).or_fail

  pending
end

describe "enrolling a second factor" do
  it "hands back a provisioning URI an authenticator app can read" do
    service, _, accounts, _ = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    pending.provisioning_uri.should start_with("otpauth://totp/Acme%3Aphone?")
    secret_of(pending).size.should eq(KemalIdentity::RandomSource::TOKEN_BYTES)
  end

  it "gives every enrolment a distinct secret" do
    service, _, accounts, _ = mfa_harness

    secrets = Array.new(5) { |i| secret_of(service.enrol(account(accounts), "phone #{i}")) }

    secrets.map(&.hexstring).uniq!.size.should eq(5)
  end

  # A secret that was generated but never proved is a secret nobody may actually hold — a
  # mis-scanned QR code, a clock two minutes out, an app that failed to save. Counting it
  # immediately is how a person locks themselves out of their own account.
  it "does not count until a code has proved it" do
    service, _, accounts, _ = mfa_harness
    service.enrol(account(accounts), "phone")

    service.enrolled?("a1").should be_false
  end

  it "counts once a code has proved it" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    service.confirm(pending.factor.id, code_for(pending, clock)).should_not be_nil
    service.enrolled?("a1").should be_true
  end

  it "refuses to confirm with the wrong code" do
    service, _, accounts, _ = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    service.confirm(pending.factor.id, "000000").should be_nil
    service.enrolled?("a1").should be_false
  end

  it "refuses to confirm a factor that does not exist" do
    service, _, _, _ = mfa_harness

    service.confirm("nope", "123456").should be_nil
  end

  # Refused before the limiter is touched, so an endpoint that is already finished cannot be
  # hammered to spend somebody else's verification quota.
  it "refuses to confirm the same factor twice, without spending any quota" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 2, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    pending = service.enrol(account(accounts), "phone")
    service.confirm(pending.factor.id, code_for(pending, clock))

    clock.advance(30.seconds)
    5.times { service.confirm(pending.factor.id, code_for(pending, clock)).should be_nil }

    # The quota is untouched, so a real code still verifies.
    service.verify("a1", code_for(pending, clock)).should be_a(KemalIdentity::MFA::Verified)
  end

  it "refuses a disabled account" do
    service, _, accounts, clock = mfa_harness
    accounts.disable("a1", clock.now)

    expect_raises(ArgumentError) { service.enrol(account(accounts), "phone") }
  end

  it "refuses a label that would change how the provisioning URI parses" do
    service, _, accounts, _ = mfa_harness

    expect_raises(ArgumentError, /colon/) { service.enrol(account(accounts), "a:b") }
    expect_raises(ArgumentError) { service.enrol(account(accounts), "  ") }
  end

  # The stored secret must be useless to whoever holds the table.
  it "stores the secret only sealed" do
    service, repo, accounts, _ = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    stored = repo.find_factor(pending.factor.id).or_fail

    stored.sealed_secret.should_not eq(secret_of(pending))
    stored.sealed_secret.hexstring.should_not contain(secret_of(pending).hexstring)
  end

  it "redacts the enrolment, so a log line is not a second factor" do
    service, _, accounts, _ = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    "#{pending}".should_not contain("otpauth")
    pending.inspect.should contain("[REDACTED]")
  end
end

describe "verifying a code" do
  it "accepts the current code" do
    service, _, accounts, clock = mfa_harness
    pending = enrolled(service, accounts, clock)

    clock.advance(30.seconds)
    result = service.verify("a1", code_for(pending, clock))

    result.should be_a(KemalIdentity::MFA::Verified)
    result.as(KemalIdentity::MFA::Verified).by_recovery_code?.should be_false
  end

  # The reason this is single-use. A code stays arithmetically correct for its whole period
  # plus the drift either side, which is exactly the window somebody who read it over a
  # shoulder is working in.
  it "refuses the same code a second time" do
    service, _, accounts, clock = mfa_harness
    pending = enrolled(service, accounts, clock)

    clock.advance(30.seconds)
    code = code_for(pending, clock)

    service.verify("a1", code).should be_a(KemalIdentity::MFA::Verified)

    replayed = service.verify("a1", code)
    replayed.should be_a(KemalIdentity::Failed)
    replayed.as(KemalIdentity::Failed).reason
      .should eq(KemalIdentity::FailureReason::ReplayedToken)
  end

  # Within the drift window an older code is still arithmetically valid, and must not work
  # once a later one has been used.
  it "refuses a code older than the one already used" do
    service, _, accounts, clock = mfa_harness
    pending = enrolled(service, accounts, clock)

    clock.advance(60.seconds)
    previous = code_for(pending, clock, offset: -1)

    service.verify("a1", code_for(pending, clock)).should be_a(KemalIdentity::MFA::Verified)
    service.verify("a1", previous).should be_a(KemalIdentity::Failed)
  end

  it "tolerates one step of clock drift either side" do
    service, _, accounts, clock = mfa_harness(drift: 1)
    pending = enrolled(service, accounts, clock)

    clock.advance(30.seconds)
    service.verify("a1", code_for(pending, clock, offset: 1))
      .should be_a(KemalIdentity::MFA::Verified)

    clock.advance(120.seconds)
    service.verify("a1", code_for(pending, clock, offset: -1))
      .should be_a(KemalIdentity::MFA::Verified)
  end

  it "refuses a code further out than the configured drift" do
    service, _, accounts, clock = mfa_harness(drift: 1)
    pending = enrolled(service, accounts, clock)

    clock.advance(30.seconds)
    service.verify("a1", code_for(pending, clock, offset: 3)).should be_a(KemalIdentity::Failed)
  end

  # A wide window is an authentication bypass with a limit on it, not a convenience.
  it "refuses at boot a drift wide enough to be a bypass" do
    expect_raises(KemalIdentity::ConfigurationError, /drift/) { mfa_harness(drift: 3) }
  end

  it "refuses a code from another account's factor" do
    service, _, accounts, clock = mfa_harness
    pending = enrolled(service, accounts, clock)

    clock.advance(30.seconds)
    service.verify("a2", code_for(pending, clock)).should be_a(KemalIdentity::Failed)
  end

  it "refuses everything for an account with no confirmed factor" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")

    service.verify("a1", code_for(pending, clock)).should be_a(KemalIdentity::Failed)
  end

  # Two devices is a normal arrangement, and either should work.
  it "accepts a code from any confirmed factor on the account" do
    service, _, accounts, clock = mfa_harness
    first = enrolled(service, accounts, clock, "laptop")
    clock.advance(30.seconds)
    second = enrolled(service, accounts, clock, "phone")

    clock.advance(30.seconds)
    service.verify("a1", code_for(first, clock)).should be_a(KemalIdentity::MFA::Verified)

    clock.advance(30.seconds)
    service.verify("a1", code_for(second, clock)).should be_a(KemalIdentity::MFA::Verified)
  end

  # Spending the wrong factor's counter would let one device's use lock out the other.
  it "spends only the counter of the factor that matched" do
    service, repo, accounts, clock = mfa_harness
    first = enrolled(service, accounts, clock, "laptop")
    clock.advance(30.seconds)
    second = enrolled(service, accounts, clock, "phone")

    before = repo.find_factor(second.factor.id).or_fail.last_used_counter

    clock.advance(30.seconds)
    service.verify("a1", code_for(first, clock))

    repo.find_factor(second.factor.id).or_fail.last_used_counter.should eq(before)
  end

  it "never raises for anything a client controls" do
    service, _, accounts, clock = mfa_harness
    enrolled(service, accounts, clock)

    ["", "abcdef", "12345", "1234567", "000000", "1" * 2_000_000, "  ", "-1234-"].each do |code|
      service.verify("a1", code).should be_a(KemalIdentity::MFA::VerificationResult)
    end
  end

  # A row sealed under a key the application no longer has is a data problem, and it must not
  # become a 500 on the login path.
  it "fails rather than raising when the stored secret will not open" do
    service, repo, accounts, clock = mfa_harness
    pending = enrolled(service, accounts, clock)

    corrupted = repo.find_factor(pending.factor.id).or_fail
    corrupted.sealed_secret[corrupted.sealed_secret.size - 1] ^= 0x01

    clock.advance(30.seconds)
    service.verify("a1", code_for(pending, clock)).should be_a(KemalIdentity::Failed)
  end
end

# Six digits is one of a million, and a code is valid for ninety seconds with the default
# drift. Without a limit, a million guesses is a few minutes of traffic.
describe "guessing codes in a loop" do
  it "is throttled, and says when to come back" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 3, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    enrolled(service, accounts, clock)

    3.times { service.verify("a1", "000000") }

    denied = service.verify("a1", "000000")
    denied.should be_a(KemalIdentity::Failed)

    failure = denied.as(KemalIdentity::Failed)
    failure.reason.should eq(KemalIdentity::FailureReason::RateLimited)
    failure.retry_after.should_not be_nil
  end

  # Counted before the code is checked, for the reason `RateLimiter` gives: counting after the
  # work means a wrong guess that is slow is a free guess.
  it "throttles a correct code too, once the quota is spent" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 2, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    pending = enrolled(service, accounts, clock)

    2.times { service.verify("a1", "000000") }

    clock.advance(30.seconds)
    result = service.verify("a1", code_for(pending, clock))

    result.should be_a(KemalIdentity::Failed)
    result.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::RateLimited)
  end

  it "clears the quota once a code verifies" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 3, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    pending = enrolled(service, accounts, clock)

    service.verify("a1", "000000")

    clock.advance(30.seconds)
    service.verify("a1", code_for(pending, clock)).should be_a(KemalIdentity::MFA::Verified)

    # Three more wrong guesses must all be *rejected on their merits*. Without the reset the
    # earlier failure and the success would still be on the counter, and the third of these
    # would come back throttled instead.
    3.times do
      result = service.verify("a1", "000000")

      result.as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::InvalidCredential)
    end
  end

  # An unconfirmed factor is still a guessable secret.
  it "throttles confirmation attempts too" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 2, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    pending = service.enrol(account(accounts), "phone")

    2.times { service.confirm(pending.factor.id, "000000") }

    service.confirm(pending.factor.id, code_for(pending, clock)).should be_nil
    service.enrolled?("a1").should be_false
  end
end

# The way back in when the phone is gone, and therefore a complete bypass of the second factor.
describe "recovery codes" do
  it "are issued when a first factor turns MFA on" do
    service, _, accounts, clock = mfa_harness(recovery_code_count: 10)
    pending = service.enrol(account(accounts), "phone")

    confirmed = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail

    confirmed.recovery_codes.size.should eq(10)
    service.unused_recovery_codes("a1").should eq(10)
  end

  # Re-enrolling a second device must not silently void the list somebody wrote down.
  it "are not reissued when a second factor is added" do
    service, _, accounts, clock = mfa_harness
    enrolled(service, accounts, clock, "laptop")

    clock.advance(30.seconds)
    second = service.enrol(account(accounts), "phone")
    confirmed = service.confirm(second.factor.id, code_for(second, clock)).or_fail

    confirmed.recovery_codes.should be_empty
    service.unused_recovery_codes("a1").should eq(10)
  end

  it "each work exactly once" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    codes = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    result = service.redeem_recovery_code("a1", codes.first.reveal)
    result.should be_a(KemalIdentity::MFA::Verified)
    result.as(KemalIdentity::MFA::Verified).by_recovery_code?.should be_true

    service.redeem_recovery_code("a1", codes.first.reveal).should be_a(KemalIdentity::Failed)
    service.unused_recovery_codes("a1").should eq(9)
  end

  it "are distinct from one another" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    codes = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    codes.map(&.reveal).uniq!.size.should eq(codes.size)
  end

  it "redact themselves" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    code = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes.first

    "#{code}".should_not contain(code.reveal)
  end

  # A person typing one back will not reproduce the spacing it was printed with.
  it "accept the spacing a person types back" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    code = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes.first

    spaced = code.reveal.chars.each_slice(4).map(&.join).join(" ")

    service.redeem_recovery_code("a1", spaced).should be_a(KemalIdentity::MFA::Verified)
  end

  it "reject a code belonging to another account" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    codes = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    service.redeem_recovery_code("a2", codes.first.reveal).should be_a(KemalIdentity::Failed)
    service.unused_recovery_codes("a1").should eq(10)
  end

  it "are throttled like any other code submission" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 2, window: 15.minutes, clock: KemalIdentity::Testing::TestClock.new(
      KemalIdentity::Testing::FIXED_NOW
    )
    )
    service, _, accounts, clock = mfa_harness(rate_limiter: limiter)
    pending = service.enrol(account(accounts), "phone")
    codes = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    2.times { service.redeem_recovery_code("a1", "x" * 27) }

    denied = service.redeem_recovery_code("a1", codes.first.reveal)
    denied.should be_a(KemalIdentity::Failed)
    denied.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::RateLimited)
  end

  it "never raise for anything a client controls" do
    service, _, accounts, clock = mfa_harness
    enrolled(service, accounts, clock)

    ["", "   ", "x", "!" * 27, "a" * 2_000_000, "----"].each do |candidate|
      service.redeem_recovery_code("a1", candidate)
        .should be_a(KemalIdentity::MFA::VerificationResult)
    end
  end

  # Rejected on shape, before hashing and before any lookup, and recorded as such: an audit
  # trail full of `InvalidCredential` cannot tell a wrong code from a scanner sending noise.
  it "reject a value of the wrong shape before touching the store" do
    service, _, accounts, clock = mfa_harness
    enrolled(service, accounts, clock)

    ["x", "!" * 43, "a" * 2_000_000, "  "].each do |candidate|
      result = service.redeem_recovery_code("a1", candidate)

      result.as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::MalformedCredential)
    end
  end

  # This is what somebody calls when they think the old list leaked, so the old list must not
  # survive it.
  it "are voided when regenerated" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    old = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    fresh = service.regenerate_recovery_codes("a1")

    service.redeem_recovery_code("a1", old.first.reveal).should be_a(KemalIdentity::Failed)
    service.redeem_recovery_code("a1", fresh.first.reveal).should be_a(KemalIdentity::MFA::Verified)
  end
end

# `docs/02-security-model.md` lists MFA recovery among the events that revoke every session an
# account has. Somebody is redeeming a code because the device is gone, and "lost" and "taken"
# look identical from here.
describe "redeeming a recovery code and the account's other sessions" do
  it "signs the account's other sessions out" do
    mfa, sessions, repo, accounts, clock = mfa_harness_with_sessions
    holder = accounts.find_by_id("a1").or_fail

    elsewhere = sessions.start(holder, KemalIdentity::AssuranceLevel::Password)
    current = sessions.start(holder, KemalIdentity::AssuranceLevel::Password)

    pending = mfa.enrol(holder, "phone")
    codes = mfa.confirm(
      pending.factor.id,
      TOTP.code(
        KemalIdentity::MFA::Base32.decode?(
          URI.parse(pending.provisioning_uri).query_params["secret"]
        ).or_fail,
        TOTP.counter(clock.now)
      )
    ).or_fail.recovery_codes

    mfa.redeem_recovery_code("a1", codes.first.reveal, except_session_id: current.record.id)
      .should be_a(KemalIdentity::MFA::Verified)

    repo.find_by_digest(elsewhere.record.token_digest).or_fail.session.revoked?.should be_true
  end

  # Or the person is signed out by their own recovery, which is not what a way back in is for.
  it "spares the session doing the redeeming" do
    mfa, sessions, repo, accounts, clock = mfa_harness_with_sessions
    holder = accounts.find_by_id("a1").or_fail
    current = sessions.start(holder, KemalIdentity::AssuranceLevel::Password)

    pending = mfa.enrol(holder, "phone")
    codes = mfa.confirm(
      pending.factor.id,
      TOTP.code(
        KemalIdentity::MFA::Base32.decode?(
          URI.parse(pending.provisioning_uri).query_params["secret"]
        ).or_fail,
        TOTP.counter(clock.now)
      )
    ).or_fail.recovery_codes

    mfa.redeem_recovery_code("a1", codes.first.reveal, except_session_id: current.record.id)

    repo.find_by_digest(current.record.token_digest).or_fail.session.revoked?.should be_false
  end

  # A failed redemption must not be a way to sign somebody out.
  it "leaves every session alone when the code does not verify" do
    mfa, sessions, repo, accounts, _ = mfa_harness_with_sessions
    holder = accounts.find_by_id("a1").or_fail
    session = sessions.start(holder, KemalIdentity::AssuranceLevel::Password)

    mfa.redeem_recovery_code("a1", "x" * 43).should be_a(KemalIdentity::Failed)

    repo.find_by_digest(session.record.token_digest).or_fail.session.revoked?.should be_false
  end
end

describe "removing a factor" do
  it "stops that factor working and leaves the others" do
    service, _, accounts, clock = mfa_harness
    first = enrolled(service, accounts, clock, "laptop")
    clock.advance(30.seconds)
    second = enrolled(service, accounts, clock, "phone")

    service.remove(first.factor.id).should be_true

    clock.advance(30.seconds)
    service.verify("a1", code_for(first, clock)).should be_a(KemalIdentity::Failed)
    service.verify("a1", code_for(second, clock)).should be_a(KemalIdentity::MFA::Verified)
  end

  # Removing one of two devices is not "MFA is off", and voiding the codes would surprise
  # somebody in the direction of locking them out.
  it "leaves the recovery codes alone while another factor remains" do
    service, _, accounts, clock = mfa_harness
    first = enrolled(service, accounts, clock, "laptop")
    clock.advance(30.seconds)
    enrolled(service, accounts, clock, "phone")

    service.remove(first.factor.id)

    service.enrolled?("a1").should be_true
    service.unused_recovery_codes("a1").should eq(10)
  end

  # Removing the *last* one is "MFA is off", and then the codes have to go with it — for the
  # reason `#disable` already voids them. A list written down years ago that survives into a
  # later re-enrolment is a full bypass of the new factor. MFA-01 in `blueprints/0025`.
  it "voids the recovery codes when the last factor goes" do
    service, _, accounts, clock = mfa_harness
    only = enrolled(service, accounts, clock, "laptop")

    service.remove(only.factor.id).should be_true

    service.enrolled?("a1").should be_false
    service.unused_recovery_codes("a1").should eq(0)
  end

  it "returns false for a factor that was not there" do
    service, _, _, _ = mfa_harness

    service.remove("nope").should be_false
  end

  # A factor id is not secret material — it is in the audit trail and in every management
  # listing — so the form a route hands a client-supplied id to must be scoped to the caller.
  # The same defect `ApiTokens::Service#revoke` had before v0.9.0. MFA-01.
  describe "scoped to an owner" do
    it "refuses another account's factor" do
      service, _, accounts, clock = mfa_harness
      victim = enrolled(service, accounts, clock, "laptop")

      service.remove(victim.factor.id, "somebody-else").should be_false
      service.factors("a1").size.should eq(1)
    end

    it "answers the same for a factor that does not exist" do
      service, _, _, _ = mfa_harness

      service.remove("nope", "a1").should be_false
    end

    it "refuses the account's last factor unless the caller asks for it" do
      service, _, accounts, clock = mfa_harness
      only = enrolled(service, accounts, clock, "laptop")

      # The default is the safe one for a settings screen: "remove this device" must not
      # silently mean "turn MFA off".
      service.remove(only.factor.id, "a1").should be_false
      service.enrolled?("a1").should be_true
      service.unused_recovery_codes("a1").should eq(10)

      service.remove(only.factor.id, "a1", allow_last: true).should be_true
      service.enrolled?("a1").should be_false
      service.unused_recovery_codes("a1").should eq(0)
    end

    it "removes one of several without the caller having to ask" do
      service, _, accounts, clock = mfa_harness
      first = enrolled(service, accounts, clock, "laptop")
      clock.advance(30.seconds)
      second = enrolled(service, accounts, clock, "phone")

      service.remove(first.factor.id, "a1").should be_true

      service.factors("a1").map(&.id).should eq([second.factor.id])
    end

    it "does not count an unconfirmed factor as the one keeping MFA on" do
      service, _, accounts, clock = mfa_harness
      confirmed = enrolled(service, accounts, clock, "laptop")
      service.enrol(account(accounts), "half-finished")

      # Two rows, one confirmed. Removing the confirmed one still leaves the account with no
      # second factor anybody can produce, so it is still the last one.
      service.remove(confirmed.factor.id, "a1").should be_false
    end
  end
end

describe "disabling MFA" do
  it "removes every factor" do
    service, _, accounts, clock = mfa_harness
    first = enrolled(service, accounts, clock, "laptop")
    clock.advance(30.seconds)
    enrolled(service, accounts, clock, "phone")

    service.disable("a1").should eq(2)

    service.enrolled?("a1").should be_false
    clock.advance(30.seconds)
    service.verify("a1", code_for(first, clock)).should be_a(KemalIdentity::Failed)
  end

  # Codes that outlive the factors they were issued alongside are a bypass of a control that
  # no longer exists.
  it "voids the recovery codes with them" do
    service, _, accounts, clock = mfa_harness
    pending = service.enrol(account(accounts), "phone")
    codes = service.confirm(pending.factor.id, code_for(pending, clock)).or_fail.recovery_codes

    service.disable("a1")

    service.unused_recovery_codes("a1").should eq(0)
    service.redeem_recovery_code("a1", codes.first.reveal).should be_a(KemalIdentity::Failed)
  end

  it "returns zero for an account that had none" do
    service, _, _, _ = mfa_harness

    service.disable("a1").should eq(0)
  end
end

# Two properties of this design are deliberately not asserted below, because no behavioural
# spec can see them, and mutation testing reports both as survivors:
#
# * **`TOTP.match` checks the code's shape before computing any HMAC.** Removing that check
#   changes nothing an assertion can reach — a wrong-length candidate still fails the
#   comparison. It is a cost guard: it is what makes a two-megabyte "code" a length comparison
#   rather than several HMACs and a two-megabyte compare.
# * **`AesSecretBox` derives its encryption and MAC keys from different contexts.** Give both
#   the same context and every round trip still works. The property being bought is that
#   breaking one key does not hand over the other, which is a statement about a construction
#   rather than about an output.
describe "configuring the service" do
  it "refuses an issuer that would change how the provisioning URI parses" do
    expect_raises(KemalIdentity::ConfigurationError, /issuer/) do
      KemalIdentity::MFA::Service.new(
        factors: KemalIdentity::Testing::MemoryMfaRepository.new,
        secret_box: KemalIdentity::MFA::AesSecretBox.new(
          BOX_KEY, KemalIdentity::Testing::DeterministicRandom.new
        ),
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
        random: KemalIdentity::Testing::DeterministicRandom.new,
        issuer: "Acme:Corp",
      )
    end
  end

  it "refuses a recovery code count of zero, which would issue none" do
    expect_raises(KemalIdentity::ConfigurationError, /recovery_code_count/) do
      mfa_harness(recovery_code_count: 0)
    end
  end
end

# MFA-04 in `blueprints/0025` found this by redeeming a code the shard had just issued and being
# told it was malformed. `RandomSource#token` is base64url, whose alphabet contains `-`, and
# `redeem_recovery_code` stripped `-` as a separator before checking the length — so a code
# containing one was shortened by a character and rejected. Measured: 46.8% of codes, on the one
# credential that is the last way in.
describe "the recovery code alphabet" do
  it "issues codes that contain no separator at all" do
    service, _, accounts, clock = mfa_harness(recovery_code_count: 50)
    codes = enrolled_with_codes(service, accounts, clock)

    codes.size.should eq(50)
    codes.each do |code|
      code.reveal.includes?('-').should be_false
      code.reveal.size.should eq(KemalIdentity::RandomSource.token_length(32))
    end
  end

  it "redeems every code it issues" do
    service, _, accounts, clock = mfa_harness(recovery_code_count: 25)
    codes = enrolled_with_codes(service, accounts, clock)

    # Not "the first one works": all of them, because the defect was a coin flip per code and a
    # spec that checked one had an even chance of passing.
    codes.each do |code|
      service.redeem_recovery_code("a1", code.reveal).should be_a(KemalIdentity::MFA::Verified)
    end

    service.unused_recovery_codes("a1").should eq(0)
  end

  it "still accepts a code that already contains a hyphen, which earlier versions issued" do
    service, repo, accounts, clock = mfa_harness
    enrolled(service, accounts, clock, "laptop")

    # A list from before the fix: written straight into the store, hyphen and all.
    legacy = KemalIdentity::Secret.new("abc-def#{"g" * (KemalIdentity::RandomSource.token_length(32) - 7)}")
    legacy.reveal.size.should eq(KemalIdentity::RandomSource.token_length(32))

    repo.replace_recovery_codes("a1", [
      KemalIdentity::MFA::RecoveryCode.new(
        id: "r1", account_id: "a1", code_digest: legacy.digest, created_at: clock.now
      ),
    ])

    service.redeem_recovery_code("a1", legacy.reveal).should be_a(KemalIdentity::MFA::Verified)
  end

  it "accepts a code typed with the separators an application displayed" do
    service, repo, accounts, clock = mfa_harness
    enrolled(service, accounts, clock, "laptop")

    stored = KemalIdentity::Secret.new("h" * KemalIdentity::RandomSource.token_length(32))
    repo.replace_recovery_codes("a1", [
      KemalIdentity::MFA::RecoveryCode.new(
        id: "r1", account_id: "a1", code_digest: stored.digest, created_at: clock.now
      ),
    ])

    grouped = stored.reveal.chars.each_slice(4).map(&.join).join('-')
    grouped.should contain('-')

    service.redeem_recovery_code("a1", " #{grouped} ").should be_a(KemalIdentity::MFA::Verified)
  end

  it "still refuses something of the wrong length under either reading" do
    service, _, accounts, clock = mfa_harness
    enrolled(service, accounts, clock, "laptop")

    KemalIdentity::Testing.should_fail_with(
      service.redeem_recovery_code("a1", "too-short"),
      KemalIdentity::FailureReason::MalformedCredential
    )
  end
end

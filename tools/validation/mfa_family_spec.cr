require "spec"
require "uri"
require "kemal_identity"
require "kemal_identity/testing"

# MFA-01 and MFA-04, from a consumer project.
#
# MFA-01: a person registers two authenticator apps and a hardware credential, then loses one
# device. MFA-04: they lose *every* factor and support has to restore access without creating an
# account-takeover shortcut.

alias TOTP = KemalIdentity::MFA::TOTP

BOX_KEY = KemalIdentity::Secret.new("m" * 32)
NOWM    = Time.utc(2026, 9, 2, 12, 0, 0)

record MfaRig,
  clock : KemalIdentity::Testing::TestClock,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  factors : KemalIdentity::Testing::MemoryMfaRepository,
  sessions : KemalIdentity::Sessions::Service,
  mfa : KemalIdentity::MFA::Service

def rig(
  limiter : KemalIdentity::RateLimiter = KemalIdentity::NullRateLimiter.new,
  logins : Array(String) = ["ada", "mallory"],
) : MfaRig
  clock = KemalIdentity::Testing::TestClock.new(NOWM)
  random = KemalIdentity::Testing::DeterministicRandom.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new

  logins.each do |id|
    accounts.insert(KemalIdentity::Accounts::Account.new(
      id: id, normalized_login: "#{id}@example.com", auth_version: 1,
      created_at: NOWM, updated_at: NOWM, password_digest: "digest", password_scheme: "test",
    ))
  end

  session_repo = KemalIdentity::Testing::MemorySessionRepository.new(accounts)
  sessions = KemalIdentity::Sessions::Service.new(
    sessions: session_repo, clock: clock, random: random
  )

  factors = KemalIdentity::Testing::MemoryMfaRepository.new

  MfaRig.new(
    clock: clock, accounts: accounts, factors: factors, sessions: sessions,
    mfa: KemalIdentity::MFA::Service.new(
      factors: factors,
      secret_box: KemalIdentity::MFA::AesSecretBox.new(BOX_KEY, random),
      clock: clock, random: random, issuer: "Acme",
      rate_limiter: limiter, sessions: sessions,
    )
  )
end

def secret_of(pending : KemalIdentity::MFA::PendingEnrolment) : Bytes
  KemalIdentity::MFA::Base32.decode?(
    URI.parse(pending.provisioning_uri).query_params["secret"]
  ).not_nil!
end

def code_for(pending : KemalIdentity::MFA::PendingEnrolment, clock, offset : Int32 = 0) : String
  TOTP.code(secret_of(pending), TOTP.counter(clock.now) + offset)
end

def enrol!(r : MfaRig, label : String, account_id : String = "ada")
  pending = r.mfa.enrol(r.accounts.find_by_id(account_id).not_nil!, label)
  confirmed = r.mfa.confirm(pending.factor.id, code_for(pending, r.clock))
  {pending, confirmed}
end

describe "MFA-01 — several factors on one account" do
  it "gives every factor a first-class id, label and lifecycle" do
    r = rig

    phone, first = enrol!(r, "phone")
    tablet, second = enrol!(r, "tablet")
    key, third = enrol!(r, "yubikey")

    [phone, tablet, key].map(&.factor.id).uniq!.size.should eq(3)

    # Recovery codes come with the *first* factor only: re-enrolling a second device must not
    # silently void the list somebody wrote down.
    first.not_nil!.recovery_codes.size.should eq(10)
    second.not_nil!.recovery_codes.should be_empty
    third.not_nil!.recovery_codes.should be_empty

    listed = r.mfa.factors("ada")
    listed.size.should eq(3)
    listed.map(&.label).sort!.should eq(["phone", "tablet", "yubikey"])
    listed.each(&.confirmed?.should be_true)
  end

  it "verifies against whichever factor the person actually used, and says which" do
    r = rig

    phone, _ = enrol!(r, "phone")
    tablet, _ = enrol!(r, "tablet")

    r.clock.advance(1.minute)
    verified = r.mfa.verify("ada", code_for(tablet, r.clock)).as(KemalIdentity::MFA::Verified)
    verified.factor.not_nil!.id.should eq(tablet.factor.id)
    verified.by_recovery_code?.should be_false

    r.clock.advance(1.minute)
    r.mfa.verify("ada", code_for(phone, r.clock)).as(KemalIdentity::MFA::Verified)
      .factor.not_nil!.id.should eq(phone.factor.id)
  end

  it "spends only the factor that matched, so the other device still works" do
    r = rig

    phone, _ = enrol!(r, "phone")
    tablet, _ = enrol!(r, "tablet")

    r.clock.advance(1.minute)
    phone_code = code_for(phone, r.clock)
    tablet_code = code_for(tablet, r.clock)

    r.mfa.verify("ada", phone_code).should be_a(KemalIdentity::MFA::Verified)

    # The phone's counter is spent — that is the replay an attacker who watched somebody type it
    # would attempt.
    KemalIdentity::Testing.should_fail_with(
      r.mfa.verify("ada", phone_code), KemalIdentity::FailureReason::ReplayedToken
    )

    # The tablet's is not. A counter is per factor, so one device's replay protection does not
    # consume another's.
    r.mfa.verify("ada", tablet_code).should be_a(KemalIdentity::MFA::Verified)
  end

  it "cannot have one factor's spent counter replayed through another" do
    r = rig

    phone, _ = enrol!(r, "phone")
    tablet, _ = enrol!(r, "tablet")

    # The two factors hold *different* secrets, and the shard generates them — `enrol` takes no
    # secret, so two rows cannot share one by an application's mistake. That is what makes the
    # cross-factor replay this condition asks about unreachable rather than merely unlikely.
    secret_of(phone).should_not eq(secret_of(tablet))

    r.clock.advance(1.minute)
    code = code_for(phone, r.clock)
    r.mfa.verify("ada", code).should be_a(KemalIdentity::MFA::Verified)

    KemalIdentity::Testing.should_fail_with(
      r.mfa.verify("ada", code), KemalIdentity::FailureReason::ReplayedToken
    )
  end

  it "keeps the rest working when one device is lost" do
    r = rig

    phone, _ = enrol!(r, "phone")
    tablet, _ = enrol!(r, "tablet")

    r.mfa.remove(phone.factor.id, "ada").should be_true

    r.mfa.factors("ada").map(&.id).should eq([tablet.factor.id])
    r.mfa.enrolled?("ada").should be_true

    # And the recovery codes are untouched: removing one of two devices is not "MFA is off", and
    # voiding the list would be a surprise in the direction of locking somebody out.
    r.mfa.unused_recovery_codes("ada").should eq(10)

    r.clock.advance(1.minute)
    r.mfa.verify("ada", code_for(tablet, r.clock)).should be_a(KemalIdentity::MFA::Verified)
  end

  it "refuses to remove the last confirmed factor unless the caller says so" do
    r = rig

    phone, _ = enrol!(r, "phone")

    # The default refuses, because "remove a device" and "turn MFA off" are different intents
    # and the second one lowers the account's security.
    r.mfa.remove(phone.factor.id, "ada").should be_false
    r.mfa.enrolled?("ada").should be_true

    # Said explicitly, it goes — and takes the recovery codes with it, because codes that
    # outlive the factors they were issued alongside are a bypass of a control that is gone.
    r.mfa.remove(phone.factor.id, "ada", allow_last: true).should be_true
    r.mfa.enrolled?("ada").should be_false
    r.mfa.unused_recovery_codes("ada").should eq(0)
  end

  it "will not remove somebody else's factor" do
    r = rig

    victim, _ = enrol!(r, "phone", account_id: "ada")

    # A factor id is not secret material: it is in `mfa.verified` and `mfa.factor_removed` audit
    # lines and in any management listing. So the route that lets a client name one must be
    # scoped to the caller, exactly as token revocation is.
    r.mfa.remove(victim.factor.id, "mallory").should be_false
    r.mfa.factors("ada").size.should eq(1)

    # And an id that does not exist answers the same way, so the difference cannot be used to
    # discover whether one is real.
    r.mfa.remove("no-such-factor", "mallory").should be_false
  end

  it "will not confirm somebody else's pending enrolment" do
    r = rig

    pending = r.mfa.enrol(r.accounts.find_by_id("ada").not_nil!, "phone")

    r.mfa.confirm(pending.factor.id, code_for(pending, r.clock), account_id: "mallory")
      .should be_nil
    r.mfa.factors("ada").first.confirmed?.should be_false
  end

  it "identifies the factor in the audit trail and never its secret" do
    r = rig

    phone, _ = enrol!(r, "phone")

    factor = r.mfa.factors("ada").first
    sealed = factor.sealed_secret

    # `Factor` redacts itself: the sealed secret cannot reach a log line or a template through
    # an accidental interpolation.
    factor.to_s.should_not contain(sealed.hexstring)
    factor.inspect.should_not contain(sealed.hexstring)
    factor.to_s.should contain(factor.id)

    # The provisioning URI does carry the secret — it has to, that is what the QR code is — and
    # it is deliberately not on the stored record: only `PendingEnrolment` has it, once.
    phone.provisioning_uri.should contain("secret=")
    r.mfa.factors("ada").first.responds_to?(:provisioning_uri).should be_false
  end
end

describe "MFA-04 — recovery, and what it must not become" do
  it "names recovery separately from a real second factor" do
    r = rig

    _, confirmed = enrol!(r, "phone")
    codes = confirmed.not_nil!.recovery_codes

    result = KemalIdentity::Testing.should_verify(
      r.mfa.redeem_recovery_code("ada", codes.first.reveal)
    )

    # The distinction the application needs in order to treat the two differently at all.
    result.by_recovery_code?.should be_true
    result.factor.should be_nil
  end

  it "has an assurance level of its own, below a real second factor" do
    # Before this level existed, the documented flow raised the session to `MFA` with a recovery
    # code, so a permission declared `minimum_assurance: MFA` — "changing payout details needs
    # phishing-resistant MFA" — was reachable with a printed list.
    KemalIdentity::AssuranceLevel::Password.value.should eq(20)
    KemalIdentity::AssuranceLevel::Recovery.value.should eq(25)
    KemalIdentity::AssuranceLevel::MFA.value.should eq(30)

    recovered = KemalIdentity::Principal.new(
      subject: "ada",
      assurance: KemalIdentity::AssuranceLevel::Recovery,
      authenticated_at: NOWM,
      mfa_verified_at: NOWM,
    )

    # In, and able to reach whatever a password reaches.
    recovered.at_least?(KemalIdentity::AssuranceLevel::Password).should be_true

    # And not standing in for a device.
    recovered.at_least?(KemalIdentity::AssuranceLevel::MFA).should be_false

    # Fresh, because somebody just typed something: recovery is an interactive act, unlike a
    # remembered cookie or an API token.
    recovered.fresh?(within: 1.minute, now: NOWM).should be_true
  end

  it "issues codes that can all actually be redeemed" do
    r = rig

    _, confirmed = enrol!(r, "phone")
    codes = confirmed.not_nil!.recovery_codes

    # The defect this replaced was a coin flip per code — 46.8% of them contained a `-`, which
    # the redemption path stripped before checking the length and then called malformed. A spec
    # that tried one code had an even chance of passing.
    codes.each { |code| code.reveal.includes?('-').should be_false }

    codes.each_with_index do |code, index|
      KemalIdentity::Testing.should_verify(r.mfa.redeem_recovery_code("ada", code.reveal))
      r.mfa.unused_recovery_codes("ada").should eq(codes.size - index - 1)
    end
  end

  it "signs the account's other sessions out, sparing the one doing the recovery" do
    r = rig

    _, confirmed = enrol!(r, "phone")
    codes = confirmed.not_nil!.recovery_codes

    account = r.accounts.find_by_id("ada").not_nil!
    current = r.sessions.start(account, KemalIdentity::AssuranceLevel::Password)
    elsewhere = r.sessions.start(account, KemalIdentity::AssuranceLevel::MFA)

    r.mfa.redeem_recovery_code("ada", codes.first.reveal, except_session_id: current.record.id)
      .should be_a(KemalIdentity::MFA::Verified)

    # "Lost" and "taken" look identical from here, so whatever is already signed in elsewhere is
    # exactly what needs ending.
    r.sessions.resolve(elsewhere.token.reveal).should be_a(KemalIdentity::Failed)
    r.sessions.resolve(current.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "spends a code exactly once and reports how many are left" do
    r = rig

    _, confirmed = enrol!(r, "phone")
    codes = confirmed.not_nil!.recovery_codes
    codes.size.should eq(10)

    r.mfa.redeem_recovery_code("ada", codes.first.reveal).should be_a(KemalIdentity::MFA::Verified)
    r.mfa.unused_recovery_codes("ada").should eq(9)

    KemalIdentity::Testing.should_fail_with(
      r.mfa.redeem_recovery_code("ada", codes.first.reveal),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  it "is rate limited, and refuses rather than guessing when the limiter is unavailable" do
    limited = rig(limiter: KemalIdentity::FixedWindowRateLimiter.new(
      limit: 3, window: 1.hour, clock: KemalIdentity::Testing::TestClock.new(NOWM)
    ))

    _, confirmed = enrol!(limited, "phone")
    confirmed.not_nil!.recovery_codes

    # Enrolment and confirmation already spent attempts; the limit is per account and shared
    # across verify, confirm and recovery, which is the conservative arrangement.
    outcomes = 6.times.map { limited.mfa.redeem_recovery_code("ada", "0" * 10) }.to_a
    outcomes.any? do |outcome|
      outcome.is_a?(KemalIdentity::Failed) &&
        outcome.reason == KemalIdentity::FailureReason::RateLimited
    end.should be_true
  end

  it "cannot be reached with an API token, because a token is not an interactive credential" do
    # The chain MFA-04 asks about: an automated credential must not be a way into recovery. The
    # shard's half of that is `AssuranceLevel::ApiToken` being below `Password` and `fresh?`
    # answering false for it, so a route guarding recovery with `require_fresh!` refuses a
    # token-bearing request outright.
    token_principal = KemalIdentity::Principal.new(
      subject: "ada",
      assurance: KemalIdentity::AssuranceLevel::ApiToken,
      authenticated_at: NOWM,
      credential: KemalIdentity::CredentialRef.new(KemalIdentity::CredentialKind::ApiToken, id: "t1"),
    )

    token_principal.fresh?(within: 1.second, now: NOWM).should be_false
    token_principal.at_least?(KemalIdentity::AssuranceLevel::Password).should be_false

    remembered = KemalIdentity::Principal.new(
      subject: "ada",
      assurance: KemalIdentity::AssuranceLevel::Remembered,
      authenticated_at: NOWM,
    )
    remembered.fresh?(within: 1.second, now: NOWM).should be_false
  end

  it "replaces a lost factor set only after the old ones are gone, and reissues codes" do
    r = rig

    phone, confirmed = enrol!(r, "phone")
    first_codes = confirmed.not_nil!.recovery_codes.map(&.reveal)

    # Support-assisted recovery: every factor gone, every code with them.
    r.mfa.disable("ada").should eq(1)
    r.mfa.enrolled?("ada").should be_false
    r.mfa.unused_recovery_codes("ada").should eq(0)

    # The codes from before do not survive the reset — they would be a bypass of a control that
    # no longer exists.
    KemalIdentity::Testing.should_fail_with(
      r.mfa.redeem_recovery_code("ada", first_codes.first),
      KemalIdentity::FailureReason::InvalidCredential
    )

    # Enrolling again issues a fresh list, because this is now the first factor again.
    r.clock.advance(1.minute)
    _, again = enrol!(r, "new phone")
    second_codes = again.not_nil!.recovery_codes
    second_codes.size.should eq(10)
    second_codes.map(&.reveal).should_not eq(first_codes)

    phone.factor.id.should_not eq(r.mfa.factors("ada").first.id)
  end

  it "voids the old list when codes are regenerated" do
    r = rig

    _, confirmed = enrol!(r, "phone")
    old = confirmed.not_nil!.recovery_codes.map(&.reveal)

    fresh = r.mfa.regenerate_recovery_codes("ada")
    fresh.size.should eq(10)

    KemalIdentity::Testing.should_fail_with(
      r.mfa.redeem_recovery_code("ada", old.first),
      KemalIdentity::FailureReason::InvalidCredential
    )
    r.mfa.redeem_recovery_code("ada", fresh.first.reveal).should be_a(KemalIdentity::MFA::Verified)
  end
end

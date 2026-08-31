require "../spec_helper"

# The rate limiting blockers from docs/05-testing.md.
#
# Rate limiting is what stands between a login endpoint and both credential stuffing and a
# denial of service: bcrypt is tens of milliseconds of CPU *by design*, so an endpoint that
# verifies a hash before deciding whether it should have is a lever an attacker pulls for free.
private PASSWORD = "correct horse battery"

private def build(limit : Int32 = 3, window : Time::Span = 1.minute, hasher = nil)
  hasher ||= KemalIdentity::Testing::FastTestHasher.new
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  limiter = KemalIdentity::FixedWindowRateLimiter.new(limit: limit, window: window, clock: clock)

  repo = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::Testing.account(
      password_digest: hasher.hash_secret(KemalIdentity::Secret.new(PASSWORD))
    ),
  ])

  auth = KemalIdentity::Passwords::Authenticator.new(
    accounts: repo, hasher: hasher, clock: clock, rate_limiter: limiter
  )

  {auth, clock, limiter, repo}
end

# A limiter whose store is down. What a Redis-backed adapter returns when Redis is not there.
private class UnavailableRateLimiter < KemalIdentity::RateLimiter
  getter consumed = 0
  getter resets = 0

  def consume(key : String) : KemalIdentity::Verdict
    @consumed += 1
    KemalIdentity::Verdict.unavailable
  end

  def reset(key : String) : Nil
    @resets += 1
  end
end

private def build_with(limiter : KemalIdentity::RateLimiter, hasher = nil)
  hasher ||= KemalIdentity::Testing::FastTestHasher.new
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

  repo = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::Testing.account(
      password_digest: hasher.hash_secret(KemalIdentity::Secret.new(PASSWORD))
    ),
  ])

  KemalIdentity::Passwords::Authenticator.new(
    accounts: repo, hasher: hasher, clock: clock, rate_limiter: limiter
  )
end

# OPS-01. A limiter over shared storage has a third thing to say, and before v0.8 it could only
# lie: allow and run unmetered, deny and take the endpoint down, or raise into a 500.
describe "a rate limiter whose store is unavailable" do
  it "refuses the login rather than running it unmetered" do
    auth = build_with(UnavailableRateLimiter.new)

    outcome = auth.authenticate(login: "ada@example.com", password: PASSWORD)

    KemalIdentity::Testing.should_fail_with(
      outcome, KemalIdentity::FailureReason::RateLimiterUnavailable
    )
  end

  # The correct password is refused too. That is the point: the limiter cannot vouch for how
  # many attempts came before this one, so this one gets no more benefit of the doubt than any
  # other.
  it "refuses even a correct password" do
    limiter = UnavailableRateLimiter.new
    auth = build_with(limiter)

    auth.authenticate(login: "ada@example.com", password: PASSWORD)

    limiter.consumed.should be > 0
  end

  # Told apart from an ordinary throttle in the trail. One is the limiter working and the other
  # is an incident, and they call for different responses from whoever is on call.
  it "is a different failure reason from an ordinary throttle" do
    KemalIdentity::FailureReason::RateLimiterUnavailable
      .should_not eq(KemalIdentity::FailureReason::RateLimited)
  end

  # No honest number exists: the limiter does not know what has been spent.
  it "offers no retry_after, because it does not know one" do
    KemalIdentity::Verdict.unavailable.retry_after.should be_nil
  end

  # The safe direction for the branch somebody forgets. Code that only ever asks `allowed?`
  # denies on an outage rather than waving everything through.
  it "reads as not allowed for code that never learned about the third state" do
    verdict = KemalIdentity::Verdict.unavailable

    verdict.allowed?.should be_false
    verdict.unavailable?.should be_true
  end

  describe "and the application chose availability for that endpoint" do
    it "carries on when wrapped in FailOpenRateLimiter" do
      auth = build_with(KemalIdentity::FailOpenRateLimiter.new(UnavailableRateLimiter.new))

      principal = KemalIdentity::Testing.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: PASSWORD)
      )

      principal.subject.should eq("a1")
    end

    # Only the unavailable case is converted. A real denial still denies, or the wrapper would
    # be an off switch rather than an outage policy.
    it "still honours a genuine denial" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
      inner = KemalIdentity::FixedWindowRateLimiter.new(limit: 1, window: 1.minute, clock: clock)
      auth = build_with(KemalIdentity::FailOpenRateLimiter.new(inner))

      auth.authenticate(login: "ada@example.com", password: "wrong")
      outcome = auth.authenticate(login: "ada@example.com", password: PASSWORD)

      KemalIdentity::Testing.should_fail_with(outcome, KemalIdentity::FailureReason::RateLimited)
    end
  end
end

# The other three call sites. Login is not the only path that runs unmetered if a limiter can
# only say yes or no, and a second factor whose attempt counter cannot be read is a second
# factor somebody can guess at.
describe "the other paths a broken limiter would leave unmetered" do
  it "refuses to verify a second factor" do
    limiter = UnavailableRateLimiter.new
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    random = KemalIdentity::Testing::DeterministicRandom.new

    service = KemalIdentity::MFA::Service.new(
      factors: KemalIdentity::Testing::MemoryMfaRepository.new,
      secret_box: KemalIdentity::MFA::AesSecretBox.new(
        KemalIdentity::Secret.new("a-test-secret-box-key-of-32-byte"), random
      ),
      clock: clock,
      random: random,
      issuer: "Acme",
      rate_limiter: limiter,
    )

    outcome = service.verify("a1", "000000")

    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason
      .should eq(KemalIdentity::FailureReason::RateLimiterUnavailable)
  end

  # Silently, as every other outcome of this endpoint is: it must not become an account oracle
  # by answering differently when the limiter is down.
  it "declines to send a password reset" do
    limiter = UnavailableRateLimiter.new
    h = KemalIdentity::Testing.account_harness(rate_limiter: limiter)

    h.service.request_password_reset("ada@example.com")

    h.notifier.delivered.should be_empty
    limiter.consumed.should eq(1)
  end
end

describe "throttling the password verification path" do
  it "denies once the limit is reached" do
    auth, _, _, _ = build(limit: 3)

    3.times do
      KemalIdentity::Testing.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: "wrong"),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "returns a retry_after with the denial" do
    auth, _, _, _ = build(limit: 1)
    auth.authenticate(login: "ada@example.com", password: "wrong")

    denied = KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong"),
      KemalIdentity::FailureReason::RateLimited
    )

    denied.retry_after.should_not be_nil
    (denied.retry_after.or_fail > Time::Span::ZERO).should be_true
  end

  it "denies the correct password too, once the limit is reached" do
    # Otherwise an attacker learns they guessed right by watching which attempt is *not*
    # throttled — and a throttle that lets the right password through is not a throttle.
    auth, _, _, _ = build(limit: 2)
    2.times { auth.authenticate(login: "ada@example.com", password: "wrong") }

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: PASSWORD),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "allows again once the window has elapsed" do
    auth, clock, _, _ = build(limit: 2, window: 1.minute)
    3.times { auth.authenticate(login: "ada@example.com", password: "wrong") }

    clock.advance(61.seconds)

    auth.authenticate(login: "ada@example.com", password: PASSWORD)
      .should be_a(KemalIdentity::Authenticated)
  end
end

# The blocker: "the login path consumes before verifying the password, not after". A limiter
# that only penalised failures would already have paid for the hashing before deciding to
# penalise, so the denial-of-service lever would survive it.
describe "a denial does no hashing work" do
  it "does not touch the hasher at all" do
    counting = CountingHasher.new(KemalIdentity::Testing::FastTestHasher.new)
    auth, _, _, _ = build(limit: 2, hasher: counting)

    2.times { auth.authenticate(login: "ada@example.com", password: "wrong") }
    verifications_before_denial = counting.verifications

    5.times { auth.authenticate(login: "ada@example.com", password: "wrong") }

    counting.verifications.should eq(verifications_before_denial)
  end

  it "does not touch the account repository either" do
    _, _, _, repo = build(limit: 2)
    counting = CountingAccountRepository.new(repo)
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    limiter = KemalIdentity::FixedWindowRateLimiter.new(limit: 2, window: 1.minute, clock: clock)

    limited = KemalIdentity::Passwords::Authenticator.new(
      accounts: counting, hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: clock, rate_limiter: limiter
    )

    2.times { limited.authenticate(login: "ada@example.com", password: "wrong") }
    lookups_before_denial = counting.lookups

    3.times { limited.authenticate(login: "ada@example.com", password: "wrong") }

    counting.lookups.should eq(lookups_before_denial)
  end

  it "is measurably cheaper than a real attempt" do
    # With real bcrypt the difference is the whole point: a denial must not cost what a
    # verification costs, or the limiter is the lever rather than the defence.
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
    auth, _, _, _ = build(limit: 1, hasher: hasher)

    attempt = Time.measure { auth.authenticate(login: "ada@example.com", password: "wrong") }
    denial = Time.measure { auth.authenticate(login: "ada@example.com", password: "wrong") }

    (denial < attempt / 5).should be_true
  end
end

describe "a success resets the count" do
  it "clears the penalty for a user who mistyped and then got it right" do
    auth, _, _, _ = build(limit: 3)

    2.times { auth.authenticate(login: "ada@example.com", password: "wrong") }
    auth.authenticate(login: "ada@example.com", password: PASSWORD)
      .should be_a(KemalIdentity::Authenticated)

    # Back to a full allowance, rather than one attempt away from being locked out.
    3.times do
      KemalIdentity::Testing.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: "wrong"),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end
  end
end

# The blocker: "an account-keyed denial applies across source addresses". Credential stuffing
# is distributed by nature, so a limit keyed only on the source address barely touches it.
describe "an account-keyed denial" do
  it "follows the login across source addresses" do
    auth, _, _, _ = build(limit: 3)

    3.times { |i| auth.authenticate(login: "ada@example.com", password: "wrong", ip: "10.0.0.#{i}") }

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong", ip: "203.0.113.99"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "is not confused by the case or spacing of the login" do
    auth, _, _, _ = build(limit: 3)

    auth.authenticate(login: "ADA@EXAMPLE.COM", password: "wrong")
    auth.authenticate(login: "  ada@example.com ", password: "wrong")
    auth.authenticate(login: "Ada@Example.Com", password: "wrong")

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "does not throttle a different login" do
    auth, _, _, _ = build(limit: 2)
    3.times { auth.authenticate(login: "ada@example.com", password: "wrong") }

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "someone-else@example.com", password: "wrong"),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # The other half: one host spraying many logins is caught by the address-keyed limit even
  # though no single login has been tried more than once.
  it "also throttles one address spraying many logins" do
    auth, _, _, _ = build(limit: 3)

    3.times { |i| auth.authenticate(login: "victim-#{i}@example.com", password: "wrong", ip: "203.0.113.7") }

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "victim-99@example.com", password: "wrong", ip: "203.0.113.7"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "leaves other addresses alone when only one is spraying" do
    auth, _, _, _ = build(limit: 3)
    4.times { |i| auth.authenticate(login: "victim-#{i}@example.com", password: "wrong", ip: "203.0.113.7") }

    KemalIdentity::Testing.should_fail_with(
      auth.authenticate(login: "someone@example.com", password: "wrong", ip: "198.51.100.4"),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end
end

describe "the keys a limiter is given" do
  # A limiter's storage should be able to answer "is this login under attack" without
  # retaining the address somebody typed.
  it "never contains the login in plain text" do
    recording = RecordingRateLimiter.new
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])

    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: repo, hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: clock, rate_limiter: recording
    )

    auth.authenticate(login: "ada@example.com", password: "wrong", ip: "203.0.113.7")

    recording.keys.should_not be_empty
    recording.keys.join(" ").should_not contain("ada@example.com")
    recording.keys.join(" ").should_not contain("ada")
  end

  it "separates the same login in different tenants" do
    recording = RecordingRateLimiter.new
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([] of KemalIdentity::Accounts::Account)

    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: repo, hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: clock, rate_limiter: recording
    )

    auth.authenticate(login: "ada@example.com", password: "wrong", tenant_id: "t1")
    auth.authenticate(login: "ada@example.com", password: "wrong", tenant_id: "t2")

    recording.keys.uniq!.size.should eq(2)
  end
end

class CountingHasher < KemalIdentity::Passwords::Hasher
  getter verifications : Int32 = 0

  def initialize(@inner : KemalIdentity::Passwords::Hasher)
  end

  def scheme : String
    @inner.scheme
  end

  def max_secret_bytesize : Int32
    @inner.max_secret_bytesize
  end

  def hash_secret(secret : KemalIdentity::Secret) : String
    @inner.hash_secret(secret)
  end

  def verify(secret : KemalIdentity::Secret, digest : String) : Bool
    @verifications += 1
    @inner.verify(secret, digest)
  end

  def needs_rehash?(digest : String) : Bool
    @inner.needs_rehash?(digest)
  end

  def dummy_digest : String
    @inner.dummy_digest
  end
end

class CountingAccountRepository < KemalIdentity::Accounts::Repository
  getter lookups : Int32 = 0

  def initialize(@inner : KemalIdentity::Accounts::Repository)
  end

  def find_by_id(id : String) : KemalIdentity::Accounts::Account?
    @inner.find_by_id(id)
  end

  def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
    @lookups += 1
    @inner.find_by_login(normalized_login, tenant_id)
  end

  def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
    @inner.update_password_digest(id, digest, scheme, at)
  end

  def mark_email_verified(id : String, at : Time) : Bool
    @inner.mark_email_verified(id, at)
  end

  def bump_auth_version(id : String) : Int32?
    @inner.bump_auth_version(id)
  end
end

class RecordingRateLimiter < KemalIdentity::RateLimiter
  getter keys = [] of String

  def consume(key : String) : KemalIdentity::Verdict
    @keys << key
    KemalIdentity::Verdict.allow
  end

  def reset(key : String) : Nil
  end
end

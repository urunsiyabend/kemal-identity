require "../spec_helper"

# The rate limiting blockers from docs/05-testing.md.
#
# Rate limiting is what stands between a login endpoint and both credential stuffing and a
# denial of service: bcrypt is tens of milliseconds of CPU *by design*, so an endpoint that
# verifies a hash before deciding whether it should have is a lever an attacker pulls for free.
private PASSWORD = "correct horse battery"

private def build(limit : Int32 = 3, window : Time::Span = 1.minute, hasher = nil)
  hasher ||= KemalIdentity::Testing::FastTestHasher.new
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  limiter = KemalIdentity::FixedWindowRateLimiter.new(limit: limit, window: window, clock: clock)

  repo = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::SpecHelper.account(
      password_digest: hasher.hash_secret(KemalIdentity::Secret.new(PASSWORD))
    ),
  ])

  auth = KemalIdentity::Passwords::Authenticator.new(
    accounts: repo, hasher: hasher, clock: clock, rate_limiter: limiter
  )

  {auth, clock, limiter, repo}
end

describe "throttling the password verification path" do
  it "denies once the limit is reached" do
    auth, _, _, _ = build(limit: 3)

    3.times do
      KemalIdentity::SpecHelper.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: "wrong"),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "returns a retry_after with the denial" do
    auth, _, _, _ = build(limit: 1)
    auth.authenticate(login: "ada@example.com", password: "wrong")

    denied = KemalIdentity::SpecHelper.should_fail_with(
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

    KemalIdentity::SpecHelper.should_fail_with(
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
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
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
      KemalIdentity::SpecHelper.should_fail_with(
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

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong", ip: "203.0.113.99"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "is not confused by the case or spacing of the login" do
    auth, _, _, _ = build(limit: 3)

    auth.authenticate(login: "ADA@EXAMPLE.COM", password: "wrong")
    auth.authenticate(login: "  ada@example.com ", password: "wrong")
    auth.authenticate(login: "Ada@Example.Com", password: "wrong")

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "wrong"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "does not throttle a different login" do
    auth, _, _, _ = build(limit: 2)
    3.times { auth.authenticate(login: "ada@example.com", password: "wrong") }

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "someone-else@example.com", password: "wrong"),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # The other half: one host spraying many logins is caught by the address-keyed limit even
  # though no single login has been tried more than once.
  it "also throttles one address spraying many logins" do
    auth, _, _, _ = build(limit: 3)

    3.times { |i| auth.authenticate(login: "victim-#{i}@example.com", password: "wrong", ip: "203.0.113.7") }

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "victim-99@example.com", password: "wrong", ip: "203.0.113.7"),
      KemalIdentity::FailureReason::RateLimited
    )
  end

  it "leaves other addresses alone when only one is spraying" do
    auth, _, _, _ = build(limit: 3)
    4.times { |i| auth.authenticate(login: "victim-#{i}@example.com", password: "wrong", ip: "203.0.113.7") }

    KemalIdentity::SpecHelper.should_fail_with(
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
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])

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
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
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

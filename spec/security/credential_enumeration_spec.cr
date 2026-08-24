require "../spec_helper"

# The credential blockers from docs/05-testing.md. Named for the attack: an oracle that tells
# an attacker which logins exist turns a password-spraying campaign into a targeted one, and
# leaks the membership of whatever the application is (a bank, a clinic, a dating site)
# before any password is ever guessed.

private def build(hasher : KemalIdentity::Passwords::Hasher, accounts : Array(KemalIdentity::Accounts::Account))
  repo = KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  {repo, KemalIdentity::Passwords::Authenticator.new(accounts: repo, hasher: hasher, clock: clock)}
end

private def account_with_password(
  hasher : KemalIdentity::Passwords::Hasher,
  password : String,
  id : String = "a1",
  login : String = "ada@example.com",
  disabled_at : Time? = nil,
)
  KemalIdentity::SpecHelper.account(
    id: id,
    login: login,
    disabled_at: disabled_at,
    password_digest: hasher.hash_secret(KemalIdentity::Secret.new(password)),
  )
end

describe "account enumeration through the response" do
  hasher = KemalIdentity::Testing::FastTestHasher.new
  _, auth = build(hasher, [account_with_password(hasher, "correct horse battery")])

  it "gives an unknown login and a wrong password the identical outcome" do
    unknown = auth.authenticate(login: "nobody@example.com", password: "correct horse battery")
    wrong = auth.authenticate(login: "ada@example.com", password: "wrong password entirely")

    KemalIdentity::SpecHelper.should_fail_with(unknown, KemalIdentity::FailureReason::InvalidCredential)
    KemalIdentity::SpecHelper.should_fail_with(wrong, KemalIdentity::FailureReason::InvalidCredential)

    # Byte-for-byte the same value, so nothing downstream can branch on it even by accident.
    unknown.should eq(wrong)
  end

  it "gives an empty password the same outcome as a wrong one" do
    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: ""),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  it "does not confirm a login through a wrong-tenant lookup" do
    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "correct horse battery", tenant_id: "t1"),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # An account with no password credential authenticates through an external identity only.
  # Falling through to the dummy digest means it cannot be told apart from a nonexistent one,
  # and — the part that matters — cannot be logged into by supplying nothing.
  it "cannot be logged into when the account has no password credential" do
    hasher = KemalIdentity::Testing::FastTestHasher.new
    _, auth = build(hasher, [KemalIdentity::SpecHelper.account(password_digest: nil)])

    ["", "any password", "null"].each do |attempt|
      KemalIdentity::SpecHelper.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: attempt),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end
  end

  # The reason exists for the audit log. docs/04-kemal-integration.md: a response that varies
  # with it is the oracle this whole section is about.
  it "distinguishes a disabled account only in the reason, for the log" do
    hasher = KemalIdentity::Testing::FastTestHasher.new
    _, auth = build(hasher, [
      account_with_password(hasher, "correct horse battery", disabled_at: KemalIdentity::SpecHelper::FIXED_NOW),
    ])

    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "correct horse battery"),
      KemalIdentity::FailureReason::DisabledAccount
    )
  end

  it "normalizes the login, so case and whitespace are not a way to miss an account" do
    hasher = KemalIdentity::Testing::FastTestHasher.new
    _, auth = build(hasher, [account_with_password(hasher, "correct horse battery")])

    ["ADA@EXAMPLE.COM", "  ada@example.com  ", "Ada@Example.Com"].each do |variant|
      auth.authenticate(login: variant, password: "correct horse battery")
        .should be_a(KemalIdentity::Authenticated)
    end
  end
end

# The half that is usually missed. A generic body is worthless if the unknown-login path
# answers a hundred milliseconds early.
#
# Distributions, not single samples, and a tolerance rather than equality — wide enough not to
# flake on a loaded CI runner, tight enough that removing the dummy-digest path fails by
# orders of magnitude rather than by tens of percent.
describe "account enumeration through timing" do
  # Real bcrypt, because the property under test is that real hashing work happens on both
  # paths. Cost 4 keeps it quick; the ratio does not depend on the cost.
  hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
  _, auth = build(hasher, [
    account_with_password(hasher, "correct horse battery"),
    account_with_password(hasher, "correct horse battery", id: "a2", login: "dis@example.com",
      disabled_at: KemalIdentity::SpecHelper::FIXED_NOW),
  ])

  samples = 11
  tolerance = 3.0

  median = ->(spans : Array(Time::Span)) { spans.sort![spans.size // 2] }

  measure = ->(login : String, password : String) do
    auth.authenticate(login: login, password: password) # discard the first, warming nothing unfairly
    Array.new(samples) { Time.measure { auth.authenticate(login: login, password: password) } }
  end

  it "spends comparable time on an unknown login and on a wrong password" do
    unknown = median.call(measure.call("nobody@example.com", "some password"))
    wrong = median.call(measure.call("ada@example.com", "some password"))

    ratio = wrong.total_nanoseconds / unknown.total_nanoseconds
    ratio.should be < tolerance
    ratio.should be > (1.0 / tolerance)
  end

  # The reason the disabled check sits after verification rather than in front of it.
  it "spends comparable time on a disabled account and on a live one" do
    disabled = median.call(measure.call("dis@example.com", "correct horse battery"))
    wrong = median.call(measure.call("ada@example.com", "some password"))

    ratio = disabled.total_nanoseconds / wrong.total_nanoseconds
    ratio.should be < tolerance
    ratio.should be > (1.0 / tolerance)
  end

  it "does real hashing work on the unknown-login path" do
    # The property underneath the ratios: an early return would be immeasurably fast.
    median.call(measure.call("nobody@example.com", "some password")).should be > 100.microseconds
  end
end

describe "over-length passwords at the login boundary" do
  hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
  _, auth = build(hasher, [account_with_password(hasher, "a" * 71)])

  it "refuses a longer password rather than truncating into a match" do
    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "a" * 72),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # A hostile length must be a value, not a 500. docs/02's documented login snippet calls
  # verify with no length check in front of it.
  it "answers a megabyte-long password without raising" do
    KemalIdentity::SpecHelper.should_fail_with(
      auth.authenticate(login: "ada@example.com", password: "a" * 1_000_000),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  it "still accepts a password exactly at the limit" do
    auth.authenticate(login: "ada@example.com", password: "a" * 71)
      .should be_a(KemalIdentity::Authenticated)
  end
end

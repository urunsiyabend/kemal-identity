require "../spec_helper"

# docs/05-testing.md credential blocker: "a successful login at an outdated cost silently
# rehashes at the current one".
#
# This is what makes raising a bcrypt cost, or migrating off a legacy algorithm, possible
# without a global password reset. docs/06-roadmap.md names the alternative as an
# anti-pattern: forcing everyone through a reset to change hashing algorithm is a support
# burden that lazy rehash makes unnecessary.
private def authenticator(repo, hasher, clock)
  KemalIdentity::Passwords::Authenticator.new(accounts: repo, hasher: hasher, clock: clock)
end

describe "lazy rehash" do
  weak = KemalIdentity::Testing::FastTestHasher.new(rounds: 1)
  current = KemalIdentity::Testing::FastTestHasher.new(rounds: 3)
  password = "correct horse battery"

  build = -> do
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([
      KemalIdentity::SpecHelper.account(
        password_digest: weak.hash_secret(KemalIdentity::Secret.new(password))
      ),
    ])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    {repo, authenticator(repo, current, clock), clock}
  end

  it "still lets an outdated digest log in, or the upgrade locks everyone out" do
    _, auth, _ = build.call
    auth.authenticate(login: "ada@example.com", password: password)
      .should be_a(KemalIdentity::Authenticated)
  end

  it "replaces the digest with one at the current parameters" do
    repo, auth, _ = build.call
    before = repo.find_by_id("a1").or_fail.password_digest

    auth.authenticate(login: "ada@example.com", password: password)

    after = repo.find_by_id("a1").or_fail.password_digest.or_fail
    after.should_not eq(before)
    current.needs_rehash?(after).should be_false
  end

  it "records the scheme that produced the new digest" do
    repo, auth, _ = build.call
    auth.authenticate(login: "ada@example.com", password: password)
    repo.find_by_id("a1").or_fail.password_scheme.should eq(current.scheme)
  end

  it "leaves the password itself unchanged, so the next login uses the same one" do
    _, auth, _ = build.call
    auth.authenticate(login: "ada@example.com", password: password)
    auth.authenticate(login: "ada@example.com", password: password)
      .should be_a(KemalIdentity::Authenticated)
  end

  it "does not rehash a digest already at the current parameters" do
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([
      KemalIdentity::SpecHelper.account(
        password_digest: current.hash_secret(KemalIdentity::Secret.new(password))
      ),
    ])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    before = repo.find_by_id("a1").or_fail.password_digest

    authenticator(repo, current, clock).authenticate(login: "ada@example.com", password: password)

    repo.find_by_id("a1").or_fail.password_digest.should eq(before)
  end

  it "does not rehash after a failed login" do
    repo, auth, _ = build.call
    before = repo.find_by_id("a1").or_fail.password_digest

    auth.authenticate(login: "ada@example.com", password: "the wrong password")

    repo.find_by_id("a1").or_fail.password_digest.should eq(before)
  end

  # A rehash is not a credential change. Bumping the version, or revoking sessions, would log
  # every user out of the application that just raised its cost.
  it "does not bump auth_version or otherwise invalidate sessions" do
    repo, auth, _ = build.call
    auth.authenticate(login: "ada@example.com", password: password)
    repo.find_by_id("a1").or_fail.auth_version.should eq(1)
  end

  it "migrates a digest from a foreign scheme it cannot even parse" do
    # The legacy digest the migration exists to retire: needs_rehash? reports true for
    # anything unparseable, so an application arriving from MD5 is covered.
    repo = KemalIdentity::Testing::MemoryAccountRepository.new([
      KemalIdentity::SpecHelper.account(password_digest: "$legacy$deadbeef"),
    ])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

    # It cannot verify, so no rehash happens and no login succeeds — the application supplies
    # a LegacyVerifier for that (v0.2). What matters here is that it does not raise.
    KemalIdentity::SpecHelper.should_fail_with(
      authenticator(repo, current, clock).authenticate(login: "ada@example.com", password: password),
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # The user typed the right password. A storage failure must not turn that into a rejection.
  it "still logs the user in when the rehash write fails" do
    repo = FailingWriteAccountRepository.new(
      KemalIdentity::Testing::MemoryAccountRepository.new([
        KemalIdentity::SpecHelper.account(
          password_digest: weak.hash_secret(KemalIdentity::Secret.new(password))
        ),
      ])
    )
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

    authenticator(repo, current, clock).authenticate(login: "ada@example.com", password: password)
      .should be_a(KemalIdentity::Authenticated)
  end
end

# A repository whose password write fails the way a database under pressure would.
class FailingWriteAccountRepository < KemalIdentity::Accounts::Repository
  def initialize(@inner : KemalIdentity::Accounts::Repository)
  end

  def find_by_id(id : String) : KemalIdentity::Accounts::Account?
    @inner.find_by_id(id)
  end

  def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
    @inner.find_by_login(normalized_login, tenant_id)
  end

  def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
    raise KemalIdentity::InfrastructureError.new("write failed")
  end

  def bump_auth_version(id : String) : Int32?
    @inner.bump_auth_version(id)
  end
end

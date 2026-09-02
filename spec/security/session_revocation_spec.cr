require "../spec_helper"

# The revocation half of the docs/05-testing.md lifecycle blockers. Revocation is the whole
# reason this shard keeps sessions server-side rather than in a signed token, so these are the
# specs that justify the design.

describe "a disabled account" do
  it "invalidates its live sessions on the very next request" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    h.accounts.disable("a1", h.clock.now)

    # No revocation call, no sweep, no logout. The next read simply fails.
    KemalIdentity::Testing.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::DisabledAccount)
  end

  it "invalidates every one of its sessions, not just one" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    tokens = Array.new(3) { h.service.start(account, KemalIdentity::AssuranceLevel::Password).token }

    h.accounts.disable("a1", h.clock.now)

    tokens.each do |token|
      h.service.resolve(token.reveal).should be_a(KemalIdentity::Failed)
    end
  end

  it "cannot have a new session started for it" do
    h = KemalIdentity::Testing.harness(
      accounts: [KemalIdentity::Testing.account(disabled_at: KemalIdentity::Testing::FIXED_NOW)]
    )
    expect_raises(ArgumentError) do
      h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    end
  end
end

describe "an auth_version bump" do
  # Belt to revocation's braces: invalidates every session for an account without
  # enumerating rows, so a session created concurrently with a password change cannot slip
  # through.
  it "invalidates sessions minted before it" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.accounts.bump_auth_version("a1")

    KemalIdentity::Testing.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::StaleAuthVersion)
  end

  it "leaves sessions minted after it alone" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    h.accounts.bump_auth_version("a1")

    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "does not touch another account's sessions" do
    h = KemalIdentity::Testing.harness(accounts: [
      KemalIdentity::Testing.account(id: "a1", login: "ada@example.com"),
      KemalIdentity::Testing.account(id: "a2", login: "bob@example.com"),
    ])
    other = h.service.start(h.accounts.find_by_id("a2").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.accounts.bump_auth_version("a1")

    h.service.resolve(other.token.reveal).should be_a(KemalIdentity::Authenticated)
  end
end

describe "a password change" do
  it "revokes the account's other sessions" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
    elsewhere = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id).should eq(1)

    KemalIdentity::Testing.should_fail_with(h.service.resolve(elsewhere.token.reveal), KemalIdentity::FailureReason::Revoked)
  end

  # Changing your own password should not log you out of the tab you changed it in.
  it "keeps the session it was performed from, by default" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id)

    h.service.resolve(current.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "revokes the current session too when configured to" do
    config = KemalIdentity::Sessions::Config.new(revoke_current_on_credential_change: true)
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id).should eq(1)

    KemalIdentity::Testing.should_fail_with(h.service.resolve(current.token.reveal), KemalIdentity::FailureReason::Revoked)
  end

  # The pairing docs/02 calls belt and braces: enumeration handles the sessions that exist,
  # the version bump handles anything created alongside it.
  it "is paired with an auth_version bump so a concurrent session cannot survive" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail

    # A session minted from a stale read of the account, concurrent with the change.
    concurrent = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: concurrent.record.id)
    h.accounts.bump_auth_version("a1")

    # Revocation spared it; the version bump does not.
    KemalIdentity::Testing.should_fail_with(h.service.resolve(concurrent.token.reveal), KemalIdentity::FailureReason::StaleAuthVersion)
  end
end

describe "log out everywhere" do
  it "revokes every session and reports how many it ended" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    tokens = Array.new(4) { h.service.start(account, KemalIdentity::AssuranceLevel::Password).token }

    h.service.revoke_all("a1").should eq(4)

    tokens.each { |token| h.service.resolve(token.reveal).should be_a(KemalIdentity::Failed) }
  end

  it "can spare the current session" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    keep = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
    h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_all("a1", except_id: keep.record.id).should eq(1)

    h.service.resolve(keep.token.reveal).should be_a(KemalIdentity::Authenticated)
  end
end

# A repository that can move an account between tenants. `MemoryAccountRepository` cannot, and
# should not: changing an account's tenant is an application action against its own table, so
# only a spec that is measuring the consequence needs it.
class MovableAccountRepository < KemalIdentity::Testing::MemoryAccountRepository
  def move_to_tenant(id : String, tenant_id : String?) : Nil
    existing = find_by_id(id).or_fail("no such account to move")

    @accounts[id] = KemalIdentity::Accounts::Account.new(
      id: existing.id,
      normalized_login: existing.normalized_login,
      tenant_id: tenant_id,
      auth_version: existing.auth_version,
      password_digest: existing.password_digest,
      password_scheme: existing.password_scheme,
      email_verified_at: existing.email_verified_at,
      disabled_at: existing.disabled_at,
      created_at: existing.created_at,
      updated_at: existing.updated_at,
    )
  end
end

# `docs/02-security-model.md` lists a change to the account's tenant among the events that must
# revoke an account's sessions, and this is why: the tenant is the one authorization input a
# session copies, so nothing else notices the change. Found by AUT-06 in `blueprints/0025`.
private def moved_harness
  accounts = MovableAccountRepository.new([KemalIdentity::Testing.account])
  sessions = KemalIdentity::Testing::MemorySessionRepository.new(accounts)
  clock = KemalIdentity::Testing::TestClock.new
  service = KemalIdentity::Sessions::Service.new(
    sessions: sessions, clock: clock,
    random: KemalIdentity::Testing::DeterministicRandom.new
  )

  {accounts, clock, service}
end

describe "a change to the account's tenant" do
  it "is not felt by a session that already exists, however long it waits" do
    accounts, clock, service = moved_harness
    issued = service.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    issued.principal.tenant_id.should be_nil

    accounts.move_to_tenant("a1", "org-a")
    accounts.find_by_id("a1").or_fail.tenant_id.should eq("org-a")

    # A session started now is confined. There is no cache to expire here — the principal is
    # rebuilt from the session row on every read, and the row still says what it said at login.
    service.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
      .principal.tenant_id.should eq("org-a")

    # Kept active — an hour of idle at a time, well inside the two-hour idle timeout — so the
    # window measured is the session's absolute lifetime rather than how long a tab sat unused.
    11.times do
      clock.advance(1.hour)
      resolved = service.resolve(issued.token.reveal).as(KemalIdentity::Authenticated).principal
      resolved.tenant_id.should be_nil
    end

    # And it ends when the session does, not before: twelve hours, the absolute deadline.
    clock.advance(1.hour)
    KemalIdentity::Testing.should_fail_with(
      service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Expired
    )
  end

  it "is felt immediately once auth_version is bumped, which is what the docs require" do
    accounts, _clock, service = moved_harness
    issued = service.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    accounts.move_to_tenant("a1", "org-a")
    accounts.bump_auth_version("a1")

    KemalIdentity::Testing.should_fail_with(
      service.resolve(issued.token.reveal), KemalIdentity::FailureReason::StaleAuthVersion
    )
  end

  it "is felt immediately once the account's sessions are revoked, which is the other way" do
    accounts, _clock, service = moved_harness
    issued = service.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    accounts.move_to_tenant("a1", "org-a")
    service.revoke_all("a1").should eq(1)

    KemalIdentity::Testing.should_fail_with(
      service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Revoked
    )
  end
end

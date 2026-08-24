require "../spec_helper"

# The revocation half of the docs/05-testing.md lifecycle blockers. Revocation is the whole
# reason this shard keeps sessions server-side rather than in a signed token, so these are the
# specs that justify the design.

describe "a disabled account" do
  it "invalidates its live sessions on the very next request" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    h.accounts.disable("a1", h.clock.now)

    # No revocation call, no sweep, no logout. The next read simply fails.
    KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::DisabledAccount)
  end

  it "invalidates every one of its sessions, not just one" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    tokens = Array.new(3) { h.service.start(account, KemalIdentity::AssuranceLevel::Password).token }

    h.accounts.disable("a1", h.clock.now)

    tokens.each do |token|
      h.service.resolve(token.reveal).should be_a(KemalIdentity::Failed)
    end
  end

  it "cannot have a new session started for it" do
    h = KemalIdentity::SpecHelper.harness(
      accounts: [KemalIdentity::SpecHelper.account(disabled_at: KemalIdentity::SpecHelper::FIXED_NOW)]
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
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.accounts.bump_auth_version("a1")

    KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::StaleAuthVersion)
  end

  it "leaves sessions minted after it alone" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    h.accounts.bump_auth_version("a1")

    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "does not touch another account's sessions" do
    h = KemalIdentity::SpecHelper.harness(accounts: [
      KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com"),
      KemalIdentity::SpecHelper.account(id: "a2", login: "bob@example.com"),
    ])
    other = h.service.start(h.accounts.find_by_id("a2").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.accounts.bump_auth_version("a1")

    h.service.resolve(other.token.reveal).should be_a(KemalIdentity::Authenticated)
  end
end

describe "a password change" do
  it "revokes the account's other sessions" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
    elsewhere = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id).should eq(1)

    KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(elsewhere.token.reveal), KemalIdentity::FailureReason::Revoked)
  end

  # Changing your own password should not log you out of the tab you changed it in.
  it "keeps the session it was performed from, by default" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id)

    h.service.resolve(current.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "revokes the current session too when configured to" do
    config = KemalIdentity::Sessions::Config.new(revoke_current_on_credential_change: true)
    h = KemalIdentity::SpecHelper.harness(config: config, accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    current = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: current.record.id).should eq(1)

    KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(current.token.reveal), KemalIdentity::FailureReason::Revoked)
  end

  # The pairing docs/02 calls belt and braces: enumeration handles the sessions that exist,
  # the version bump handles anything created alongside it.
  it "is paired with an auth_version bump so a concurrent session cannot survive" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail

    # A session minted from a stale read of the account, concurrent with the change.
    concurrent = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_after_credential_change("a1", current_session_id: concurrent.record.id)
    h.accounts.bump_auth_version("a1")

    # Revocation spared it; the version bump does not.
    KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(concurrent.token.reveal), KemalIdentity::FailureReason::StaleAuthVersion)
  end
end

describe "log out everywhere" do
  it "revokes every session and reports how many it ended" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    tokens = Array.new(4) { h.service.start(account, KemalIdentity::AssuranceLevel::Password).token }

    h.service.revoke_all("a1").should eq(4)

    tokens.each { |token| h.service.resolve(token.reveal).should be_a(KemalIdentity::Failed) }
  end

  it "can spare the current session" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail
    keep = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
    h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke_all("a1", except_id: keep.record.id).should eq(1)

    h.service.resolve(keep.token.reveal).should be_a(KemalIdentity::Authenticated)
  end
end

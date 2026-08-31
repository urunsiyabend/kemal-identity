require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"
require "../lib/kemal_identity/spec/contract/session_repository_contract"
require "../src/kv_sessions"

# OPS-04: PostgreSQL for accounts, a key-value store for sessions. The shard's own contract is
# the test — an adapter that passes it behaves like the ones that ship.
it_behaves_like_a_session_repository do |accounts|
  KVSessionRepository.new(
    KVStore.new,
    KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
  )
end

describe "OPS-04: what a key-value store costs" do
  # Pass condition: "account disabled state remains promptly available". SQL joins it; a
  # key-value store has to read it, and reading it is what keeps it fresh.
  it "sees an account disabled after the session was minted" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    sessions = KemalIdentity::Sessions::Service.new(
      sessions: KVSessionRepository.new(KVStore.new, accounts),
      clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
    )

    issued = sessions.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    sessions.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    accounts.disable("a1", clock.now)

    outcome = sessions.resolve(issued.token.reveal)
    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason
      .should eq(KemalIdentity::FailureReason::DisabledAccount)
  end

  # Pass condition: "TTL cleanup is an optimisation rather than the only expiry check."
  # Nothing was swept, and the expired session still fails on read.
  it "expires a session on read, with no sweeper having run" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    store = KVStore.new
    repo = KVSessionRepository.new(store, accounts)
    sessions = KemalIdentity::Sessions::Service.new(
      sessions: repo, clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
      config: KemalIdentity::Sessions::Config.new(idle_timeout: 10.minutes, absolute_timeout: 1.hour),
    )

    issued = sessions.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    clock.advance(2.hours)

    outcome = sessions.resolve(issued.token.reveal)
    outcome.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::Expired)

    # The row is still there. Expiry was decided on read, not by cleanup.
    store.keys_with_prefix("session:digest:").size.should eq(1)
  end

  # Pass condition: "Required atomic operations are expressible in the contract."
  it "revokes concurrently without double-counting" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    repo = KVSessionRepository.new(KVStore.new, accounts)

    record = KemalIdentity::Sessions::Record.new(
      id: "s-1", account_id: "a1", token_digest: Bytes[1, 2, 3],
      auth_version: 1, assurance: KemalIdentity::AssuranceLevel::Password,
      created_at: clock.now, authenticated_at: clock.now, last_seen_at: clock.now,
      idle_expires_at: clock.now + 1.hour, absolute_expires_at: clock.now + 12.hours,
    )
    repo.create(record)

    results = Channel(Bool).new
    16.times { spawn { results.send(repo.revoke("s-1", clock.now)) } }

    succeeded = 0
    16.times { succeeded += 1 if results.receive }

    # Exactly one revocation may report that it changed something.
    succeeded.should eq(1)
  end
end

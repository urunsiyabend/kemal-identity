# Shared spec for `KemalIdentity::Sessions::Repository`. Every implementation runs it,
# including `MemorySessionRepository`.
#
# The block is handed the accounts to seed and returns a session repository already wired to
# a store containing them — the lookup joins session state to account status, so a session
# repository with no accounts behind it cannot satisfy this contract.
def it_behaves_like_a_session_repository(&build : Array(KemalIdentity::Accounts::Account) -> KemalIdentity::Sessions::Repository)
  now = KemalIdentity::Testing::FIXED_NOW

  account = ->(id : String, auth_version : Int32, disabled_at : Time?) do
    KemalIdentity::Accounts::Account.new(
      id: id,
      normalized_login: "#{id}@example.com",
      auth_version: auth_version,
      disabled_at: disabled_at,
      created_at: now,
      updated_at: now,
    )
  end

  digest = ->(value : String) { KemalIdentity::Secret.new(value).digest }

  session = ->(id : String, account_id : String, token : String, auth_version : Int32) do
    KemalIdentity::Sessions::Record.new(
      id: id,
      account_id: account_id,
      token_digest: digest.call(token),
      auth_version: auth_version,
      assurance: KemalIdentity::AssuranceLevel::Password,
      created_at: now,
      authenticated_at: now,
      last_seen_at: now,
      idle_expires_at: now + 30.minutes,
      absolute_expires_at: now + 12.hours,
    )
  end

  one_account = [account.call("a1", 1, nil)]

  describe "#create and #find_by_digest" do
    it "round trips a session" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      found = repo.find_by_digest(digest.call("token-1"))
      found.should_not be_nil
      found.try(&.session.id).should eq("s1")
      found.try(&.session.account_id).should eq("a1")
    end

    it "preserves every field it was given" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      stored = repo.find_by_digest(digest.call("token-1")).or_fail.session

      stored.assurance.should eq(KemalIdentity::AssuranceLevel::Password)
      stored.authenticated_at.should eq(now)
      stored.last_seen_at.should eq(now)
      stored.idle_expires_at.should eq(now + 30.minutes)
      stored.absolute_expires_at.should eq(now + 12.hours)
      stored.revoked_at.should be_nil
      stored.token_digest.should eq(digest.call("token-1"))
    end

    it "returns nil for an unknown digest rather than raising" do
      repo = build.call(one_account)
      repo.find_by_digest(digest.call("never-issued")).should be_nil
    end

    it "returns nil for an empty digest rather than raising" do
      repo = build.call(one_account)
      repo.find_by_digest(Bytes.new(0)).should be_nil
    end

    # The unique index on token_digest exists so that a collision is a loud error instead of
    # two accounts silently sharing a session. An implementation that upserted here would
    # produce exactly the failure the index prevents.
    it "refuses a duplicate digest instead of overwriting" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.create(session.call("s2", "a1", "token-1", 1))
      end

      repo.find_by_digest(digest.call("token-1")).or_fail.session.id.should eq("s1")
    end

    it "keeps concurrent sessions for one account distinct" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))

      repo.find_by_digest(digest.call("token-1")).or_fail.session.id.should eq("s1")
      repo.find_by_digest(digest.call("token-2")).or_fail.session.id.should eq("s2")
    end

    # The reference SQL is an inner join, so this fails closed. A session pointing at an
    # account that no longer exists must not resolve.
    it "returns nil when the session's account does not exist" do
      repo = build.call([] of KemalIdentity::Accounts::Account)
      repo.create(session.call("s1", "ghost", "token-1", 1))
      repo.find_by_digest(digest.call("token-1")).should be_nil
    end
  end

  # Decision D7: session state and account status arrive together, or every authenticated
  # request pays for two round trips.
  describe "the joined account status" do
    it "carries the account's current auth_version" do
      repo = build.call([account.call("a1", 7, nil)])
      repo.create(session.call("s1", "a1", "token-1", 7))

      found = repo.find_by_digest(digest.call("token-1")).or_fail
      found.account_auth_version.should eq(7)
      found.stale_auth_version?.should be_false
    end

    it "reports a session minted before an auth_version bump as stale" do
      repo = build.call([account.call("a1", 8, nil)])
      repo.create(session.call("s1", "a1", "token-1", 7))

      found = repo.find_by_digest(digest.call("token-1")).or_fail
      found.stale_auth_version?.should be_true
    end

    it "carries the account's disabled_at" do
      disabled_at = now - 1.hour
      repo = build.call([account.call("a1", 1, disabled_at)])
      repo.create(session.call("s1", "a1", "token-1", 1))

      found = repo.find_by_digest(digest.call("token-1")).or_fail
      found.account_disabled_at.should eq(disabled_at)
      found.account_disabled?.should be_true
    end

    it "reports an enabled account as not disabled" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      found = repo.find_by_digest(digest.call("token-1")).or_fail
      found.account_disabled_at.should be_nil
      found.account_disabled?.should be_false
    end

    # The repository reports facts. Deciding what they mean is SessionService's job, which is
    # what lets a "list my devices" screen see revoked rows through the same repository.
    it "still resolves a revoked session, leaving the verdict to the caller" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.revoke("s1", now)

      found = repo.find_by_digest(digest.call("token-1"))
      found.should_not be_nil
      found.or_fail.session.revoked_at.should eq(now)
    end
  end

  describe "#touch" do
    it "moves last_seen_at and idle_expires_at forward" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      repo.touch("s1", now + 5.minutes, now + 35.minutes).should be_true

      stored = repo.find_by_digest(digest.call("token-1")).or_fail.session
      stored.last_seen_at.should eq(now + 5.minutes)
      stored.idle_expires_at.should eq(now + 35.minutes)
    end

    it "leaves absolute_expires_at alone, so activity cannot extend a session forever" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.touch("s1", now + 5.minutes, now + 35.minutes)

      repo.find_by_digest(digest.call("token-1")).or_fail
        .session.absolute_expires_at.should eq(now + 12.hours)
    end

    it "returns false for an unknown session" do
      repo = build.call(one_account)
      repo.touch("nope", now, now + 30.minutes).should be_false
    end

    it "affects only the named session" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))
      repo.touch("s1", now + 5.minutes, now + 35.minutes)

      repo.find_by_digest(digest.call("token-2")).or_fail.session.last_seen_at.should eq(now)
    end
  end

  describe "#revoke" do
    it "stamps revoked_at" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      repo.revoke("s1", now + 1.minute).should be_true
      repo.find_by_digest(digest.call("token-1")).or_fail
        .session.revoked_at.should eq(now + 1.minute)
    end

    it "returns false for an unknown session" do
      repo = build.call(one_account)
      repo.revoke("nope", now).should be_false
    end

    # Logging out twice is not an error, but the caller still learns that nothing changed.
    it "returns false for an already revoked session and does not re-stamp it" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.revoke("s1", now)

      repo.revoke("s1", now + 1.hour).should be_false
      repo.find_by_digest(digest.call("token-1")).or_fail.session.revoked_at.should eq(now)
    end
  end

  describe "#revoke_all_for_account" do
    it "revokes every live session and returns the count" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))

      repo.revoke_all_for_account("a1", now + 1.minute).should eq(2)
      repo.find_by_digest(digest.call("token-1")).or_fail.session.revoked?.should be_true
      repo.find_by_digest(digest.call("token-2")).or_fail.session.revoked?.should be_true
    end

    it "spares exactly one session when given except_id" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))
      repo.create(session.call("s3", "a1", "token-3", 1))

      repo.revoke_all_for_account("a1", now + 1.minute, except_id: "s2").should eq(2)

      repo.find_by_digest(digest.call("token-1")).or_fail.session.revoked?.should be_true
      repo.find_by_digest(digest.call("token-2")).or_fail.session.revoked?.should be_false
      repo.find_by_digest(digest.call("token-3")).or_fail.session.revoked?.should be_true
    end

    it "does not touch another account's sessions" do
      repo = build.call([account.call("a1", 1, nil), account.call("a2", 1, nil)])
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a2", "token-2", 1))

      repo.revoke_all_for_account("a1", now).should eq(1)
      repo.find_by_digest(digest.call("token-2")).or_fail.session.revoked?.should be_false
    end

    # The count is the number of sessions actually ended, so an audit log entry saying
    # "revoked 4 sessions" means four people were logged out.
    it "does not count or re-stamp sessions that were already revoked" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))
      repo.revoke("s1", now)

      repo.revoke_all_for_account("a1", now + 1.hour).should eq(1)
      repo.find_by_digest(digest.call("token-1")).or_fail.session.revoked_at.should eq(now)
    end

    it "returns zero for an account with no sessions" do
      repo = build.call(one_account)
      repo.revoke_all_for_account("a1", now).should eq(0)
    end
  end

  # A revoked session is not necessarily an expired one, and the row is the evidence that a
  # logout happened. The retention window is the application's to choose.
  describe "#delete_revoked_before" do
    it "removes revoked rows revoked at or before the given instant" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.revoke("s1", now)

      repo.delete_revoked_before(now).should eq(1)
      repo.find_by_digest(digest.call("token-1")).should be_nil
    end

    it "leaves a session revoked after that instant alone" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.revoke("s1", now + 1.hour)

      repo.delete_revoked_before(now).should eq(0)
      repo.find_by_digest(digest.call("token-1")).should_not be_nil
    end

    it "never touches a live session, however old" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))

      repo.delete_revoked_before(now + 100.hours).should eq(0)
      repo.find_by_digest(digest.call("token-1")).should_not be_nil
    end
  end

  describe "#delete_expired" do
    it "removes only rows past absolute_expires_at" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.create(session.call("s2", "a1", "token-2", 1))

      # s1 is 12 hours out; asking at 13 hours removes it, at 11 hours removes nothing.
      repo.delete_expired(now + 11.hours).should eq(0)
      repo.find_by_digest(digest.call("token-1")).should_not be_nil

      repo.delete_expired(now + 13.hours).should eq(2)
      repo.find_by_digest(digest.call("token-1")).should be_nil
      repo.find_by_digest(digest.call("token-2")).should be_nil
    end

    it "treats the boundary as expired" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.delete_expired(now + 12.hours).should eq(1)
    end

    # Disk reclamation only. A live session must survive a sweep, or the sweeper becomes a
    # correctness dependency, which is the trap docs/02 records from kemal-session #116.
    it "leaves a live session alone" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.delete_expired(now).should eq(0)
      repo.find_by_digest(digest.call("token-1")).should_not be_nil
    end

    it "removes an expired session even though it was never revoked" do
      repo = build.call(one_account)
      repo.create(session.call("s1", "a1", "token-1", 1))
      repo.delete_expired(now + 100.hours).should eq(1)
    end
  end
  # docs/05-testing.md lists this under concurrency blockers. It belongs in the contract
  # rather than in a spec against the double, so that the PostgreSQL adapter has to satisfy
  # it too — there, the guarantee comes from the unique index rather than from a mutex.
  describe "concurrent writers" do
    it "lets exactly one of two simultaneous creates win the same digest" do
      repo = build.call(one_account)
      failures = Atomic(Int32).new(0)

      join_fibers(2) do |index|
        repo.create(session.call("s#{index}", "a1", "contested-token", 1))
      rescue KemalIdentity::InfrastructureError
        failures.add(1)
      end

      # One winner, one loser. Two winners would mean two sessions sharing a token.
      failures.get.should eq(1)
      repo.find_by_digest(digest.call("contested-token")).should_not be_nil
    end

    it "keeps simultaneous logins for one account distinct" do
      repo = build.call(one_account)

      join_fibers(8) do |index|
        repo.create(session.call("s#{index}", "a1", "token-#{index}", 1))
      end

      8.times do |index|
        found = repo.find_by_digest(digest.call("token-#{index}"))
        found.should_not be_nil
        found.or_fail.session.id.should eq("s#{index}")
      end
    end
  end
end

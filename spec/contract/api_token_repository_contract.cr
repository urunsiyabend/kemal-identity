# Shared spec for `KemalIdentity::ApiTokens::Repository`. Every implementation runs it.
#
# The block is handed the accounts to seed and returns a repository already wired to a store
# containing them — the lookup joins token state to account status, so a token repository with
# no accounts behind it cannot satisfy this contract.
def it_behaves_like_an_api_token_repository(&build : Array(KemalIdentity::Accounts::Account) -> KemalIdentity::ApiTokens::Repository)
  now = KemalIdentity::SpecHelper::FIXED_NOW
  digest = ->(value : String) { KemalIdentity::Secret.new(value).digest }

  token = ->(id : String, account_id : String, raw : String, expires_in : Time::Span?) do
    KemalIdentity::ApiTokens::Token.new(
      id: id,
      account_id: account_id,
      name: "token #{id}",
      token_digest: digest.call(raw),
      created_at: now,
      expires_at: expires_in.nil? ? nil : now + expires_in,
    )
  end

  one_account = [KemalIdentity::SpecHelper.account]

  describe "#create and #find_by_digest" do
    it "round trips a token" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      found = repo.find_by_digest(digest.call("raw-1"))
      found.should_not be_nil
      found.or_fail.token.id.should eq("t1")
      found.or_fail.token.account_id.should eq("a1")
      found.or_fail.token.name.should eq("token t1")
    end

    # The fail-open hazard of adding scopes to an existing contract, asserted rather than
    # documented: an adapter written before v0.8 keeps compiling — the field is defaulted — and
    # silently drops the column, so an attenuated token comes back unrestricted. Only a contract
    # example catches that, which is why these three states are here and not in a paragraph.
    describe "scopes" do
      scoped = ->(id : String, raw : String, scopes : Array(String)?) do
        KemalIdentity::ApiTokens::Token.new(
          id: id,
          account_id: "a1",
          name: "token #{id}",
          token_digest: digest.call(raw),
          created_at: now,
          scopes: scopes,
        )
      end

      it "round trips an attenuated token" do
        repo = build.call(one_account)
        repo.create(scoped.call("t1", "raw-1", ["invoices.read", "invoices.refund"]))

        repo.find_by_digest(digest.call("raw-1")).or_fail.token.scopes
          .should eq(["invoices.read", "invoices.refund"])
      end

      # nil means "not attenuated". Every token issued before scopes existed reads back this
      # way, and reading it as an empty set would deny all of them.
      it "round trips a token with no attenuation as nil, not as an empty list" do
        repo = build.call(one_account)
        repo.create(scoped.call("t1", "raw-1", nil))

        repo.find_by_digest(digest.call("raw-1")).or_fail.token.scopes.should be_nil
      end

      # The other edge, and the dangerous one: an empty list means "permits nothing". An adapter
      # that stores it as NULL turns a deliberately powerless token into an unrestricted one.
      it "keeps an empty scope list distinct from no scopes at all" do
        repo = build.call(one_account)
        repo.create(scoped.call("t1", "raw-1", [] of String))

        repo.find_by_digest(digest.call("raw-1")).or_fail.token.scopes
          .or_fail("an empty scope list must not read back as nil").should be_empty
      end

      it "carries scopes through the management listing as well as the lookup" do
        repo = build.call(one_account)
        repo.create(scoped.call("t1", "raw-1", ["invoices.read"]))

        repo.list_for_account("a1").first.scopes.should eq(["invoices.read"])
      end
    end

    it "preserves an expiry when there is one, and none when there is not" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", 30.days))
      repo.create(token.call("t2", "a1", "raw-2", nil))

      repo.find_by_digest(digest.call("raw-1")).or_fail.token.expires_at.should eq(now + 30.days)
      repo.find_by_digest(digest.call("raw-2")).or_fail.token.expires_at.should be_nil
    end

    it "returns nil for a digest nobody issued, rather than raising" do
      build.call(one_account).find_by_digest(digest.call("never-issued")).should be_nil
    end

    it "returns nil for an empty digest" do
      build.call(one_account).find_by_digest(Bytes.new(0)).should be_nil
    end

    # An inner join, so the failure mode is closed: a token pointing at an account that no
    # longer exists resolves to nothing.
    it "returns nil when the token's account does not exist" do
      repo = build.call([] of KemalIdentity::Accounts::Account)
      repo.create(token.call("t1", "ghost", "raw-1", nil))

      repo.find_by_digest(digest.call("raw-1")).should be_nil
    end

    it "refuses a duplicate digest instead of overwriting" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.create(token.call("t2", "a1", "raw-1", nil))
      end
    end

    # The repository reports facts; the service decides what they mean. That is what lets a
    # management screen list revoked tokens through the same repository.
    it "still resolves a revoked token, leaving the verdict to the caller" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.revoke("t1", now)

      repo.find_by_digest(digest.call("raw-1")).or_fail.token.revoked_at.should eq(now)
    end
  end

  describe "the joined account status" do
    it "carries the account's current auth_version" do
      repo = build.call([KemalIdentity::SpecHelper.account(auth_version: 7)])
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.find_by_digest(digest.call("raw-1")).or_fail.account_auth_version.should eq(7)
    end

    it "carries the account's disabled_at" do
      disabled_at = now - 1.hour
      repo = build.call([KemalIdentity::SpecHelper.account(disabled_at: disabled_at)])
      repo.create(token.call("t1", "a1", "raw-1", nil))

      found = repo.find_by_digest(digest.call("raw-1")).or_fail
      found.account_disabled_at.should eq(disabled_at)
      found.account_disabled?.should be_true
    end

    it "reports an enabled account as not disabled" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.find_by_digest(digest.call("raw-1")).or_fail.account_disabled?.should be_false
    end
  end

  describe "#touch" do
    it "moves last_used_at forward" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.touch("t1", now + 5.minutes).should be_true
      repo.find_by_digest(digest.call("raw-1")).or_fail.token.last_used_at.should eq(now + 5.minutes)
    end

    it "starts out never used" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.find_by_digest(digest.call("raw-1")).or_fail.token.last_used_at.should be_nil
    end

    it "returns false for an unknown token" do
      build.call(one_account).touch("nope", now).should be_false
    end

    it "affects only the named token" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a1", "raw-2", nil))
      repo.touch("t1", now + 5.minutes)

      repo.find_by_digest(digest.call("raw-2")).or_fail.token.last_used_at.should be_nil
    end
  end

  describe "#revoke" do
    it "stamps revoked_at" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.revoke("t1", now + 1.minute).should be_true
      repo.find_by_digest(digest.call("raw-1")).or_fail.token.revoked_at.should eq(now + 1.minute)
    end

    it "returns false for an unknown token" do
      build.call(one_account).revoke("nope", now).should be_false
    end

    # Revoking twice is not an error, but the caller still learns nothing changed — and the
    # first timestamp is the one an audit trail cares about.
    it "returns false for an already revoked token and does not re-stamp it" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.revoke("t1", now)

      repo.revoke("t1", now + 1.hour).should be_false
      repo.find_by_digest(digest.call("raw-1")).or_fail.token.revoked_at.should eq(now)
    end
  end

  describe "#revoke_all_for_account" do
    it "revokes every live token and returns the count" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a1", "raw-2", nil))

      repo.revoke_all_for_account("a1", now).should eq(2)
      repo.find_by_digest(digest.call("raw-2")).or_fail.token.revoked?.should be_true
    end

    it "does not touch another account's tokens" do
      repo = build.call([
        KemalIdentity::SpecHelper.account(id: "a1", login: "a1@example.com"),
        KemalIdentity::SpecHelper.account(id: "a2", login: "a2@example.com"),
      ])
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a2", "raw-2", nil))

      repo.revoke_all_for_account("a1", now).should eq(1)
      repo.find_by_digest(digest.call("raw-2")).or_fail.token.revoked?.should be_false
    end

    it "does not count or re-stamp tokens that were already revoked" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a1", "raw-2", nil))
      repo.revoke("t1", now)

      repo.revoke_all_for_account("a1", now + 1.hour).should eq(1)
      repo.find_by_digest(digest.call("raw-1")).or_fail.token.revoked_at.should eq(now)
    end

    it "returns zero for an account with no tokens" do
      build.call(one_account).revoke_all_for_account("a1", now).should eq(0)
    end
  end

  # The management screen. It lists revoked tokens too, because "when did I revoke that?" is
  # exactly the question such a screen exists to answer.
  describe "#list_for_account" do
    it "lists every token, revoked ones included" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a1", "raw-2", nil))
      repo.revoke("t1", now)

      repo.list_for_account("a1").map(&.id).sort!.should eq(["t1", "t2"])
    end

    it "does not list another account's tokens" do
      repo = build.call([
        KemalIdentity::SpecHelper.account(id: "a1", login: "a1@example.com"),
        KemalIdentity::SpecHelper.account(id: "a2", login: "a2@example.com"),
      ])
      repo.create(token.call("t1", "a1", "raw-1", nil))
      repo.create(token.call("t2", "a2", "raw-2", nil))

      repo.list_for_account("a2").map(&.id).should eq(["t2"])
    end

    it "returns an empty array for an account with no tokens" do
      build.call(one_account).list_for_account("a1").should be_empty
    end

    # A listing must never be a way to read the secret back.
    it "carries digests, never anything a client could present" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      listed = repo.list_for_account("a1").first
      listed.token_digest.should eq(digest.call("raw-1"))
      listed.inspect.should contain("[REDACTED]")
    end
  end

  describe "#delete_expired" do
    it "removes only rows past their expiry" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", 10.days))
      repo.create(token.call("t2", "a1", "raw-2", 40.days))

      repo.delete_expired(now + 20.days).should eq(1)
      repo.find_by_digest(digest.call("raw-2")).should_not be_nil
    end

    # A token with no expiry is never expired, so a sweep must never reach a deploy key.
    it "never removes a token that has no expiry" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", nil))

      repo.delete_expired(now + 1000.days).should eq(0)
      repo.find_by_digest(digest.call("raw-1")).should_not be_nil
    end

    it "leaves a live token alone" do
      repo = build.call(one_account)
      repo.create(token.call("t1", "a1", "raw-1", 30.days))

      repo.delete_expired(now).should eq(0)
    end
  end
end

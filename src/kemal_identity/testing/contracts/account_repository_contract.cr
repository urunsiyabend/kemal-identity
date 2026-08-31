# Shared spec for `KemalIdentity::Accounts::Repository`. Every implementation runs it,
# including `MemoryAccountRepository` — a double that quietly behaves differently from
# PostgreSQL turns a green suite into false confidence, which is the whole reason contracts
# exist.
#
# The block is handed the accounts to seed and returns a repository containing exactly those.
# Seeding is per-implementation on purpose: `create` is deliberately *not* on the contract,
# because an adapter over somebody's existing `users` table has no business inserting rows
# into it.
def it_behaves_like_an_account_repository(&build : Array(KemalIdentity::Accounts::Account) -> KemalIdentity::Accounts::Repository)
  now = KemalIdentity::Testing::FIXED_NOW

  account = ->(id : String, login : String, tenant : String?) do
    KemalIdentity::Accounts::Account.new(
      id: id,
      normalized_login: login,
      tenant_id: tenant,
      password_digest: "digest-for-#{id}",
      password_scheme: "test",
      created_at: now,
      updated_at: now,
    )
  end

  describe "#find_by_id" do
    it "returns the account" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.find_by_id("a1").try(&.id).should eq("a1")
    end

    it "returns nil for an unknown id rather than raising" do
      build.call([] of KemalIdentity::Accounts::Account).find_by_id("nope").should be_nil
    end

    it "does not match on a prefix of an id" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.find_by_id("a").should be_nil
    end
  end

  describe "#find_by_login" do
    it "finds an account by its stored normalized login" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.find_by_login("ada@example.com").try(&.id).should eq("a1")
    end

    it "returns nil for an unknown login rather than raising" do
      build.call([] of KemalIdentity::Accounts::Account).find_by_login("nobody@example.com").should be_nil
    end

    # The repository compares by equality against the stored column. Normalising here as
    # well would hide a caller that forgot to, and that caller would then write a row the
    # lookup cannot find.
    it "does not normalize its argument" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.find_by_login("ADA@EXAMPLE.COM").should be_nil
      repo.find_by_login("  ada@example.com  ").should be_nil
    end

    describe "tenancy" do
      it "matches only the null tenant when given nil" do
        repo = build.call([
          account.call("a1", "ada@example.com", nil),
          account.call("a2", "ada@example.com", "t1"),
        ])
        repo.find_by_login("ada@example.com", nil).try(&.id).should eq("a1")
      end

      it "matches only the given tenant" do
        repo = build.call([
          account.call("a1", "ada@example.com", nil),
          account.call("a2", "ada@example.com", "t1"),
        ])
        repo.find_by_login("ada@example.com", "t1").try(&.id).should eq("a2")
      end

      # `= NULL` matches nothing in SQL, so this is the case an implementation gets wrong by
      # writing the obvious query.
      it "does not treat a nil tenant as a wildcard" do
        repo = build.call([account.call("a2", "ada@example.com", "t1")])
        repo.find_by_login("ada@example.com", nil).should be_nil
      end

      it "does not leak an account across tenants" do
        repo = build.call([account.call("a2", "ada@example.com", "t1")])
        repo.find_by_login("ada@example.com", "t2").should be_nil
      end
    end
  end

  describe "#update_password_digest" do
    it "replaces the digest and scheme" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.update_password_digest("a1", "new-digest", "bcrypt", now + 1.hour).should be_true

      updated = repo.find_by_id("a1").or_fail
      updated.password_digest.should eq("new-digest")
      updated.password_scheme.should eq("bcrypt")
      updated.updated_at.should eq(now + 1.hour)
    end

    it "returns false for an unknown account" do
      repo = build.call([] of KemalIdentity::Accounts::Account)
      repo.update_password_digest("nope", "new-digest", "bcrypt", now).should be_false
    end

    it "touches nothing else" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.update_password_digest("a1", "new-digest", "bcrypt", now)

      updated = repo.find_by_id("a1").or_fail
      updated.normalized_login.should eq("ada@example.com")
      updated.created_at.should eq(now)
    end

    # A rehash at a higher cost is not a credential change. Bumping auth_version here would
    # log every user out of the application that just raised its bcrypt cost.
    it "does not bump auth_version" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      before = repo.find_by_id("a1").or_fail.auth_version
      repo.update_password_digest("a1", "new-digest", "bcrypt", now)
      repo.find_by_id("a1").or_fail.auth_version.should eq(before)
    end

    it "affects only the named account" do
      repo = build.call([
        account.call("a1", "ada@example.com", nil),
        account.call("a2", "bob@example.com", nil),
      ])
      repo.update_password_digest("a1", "new-digest", "bcrypt", now)
      repo.find_by_id("a2").or_fail.password_digest.should eq("digest-for-a2")
    end
  end

  describe "#mark_email_verified" do
    it "records when the address was proved" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.mark_email_verified("a1", now + 1.hour).should be_true

      updated = repo.find_by_id("a1").or_fail
      updated.email_verified_at.should eq(now + 1.hour)
      updated.email_verified?.should be_true
    end

    it "starts out unverified" do
      build.call([account.call("a1", "ada@example.com", nil)])
        .find_by_id("a1").or_fail.email_verified?.should be_false
    end

    # Clicking a confirmation link twice is not an error.
    it "is idempotent, moving the timestamp forward" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.mark_email_verified("a1", now).should be_true
      repo.mark_email_verified("a1", now + 1.hour).should be_true

      repo.find_by_id("a1").or_fail.email_verified_at.should eq(now + 1.hour)
    end

    it "returns false for an unknown account" do
      build.call([] of KemalIdentity::Accounts::Account)
        .mark_email_verified("nope", now).should be_false
    end

    it "affects only the named account" do
      repo = build.call([
        account.call("a1", "ada@example.com", nil),
        account.call("a2", "bob@example.com", nil),
      ])
      repo.mark_email_verified("a1", now)
      repo.find_by_id("a2").or_fail.email_verified?.should be_false
    end

    it "does not disturb the password credential" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.mark_email_verified("a1", now)
      repo.find_by_id("a1").or_fail.password_digest.should eq("digest-for-a1")
    end
  end

  describe "#bump_auth_version" do
    it "increments and returns the new version" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.bump_auth_version("a1").should eq(2)
      repo.find_by_id("a1").or_fail.auth_version.should eq(2)
    end

    it "increments monotonically across calls" do
      repo = build.call([account.call("a1", "ada@example.com", nil)])
      repo.bump_auth_version("a1")
      repo.bump_auth_version("a1").should eq(3)
    end

    it "returns nil for an unknown account" do
      build.call([] of KemalIdentity::Accounts::Account).bump_auth_version("nope").should be_nil
    end

    it "affects only the named account" do
      repo = build.call([
        account.call("a1", "ada@example.com", nil),
        account.call("a2", "bob@example.com", nil),
      ])
      repo.bump_auth_version("a1")
      repo.find_by_id("a2").or_fail.auth_version.should eq(1)
    end
  end
end

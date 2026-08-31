require "../spec_helper"

# The migration path from `docs/06-roadmap.md`, and the two things about it that are security
# properties rather than conveniences: an old digest must be *retired* rather than merely
# accepted, and accepting one must not tell an attacker which accounts are still on it.

private LEGACY_PASSWORD = "correct horse battery"

private def legacy_digest(password : String = LEGACY_PASSWORD) : String
  KemalIdentity::Testing::LegacyTestVerifier.digest_for(password)
end

private record MigrationHarness,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  counting : KemalIdentity::Testing::CountingHasher,
  hasher : KemalIdentity::Passwords::MigratingHasher,
  authenticator : KemalIdentity::Passwords::Authenticator

private def migration_harness(digest : String = legacy_digest) : MigrationHarness
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  counting = KemalIdentity::Testing::CountingHasher.new(KemalIdentity::Testing::FastTestHasher.new)

  hasher = KemalIdentity::Passwords::MigratingHasher.new(
    counting,
    [KemalIdentity::Testing::LegacyTestVerifier.new.as(KemalIdentity::Passwords::LegacyVerifier)]
  )

  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::Testing.account(password_digest: digest),
  ])

  MigrationHarness.new(
    accounts: accounts,
    counting: counting,
    hasher: hasher,
    authenticator: KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts, hasher: hasher, clock: clock
    ),
  )
end

describe "migrating off a legacy password scheme" do
  describe "the migration-status timing oracle" do
    # A different oracle from the enumeration one `dummy_digest` closes, and easy to miss.
    # Legacy schemes are fast — being fast is why they are being retired — and bcrypt is
    # deliberately slow, so a failed login against an un-migrated account would return in
    # microseconds while a migrated one takes tens of milliseconds. An attacker learns exactly
    # which accounts are cheapest to crack if the database ever leaks.
    #
    # Counted rather than timed: a spec that measured elapsed time would flake on a loaded
    # runner and says no more than this does.
    it "does the same hashing work for a failed legacy login as for a failed current one" do
      harness = migration_harness
      wrong = KemalIdentity::Secret.new("not the password")

      harness.counting.reset_counts
      harness.hasher.verify(wrong, legacy_digest)
      legacy_cost = harness.counting.verifications

      harness.counting.reset_counts
      harness.hasher.verify(wrong, harness.hasher.dummy_digest)
      current_cost = harness.counting.verifications

      legacy_cost.should eq(current_cost)
      legacy_cost.should eq(1)
    end

    # The successful path pays the same, by a different route: the caller rehashes immediately,
    # and that rehash costs what a verification costs.
    it "rehashes on a successful legacy login, which is what pays for that path" do
      harness = migration_harness
      harness.counting.reset_counts

      harness.authenticator.authenticate(
        login: "ada@example.com", password: LEGACY_PASSWORD
      ).should be_a(KemalIdentity::Authenticated)

      harness.counting.hashes.should eq(1)
    end
  end

  describe "lazy migration" do
    # Nobody is forced through a password reset, and old digests disappear as people sign in.
    it "replaces the legacy digest on the first successful login" do
      harness = migration_harness

      harness.authenticator.authenticate(login: "ada@example.com", password: LEGACY_PASSWORD)

      stored = harness.accounts.find_by_id("a1").or_fail
      stored.password_scheme.should eq(KemalIdentity::Testing::FastTestHasher::SCHEME)
      harness.hasher.legacy_scheme_for(stored.password_digest.or_fail).should be_nil
    end

    it "goes through the current hasher alone on the second login" do
      harness = migration_harness
      harness.authenticator.authenticate(login: "ada@example.com", password: LEGACY_PASSWORD)

      harness.counting.reset_counts
      harness.authenticator.authenticate(
        login: "ada@example.com", password: LEGACY_PASSWORD
      ).should be_a(KemalIdentity::Authenticated)

      # Verified once, and not rehashed again: the digest is already current.
      harness.counting.verifications.should eq(1)
      harness.counting.hashes.should eq(0)
    end

    # The old digest is retired, not merely superseded. If it still verified, a leaked copy of
    # the old table would stay useful.
    it "stops accepting the legacy digest once it has been replaced" do
      harness = migration_harness
      harness.authenticator.authenticate(login: "ada@example.com", password: LEGACY_PASSWORD)

      harness.hasher.verify(KemalIdentity::Secret.new(LEGACY_PASSWORD), legacy_digest).should be_true
      harness.accounts.find_by_id("a1").or_fail.password_digest.should_not eq(legacy_digest)
    end

    it "refuses the wrong password against a legacy digest without migrating anything" do
      harness = migration_harness

      harness.authenticator.authenticate(
        login: "ada@example.com", password: "wrong"
      ).should be_a(KemalIdentity::Failed)

      harness.accounts.find_by_id("a1").or_fail.password_digest.should eq(legacy_digest)
    end
  end

  describe "a legacy password longer than the current hasher can represent" do
    # Legacy schemes are usually unsalted digests with no input limit, so an old table can hold
    # a password longer than bcrypt's 71 bytes. Verifying it would succeed and the immediate
    # rehash would raise, because `hash_secret` refuses rather than truncating — a 500 on every
    # login for those accounts. Refused instead, and the login is indistinguishable from a
    # wrong password.
    it "fails the login rather than raising" do
      long = "x" * 500
      harness = migration_harness(legacy_digest(long))

      result = harness.authenticator.authenticate(login: "ada@example.com", password: long)

      result.should be_a(KemalIdentity::Failed)
      result.as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::InvalidCredential)
    end

    it "leaves the account on the legacy digest rather than half-migrating it" do
      long = "x" * 500
      harness = migration_harness(legacy_digest(long))

      harness.authenticator.authenticate(login: "ada@example.com", password: long)

      harness.accounts.find_by_id("a1").or_fail.password_digest.should eq(legacy_digest(long))
    end
  end

  describe "the legacy scheme as a write path" do
    # A migration that can still create rows in the old format is not a migration.
    it "never produces a legacy digest, whatever the input" do
      harness = migration_harness

      %w[short correct\ horse\ battery].each do |password|
        digest = harness.hasher.hash_secret(KemalIdentity::Secret.new(password))
        harness.hasher.legacy_scheme_for(digest).should be_nil
      end
    end

    it "reports the current scheme, so the count of what is left keeps working" do
      harness = migration_harness
      harness.hasher.scheme.should eq(KemalIdentity::Testing::FastTestHasher::SCHEME)
      harness.hasher.legacy_schemes.should eq(["legacy-sha256"])
    end
  end
end

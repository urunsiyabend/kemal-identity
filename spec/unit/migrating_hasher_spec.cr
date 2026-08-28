require "../spec_helper"

private def legacy : KemalIdentity::Testing::LegacyTestVerifier
  KemalIdentity::Testing::LegacyTestVerifier.new
end

private def migrating(
  rounds : Int32 = 2,
) : KemalIdentity::Passwords::MigratingHasher
  KemalIdentity::Passwords::MigratingHasher.new(
    KemalIdentity::Testing::FastTestHasher.new(rounds: rounds),
    [legacy.as(KemalIdentity::Passwords::LegacyVerifier)]
  )
end

describe KemalIdentity::Passwords::MigratingHasher do
  # It is a hasher wherever a hasher goes. Wrapping the current one must not change any of the
  # behaviour the contract pins down — that is what makes it droppable into an existing
  # configuration.
  it_behaves_like_a_hasher do
    [migrating(rounds: 2), migrating(rounds: 1)] of KemalIdentity::Passwords::Hasher
  end

  secret = KemalIdentity::Secret.new("correct horse battery")

  describe "verification" do
    it "verifies a digest the current hasher owns" do
      hasher = migrating
      hasher.verify(secret, hasher.hash_secret(secret)).should be_true
    end

    it "verifies a digest from the scheme being migrated off" do
      digest = KemalIdentity::Testing::LegacyTestVerifier.digest_for("correct horse battery")

      migrating.verify(secret, digest).should be_true
    end

    it "refuses the wrong password against a legacy digest" do
      digest = KemalIdentity::Testing::LegacyTestVerifier.digest_for("something else")

      migrating.verify(secret, digest).should be_false
    end

    # The rule `Hasher` states and the reason `verify` never raises: this runs on the request
    # path against whatever a client posted.
    it "returns false rather than raising for an over-length secret" do
      digest = KemalIdentity::Testing::LegacyTestVerifier.digest_for("x" * 500)

      migrating.verify(KemalIdentity::Secret.new("x" * 500), digest).should be_false
    end

    it "returns false for a digest nobody recognises" do
      migrating.verify(secret, "not a digest at all").should be_false
    end
  end

  describe "writing" do
    # A migration that can still create rows in the old format is not a migration.
    it "always produces a current-scheme digest" do
      hasher = migrating
      digest = hasher.hash_secret(secret)

      hasher.legacy_scheme_for(digest).should be_nil
      hasher.scheme.should eq(KemalIdentity::Testing::FastTestHasher::SCHEME)
    end

    # This is what makes lazy rehash retire the old digests: the authenticator rehashes
    # whenever `needs_rehash?` is true, and it is true for every legacy digest by construction.
    it "reports a legacy digest as needing a rehash" do
      digest = KemalIdentity::Testing::LegacyTestVerifier.digest_for("correct horse battery")

      migrating.needs_rehash?(digest).should be_true
    end
  end

  describe "routing" do
    it "names which legacy scheme owns a digest, for a progress report" do
      hasher = migrating
      digest = KemalIdentity::Testing::LegacyTestVerifier.digest_for("x")

      hasher.legacy_scheme_for(digest).should eq("legacy-sha256")
      hasher.legacy_schemes.should eq(["legacy-sha256"])
    end

    # Trying every verifier in turn would make a login cost the sum of every legacy scheme, and
    # make that cost depend on which scheme the account uses.
    it "does not consult a legacy verifier for a digest the current hasher owns" do
      inner = KemalIdentity::Testing::CountingHasher.new(KemalIdentity::Testing::FastTestHasher.new)
      refusing = KemalIdentity::Testing::LegacyTestVerifier.new(prefix: "never$")

      hasher = KemalIdentity::Passwords::MigratingHasher.new(
        inner, [refusing.as(KemalIdentity::Passwords::LegacyVerifier)]
      )

      digest = hasher.hash_secret(secret)
      inner.reset_counts

      hasher.verify(secret, digest).should be_true
      inner.verifications.should eq(1)
    end
  end

  describe "configuration" do
    it "refuses to be built with no legacy verifier" do
      expect_raises(KemalIdentity::ConfigurationError, /at least one/) do
        KemalIdentity::Passwords::MigratingHasher.new(
          KemalIdentity::Testing::FastTestHasher.new,
          [] of KemalIdentity::Passwords::LegacyVerifier
        )
      end
    end

    # Two verifiers under one name make a progress report lie about which scheme is left.
    it "refuses two legacy verifiers sharing a name" do
      expect_raises(KemalIdentity::ConfigurationError, /share a name/) do
        KemalIdentity::Passwords::MigratingHasher.new(
          KemalIdentity::Testing::FastTestHasher.new,
          [
            KemalIdentity::Testing::LegacyTestVerifier.new(name: "same").as(KemalIdentity::Passwords::LegacyVerifier),
            KemalIdentity::Testing::LegacyTestVerifier.new(name: "same", prefix: "other$").as(KemalIdentity::Passwords::LegacyVerifier),
          ]
        )
      end
    end
  end
end

require "../spec_helper"

describe KemalIdentity::Passwords::BcryptHasher do
  # Cost 4 is bcrypt's minimum and is used throughout this file so the contract can run
  # against the real algorithm without the suite taking minutes. The production default is
  # 12, and `bench/` is where a cost is actually chosen.
  it_behaves_like_a_hasher do
    [
      KemalIdentity::Passwords::BcryptHasher.new(cost: 5),
      KemalIdentity::Passwords::BcryptHasher.new(cost: 4),
    ] of KemalIdentity::Passwords::Hasher
  end

  it "defaults to a cost above the standard library's" do
    KemalIdentity::Passwords::BcryptHasher::DEFAULT_COST.should eq(12)
    KemalIdentity::Passwords::BcryptHasher::DEFAULT_COST.should be > Crypto::Bcrypt::DEFAULT_COST
  end

  it "names bcrypt as its scheme, for auth_accounts.password_scheme" do
    KemalIdentity::Passwords::BcryptHasher.new(cost: 4).scheme.should eq("bcrypt")
  end

  it "produces a digest the standard library recognises" do
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
    digest = hasher.hash_secret(KemalIdentity::Secret.new("correct horse"))

    digest.should start_with("$2a$04$")
    Crypto::Bcrypt::Password.new(digest).verify("correct horse").should be_true
  end

  it "verifies a digest produced by the standard library directly" do
    # Applications arriving from another bcrypt implementation have exactly these digests.
    foreign = Crypto::Bcrypt::Password.create("correct horse", cost: 4).to_s
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)

    hasher.verify(KemalIdentity::Secret.new("correct horse"), foreign).should be_true
    hasher.verify(KemalIdentity::Secret.new("wrong horse"), foreign).should be_false
  end

  describe "cost configuration" do
    it "rejects a cost below the algorithm's range at construction" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Passwords::BcryptHasher.new(cost: 3)
      end
    end

    it "rejects a cost above the algorithm's range at construction" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Passwords::BcryptHasher.new(cost: 32)
      end
    end

    it "records the cost in the digest, which is what makes lazy rehash possible" do
      KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
        .hash_secret(KemalIdentity::Secret.new("correct horse"))
        .should start_with("$2a$04$")
    end
  end
end

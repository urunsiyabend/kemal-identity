require "../spec_helper"

# docs/02-security-model.md, release blocker: "Explicit rejection of over-length passwords,
# never truncation."
#
# Named for the attack rather than the method. If the hasher truncated at bcrypt's 71-byte
# limit, then a 71-byte password and that same password followed by *anything at all* would
# open the same account — so an attacker who learns a prefix gets in, and a password manager
# generating 100-character secrets silently provides no more security than 71.
describe "password truncation" do
  hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
  limit = hasher.max_secret_bytesize

  it "rejects a secret one byte over the algorithm's limit instead of cutting it" do
    expect_raises(ArgumentError) do
      hasher.hash_secret(KemalIdentity::Secret.new("a" * (limit + 1)))
    end
  end

  it "does not let a longer secret open an account created at the limit" do
    digest = hasher.hash_secret(KemalIdentity::Secret.new("a" * limit))

    hasher.verify(KemalIdentity::Secret.new("a" * limit), digest).should be_true
    hasher.verify(KemalIdentity::Secret.new("a" * limit + "b"), digest).should be_false
    hasher.verify(KemalIdentity::Secret.new("a" * (limit * 2)), digest).should be_false
  end

  it "measures the limit in bytes, so a multi-byte password is not silently cut" do
    # 36 two-byte characters is 72 bytes: one over the limit, but only 36 characters, so a
    # limit checked in characters would let it through and truncate mid-character.
    over = "é" * 36
    over.size.should eq(36)
    over.bytesize.should eq(72)
    over.bytesize.should be > limit

    expect_raises(ArgumentError) { hasher.hash_secret(KemalIdentity::Secret.new(over)) }
  end

  it "rejects an over-length secret on the request path as a value, not an exception" do
    # A guard raising here would turn a hostile login POST into a 500 and hand out a
    # distinguishable response. `verify` is on the request path; expected failures are
    # values (src/CLAUDE.md).
    digest = hasher.hash_secret(KemalIdentity::Secret.new("correct horse"))
    hasher.verify(KemalIdentity::Secret.new("a" * 10_000), digest).should be_false
  end

  it "never puts the secret in the error message" do
    error = expect_raises(ArgumentError) do
      hasher.hash_secret(KemalIdentity::Secret.new("hunter2" + "a" * limit))
    end
    error.message.to_s.should_not contain("hunter2")
  end
end

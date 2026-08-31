# Shared spec for `KemalIdentity::Passwords::Hasher`. Every implementation runs it, the
# `FastTestHasher` double included — a double that behaves differently from the real hasher
# turns a green suite into false confidence, and this is the contract people get subtly
# wrong.
#
# The block returns two hashers as `[current, weaker] of Hasher`: the first at the current
# parameters, the second at parameters *below* them, so `needs_rehash?` can be tested
# without hard-coding what a cost looks like for a given algorithm. The `of Hasher` on the
# literal is what gives the array the abstract element type.
def it_behaves_like_a_hasher(&block : -> Array(KemalIdentity::Passwords::Hasher))
  secret = ->(value : String) { KemalIdentity::Secret.new(value) }

  it "names its scheme" do
    current = block.call.first
    current.scheme.should_not be_empty
  end

  it "verifies a secret against its own digest" do
    current = block.call.first
    current.verify(secret.call("correct horse"), current.hash_secret(secret.call("correct horse"))).should be_true
  end

  it "rejects a different secret" do
    current = block.call.first
    current.verify(secret.call("wrong horse"), current.hash_secret(secret.call("correct horse"))).should be_false
  end

  it "rejects a secret that merely shares a prefix" do
    current = block.call.first
    current.verify(secret.call("correct hors"), current.hash_secret(secret.call("correct horse"))).should be_false
  end

  it "salts, so the same secret digests differently every time" do
    current = block.call.first
    current.hash_secret(secret.call("same")).should_not eq(current.hash_secret(secret.call("same")))
  end

  it "verifies against either of two digests of the same secret" do
    current = block.call.first
    first = current.hash_secret(secret.call("same"))
    second = current.hash_secret(secret.call("same"))
    current.verify(secret.call("same"), first).should be_true
    current.verify(secret.call("same"), second).should be_true
  end

  describe "the algorithm's input limit" do
    it "reports a positive maximum in bytes" do
      current = block.call.first
      current.max_secret_bytesize.should be > 0
    end

    it "hashes a secret exactly at the limit" do
      current = block.call.first
      at_limit = secret.call("a" * current.max_secret_bytesize)
      current.verify(at_limit, current.hash_secret(at_limit)).should be_true
    end

    # The whole point: if the limit truncated, these two would open the same account.
    it "does not truncate, so a longer secret does not verify against a digest at the limit" do
      current = block.call.first
      at_limit = "a" * current.max_secret_bytesize
      digest = current.hash_secret(secret.call(at_limit))
      current.verify(secret.call(at_limit + "extra"), digest).should be_false
    end

    it "raises rather than truncating when hashing an over-length secret" do
      current = block.call.first
      too_long = secret.call("a" * (current.max_secret_bytesize + 1))
      expect_raises(ArgumentError) { current.hash_secret(too_long) }
    end

    it "does not leak the secret in the over-length error message" do
      current = block.call.first
      too_long = secret.call("hunter2" + "a" * current.max_secret_bytesize)
      error = expect_raises(ArgumentError) { current.hash_secret(too_long) }
      error.message.to_s.should_not contain("hunter2")
    end

    # On the request path, fed by whatever a client posted. A hostile length has to be a
    # value, not an exception.
    it "returns false rather than raising when verifying an over-length secret" do
      current = block.call.first
      digest = current.hash_secret(secret.call("correct horse"))
      current.verify(secret.call("a" * (current.max_secret_bytesize + 1)), digest).should be_false
    end

    it "counts the limit in bytes, not characters" do
      current = block.call.first
      # A single "é" is two bytes in UTF-8, so this string is one byte over the limit while
      # being comfortably under it in characters.
      over = "é" * (current.max_secret_bytesize // 2 + 1)
      over.size.should be < current.max_secret_bytesize
      over.bytesize.should be > current.max_secret_bytesize
      expect_raises(ArgumentError) { current.hash_secret(secret.call(over)) }
    end

    it "raises on an empty secret" do
      current = block.call.first
      expect_raises(ArgumentError) { current.hash_secret(secret.call("")) }
    end

    it "returns false for an empty secret on verify" do
      current = block.call.first
      current.verify(secret.call(""), current.hash_secret(secret.call("correct horse"))).should be_false
    end
  end

  describe "#needs_rehash?" do
    it "is false for a digest at the current parameters" do
      current = block.call.first
      current.needs_rehash?(current.hash_secret(secret.call("correct horse"))).should be_false
    end

    it "is true for a digest at weaker parameters" do
      current, weaker = block.call.first(2)
      current.needs_rehash?(weaker.hash_secret(secret.call("correct horse"))).should be_true
    end

    it "is true for a digest it cannot parse" do
      current = block.call.first
      current.needs_rehash?("not-a-digest-at-all").should be_true
    end

    # The lazy-rehash path in docs/06-roadmap.md: the old digest still has to verify, or
    # every existing user is locked out by the upgrade.
    it "still verifies a digest at weaker parameters" do
      current, weaker = block.call.first(2)
      current.verify(secret.call("correct horse"), weaker.hash_secret(secret.call("correct horse"))).should be_true
    end
  end

  describe "#verify with an unusable digest" do
    it "returns false rather than raising for a malformed digest" do
      current = block.call.first
      current.verify(secret.call("correct horse"), "not-a-digest-at-all").should be_false
    end

    it "returns false rather than raising for an empty digest" do
      current = block.call.first
      current.verify(secret.call("correct horse"), "").should be_false
    end
  end

  describe "#dummy_digest" do
    it "is stable within a hasher, so it is not recomputed per request" do
      current = block.call.first
      current.dummy_digest.should eq(current.dummy_digest)
    end

    it "does not need a rehash, so the unknown-login path looks like any other" do
      current = block.call.first
      current.needs_rehash?(current.dummy_digest).should be_false
    end

    it "verifies false against every input" do
      current = block.call.first
      ["", "password", "correct horse", current.dummy_digest, "a" * 71].each do |candidate|
        current.verify(secret.call(candidate), current.dummy_digest).should be_false
      end
    end

    # Unguessable rather than a documented constant: a hard-coded dummy secret is a value an
    # attacker can submit, and any code path that trusted `verify` alone would then
    # authenticate an account that does not exist.
    it "differs between hashers, so it is not a guessable constant" do
      first = block.call.first
      second = block.call.first
      first.dummy_digest.should_not eq(second.dummy_digest)
    end
  end
end

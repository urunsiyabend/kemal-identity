require "../spec_helper"

# One context for the whole file. Each `HashingExecutor.new(inner, size:)` builds a thread
# pool, and the contract spec constructs two hashers per example -- sharing avoids spawning a
# pool per example for no benefit.
SPEC_HASHING_CONTEXT = Fiber::ExecutionContext::Parallel.new("spec-hashing", 2)

describe KemalIdentity::Passwords::HashingExecutor do
  # It satisfies the same contract as the hasher it wraps. That is what lets it be dropped in
  # anywhere a hasher goes, and it is why dispatch could be added without touching the Hasher
  # API.
  it_behaves_like_a_hasher do
    [
      KemalIdentity::Passwords::HashingExecutor.new(
        KemalIdentity::Testing::FastTestHasher.new(rounds: 2), context: SPEC_HASHING_CONTEXT
      ),
      KemalIdentity::Passwords::HashingExecutor.new(
        KemalIdentity::Testing::FastTestHasher.new(rounds: 1), context: SPEC_HASHING_CONTEXT
      ),
    ] of KemalIdentity::Passwords::Hasher
  end

  inner = KemalIdentity::Testing::FastTestHasher.new
  executor = KemalIdentity::Passwords::HashingExecutor.new(inner, context: SPEC_HASHING_CONTEXT)
  secret = KemalIdentity::Secret.new("correct horse battery")

  describe "delegation" do
    it "reports the wrapped hasher's scheme and limit" do
      executor.scheme.should eq(inner.scheme)
      executor.max_secret_bytesize.should eq(inner.max_secret_bytesize)
    end

    it "shares the wrapped hasher's dummy digest, so the timing equalisation still holds" do
      executor.dummy_digest.should eq(inner.dummy_digest)
    end

    it "verifies a digest the wrapped hasher produced directly" do
      executor.verify(secret, inner.hash_secret(secret)).should be_true
    end

    it "produces a digest the wrapped hasher verifies directly" do
      inner.verify(secret, executor.hash_secret(secret)).should be_true
    end

    it "exposes the hasher it wraps" do
      executor.inner.should be(inner)
    end
  end

  # A work dispatcher that swallowed an exception would leave the caller parked on a channel
  # that never receives -- a hang rather than an error, which is the worse failure.
  describe "exceptions crossing back from the hashing context" do
    it "re-raises an over-length secret's ArgumentError on the calling fiber" do
      expect_raises(ArgumentError) do
        executor.hash_secret(KemalIdentity::Secret.new("a" * 100))
      end
    end

    it "re-raises an empty secret's ArgumentError" do
      expect_raises(ArgumentError) { executor.hash_secret(KemalIdentity::Secret.new("")) }
    end

    it "keeps the secret out of the re-raised message" do
      error = expect_raises(ArgumentError) do
        executor.hash_secret(KemalIdentity::Secret.new("hunter2" + "a" * 100))
      end
      error.message.to_s.should_not contain("hunter2")
    end

    it "re-raises whatever the wrapped hasher raises, unchanged" do
      exploding = KemalIdentity::Passwords::HashingExecutor.new(
        ExplodingHasher.new, context: SPEC_HASHING_CONTEXT
      )

      error = expect_raises(KemalIdentity::InfrastructureError) do
        exploding.verify(secret, "digest")
      end
      error.message.should eq("crypto backend unavailable")
    end

    it "still works after an exception, rather than leaving the context poisoned" do
      expect_raises(ArgumentError) { executor.hash_secret(KemalIdentity::Secret.new("")) }
      executor.verify(secret, executor.hash_secret(secret)).should be_true
    end
  end

  describe "concurrent callers" do
    it "gives every caller its own result" do
      secrets = Array.new(16) { |i| KemalIdentity::Secret.new("password-#{i}") }
      digests = secrets.map { |candidate| inner.hash_secret(candidate) }
      results = Array.new(16) { false }
      group = WaitGroup.new(16)

      16.times do |i|
        spawn do
          # Each caller checks its own secret against its own digest. A dispatcher that
          # crossed results between callers would authenticate the wrong person.
          results[i] = executor.verify(secrets[i], digests[i])
        ensure
          group.done
        end
      end

      group.wait

      results.all?.should be_true
    end

    it "does not match one caller's secret against another's digest" do
      a = KemalIdentity::Secret.new("password-a")
      b_digest = inner.hash_secret(KemalIdentity::Secret.new("password-b"))

      results = Array.new(16) { true }
      group = WaitGroup.new(16)

      16.times do |i|
        spawn do
          results[i] = executor.verify(a, b_digest)
        ensure
          group.done
        end
      end

      group.wait

      results.none?.should be_true
    end
  end

  describe "configuration" do
    it "refuses a non-positive pool size" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Passwords::HashingExecutor.new(inner, size: 0)
      end
    end

    it "defaults to a small pool, because the point is a ceiling and not throughput" do
      KemalIdentity::Passwords::HashingExecutor::DEFAULT_SIZE.should eq(2)
    end
  end
end

class ExplodingHasher < KemalIdentity::Passwords::Hasher
  def scheme : String
    "exploding"
  end

  def max_secret_bytesize : Int32
    71
  end

  def hash_secret(secret : KemalIdentity::Secret) : String
    raise KemalIdentity::InfrastructureError.new("crypto backend unavailable")
  end

  def verify(secret : KemalIdentity::Secret, digest : String) : Bool
    raise KemalIdentity::InfrastructureError.new("crypto backend unavailable")
  end

  def needs_rehash?(digest : String) : Bool
    false
  end

  def dummy_digest : String
    "dummy"
  end
end

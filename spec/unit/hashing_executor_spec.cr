require "../spec_helper"

# Building an executor, in whichever way this Crystal allows.
#
# Where execution contexts exist, one context is shared by the whole file: each
# `HashingExecutor.new(inner, size:)` builds a thread pool, and the contract spec constructs
# two hashers per example, so sharing avoids a pool per example for no benefit.
#
# Where they do not, the executor is built with the deliberate `allow_inline: true` opt-out. It
# then satisfies the same `Hasher` contract while dispatching nowhere -- which is exactly the
# claim worth testing on those versions.
{% if Fiber.has_constant?("ExecutionContext") %}
  SPEC_HASHING_CONTEXT = Fiber::ExecutionContext::Parallel.new("spec-hashing", 2)

  private def build_executor(inner : KemalIdentity::Passwords::Hasher) : KemalIdentity::Passwords::HashingExecutor
    KemalIdentity::Passwords::HashingExecutor.new(inner, context: SPEC_HASHING_CONTEXT)
  end
{% else %}
  private def build_executor(inner : KemalIdentity::Passwords::Hasher) : KemalIdentity::Passwords::HashingExecutor
    KemalIdentity::Passwords::HashingExecutor.new(inner, allow_inline: true)
  end
{% end %}

describe KemalIdentity::Passwords::HashingExecutor do
  # It satisfies the same contract as the hasher it wraps. That is what lets it be dropped in
  # anywhere a hasher goes, and it is why dispatch could be added without touching the Hasher
  # API.
  it_behaves_like_a_hasher do
    [
      build_executor(KemalIdentity::Testing::FastTestHasher.new(rounds: 2)),
      build_executor(KemalIdentity::Testing::FastTestHasher.new(rounds: 1)),
    ] of KemalIdentity::Passwords::Hasher
  end

  inner = KemalIdentity::Testing::FastTestHasher.new
  executor = build_executor(inner)
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
      exploding = build_executor(ExplodingHasher.new)

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

      join_fibers(16) do |i|
        # Each caller checks its own secret against its own digest. A dispatcher that
        # crossed results between callers would authenticate the wrong person.
        results[i] = executor.verify(secrets[i], digests[i])
      end

      results.all?.should be_true
    end

    it "does not match one caller's secret against another's digest" do
      a = KemalIdentity::Secret.new("password-a")
      b_digest = inner.hash_secret(KemalIdentity::Secret.new("password-b"))

      results = Array.new(16) { true }

      join_fibers(16) do |i|
        results[i] = executor.verify(a, b_digest)
      end

      results.none?.should be_true
    end
  end

  describe "configuration" do
    it "refuses a non-positive pool size" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Passwords::HashingExecutor.new(inner, size: 0, allow_inline: true)
      end
    end

    # The protection either exists or says loudly that it does not. A security property that
    # silently disappears on an older compiler is worse than one that is absent noisily.
    {% if Fiber.has_constant?("ExecutionContext") %}
      it "dispatches, because this Crystal has execution contexts" do
        KemalIdentity::Passwords::HashingExecutor.new(inner, size: 1).dispatching?.should be_true
      end
    {% else %}
      it "refuses to be built without the opt-out, because this Crystal cannot dispatch" do
        error = expect_raises(KemalIdentity::ConfigurationError) do
          KemalIdentity::Passwords::HashingExecutor.new(inner, size: 1)
        end
        error.message.to_s.should contain("allow_inline")
      end

      it "runs inline when the opt-out is taken, and says so" do
        KemalIdentity::Passwords::HashingExecutor.new(inner, size: 1, allow_inline: true)
          .dispatching?.should be_false
      end
    {% end %}

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

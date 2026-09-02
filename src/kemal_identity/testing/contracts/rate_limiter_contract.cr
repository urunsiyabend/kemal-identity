# Shared specs for `KemalIdentity::RateLimiter`.
#
# There are two, and the split was forced by writing a second real implementation:
# `ExponentialBackoffRateLimiter` cannot satisfy `it_behaves_like_a_rate_limiter` because that
# suite describes a **fixed-window strategy** — "allows `limit` attempts, then denies until the
# window passes" — rather than the contract. A shared contract that only one strategy can pass
# is a contract that tells the next adapter author to implement the wrong thing.
#
# So `it_behaves_like_a_rate_limiter_of_any_strategy` holds what every limiter owes its caller
# whatever curve it uses: atomicity under concurrency, independent keys, `reset` clearing, and
# an honest `retry_after`. Run it for any implementation. Run the window suite below as well
# only if the implementation *is* a window.
#
# `NullRateLimiter` satisfies neither, deliberately — allowing everything is its whole purpose
# — and has its own spec.
def it_behaves_like_a_rate_limiter_of_any_strategy(
  &build : -> Tuple(KemalIdentity::RateLimiter, KemalIdentity::Testing::TestClock)
)
  it "eventually refuses a caller that never stops" do
    limiter, _ = build.call

    # No claim about *when*: a window refuses on attempt limit+1, a backoff refuses on the
    # second. Either way, hammering one key has to stop working, or the limiter is a no-op.
    refused = (1..1000).any? { !limiter.consume("key").allowed? }
    refused.should be_true
  end

  it "tells a refused caller when to come back, and says nothing when it allows" do
    limiter, _ = build.call

    first = limiter.consume("key")
    first.allowed?.should be_true
    first.retry_after.should be_nil

    verdict = (1..1000).each do |_|
      answer = limiter.consume("key")
      break answer unless answer.allowed?
    end

    verdict = verdict.as(KemalIdentity::Verdict)
    verdict.retry_after.or_fail("a refusal must say when to come back").should be > Time::Span.zero
  end

  it "counts each key separately" do
    limiter, _ = build.call

    # Refuse "a" outright, then show "b" is untouched.
    1000.times { break if !limiter.consume("a").allowed? }
    limiter.consume("b").allowed?.should be_true
  end

  it "clears a key on reset, and only that key" do
    limiter, _ = build.call

    1000.times { break if !limiter.consume("a").allowed? }
    1000.times { break if !limiter.consume("b").allowed? }

    limiter.reset("a")

    limiter.consume("a").allowed?.should be_true
    limiter.consume("b").allowed?.should be_false
  end

  it "is safe to reset a key that was never consumed, and to reset twice" do
    limiter, _ = build.call

    limiter.reset("never-seen")
    limiter.reset("never-seen")
    limiter.consume("never-seen").allowed?.should be_true
  end

  # A limiter is a shared counter by definition, so this is not a theoretical concern. What is
  # asserted is that the *same* number of attempts pass however they are interleaved — a lost
  # update would let more through.
  it "loses no update under concurrent consumers" do
    sequential, _ = build.call
    expected = 0
    20.times { expected += 1 if sequential.consume("k").allowed? }

    concurrent, _ = build.call
    allowed = Atomic(Int32).new(0)

    join_fibers(20) do
      allowed.add(1) if concurrent.consume("k").allowed?
    end

    allowed.get.should eq(expected)
  end
end

# The fixed-window suite: run it for an implementation that *is* a window.
#
# The block returns a limiter configured to allow `limit` attempts per window, and the clock
# that limiter reads, so a spec can move the window without sleeping.
def it_behaves_like_a_rate_limiter(
  limit : Int32,
  window : Time::Span,
  &build : -> Tuple(KemalIdentity::RateLimiter, KemalIdentity::Testing::TestClock)
)
  it "allows attempts up to the limit" do
    limiter, _ = build.call
    limit.times { limiter.consume("key").allowed?.should be_true }
  end

  it "denies the attempt after the limit" do
    limiter, _ = build.call
    limit.times { limiter.consume("key") }
    limiter.consume("key").allowed?.should be_false
  end

  it "keeps denying while the window stands" do
    limiter, _ = build.call
    (limit + 5).times { limiter.consume("key") }
    limiter.consume("key").allowed?.should be_false
  end

  # An honest client needs to know whether to wait a second or an hour. The attacker already
  # knows they are being throttled — that is what being throttled means.
  it "tells a denied caller when to come back" do
    limiter, _ = build.call
    limit.times { limiter.consume("key") }

    retry_after = limiter.consume("key").retry_after
    retry_after.should_not be_nil
    (retry_after.or_fail > Time::Span::ZERO).should be_true
    (retry_after.or_fail <= window).should be_true
  end

  it "says nothing about retrying when it allows" do
    limiter, _ = build.call
    limiter.consume("key").retry_after.should be_nil
  end

  it "counts each key separately" do
    limiter, _ = build.call
    limit.times { limiter.consume("noisy") }

    limiter.consume("noisy").allowed?.should be_false
    limiter.consume("quiet").allowed?.should be_true
  end

  it "allows again once the window has passed" do
    limiter, clock = build.call
    (limit + 1).times { limiter.consume("key") }

    clock.advance(window + 1.second)

    limiter.consume("key").allowed?.should be_true
  end

  describe "#reset" do
    it "clears the count" do
      limiter, _ = build.call
      limit.times { limiter.consume("key") }
      limiter.consume("key").allowed?.should be_false

      limiter.reset("key")

      limiter.consume("key").allowed?.should be_true
    end

    it "is safe for a key that was never consumed" do
      limiter, _ = build.call
      limiter.reset("never-seen")
      limiter.consume("never-seen").allowed?.should be_true
    end

    it "is idempotent" do
      limiter, _ = build.call
      limit.times { limiter.consume("key") }
      3.times { limiter.reset("key") }
      limiter.consume("key").allowed?.should be_true
    end

    it "clears only the key it was given" do
      limiter, _ = build.call
      limit.times { limiter.consume("a") }
      limit.times { limiter.consume("b") }

      limiter.reset("a")

      limiter.consume("a").allowed?.should be_true
      limiter.consume("b").allowed?.should be_false
    end
  end

  # A limiter is a shared counter by definition, so this is not a theoretical concern.
  describe "concurrent consumers" do
    it "counts every attempt exactly once" do
      limiter, _ = build.call
      allowed = Atomic(Int32).new(0)

      join_fibers(limit * 2) do
        allowed.add(1) if limiter.consume("contested").allowed?
      end

      # Exactly `limit` may pass. More would mean a lost update; fewer, a double count.
      allowed.get.should eq(limit)
    end
  end
end

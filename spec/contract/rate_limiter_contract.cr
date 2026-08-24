# Shared spec for `KemalIdentity::RateLimiter`.
#
# Run by every implementation that actually limits. `NullRateLimiter` deliberately does not
# satisfy it — allowing everything is its whole purpose — and has its own spec instead.
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
      group = WaitGroup.new(limit * 2)

      (limit * 2).times do
        spawn do
          allowed.add(1) if limiter.consume("contested").allowed?
        ensure
          group.done
        end
      end

      group.wait

      # Exactly `limit` may pass. More would mean a lost update; fewer, a double count.
      allowed.get.should eq(limit)
    end
  end
end

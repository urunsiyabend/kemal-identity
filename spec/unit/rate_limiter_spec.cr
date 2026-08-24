require "../spec_helper"

describe KemalIdentity::FixedWindowRateLimiter do
  it_behaves_like_a_rate_limiter(limit: 5, window: 1.minute) do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    {
      KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: 1.minute, clock: clock)
        .as(KemalIdentity::RateLimiter),
      clock,
    }
  end

  describe "the retry_after it reports" do
    it "shrinks as the window elapses" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      limiter = KemalIdentity::FixedWindowRateLimiter.new(limit: 1, window: 60.seconds, clock: clock)

      limiter.consume("key")
      first = limiter.consume("key").retry_after.or_fail

      clock.advance(30.seconds)
      second = limiter.consume("key").retry_after.or_fail

      (second < first).should be_true
    end
  end

  # Documented rather than smoothed over: a limiter that quietly allows more than its
  # configured limit is worse than one that says so.
  describe "the fixed-window boundary" do
    # The window is anchored to the first attempt, not to a calendar boundary, so it takes a
    # specific shape to exploit: fill a window that is about to elapse, then fill the next one
    # the moment it opens. Six attempts land within three seconds of each other against a limit
    # of three.
    it "can allow up to twice the limit across a boundary" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      limiter = KemalIdentity::FixedWindowRateLimiter.new(limit: 3, window: 60.seconds, clock: clock)

      # One attempt opens the window.
      limiter.consume("key").allowed?.should be_true

      # Two more at the very end of it.
      clock.advance(59.seconds)
      2.times { limiter.consume("key").allowed?.should be_true }
      limiter.consume("key").allowed?.should be_false

      # The window elapses and the next opens: three more, seconds after the previous three.
      clock.advance(2.seconds)
      3.times { limiter.consume("key").allowed?.should be_true }
      limiter.consume("key").allowed?.should be_false
    end
  end

  describe "memory" do
    # An attacker can otherwise mint one key per login guessed until the process runs out of
    # memory, turning the defence into the vulnerability.
    it "bounds the number of tracked keys" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      limiter = KemalIdentity::FixedWindowRateLimiter.new(
        limit: 5, window: 60.seconds, clock: clock, max_keys: 100
      )

      500.times { |i| limiter.consume("key-#{i}") }

      limiter.size.should be <= 100
    end

    it "reclaims keys whose window has elapsed" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      limiter = KemalIdentity::FixedWindowRateLimiter.new(
        limit: 5, window: 60.seconds, clock: clock, max_keys: 100
      )

      100.times { |i| limiter.consume("old-#{i}") }
      clock.advance(2.minutes)
      limiter.consume("new")

      limiter.size.should be < 100
    end
  end

  describe "boot-time validation" do
    it "refuses a non-positive limit" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::FixedWindowRateLimiter.new(limit: 0, window: 1.minute)
      end
    end

    it "refuses a non-positive window" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: Time::Span::ZERO)
      end
    end

    it "refuses a non-positive key cap" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: 1.minute, max_keys: 0)
      end
    end
  end
end

describe KemalIdentity::NullRateLimiter do
  # It deliberately does not satisfy the limiting contract. Allowing everything is the point,
  # and the shard cannot pick a sensible limit on an application's behalf.
  it "allows every attempt, however many" do
    limiter = KemalIdentity::NullRateLimiter.new
    1_000.times { limiter.consume("key").allowed?.should be_true }
  end

  it "never reports a retry_after" do
    KemalIdentity::NullRateLimiter.new.consume("key").retry_after.should be_nil
  end

  it "accepts a reset without complaint" do
    KemalIdentity::NullRateLimiter.new.reset("key")
  end
end

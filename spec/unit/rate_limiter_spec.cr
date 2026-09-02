require "../spec_helper"

describe KemalIdentity::FixedWindowRateLimiter do
  it_behaves_like_a_rate_limiter_of_any_strategy do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    {
      KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: 1.minute, clock: clock)
        .as(KemalIdentity::RateLimiter),
      clock,
    }
  end

  it_behaves_like_a_rate_limiter(limit: 5, window: 1.minute) do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    {
      KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: 1.minute, clock: clock)
        .as(KemalIdentity::RateLimiter),
      clock,
    }
  end

  describe "the retry_after it reports" do
    it "shrinks as the window elapses" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
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
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
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
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
      limiter = KemalIdentity::FixedWindowRateLimiter.new(
        limit: 5, window: 60.seconds, clock: clock, max_keys: 100
      )

      500.times { |i| limiter.consume("key-#{i}") }

      limiter.size.should be <= 100
    end

    it "reclaims keys whose window has elapsed" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
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

# The second real strategy, and the reason the contract above was split: this one cannot
# satisfy the fixed-window suite, because it is not a window. django-otp's `ThrottlingMixin` is
# the reference — `throttle_factor × 2^(n-1)` — and NIST SP 800-63B names an increasing wait as
# the mitigation for the lockout a flat limit would otherwise cause. MFA-04 in
# `blueprints/0025` measured what a flat limit costs: 103,680 attempts in thirty days.
private def backoff(factor : Time::Span = 1.second, max_delay : Time::Span = 1.hour)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  {KemalIdentity::ExponentialBackoffRateLimiter.new(
    factor: factor, max_delay: max_delay, clock: clock
  ), clock}
end

describe KemalIdentity::ExponentialBackoffRateLimiter do
  it_behaves_like_a_rate_limiter_of_any_strategy do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    {
      KemalIdentity::ExponentialBackoffRateLimiter.new(clock: clock)
        .as(KemalIdentity::RateLimiter),
      clock,
    }
  end

  it "allows the first attempt and then doubles the wait" do
    limiter, clock = backoff

    limiter.consume("key").allowed?.should be_true

    # 1s, 2s, 4s, 8s: each attempt allowed only once its own delay has elapsed.
    [1, 2, 4, 8].each do |seconds|
      limiter.consume("key").allowed?.should be_false

      clock.advance(seconds.seconds - 1.millisecond)
      limiter.consume("key").allowed?.should be_false

      clock.advance(1.millisecond)
      limiter.consume("key").allowed?.should be_true
    end
  end

  it "does not count a refused attempt, so retrying cannot push the wait out" do
    limiter, clock = backoff

    limiter.consume("key")

    first = limiter.consume("key").retry_after.or_fail
    20.times { limiter.consume("key") }
    still = limiter.consume("key").retry_after.or_fail

    # Same delay, and shrinking only with the clock. A limiter that counted refusals would
    # make a client in a retry loop wait exponentially longer for having asked.
    still.should eq(first)

    clock.advance(500.milliseconds)
    limiter.consume("key").retry_after.or_fail.should be_close(first - 500.milliseconds, 1.millisecond)
  end

  it "caps the delay" do
    limiter, _clock = backoff(factor: 1.second, max_delay: 10.seconds)

    limiter.delay_for(1).should eq(1.second)
    limiter.delay_for(4).should eq(8.seconds)
    limiter.delay_for(5).should eq(10.seconds)
    limiter.delay_for(60).should eq(10.seconds)
    limiter.delay_for(0).should eq(Time::Span.zero)
  end

  it "starts the curve over on reset, and not with the passage of time" do
    limiter, clock = backoff

    limiter.consume("key")
    clock.advance(1.second)
    limiter.consume("key")
    clock.advance(2.seconds)
    limiter.consume("key").allowed?.should be_true

    # Three consecutive attempts, so the next wait is 4s — a year later it is still 4s from
    # the last attempt, because "consecutive" means since the last success and nothing here
    # decays.
    clock.advance(365.days)
    limiter.consume("key").allowed?.should be_true

    limiter.reset("key")
    limiter.consume("key").allowed?.should be_true
    limiter.consume("key").retry_after.or_fail.should eq(1.second)
  end

  it "refuses a contradictory configuration at construction" do
    expect_raises(KemalIdentity::ConfigurationError, /factor must be positive/) do
      KemalIdentity::ExponentialBackoffRateLimiter.new(factor: Time::Span.zero)
    end

    expect_raises(KemalIdentity::ConfigurationError, /max_delay/) do
      KemalIdentity::ExponentialBackoffRateLimiter.new(factor: 1.minute, max_delay: 1.second)
    end
  end
end

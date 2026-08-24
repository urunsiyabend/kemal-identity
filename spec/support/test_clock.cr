module KemalIdentity::Testing
  # A clock that only moves when a spec moves it.
  #
  # This is what makes expiry testable at all: asserting that a session expires after
  # twelve hours advances the clock rather than sleeping. Passes the same `Clock` contract
  # spec as `SystemClock`.
  class TestClock < KemalIdentity::Clock
    def initialize(@now : Time = Time.utc(2026, 8, 24, 12, 0, 0))
    end

    def now : Time
      @now
    end

    # Move forward. Time never runs backwards on its own, so this is the only mutator, and
    # it refuses a negative span rather than quietly rewinding.
    def advance(span : Time::Span) : Time
      raise ArgumentError.new("cannot advance by a negative span") if span < Time::Span::ZERO
      @now += span
    end

    # Jump to an arbitrary instant. For setting up a fixture, not for simulating the
    # passage of time — use `advance` for that.
    def travel_to(time : Time) : Time
      @now = time
    end
  end
end

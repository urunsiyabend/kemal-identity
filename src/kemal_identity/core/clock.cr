module KemalIdentity
  # The only source of "now" in the shard.
  #
  # Every expiry, freshness and throttling decision reads the clock through this contract,
  # which is what makes those decisions testable: a spec that asserts a session expires
  # after twelve hours advances a `TestClock` instead of sleeping or stubbing the system
  # clock. `src/CLAUDE.md` bans `Time.utc` everywhere in `src/` except `SystemClock` below;
  # `spec/unit/source_hygiene_spec.cr` enforces that ban.
  abstract class Clock
    # The current instant, always UTC.
    abstract def now : Time
  end

  # The production clock. This is the single permitted call site for `Time.utc` in `src/`.
  class SystemClock < Clock
    def now : Time
      Time.utc
    end
  end
end

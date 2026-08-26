module KemalIdentity
  # What one sweep removed.
  struct SweepResult
    getter expired_sessions : Int32
    getter revoked_sessions : Int32
    getter action_tokens : Int32
    getter remember_tokens : Int32

    def initialize(
      @expired_sessions : Int32 = 0,
      @revoked_sessions : Int32 = 0,
      @action_tokens : Int32 = 0,
      @remember_tokens : Int32 = 0,
    )
    end

    def total : Int32
      @expired_sessions + @revoked_sessions + @action_tokens + @remember_tokens
    end

    def empty? : Bool
      total.zero?
    end
  end

  # Reclaims disk from rows nothing will read again.
  #
  # ### It is not a correctness mechanism, and that is the whole point
  #
  # Every check this shard makes is evaluated **on read**: a session past its deadline fails
  # when it is next resolved, a revoked one fails immediately, an action token's expiry is part
  # of the statement that consumes it. Nothing waits for a sweeper.
  #
  # That is a direct lesson from kemal-session issue #116, where `timeout` only marked a
  # session for deletion at the next GC pass, so a session past its timeout stayed valid until
  # the sweeper happened to run — and a read could refresh its access time before any expiry
  # check, reviving it. The rule this shard follows instead is **correctness on read, sweeping
  # for disk only** (`docs/02-security-model.md`), which means a sweeper that never runs costs
  # storage and nothing else.
  #
  # ### It does not start itself
  #
  # `run_every` returns the fiber it spawned and the application decides whether to call it. A
  # library that silently starts background work is a library that surprises people in a
  # multi-process deployment — four processes behind a load balancer would run four sweepers
  # against one database, which is wasteful at best (`docs/03-data-model.md`).
  #
  # ```
  # sweeper = KemalIdentity::Sweeper.new(KemalIdentity.app)
  # sweeper.run_every(1.hour)
  # ```
  #
  # For anything larger than a single process, run `sweep` from a cron job or a scheduler
  # instead, so exactly one of them is sweeping.
  #
  # ### Remember-me tokens are swept, never early
  #
  # A spent remember-me token's row **is** the evidence of a replay. Delete it before it
  # expires and a stolen token coming back looks unknown rather than replayed, so nobody is
  # told their cookie may have been copied. The repository's `delete_expired` already refuses
  # to touch anything before its expiry, and this only ever asks for that
  # (`blueprints/0012-remember-me.md`).
  class Sweeper
    # How long a revoked session row is kept after it is revoked.
    #
    # Not zero: the row is the evidence behind "you were signed out of this device", and it
    # costs almost nothing to keep for a day.
    #
    # ### This only reclaims anything for long-lived sessions
    #
    # A revoked row is swept by `delete_expired` at its absolute deadline regardless, so this
    # matters only when the retention window is **shorter than the session's remaining
    # lifetime**. With the default twelve-hour absolute timeout, a session revoked at any point
    # is gone within twelve hours anyway and this window never fires — it earns its keep when
    # `absolute_timeout` is measured in weeks, where a logout would otherwise leave a row
    # sitting until the deadline it will never reach.
    #
    # A day is short enough to reclaim, long enough to answer "was I signed out?".
    DEFAULT_REVOKED_RETENTION = 1.day

    getter? running : Bool

    def initialize(@app : Application, @revoked_retention : Time::Span = DEFAULT_REVOKED_RETENTION)
      unless @revoked_retention >= Time::Span::ZERO
        raise ConfigurationError.new("revoked_retention must not be negative")
      end

      @running = false
    end

    # Runs one sweep across every table this shard owns.
    #
    # Synchronous, so a cron job or a spec can call it directly and know it finished.
    def sweep : SweepResult
      now = @app.clock.now

      result = SweepResult.new(
        expired_sessions: @app.session_repository.delete_expired(now),
        revoked_sessions: @app.session_repository.delete_revoked_before(now - @revoked_retention),
        action_tokens: sweep_action_tokens(now),
        remember_tokens: sweep_remember_tokens(now),
      )

      unless result.empty?
        Log.info &.emit(
          "sweeper.swept",
          expired_sessions: result.expired_sessions,
          revoked_sessions: result.revoked_sessions,
          action_tokens: result.action_tokens,
          remember_tokens: result.remember_tokens
        )
      end

      result
    end

    # Sweeps every `interval` until `stop` is called, and returns the fiber doing it.
    #
    # The first sweep happens after the first interval, not immediately: a process that
    # restarts often would otherwise sweep on every boot, which is the opposite of what a
    # background job is for.
    def run_every(interval : Time::Span) : Fiber
      unless interval > Time::Span::ZERO
        raise ConfigurationError.new("interval must be positive")
      end

      @running = true

      spawn do
        while @running
          sleep interval
          next unless @running

          sweep_guarded
        end
      end
    end

    # Asks the loop to stop. It finishes its current wait first, so this is not instant.
    def stop : Nil
      @running = false
    end

    # A sweep that cannot kill the loop.
    #
    # A database hiccup an hour into a month-long process must not silently end all future
    # sweeping — the failure mode would be a table growing forever with nothing in the logs to
    # explain it. Infrastructure errors are logged and the loop waits for the next interval.
    private def sweep_guarded : Nil
      sweep
    rescue error : InfrastructureError
      Log.warn &.emit("sweeper.failed", error: error.class.name)
    end

    # Both are optional: an application that configured neither has nothing to sweep, and
    # asking `Application` for a service it was never given would raise.
    private def sweep_action_tokens(now : Time) : Int32
      tokens = @app.action_tokens
      tokens.nil? ? 0 : tokens.delete_expired(now)
    end

    private def sweep_remember_tokens(now : Time) : Int32
      tokens = @app.remember_tokens
      tokens.nil? ? 0 : tokens.delete_expired(now)
    end
  end
end

module KemalIdentity::Postgres
  # A fixed-window limiter whose counters every process sees.
  #
  # The same strategy, the same contract and the same documented burst as the in-memory
  # `KemalIdentity::FixedWindowRateLimiter` — the difference is only where the count lives.
  # In memory, six workers behind a load balancer each allow the full limit, which
  # `blueprints/0025` (OPS-01) measured at 2.2× the intended total. Here they share one row.
  #
  # ### One statement, so no process can read a stale count
  #
  # Counting, deciding and reopening an elapsed window are a single
  # `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`. PostgreSQL takes the row lock for the
  # update, so concurrent attempts from any number of processes are serialised and each sees the
  # count the previous one left. A read followed by a write would let two processes both see
  # "nine" and both allow the tenth.
  #
  # ### Time comes from the clock, not the database
  #
  # So that the shared contract can drive it with a `TestClock`, exactly as it drives the
  # in-memory limiters. Processes on different hosts therefore need synchronised clocks; skew
  # moves where a window starts and ends by the size of the skew and does not change how many
  # attempts it admits.
  #
  # ### When the database does not answer
  #
  # `Verdict.unavailable`, never an exception and never a guess — the contract on
  # `KemalIdentity::RateLimiter#consume`, and `blueprints/0023` for why. Login stays fail-closed
  # unless the application wraps this in `FailOpenRateLimiter`.
  #
  # Needs `migrations/postgres/20261008090000_create_auth_rate_limits.sql`. Include it in the
  # sweep (`KemalIdentity::Sweeper` does so when this is `rate_limiter:`), or elapsed rows
  # accumulate for as long as somebody keeps inventing keys.
  class FixedWindowRateLimiter < KemalIdentity::RateLimiter
    include KemalIdentity::SweepableRateLimiter

    getter limit : Int32
    getter window : Time::Span

    def initialize(
      @db : DB::Database,
      @limit : Int32,
      @window : Time::Span,
      @clock : Clock = SystemClock.new,
    )
      raise ConfigurationError.new("limit must be positive") unless @limit > 0
      raise ConfigurationError.new("window must be positive") unless @window > Time::Span::ZERO
      # The stored count stops at limit + 1, which must still fit the INTEGER column.
      raise ConfigurationError.new("limit must be below Int32::MAX") unless @limit < Int32::MAX
    end

    def consume(key : String) : Verdict
      now = @clock.now

      # Every SET expression reads the row as it was before this statement, so both CASEs agree
      # on whether the window had elapsed. The count stops at limit + 1: past that it decides
      # nothing, and a flood against one key must not be able to overflow the column.
      attempts, started_at = @db.query_one(<<-SQL, key, now, now - @window, @limit + 1, as: {Int32, Time})
        INSERT INTO auth_rate_limits AS r (key, attempts, window_started_at)
        VALUES ($1, 1, $2)
        ON CONFLICT (key) DO UPDATE SET
          attempts = CASE WHEN r.window_started_at <= $3 THEN 1
                          ELSE LEAST(r.attempts + 1, $4) END,
          window_started_at = CASE WHEN r.window_started_at <= $3 THEN $2
                                   ELSE r.window_started_at END
        RETURNING attempts, window_started_at
        SQL

      return Verdict.allow if attempts <= @limit

      Verdict.deny(retry_after: started_at + @window - now)
    rescue error : DB::Error | IO::Error | PQ::PQError | PQ::ConnectionError | PG::Error
      Log.warn &.emit("rate_limiter.store_unavailable", error: error.class.name)
      Verdict.unavailable
    end

    def reset(key : String) : Nil
      @db.exec("DELETE FROM auth_rate_limits WHERE key = $1", key)
    rescue error : DB::Error | IO::Error | PQ::PQError | PQ::ConnectionError | PG::Error
      # Must not raise: a reset that does not happen leaves somebody throttled slightly longer
      # than they earned, which is not worth failing a successful login over.
      Log.warn &.emit("rate_limiter.store_unavailable", error: error.class.name)
    end

    # `<=`, the same boundary `consume` reopens a window on, so the sweeper never deletes a
    # counter that `consume` would still have honoured.
    def delete_expired(now : Time) : Int32
      @db.exec("DELETE FROM auth_rate_limits WHERE window_started_at <= $1", now - @window)
        .rows_affected.to_i32
    end
  end
end

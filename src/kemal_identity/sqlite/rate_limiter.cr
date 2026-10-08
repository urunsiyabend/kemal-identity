module KemalIdentity::SQLite
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
  # `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`. SQLite holds the database write lock for
  # the statement, so concurrent attempts from every process are serialised and each sees the
  # count the previous one left. A read followed by a write would let two processes both see
  # "nine" and both allow the tenth.
  #
  # ### Time comes from the clock, not the database
  #
  # So that the shared contract can drive it with a `TestClock`, exactly as it drives the
  # in-memory limiters. Timestamps are stored as UTC text in one fixed format, so they compare
  # correctly as strings.
  #
  # ### Shared between processes on one host, not between hosts
  #
  # Every process opening the same database file shares the counters — several workers behind
  # a local reverse proxy, say. Open it with `journal_mode=wal&busy_timeout=5000`: without a busy
  # timeout a contended write fails at once with `database is locked`, which this reports as an
  # unavailable store. Across hosts, use `KemalIdentity::Postgres::FixedWindowRateLimiter`.
  #
  # ### When the database does not answer
  #
  # `Verdict.unavailable`, never an exception and never a guess — the contract on
  # `KemalIdentity::RateLimiter#consume`, and `blueprints/0023` for why. Login stays fail-closed
  # unless the application wraps this in `FailOpenRateLimiter`.
  #
  # Needs `migrations/sqlite/20261008090000_create_auth_rate_limits.sql`. Include it in the
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
      #
      # The row stores when its window *ends*, so a sweep by a limiter with a shorter window
      # cannot delete it early — the table is shared by every limiter that uses it.
      attempts, ends_at = @db.query_one(<<-SQL, key, now + @window, now, @limit + 1, as: {Int64, Time})
        INSERT INTO auth_rate_limits AS r (key, attempts, window_ends_at)
        VALUES (?1, 1, ?2)
        ON CONFLICT (key) DO UPDATE SET
          attempts = CASE WHEN r.window_ends_at <= ?3 THEN 1
                          ELSE MIN(r.attempts + 1, ?4) END,
          window_ends_at = CASE WHEN r.window_ends_at <= ?3 THEN ?2
                                ELSE r.window_ends_at END
        RETURNING attempts, window_ends_at
        SQL

      return Verdict.allow if attempts <= @limit

      Verdict.deny(retry_after: ends_at - now)
    rescue error
      # Every exception, not a list of the driver's: the body is one database call, and the
      # contract is "never raise" (`blueprints/0023`). A list misses what it does not name —
      # a TLS failure mid-query is an `OpenSSL::SSL::Error`, which is neither a `DB::Error` nor
      # an `IO::Error`, and on the login path it would have been a 500.
      Log.warn &.emit("rate_limiter.store_unavailable", error: error.class.name)
      Verdict.unavailable
    end

    def reset(key : String) : Nil
      @db.exec("DELETE FROM auth_rate_limits WHERE key = ?1", key)
    rescue error
      # Must not raise: a reset that does not happen leaves somebody throttled slightly longer
      # than they earned, which is not worth failing a successful login over.
      Log.warn &.emit("rate_limiter.store_unavailable", error: error.class.name)
    end

    # Every counter whose window has ended — each by its own deadline, whichever limiter wrote
    # it. `<=`, the boundary `consume` reopens a window on, so nothing `consume` would still
    # honour is deleted.
    def delete_expired(now : Time) : Int32
      @db.exec("DELETE FROM auth_rate_limits WHERE window_ends_at <= ?1", now)
        .rows_affected.to_i32
    end
  end
end

require "kemal_identity"
require "db"

# A rate limiter over a store more than one process can see, written the way an application
# would write it: one public contract, two methods, no core class reopened.
#
# SQLite rather than Redis so the test needs no server, and because it makes the atomicity
# question concrete: `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` is one statement, so
# counting and deciding cannot interleave.
class SharedStoreRateLimiter < KemalIdentity::RateLimiter
  # Two settings a shared SQLite store needs and a first attempt at this did not have. Without
  # them six processes against one file over-allowed a global limit of 10 by more than double,
  # silently — the failure OPS-01 exists to catch.
  #
  # `journal_mode=WAL` lets readers and one writer proceed at once; `busy_timeout` makes a
  # contended write wait rather than fail immediately with SQLITE_BUSY, which the adapter would
  # otherwise report as an unavailable store.
  def self.prepare!(db : DB::Database) : Nil
    db.exec("PRAGMA journal_mode=WAL")
    db.exec("PRAGMA busy_timeout=5000")
  end

  def self.migrate!(db : DB::Database) : Nil
    db.exec <<-SQL
      CREATE TABLE IF NOT EXISTS rate_limits (
        key           TEXT PRIMARY KEY,
        attempts      INTEGER NOT NULL,
        window_starts TEXT    NOT NULL
      )
      SQL
  end

  def initialize(
    @db : DB::Database,
    @limit : Int32,
    @window : Time::Span,
    @clock : KemalIdentity::Clock = KemalIdentity::SystemClock.new,
  )
  end

  def consume(key : String) : KemalIdentity::Verdict
    now = @clock.now
    cutoff = now - @window

    # Count and decide in one statement. The window is reset in the same write when it has
    # elapsed, so two processes cannot both believe they opened a fresh window.
    # BEGIN IMMEDIATE takes the write lock up front, so counting and deciding cannot interleave
    # with another process's read-then-write.
    attempts = @db.transaction do |tx|
      tx.connection.scalar(<<-SQL, key, now, cutoff, now).as(Int64)
      INSERT INTO rate_limits (key, attempts, window_starts)
      VALUES (?1, 1, ?2)
      ON CONFLICT (key) DO UPDATE SET
        attempts      = CASE WHEN window_starts <= ?3 THEN 1 ELSE attempts + 1 END,
        window_starts = CASE WHEN window_starts <= ?3 THEN ?4 ELSE window_starts END
      RETURNING attempts
      SQL
    end.as(Int64)

    return KemalIdentity::Verdict.allow if attempts <= @limit

    started = @db.query_one("SELECT window_starts FROM rate_limits WHERE key = ?", key, as: Time)
    KemalIdentity::Verdict.deny(retry_after: (started + @window) - now)
  rescue DB::Error | SQLite3::Exception
    # The contract: never raise, never guess. The application's policy decides what an
    # unreachable store means for this endpoint.
    KemalIdentity::Verdict.unavailable
  end

  def reset(key : String) : Nil
    @db.exec("DELETE FROM rate_limits WHERE key = ?", key)
  rescue DB::Error | SQLite3::Exception
    # Documented as harmless: a reset that does not happen leaves somebody throttled slightly
    # longer than they earned. Must not raise.
  end
end

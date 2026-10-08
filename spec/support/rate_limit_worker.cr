# One process among several sharing a rate limiter. Built and run by
# `spec/integration/multiprocess_rate_limit_spec.cr`, which sums what each prints.
#
#   rate_limit_worker <postgres|sqlite|memory> <url> <limit> <attempts> <key> <start-file>
#
# Every worker waits for the start file before its first attempt, so they genuinely overlap
# rather than running one after another while the next one is still being spawned.
require "../../src/kemal_identity/postgres"
require "../../src/kemal_identity/sqlite"

adapter, url, limit, attempts, key, start_file = ARGV

db = adapter == "memory" ? nil : DB.open(url)

limiter =
  if db.nil?
    KemalIdentity::FixedWindowRateLimiter.new(limit: limit.to_i, window: 1.hour)
  elsif adapter == "postgres"
    KemalIdentity::Postgres::FixedWindowRateLimiter.new(db, limit: limit.to_i, window: 1.hour)
  else
    KemalIdentity::SQLite::FixedWindowRateLimiter.new(db, limit: limit.to_i, window: 1.hour)
  end

until File.exists?(start_file)
  sleep 1.millisecond
end

allowed = unavailable = 0
attempts.to_i.times do
  verdict = limiter.consume(key)
  allowed += 1 if verdict.allowed?
  unavailable += 1 if verdict.unavailable?
end

puts "#{allowed} #{unavailable}"
db.try(&.close)

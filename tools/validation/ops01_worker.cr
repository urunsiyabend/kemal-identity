require "sqlite3"
require "./shared_limiter"

# One process among several, all sharing one store. Prints how many of its attempts were
# allowed; the harness sums them and checks the global limit held.
db = DB.open("sqlite3://#{ARGV[0]}")
SharedStoreRateLimiter.prepare!(db)
limiter = SharedStoreRateLimiter.new(db, limit: ARGV[1].to_i, window: 1.hour)

allowed = 0
ARGV[2].to_i.times { allowed += 1 if limiter.consume("login:ada").allowed? }

puts allowed
db.close

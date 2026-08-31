require "sqlite3"
require "./shared_limiter"
File.delete?(ARGV[0])
db = DB.open("sqlite3://#{ARGV[0]}")
SharedStoreRateLimiter.prepare!(db)
SharedStoreRateLimiter.migrate!(db)
db.close

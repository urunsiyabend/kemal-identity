require "sqlite3"
require "kemal_identity"
require "kemal_identity/sqlite"

# The other process. Waits so the watcher's cache is warm, then removes the membership with no
# way to tell the watcher's `Authz::Cache` that it did.
sleep ARGV[1].to_f.seconds

db = DB.open("sqlite3://#{ARGV[0]}")
store = KemalIdentity::SQLite::AuthzRepository.new(db)
removed = store.remove_member("ada", "org-a")
puts "revoker: removed=#{removed} at=#{ARGV[1]}s"
db.close

require "sqlite3"
require "kemal_identity"
require "kemal_identity/sqlite"

# AUT-06, measured across two processes rather than with a test clock.
#
# One process holding a warm `Authz::Cache` over a shared SQLite database, asking the same
# authorized question every 100ms and printing when the answer changes. Another process
# (`aut06_revoke.cr`) removes the membership. The gap between the two timestamps is the real
# stale-access window a replicated deployment has, which is the number AUT-06 asks for and the
# one a test clock cannot produce.
#
#   crystal build tools/validation/aut06_watcher.cr tools/validation/aut06_revoke.cr
#   ./aut06_setup /tmp/aut06.db && ./aut06_watcher /tmp/aut06.db 5 12 & ./aut06_revoke /tmp/aut06.db

path = ARGV[0]
ttl = ARGV[1].to_i.seconds
seconds = ARGV[2].to_i

db = DB.open("sqlite3://#{path}")
store = KemalIdentity::SQLite::AuthzRepository.new(db)

registry = KemalIdentity::Authz::PermissionRegistry.new(
  KemalIdentity::Authz::Permission.new("reports.read", "Read reports")
)
catalog = KemalIdentity::Authz::RoleCatalog.new(
  registry, [KemalIdentity::Authz::Role.new("member", ["reports.read"])]
)

clock = KemalIdentity::SystemClock.new
# A ttl of 0 means no cache at all, which is the default an application gets.
cache = ttl.zero? ? nil : KemalIdentity::Authz::Cache.new(clock, ttl: ttl)
rbac = KemalIdentity::Authz::RBAC.new(catalog, store, clock, cache: cache)

principal = KemalIdentity::Principal.new(
  subject: "ada",
  assurance: KemalIdentity::AssuranceLevel::Password,
  authenticated_at: clock.now,
  credential: KemalIdentity::CredentialRef.new(KemalIdentity::CredentialKind::Session, id: "sess-1"),
)
context = KemalIdentity::Authz::Context.new(tenant_id: "org-a")

started = Time.monotonic
last = nil.as(Bool?)

while Time.monotonic - started < seconds.seconds
  permitted = rbac.decide(principal, "reports.read", context).permitted?

  if last.nil?
    puts "watcher t=+0.000s first=#{permitted} ttl=#{ttl}"
  elsif last != permitted
    puts "watcher t=+#{(Time.monotonic - started).total_seconds.round(3)}s changed_to=#{permitted}"
  end

  last = permitted
  sleep 100.milliseconds
end

puts "watcher t=+#{(Time.monotonic - started).total_seconds.round(3)}s final=#{last}"
db.close

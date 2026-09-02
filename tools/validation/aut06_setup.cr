require "sqlite3"
require "kemal_identity"
require "kemal_identity/sqlite"

# One member of one tenant, holding one role. What `aut06_watcher.cr` asks about.
File.delete?(ARGV[0])
db = DB.open("sqlite3://#{ARGV[0]}")

# The shipped migration file, run as-is apart from dropping its comments: OPS-06 records that
# these are reference implementations, and a consumer that runs them verbatim is the case this
# scenario is measuring.
sql = File.read(ARGV[1])
up = sql.split("-- +micrate Down").first.sub("-- +micrate Up", "")
body = up.lines.reject { |line| line.strip.starts_with?("--") }.join('\n')

body.split(';').each do |statement|
  next if statement.strip.empty?
  db.exec(statement)
end

store = KemalIdentity::SQLite::AuthzRepository.new(db)
now = Time.utc
store.add_member(KemalIdentity::Authz::Membership.new(
  id: "m1", account_id: "ada", tenant_id: "org-a", created_at: now
))
store.grant(KemalIdentity::Authz::Assignment.new(
  id: "a1", account_id: "ada", role: "member", granted_at: now, tenant_id: "org-a"
))

puts "setup: member=#{store.member?("ada", "org-a")} roles=#{store.grants_for("ada", "org-a").tenant_roles}"
db.close

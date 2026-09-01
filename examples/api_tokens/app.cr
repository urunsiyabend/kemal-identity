# An API-only application: bearer tokens, scopes, and standards-compliant refusals.
#
# No cookies, no login form, no redirects. A client presents `Authorization: Bearer <token>` or
# it gets a 401 carrying a `WWW-Authenticate` challenge that says *why*.
#
# CI compiles this on every matrix entry — an example that has drifted from the API is worse
# than no example.
#
#     crystal run examples/api_tokens/app.cr
#
# Then, with the token it prints on boot:
#
#     curl -i localhost:3000/me           -H "Authorization: Bearer $READ_TOKEN"
#     curl -i localhost:3000/invoices     -H "Authorization: Bearer $READ_TOKEN"
#     curl -i -X POST localhost:3000/invoices/1/refund -H "Authorization: Bearer $READ_TOKEN"
#     curl -i localhost:3000/me           -H "Authorization: Bearer ki_notarealtoken"
#     curl -i localhost:3000/me
#
# The last three are the interesting ones: a refund with a read-only token is `403` with
# `error="insufficient_scope"`, a bad token is `401` with `error="invalid_token"`, and no
# credential at all is `401` with no error code — RFC 6750 §3 says a resource server SHOULD NOT
# send one when the request carried no authentication information.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

DB_PATH = ENV["DB_PATH"]? || "./kemal_identity_api_example.db"

database = DB.open("sqlite3://#{DB_PATH}?journal_mode=wal&busy_timeout=5000")

# An example gets to be its own migration tool. A real application copies `migrations/sqlite`
# into its own tooling — `docs/03-data-model.md` is emphatic that the shard must never run them.
Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';').each do |statement|
    next if statement.strip.empty?
    database.exec(statement) rescue nil # already applied
  end
end

# Permissions are code; assignments are data. The catalog lives next to the routes it guards,
# which is why `Authz::RBAC` takes one rather than reading roles from a table.
#
# `minimum_assurance` is the floor a *credential* must reach, independent of scopes. The default
# is `Password`, which no API token reaches however wide its scopes — so a permission an
# automation is allowed to hold has to say so, and one that must only ever be exercised by a
# human at a keyboard says nothing and is unreachable by token. That default is deliberate: it
# makes "reachable by automation" an explicit decision rather than an oversight.
CATALOG = KemalIdentity::Authz::RoleCatalog.new(
  KemalIdentity::Authz::PermissionRegistry.new([
    KemalIdentity::Authz::Permission.new(
      "invoices.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
    ),
    KemalIdentity::Authz::Permission.new(
      "invoices.refund", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
    ),
  ]),
  [KemalIdentity::Authz::Role.new("finance", ["invoices.read", "invoices.refund"])]
)

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(database),
  sessions: KemalIdentity::SQLite::SessionRepository.new(database),

  # The bearer credential this shard recommends: opaque, revocable, and stored as a digest.
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(database),

  authorizer: KemalIdentity::Authz::RBAC.new(
    catalog: CATALOG,
    store: KemalIdentity::SQLite::AuthzRepository.new(database),
    clock: KemalIdentity::SystemClock.new,
    random: KemalIdentity::SecureRandomSource.new,
  ),

  # Present because `Application` requires a hasher, unused because nothing here verifies a
  # password. Cheap to construct; it hashes nothing until asked.
  hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
)

APP = KemalIdentity.app

# One account and one role assignment, created directly: creating accounts is the application's
# job and deliberately not part of this shard.
if APP.accounts.find_by_login("ada@example.com").nil?
  now = Time.utc
  database.exec(<<-SQL, "a1", "ada@example.com", now, now)
    INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at)
    VALUES (?, ?, 1, ?, ?)
    SQL
end

authz = KemalIdentity::SQLite::AuthzRepository.new(database)
unless authz.assignments_for("a1").any? { |assignment| assignment.role == "finance" }
  authz.grant(KemalIdentity::Authz::Assignment.new(
    id: Random::Secure.hex(8), account_id: "a1", role: "finance", granted_at: Time.utc
  ))
end

ada = APP.accounts.find_by_login("ada@example.com") || raise "seeding the account failed"

# Two tokens for one account, and the difference between them is the whole point of scopes.
#
# `scopes: nil` would mean *unrestricted* — everything the account may do. `[]` would mean
# attenuated to nothing. The two must never be conflated, which is why `CredentialRef#scopes` is
# nilable rather than defaulting to an empty array.
#
# Effective permission is the **intersection** of the account's grant and the token's scopes,
# never the union: a token cannot introduce a permission its owner does not hold, and an account
# cannot escape its token's attenuation.
read_only = APP.api!.issue(ada, "reporting-job", scopes: ["invoices.read"])
full = APP.api!.issue(ada, "ops-console", scopes: ["invoices.read", "invoices.refund"])

puts
puts "READ_TOKEN=#{read_only.token.reveal}"
puts "FULL_TOKEN=#{full.token.reveal}"
puts
puts "The raw token exists exactly once, here. Only its digest is stored, so this line is the"
puts "only chance to copy it — the same reason GitHub shows a token once."
puts

# `login_path: nil` is what makes this an API rather than a website: with a path, a browser
# request carrying no credential is redirected to it. Without one, every refusal is a status
# code and a challenge header.
#
# A request that *presented* a bearer credential is never redirected even when a login path is
# configured — an API client sent a token and needs to be told the token failed, not handed a
# sign-in page with a 302.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, realm: "invoices")
use KemalIdentity::Kemal::AuthenticationHandler.new

# No CSRFHandler. CSRF exists because a browser attaches cookies to cross-site requests on its
# own; it does not attach an `Authorization` header on its own, and this application accepts
# nothing else. Add one the moment a cookie can authenticate a mutation here.

get "/me" do |env|
  principal = env.auth.require!

  # `credential` answers *what proved this request*, which `principal` cannot: two tokens issued
  # to one account used to produce indistinguishable principals.
  #
  # Still nilable after `require!`, and left that way rather than asserted: a principal can also
  # arrive from an authenticator that named no credential, and `try` is one character more than
  # a `not_nil!` that would be wrong on the day somebody adds one.
  credential = env.auth.credential

  {
    subject:   principal.subject,
    kind:      credential.try(&.kind.to_s),
    token:     credential.try(&.name),
    scopes:    credential.try(&.scopes),
    assurance: principal.assurance.to_s,
  }.to_json
end

get "/invoices" do |env|
  # Guarded at the point of action, with the permission it is about to perform. Not at the top of
  # the file, not in a before-filter keyed on a path: a guard that runs somewhere else is a guard
  # that can be routed around.
  env.auth.authorize!("invoices.read")
  [{id: 1, total: "42.00"}, {id: 2, total: "17.50"}].to_json
end

post "/invoices/:id/refund" do |env|
  env.auth.authorize!("invoices.refund")
  {refunded: env.params.url["id"]}.to_json
end

# Revoking a token takes effect on the next request. There is no cache and no TTL to wait out —
# `authenticate` reads the store, so revocation is immediate by construction rather than by
# invalidation.
#
# **Two arguments, not one.** `revoke(id)` revokes by id alone and is an administrative call:
# with it, this route would end a token belonging to whoever the caller names. A token id is not
# secret material — it appears in audit lines and in a management listing — so the id being long
# and random is not the defence. The two-argument form answers `false` both for somebody else's
# token and for one that does not exist, so a caller learns nothing from the difference.
delete "/tokens/:id" do |env|
  principal = env.auth.require!
  revoked = APP.api!.revoke(env.params.url["id"], principal.subject)
  env.response.status_code = revoked ? 204 : 404
  ""
end

# What a "my tokens" screen renders. Revoked ones included: "when did I revoke that?" is a
# question such a screen exists to answer.
get "/tokens" do |env|
  principal = env.auth.require!

  APP.api!.list(principal.subject).map do |token|
    {
      id: token.id, name: token.name, scopes: token.scopes,
      last_used_at: token.last_used_at, revoked: token.revoked?,
    }
  end.to_json
end

# Anything a route raises is caught by ErrorHandler and rendered as JSON, because the request
# said it wanted JSON — or because no login path exists to redirect to.
Kemal.config.port = 3000
Kemal.run

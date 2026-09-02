# One process, three audiences: server-rendered pages, a same-origin SPA, and third-party API
# clients holding bearer tokens.
#
# This is the arrangement most Kemal applications actually grow into, and the three things it
# needs are the three that have to be independently expressible:
#
#   1. **which credentials a subtree accepts** — `/app` takes a session and refuses a token,
#      `/api` takes a token and refuses a session, `/shared` takes either;
#   2. **whether a refusal is a status or a redirect** — a page sends the visitor to the login
#      form, an API path answers 401 even to a client that sent no `Accept` header;
#   3. **where CSRF applies** — exactly where a browser-attached credential could authenticate
#      the request, and nowhere else.
#
# CI compiles this on every matrix entry — an example that has drifted from the API is worse
# than no example.
#
#     crystal run examples/mixed_monolith/app.cr
#
# Then, with the credentials it prints:
#
#     curl -i localhost:3000/app/dashboard -H "Cookie: example_session=$SESSION"
#     curl -i localhost:3000/app/dashboard -H "Authorization: Bearer $TOKEN"     # 403, wrong door
#     curl -i localhost:3000/api/items     -H "Authorization: Bearer $TOKEN"
#     curl -i localhost:3000/api/items     -H "Cookie: example_session=$SESSION" # 403, wrong door
#     curl -i localhost:3000/api/items                                           # 401, not a redirect
#     curl -i localhost:3000/app/dashboard                                       # 302 to /login
#     curl -i -X POST localhost:3000/api/items -H "Authorization: Bearer $TOKEN"  # no CSRF token needed
#     curl -i -X POST localhost:3000/api/items -H "Authorization: Bearer $TOKEN" \
#          -H "Cookie: example_session=$SESSION"                                 # 403: a cookie came too

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

DB_PATH     = ENV["DB_PATH"]? || "./kemal_identity_monolith_example.db"
CSRF_SECRET = ENV["CSRF_SECRET"]? || "development-only-secret-at-least-32-bytes"

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

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(database),
  sessions: KemalIdentity::SQLite::SessionRepository.new(database),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(database),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: CSRF_SECRET, cookie_name: "example_csrf", secure: false
  ),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "example_session", secure: false, allow_insecure: true
  ),
)

# ---------------------------------------------------------------------------
# Seed: one account, one session, one token. A real application has a login route; this one
# prints credentials so the `curl` lines above work immediately.
# ---------------------------------------------------------------------------
ACCOUNTS = KemalIdentity.app.accounts

unless ACCOUNTS.find_by_id("ada")
  database.exec(
    "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) " \
    "VALUES (?, ?, ?, ?, ?)",
    "ada", "ada@example.com", 1, Time.utc, Time.utc
  )
end

ada = ACCOUNTS.find_by_id("ada")

if ada.nil?
  # The row was inserted a moment ago, so this is a broken deployment rather than a missing
  # account — say so and stop instead of serving with no credentials to print.
  abort "seed account 'ada' is not readable through the repository"
end

session = KemalIdentity.app.sessions.start(ada, KemalIdentity::AssuranceLevel::Password)
token = KemalIdentity.app.api!.issue(ada, "ada-cli")

puts "SESSION=#{session.token.reveal}"
puts "TOKEN=#{token.token.reveal}"

# ---------------------------------------------------------------------------
# The handler chain. Order matters and the comments say why.
# ---------------------------------------------------------------------------

# `api_prefixes:` is the whole of point 2. Without it the redirect decision is a *guess* made
# from the request — `Accept: application/json`, `X-Requested-With`, or an `Authorization`
# header — and a client that sends none of those still gets `302 Location: /login` for a path
# that serves no HTML. With it, /api is configuration rather than inference, and every other
# path still sends a browser to the login form.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login", api_prefixes: ["/api"])

use KemalIdentity::Kemal::AuthenticationHandler.new

# Point 3, and it needs no arguments: `CSRFHandler` exempts a request authenticated by a bearer
# token **and nothing else**. A request carrying a token *and* a session cookie is still
# protected, because the cookie alone would authenticate it — so an attacker who can trigger the
# request cross-site does not need the token. Content type is not a defence and neither is
# calling an endpoint an API.
use KemalIdentity::Kemal::CSRFHandler.new

# Point 1. `credentials:` says which kinds a subtree accepts; authentication is still required
# first, so an anonymous request is a 401 (or a redirect) rather than a hint about what the
# subtree takes.
#
# A wrong-class credential is a 403, not a 401: it is valid, it is simply the wrong door, and a
# 401 would tell a working client to authenticate again in a loop.
use KemalIdentity::Kemal::PathGuard.new(
  prefix: "/app", credentials: [KemalIdentity::CredentialKind::Session]
)
# A deployment that also accepts JWTs lists them together. Both are bearer credentials and both
# authenticate at `AssuranceLevel::ApiToken`, but they are different kinds, and an API-only
# subtree usually wants to say which of them it takes.
BEARER_KINDS = [KemalIdentity::CredentialKind::ApiToken, KemalIdentity::CredentialKind::Jwt]

use KemalIdentity::Kemal::PathGuard.new(prefix: "/api", credentials: BEARER_KINDS)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

get "/app/dashboard" do |env|
  principal = env.auth.require!
  <<-HTML
    <!doctype html>
    <title>Dashboard</title>
    <p>Signed in as #{principal.subject}, via #{env.auth.credential.try(&.kind)}.</p>
    <form method="post" action="/app/settings">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <button>Save settings</button>
    </form>
    HTML
end

post "/app/settings" do |env|
  env.auth.require!
  "settings saved"
end

get "/api/items" do |env|
  env.response.content_type = "application/json"
  {items: [] of String, owner: env.auth.require!.subject}.to_json
end

post "/api/items" do |env|
  env.response.content_type = "application/json"
  {created: true, by: env.auth.require!.subject}.to_json
end

# The shared route, and the way to declare "either" is to install no guard for it and ask for
# the principal in the route. `env.auth.credential` is what tells the application which
# credential actually proved the request, when it wants to behave differently.
get "/shared/profile" do |env|
  principal = env.auth.require!
  credential = env.auth.credential

  env.response.content_type = "application/json"
  {
    subject: principal.subject,
    via:     credential.try(&.kind).to_s,
    # Never the token, the digest or the session value — `CredentialRef` carries none of those,
    # which is why it is safe to put in a response at all.
    name: credential.try(&.name),
  }.to_json
end

get "/login" do
  <<-HTML
    <!doctype html>
    <title>Log in</title>
    <p>A real application's login form goes here. This example seeds a session instead.</p>
    HTML
end

Kemal.config.port = (ENV["PORT"]? || "3000").to_i
Kemal.run

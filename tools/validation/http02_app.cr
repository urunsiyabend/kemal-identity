require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"

# HTTP-02 — one Kemal process serving HTML pages, a same-origin SPA and third-party API
# clients. Three subtrees with three credential policies:
#
#   /app     browser session only — a bearer token must not reach it
#   /api     bearer token only — a session cookie must not reach it
#   /shared  either
#
# The interesting part is what the shard supplies and what the application has to write, so
# everything below that is hand-written is marked.

DBF      = ENV["HTTP02_DB"]
File.delete?(DBF)
DATABASE = DB.open("sqlite3://#{DBF}")

Dir.glob("#{ENV["KEMAL_IDENTITY_ROOT"]}/migrations/sqlite/*.sql").sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
    .reject(&.strip.empty?).each { |stmt| DATABASE.exec(stmt) }
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
DATABASE.exec(
  "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) " \
  "VALUES (?, ?, ?, ?, ?)",
  "ada", "ada@example.com", 1, Time.utc, Time.utc
)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  # `__Host-` forbids a non-Secure cookie, and the shard refuses the combination at boot
  # rather than issuing one — so a local HTTP probe has to rename the anchor cookie too.
  csrf: KemalIdentity::CSRFConfig.new(
    secret: "0" * 32, cookie_name: "consumer_csrf", secure: false
  ),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
)

ADA     = ACCOUNTS.find_by_id("ada").not_nil!
SESSION = KemalIdentity.app.sessions.start(ADA, KemalIdentity::AssuranceLevel::Password)
TOKEN   = KemalIdentity.app.api!.issue(ADA, "ada-cli")

File.write(ENV["HTTP02_CREDS"], "#{SESSION.token.reveal}\n#{TOKEN.token.reveal}\n")

# Both hand-written pieces are gone. Before this pass the application needed:
#
#   * `CredentialClassGuard` — 25 lines wrapping `principal.credential.kind`, because
#     `PathGuard` declared authentication, freshness and strength for a subtree but not which
#     *kind* of credential it accepted;
#   * `ApiOnly` — a handler that scoped the shard's own `ErrorHandler` by path by reassigning
#     `Kemal::Handler#next`, because `login_path:` is one setting for the whole process.
#
# The measured behaviour of both is now configuration. `tools/validation/http02_app_before.cr`
# keeps the hand-written version so the two can be probed against each other.

# `api_prefixes:` rather than a second handler: /api is never redirected, whatever it sent in
# Accept, and everything else still gets the login page.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login", api_prefixes: ["/api"])
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(
  prefix: "/app", credentials: [KemalIdentity::CredentialKind::Session]
)
use KemalIdentity::Kemal::PathGuard.new(
  prefix: "/api", credentials: [KemalIdentity::CredentialKind::ApiToken]
)

get "/app/dashboard" do |env|
  "dashboard for #{env.auth.require!.subject}"
end

post "/app/settings" do |env|
  "settings saved"
end

get "/api/items" do |env|
  "items for #{env.auth.require!.subject}"
end

post "/api/items" do |env|
  "item created"
end

# The shared route: either credential, and the application says so by asking for neither.
get "/shared/profile" do |env|
  credential = env.auth.credential
  "profile for #{env.auth.require!.subject} via #{credential.try(&.kind)}"
end

get "/login" { "login page" }
get "/health" { "ok" }

get "/csrf" do |env|
  env.auth.csrf_token
end

Kemal.config.port = ENV["HTTP02_PORT"].to_i
Kemal.config.env = "production"
Kemal.run

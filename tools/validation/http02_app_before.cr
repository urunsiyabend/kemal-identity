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

# ---------------------------------------------------------------------------
# Application-written: a credential-class guard for a subtree.
#
# The shard has `PathGuard.new(prefix:, within:, assurance:)` — authentication, freshness and
# strength for a subtree — and nothing that says *which kind* of credential a subtree accepts.
# So this is the hand-written half HTTP-02 asks about, and it is thirty lines.
# ---------------------------------------------------------------------------
class CredentialClassGuard < Kemal::Handler
  def initialize(@prefix : String, @accepts : Array(KemalIdentity::CredentialKind))
  end

  def call(env)
    return call_next(env) unless guards?(env.request.path)

    principal = env.auth.require!
    kind = principal.credential.try(&.kind)

    # A 403 rather than a 401: the caller is authenticated, they are simply using the wrong
    # door, and telling them to log in again would be a loop. Same reasoning as
    # `ForbiddenError`'s own.
    unless kind && @accepts.includes?(kind)
      raise KemalIdentity::ForbiddenError.new("wrong credential class for this subtree")
    end

    call_next(env)
  end

  private def guards?(path : String) : Bool
    return false unless path.starts_with?(@prefix)

    rest = path[@prefix.size..]
    rest.empty? || rest.starts_with?('/')
  end
end

# ---------------------------------------------------------------------------
# Application-written: JSON errors under /api, redirects everywhere else.
#
# `ErrorHandler.new(login_path:)` is one setting for the whole process, so a monolith whose
# pages want a redirect and whose API wants a status cannot express both with one of them. This
# scopes the shard's own handler by path, by registering two and letting each decline what is
# not its subtree.
# ---------------------------------------------------------------------------
class ApiOnly < Kemal::Handler
  def initialize(@prefix : String, @inner : Kemal::Handler)
  end

  def call(env)
    return call_next(env) unless env.request.path.starts_with?(@prefix)

    @inner.next = next_handler
    @inner.call(env)
  end

  private def next_handler
    self.next
  end
end

# Outermost: the browser answer, with a redirect.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")

# Inside it, for /api only: the same handler configured to answer rather than redirect.
use ApiOnly.new("/api", KemalIdentity::Kemal::ErrorHandler.new(login_path: nil))

use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use CredentialClassGuard.new("/app", [KemalIdentity::CredentialKind::Session])
use CredentialClassGuard.new("/api", [KemalIdentity::CredentialKind::ApiToken])

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

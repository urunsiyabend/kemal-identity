require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"
require "./tok04_gateway"

# TOK-04, attempt 4 — the persona's actual shape: the gateway token is the *only* bearer
# credential this application accepts. No `api_tokens`, no `jwt`, so the shard builds no chain
# and there is nothing to reach into. Registration therefore needs a handler of the consumer's
# own, which is what the pass condition says it must not.
DBF      = "#{__DIR__}/../tok04_only.db"
File.delete?(DBF)
DATABASE = DB.open("sqlite3://#{DBF}")
Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
    .reject(&.strip.empty?).each { |stmt| DATABASE.exec(stmt) }
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
DATABASE.exec(
  "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  "ada", "ada@example.com", 1, Time.utc, Time.utc
)

SECRET  = "gateway-shared-secret"
GATEWAY = GatewayAuthenticator.new(SECRET, KemalIdentity::SystemClock.new)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: "csrf-signing-key-of-at-least-32-bytes",
    cookie_name: "consumer_csrf",
    secure: false,
  ),
)

# The handler the pass condition says should not be necessary. Everything in it is public API.
class GatewayHandler < Kemal::Handler
  def call(env)
    app = KemalIdentity.app
    header = env.request.headers["Authorization"]?
    scheme, _, credential = (header || "").partition(' ')

    outcome =
      if scheme.compare("Bearer", case_insensitive: true).zero? && !credential.strip.empty?
        GATEWAY.authenticate(credential)
      else
        app.sessions.resolve(app.cookie.extract(env.request.cookies))
      end

    env.auth = KemalIdentity::Kemal::RequestContext.new(env, app, outcome)
    call_next(env)
  end
end

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use GatewayHandler.new
use KemalIdentity::Kemal::CSRFHandler.new

get "/whoami" do |env|
  principal = env.auth.require!
  "#{principal.subject} via #{env.auth.credential.try(&.kind)}"
end

post "/things" do |env|
  env.auth.require!
  "created"
end

Kemal.config.port = 4722
Kemal.config.env = "production"
Kemal.run

require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"
require "./tok04_gateway"

# TOK-04, attempt 3 — the gateway authenticator installed by reaching into the chain the shard
# built, with no handler of the consumer's own. This is the only registration route that exists.
DBF      = "#{__DIR__}/../tok04.db"
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

SECRET = "gateway-shared-secret"

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  jwt: KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new(
      KemalIdentity::JWT::HS256, KemalIdentity::Secret.new("jwt-secret-of-at-least-32-bytes!")
    ),
    issuer: "https://issuer.example.com",
    audience: "consumer-app",
    algorithms: ["HS256"],
    clock: KemalIdentity::SystemClock.new,
  ),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: "csrf-signing-key-of-at-least-32-bytes",
    cookie_name: "consumer_csrf",
    secure: false,
  ),
)

GATEWAY = GatewayAuthenticator.new(SECRET, KemalIdentity::SystemClock.new)

# The registration. Not an API: `authenticators` is a getter over a mutable array, so this
# appends to the chain the shard assembled at boot. Position 1 of 3, between the two built-ins,
# which is what the scenario asks for.
KemalIdentity.app.bearer.as(KemalIdentity::AuthenticatorChain)
  .authenticators.insert(1, GATEWAY)

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new

get "/whoami" do |env|
  principal = env.auth.require!
  credential = env.auth.credential
  "#{principal.subject} via #{credential.try(&.kind)} id=#{credential.try(&.id)}"
end

post "/things" do |env|
  env.auth.require!
  "created"
end

Kemal.config.port = 4721
Kemal.config.env = "production"
Kemal.run

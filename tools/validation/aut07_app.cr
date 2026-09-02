require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"

# AUT-07 over HTTP: what a client is actually told when it is authenticated but not strongly
# or recently enough. The in-process spec measures the decision; this measures the challenge,
# which is the third pass condition and the one only a real response can answer.

DBF      = ENV["AUT07_DB"]
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

CATALOG = KemalIdentity::Authz::RoleCatalog.new(
  KemalIdentity::Authz::PermissionRegistry.new(
    KemalIdentity::Authz::Permission.new(
      "profile.read", "Read your profile",
      minimum_assurance: KemalIdentity::AssuranceLevel::Remembered
    ),
    KemalIdentity::Authz::Permission.new(
      "reports.read", "Read reports",
      minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
    ),
    KemalIdentity::Authz::Permission.new(
      "data.export", "Export everything",
      minimum_assurance: KemalIdentity::AssuranceLevel::Password
    ),
    KemalIdentity::Authz::Permission.new(
      "payout.update", "Change payout details",
      minimum_assurance: KemalIdentity::AssuranceLevel::MFA
    ),
  ),
  [KemalIdentity::Authz::Role.new(
    "owner", ["profile.read", "reports.read", "data.export", "payout.update"]
  )]
)

AUTHZ = KemalIdentity::SQLite::AuthzRepository.new(DATABASE)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  authorizer: KemalIdentity::Authz::RBAC.new(CATALOG, AUTHZ),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
)

AUTHZ.grant(KemalIdentity::Authz::Assignment.new(
  id: "g1", account_id: "ada", role: "owner", granted_at: Time.utc
))

ADA = ACCOUNTS.find_by_id("ada").not_nil!

# Three credentials for one account: a password session, an MFA session, and a token scoped to
# every permission the account holds — the token is the interesting one, because its scopes say
# yes and its assurance says no.
PASSWORD_SESSION = KemalIdentity.app.sessions.start(ADA, KemalIdentity::AssuranceLevel::Password)
MFA_SESSION      = KemalIdentity.app.sessions.start(
  ADA, KemalIdentity::AssuranceLevel::MFA, mfa_verified_at: Time.utc
)
TOKEN = KemalIdentity.app.api!.issue(
  ADA, "ada-cli",
  scopes: ["profile.read", "reports.read", "data.export", "payout.update"]
)

File.write(
  ENV["AUT07_CREDS"],
  "#{PASSWORD_SESSION.token.reveal}\n#{MFA_SESSION.token.reveal}\n#{TOKEN.token.reveal}\n"
)

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use KemalIdentity::Kemal::AuthenticationHandler.new

get "/profile" do |env|
  env.auth.authorize!("profile.read")
  "profile"
end

get "/reports" do |env|
  env.auth.authorize!("reports.read")
  "reports"
end

get "/export" do |env|
  env.auth.authorize!("data.export")
  "export"
end

post "/payout" do |env|
  env.auth.authorize!("payout.update")
  "payout"
end

# Freshness, which is not on the permission and therefore has to be asked for here.
post "/email" do |env|
  env.auth.require_fresh!(within: 5.minutes)
  "email changed"
end

get "/health" { "ok" }

Kemal.config.port = ENV["AUT07_PORT"].to_i
Kemal.config.env = "production"
Kemal.run

require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"

DB_FILE  = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/http01.db"
File.delete?(DB_FILE)
DATABASE = DB.open("sqlite3://#{DB_FILE}")
Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
    .reject(&.strip.empty?).each { |stmt| DATABASE.exec(stmt) }
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
DATABASE.exec(
  "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  "acct-1", "ada@example.com", 1, Time.utc, Time.utc
)

TOKENS = KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: TOKENS,
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
)

ISSUED = KemalIdentity.app.api!.issue(ACCOUNTS.find_by_id("acct-1").not_nil!, "probe")
File.write("#{__DIR__}/../token.txt", ISSUED.token.reveal)

use KemalIdentity::Kemal::ErrorHandler.new
use KemalIdentity::Kemal::AuthenticationHandler.new

# A pure REST API. No HTML, no login page, no browser.
get "/api/me" do |env|
  env.auth.require!.subject
end

Kemal.config.port = 4711
Kemal.config.env = "production"
Kemal.run

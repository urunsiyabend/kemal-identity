require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"

DBF = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/http03.db"
File.delete?(DBF)
DATABASE = DB.open("sqlite3://#{DBF}")
Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
    .reject(&.strip.empty?).each { |stmt| DATABASE.exec(stmt) }
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
{"alice", "bob"}.each do |who|
  DATABASE.exec(
    "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
    who, "#{who}@example.com", 1, Time.utc, Time.utc
  )
end

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
)

# Alice gets a browser session; Bob gets a bearer token. Two different people, two credentials.
ALICE_SESSION = KemalIdentity.app.sessions.start(
  ACCOUNTS.find_by_id("alice").not_nil!, KemalIdentity::AssuranceLevel::Password
)
BOB_TOKEN = KemalIdentity.app.api!.issue(ACCOUNTS.find_by_id("bob").not_nil!, "bob-cli")

File.write("#{__DIR__}/../http03_creds.txt",
  "#{ALICE_SESSION.token.reveal}\n#{BOB_TOKEN.token.reveal}\n")

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use KemalIdentity::Kemal::AuthenticationHandler.new

# Who does the shard think is asking?
get "/whoami" do |env|
  principal = env.auth.principal?
  if principal
    credential = env.auth.credential
    "#{principal.subject} via #{credential.try(&.kind) || "none"}"
  else
    env.auth.require!   # raises, so the guard's status is what a client sees
  end
end

Kemal.config.port = 4712
Kemal.config.env = "production"
Kemal.run

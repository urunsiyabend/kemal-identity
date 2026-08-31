require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"

DBF      = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/http03b.db"
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

File.write("#{__DIR__}/../http03b_creds.txt",
  "#{ALICE_SESSION.token.reveal}\n#{BOB_TOKEN.token.reveal}\n")

# Can a consumer install bearer-first precedence, as HTTP-03 asks ("unless the route explicitly
# allows that policy")?
class BearerFirstHandler < Kemal::Handler
  def initialize(@app : KemalIdentity::Application)
  end

  def call(env)
    header = env.request.headers["Authorization"]?
    bearer = header.try { |h| h.starts_with?("Bearer ") ? h.lchop("Bearer ") : nil }

    outcome =
      if bearer && (service = @app.bearer)
        service.authenticate(bearer)
      else
        @app.sessions.resolve(@app.cookie.extract(env.request.cookies))
      end

    ctx = KemalIdentity::Kemal::RequestContext.new(env, @app, outcome)
    env.auth = ctx

    # Can this handler keep remember-me while choosing its own precedence? The shipped handler
    # does cookie -> bearer -> remember-me in an order blueprints/0012 says is subtle.
    ctx.restore_remembered! if outcome.is_a?(KemalIdentity::Anonymous)

    call_next(env)
  end
end

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use BearerFirstHandler.new(KemalIdentity.app)

# Who does the shard think is asking?
get "/whoami" do |env|
  principal = env.auth.principal?
  if principal
    credential = env.auth.credential
    "#{principal.subject} via #{credential.try(&.kind) || "none"}"
  else
    env.auth.require! # raises, so the guard's status is what a client sees
  end
end

Kemal.config.port = 4713
Kemal.config.env = "production"
Kemal.run

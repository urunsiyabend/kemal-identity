# DEV-03: the core with raw `HTTP::Server`, no Kemal anywhere.
#
# `require "kemal_identity"` only -- never `kemal_identity/kemal`. If the core reaches into the
# adapter, this does not compile.
require "kemal_identity"
require "kemal_identity/sqlite"
require "sqlite3"
require "http/server"

DBF = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/dev03.db"
File.delete?(DBF)
DATABASE = DB.open("sqlite3://#{DBF}")
Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
    .reject(&.strip.empty?).each { |stmt| DATABASE.exec(stmt) }
end
DATABASE.exec(
  "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
  "u-1", "ada@example.com", 1, Time.utc, Time.utc
)

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
CLOCK    = KemalIdentity::SystemClock.new
RANDOM   = KemalIdentity::SecureRandomSource.new

SESSIONS = KemalIdentity::Sessions::Service.new(
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  clock: CLOCK, random: RANDOM,
)
API = KemalIdentity::ApiTokens::Service.new(
  tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  clock: CLOCK, random: RANDOM,
)
# The codec is the config: `extract` and `build` take stdlib `HTTP::Cookies`, not Kemal types.
COOKIE = KemalIdentity::Sessions::CookieConfig.new(
  name: "raw_session", secure: false, allow_insecure: true
)

# The whole adapter: pull the credential out of a raw request, resolve it, map the failure.
# Cookie first or bearer first is this adapter's choice to make, which is the thing HTTP-03
# wanted and Kemal's handler decides for you.
private def resolve(request : HTTP::Request) : KemalIdentity::Outcome
  header = request.headers["Authorization"]?
  bearer = header.try { |h| h.starts_with?("Bearer ") ? h.lchop("Bearer ") : nil }
  return API.authenticate(bearer) if bearer

  SESSIONS.resolve(COOKIE.extract(request.cookies))
end

TOKEN = API.issue(ACCOUNTS.find_by_id("u-1").not_nil!, "raw-cli")
ISSUED_SESSION = SESSIONS.start(
  ACCOUNTS.find_by_id("u-1").not_nil!, KemalIdentity::AssuranceLevel::Password
)
File.write("#{__DIR__}/../dev03_creds.txt", "#{ISSUED_SESSION.token.reveal}\n#{TOKEN.token.reveal}\n")

server = HTTP::Server.new do |context|
  case resolve(context.request)
  in KemalIdentity::Authenticated
    principal = resolve(context.request).as(KemalIdentity::Authenticated).principal
    context.response.status = :ok
    context.response.print "#{principal.subject} via #{principal.credential.try(&.kind)}"
  in KemalIdentity::Anonymous
    context.response.status = :unauthorized
    context.response.headers["WWW-Authenticate"] = %(Bearer realm="raw")
    context.response.print "anonymous"
  in KemalIdentity::Failed
    context.response.status = :unauthorized
    context.response.headers["WWW-Authenticate"] = %(Bearer realm="raw", error="invalid_token")
    context.response.print "rejected"
  end
end

server.bind_tcp 4714
server.listen

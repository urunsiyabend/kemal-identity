require "kemal"
require "kemal_identity"
require "kemal_identity/kemal"
require "kemal_identity/sqlite"
require "sqlite3"
require "./tok02_fine_grained"

# TOK-02 over HTTP — the horizontal-access attempt the scenario describes: take a token that was
# selected for one organisation and change the organisation, then the repository, in the URL.
DBF      = "#{__DIR__}/../tok02.db"
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

REPOSITORIES = {
  "17" => Repo.new("17", "org-a"),
  "24" => Repo.new("24", "org-a"),
  "31" => Repo.new("31", "org-b"),
}

AUTHZ_STORE = KemalIdentity::SQLite::AuthzRepository.new(DATABASE)
{"org-a", "org-b"}.each_with_index do |org, i|
  AUTHZ_STORE.add_member(KemalIdentity::Authz::Membership.new(
    id: "m#{i}", account_id: "ada", tenant_id: org, created_at: Time.utc
  ))
  AUTHZ_STORE.grant(KemalIdentity::Authz::Assignment.new(
    id: "g#{i}", account_id: "ada", role: "developer", tenant_id: org, granted_at: Time.utc
  ))
end

RBAC = KemalIdentity::Authz::RBAC.new(
  catalog: KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new([
      KemalIdentity::Authz::Permission.new(
        "repo.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
      KemalIdentity::Authz::Permission.new(
        "repo.write", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
    ]),
    [KemalIdentity::Authz::Role.new("developer", ["repo.read", "repo.write"])]
  ),
  store: AUTHZ_STORE,
  clock: KemalIdentity::SystemClock.new,
  random: KemalIdentity::SecureRandomSource.new,
)

# Filled in after the tokens are issued: the selection is keyed on the token's id, which only
# exists once it has been issued.
RESTRICTIONS = {} of String => TokenRestriction

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  authorizer: FineGrainedAuthorizer.new(RBAC, RESTRICTIONS, REPOSITORIES),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "consumer_session", secure: false, allow_insecure: true
  ),
)

ADA = ACCOUNTS.find_by_id("ada").not_nil!

NARROW = KemalIdentity.app.api!.issue(ADA, "narrow", scopes: ["repo.read"])
WIDE   = KemalIdentity.app.api!.issue(ADA, "wide", scopes: ["repo.read", "repo.write"])

RESTRICTIONS[NARROW.record.id] = TokenRestriction.new(Set{"org-a"}, Set{"17", "24"})
RESTRICTIONS[WIDE.record.id] = TokenRestriction.new(Set{"org-b"}, Set(String).new)

File.write("#{__DIR__}/../tok02_creds.txt", "#{NARROW.token.reveal}\n#{WIDE.token.reveal}\n")

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil)
use KemalIdentity::Kemal::AuthenticationHandler.new

get "/orgs/:org/repos/:repo" do |env|
  org = env.params.url["org"]
  repo = env.params.url["repo"]

  env.auth.authorize!("repo.read", tenant: org, resource: Repo.new(repo, org))
  "read #{org}/#{repo}"
end

put "/orgs/:org/repos/:repo" do |env|
  org = env.params.url["org"]
  repo = env.params.url["repo"]

  env.auth.authorize!("repo.write", tenant: org, resource: Repo.new(repo, org))
  "wrote #{org}/#{repo}"
end

get "/orgs/:org" do |env|
  org = env.params.url["org"]
  env.auth.authorize!("repo.read", tenant: org)
  "listed #{org}"
end

Kemal.config.port = 4724
Kemal.config.env = "production"
Kemal.run

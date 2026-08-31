require "spec"
require "kemal_identity"
require "kemal_identity/sqlite"
require "sqlite3"

# TOK-01 / AUT-03, attempted exactly as an application developer would: two personal access
# tokens for one account, one for reading reports and one for publishing releases.
#
# Nothing here is allowed to reopen a core class, copy private logic, or query the token
# repository a second time.

DB_PATH = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/tok01.db"

private def migrated_db
  File.delete?(DB_PATH)
  db = DB.open("sqlite3://#{DB_PATH}")
  # Friction worth recording: the shipped migrations are micrate-format, micrate itself cannot
  # resolve on this stack (blueprints/0002), so a consumer hand-rolls this. Comments must be
  # stripped *before* splitting on `;` or a semicolon inside a column comment cuts a statement
  # in half — which is exactly the `incomplete input` error the first attempt at this produced.
  Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
    body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
    body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
      .reject(&.strip.empty?).each { |stmt| db.exec(stmt) }
  end
  db
end

private ROLES = [
  KemalIdentity::Authz::Role.new("release_manager", ["reports.read", "releases.write"]),
]

private PERMISSIONS = [
  # Automation is allowed to perform both, so both are declared at ApiToken assurance.
  KemalIdentity::Authz::Permission.new(
    "reports.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
  KemalIdentity::Authz::Permission.new(
    "releases.write", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
]

describe "TOK-01: per-token scopes" do
  it "distinguishes two tokens for one account and enforces each one's scope" do
    db = migrated_db
    clock = KemalIdentity::SystemClock.new
    random = KemalIdentity::SecureRandomSource.new

    accounts = KemalIdentity::SQLite::AccountRepository.new(db)
    db.exec(
      "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) " \
      "VALUES (?, ?, ?, ?, ?)",
      "acct-1", "ada@example.com", 1, Time.utc, Time.utc
    )

    tokens = KemalIdentity::SQLite::ApiTokenRepository.new(db)
    api = KemalIdentity::ApiTokens::Service.new(tokens: tokens, clock: clock, random: random)

    authz_store = KemalIdentity::SQLite::AuthzRepository.new(db)
    rbac = KemalIdentity::Authz::RBAC.new(
      catalog: KemalIdentity::Authz::RoleCatalog.new(
        KemalIdentity::Authz::PermissionRegistry.new(PERMISSIONS), ROLES
      ),
      store: authz_store, clock: clock, random: random
    )
    rbac.grant("acct-1", "release_manager")

    account = accounts.find_by_id("acct-1").not_nil!

    # Step 1-2: two tokens, differently scoped. No built-in migration was modified.
    reporting = api.issue(account, "reporting", scopes: ["reports.read"])
    deploying = api.issue(account, "deploy", scopes: ["reports.read", "releases.write"])

    # Step 3: both authenticate through the normal path.
    reporting_principal = api.authenticate(reporting.token.reveal)
      .as(KemalIdentity::Authenticated).principal
    deploying_principal = api.authenticate(deploying.token.reveal)
      .as(KemalIdentity::Authenticated).principal

    # Pass condition: "The application can identify the exact credential used for the request."
    reporting_principal.credential.not_nil!.id.should eq(reporting.record.id)
    deploying_principal.credential.not_nil!.id.should eq(deploying.record.id)
    reporting_principal.credential.not_nil!.id.should_not eq(deploying_principal.credential.not_nil!.id)

    # Step 4: guard using the current token's scope.
    rbac.decide(reporting_principal, "reports.read").permitted?.should be_true
    rbac.decide(deploying_principal, "releases.write").permitted?.should be_true

    # Pass condition: "a token cannot gain a permission the account lacks" — and the narrower
    # token cannot reach what the account itself may do.
    denial = rbac.decide(reporting_principal, "releases.write")
    denial.permitted?.should be_false
    denial.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::OutOfScope)

    db.close
  end

  it "denies when scope configuration is missing (fail closed)" do
    # Pass condition: "Missing scope configuration denies access."
    # A token attenuated to nothing is the explicit form of that.
    db = migrated_db
    clock = KemalIdentity::SystemClock.new
    random = KemalIdentity::SecureRandomSource.new
    accounts = KemalIdentity::SQLite::AccountRepository.new(db)
    db.exec(
      "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) " \
      "VALUES (?, ?, ?, ?, ?)",
      "acct-1", "ada@example.com", 1, Time.utc, Time.utc
    )
    tokens = KemalIdentity::SQLite::ApiTokenRepository.new(db)
    api = KemalIdentity::ApiTokens::Service.new(tokens: tokens, clock: clock, random: random)
    authz_store = KemalIdentity::SQLite::AuthzRepository.new(db)
    rbac = KemalIdentity::Authz::RBAC.new(
      catalog: KemalIdentity::Authz::RoleCatalog.new(
        KemalIdentity::Authz::PermissionRegistry.new(PERMISSIONS), ROLES
      ),
      store: authz_store, clock: clock, random: random
    )
    rbac.grant("acct-1", "release_manager")

    account = accounts.find_by_id("acct-1").not_nil!
    powerless = api.issue(account, "powerless", scopes: [] of String)
    principal = api.authenticate(powerless.token.reveal).as(KemalIdentity::Authenticated).principal

    rbac.decide(principal, "reports.read").permitted?.should be_false

    db.close
  end
end

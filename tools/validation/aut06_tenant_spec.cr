require "spec"
require "sqlite3"
require "kemal_identity"
require "kemal_identity/sqlite"
require "kemal_identity/testing"

# AUT-06, the part that is not about the grants cache.
#
# `Sessions::Service#start` copies `account.tenant_id` onto the session row, and
# `#resolve` rebuilds the principal from the *row*. So the one authorization input that is
# copied into a session is the tenant binding, and this measures how long a change to it takes
# to be felt — against real SQLite, changing the column with a plain `UPDATE`, because an
# application owns its accounts table and that is what it would do.

MIGRATIONS = %w[
  20260824120000_create_auth_accounts
  20260824120100_create_auth_sessions
  20260829090000_create_auth_authorization
]

def migrate!(db : DB::Database, root : String) : Nil
  MIGRATIONS.each do |name|
    sql = File.read(File.join(root, "migrations", "sqlite", "#{name}.sql"))
    up = sql.split("-- +micrate Down").first.sub("-- +micrate Up", "")
    body = up.lines.reject { |line| line.strip.starts_with?("--") }.join('\n')

    body.split(';').each do |statement|
      next if statement.strip.empty?
      db.exec(statement)
    end
  end
end

ROOT  = File.expand_path(ENV["KEMAL_IDENTITY_ROOT"] || "../kemal_identity")
CLOCK = KemalIdentity::Testing::TestClock.new

REG = KemalIdentity::Authz::PermissionRegistry.new(
  KemalIdentity::Authz::Permission.new("reports.read", "Read reports")
)
CAT = KemalIdentity::Authz::RoleCatalog.new(
  REG, [KemalIdentity::Authz::Role.new("member", ["reports.read"])]
)

def with_app(& : DB::Database, KemalIdentity::Sessions::Service, KemalIdentity::Authz::RBAC ->)
  path = File.tempname("aut06", ".db")

  begin
    db = DB.open("sqlite3://#{path}")
    migrate!(db, ROOT)

    sessions = KemalIdentity::Sessions::Service.new(
      KemalIdentity::SQLite::SessionRepository.new(db),
      CLOCK,
      KemalIdentity::Testing::DeterministicRandom.new,
    )
    authz = KemalIdentity::SQLite::AuthzRepository.new(db)
    rbac = KemalIdentity::Authz::RBAC.new(CAT, authz, CLOCK)

    # One account, deliberately *unconfined*: no tenant, which is what a person who belongs to
    # more than one organisation looks like (TOK-02 built the same fixture).
    #
    # Inserted with SQL because `Accounts::Repository` has no `insert` — creating accounts is
    # the application's, and only the five methods authentication needs are contract.
    db.exec(<<-SQL, CLOCK.now, CLOCK.now)
      INSERT INTO auth_accounts
        (id, tenant_id, normalized_login, auth_version, password_digest, password_scheme,
         created_at, updated_at)
      VALUES ('ada', NULL, 'ada@example.com', 1, 'digest', 'bcrypt', ?, ?)
      SQL

    now = CLOCK.now
    authz.add_member(KemalIdentity::Authz::Membership.new("m1", "ada", "org-a", now))
    authz.add_member(KemalIdentity::Authz::Membership.new("m2", "ada", "org-b", now))
    authz.grant(KemalIdentity::Authz::Assignment.new("g1", "ada", "member", now, tenant_id: "org-a"))
    authz.grant(KemalIdentity::Authz::Assignment.new("g2", "ada", "member", now, tenant_id: "org-b"))

    yield db, sessions, rbac
  ensure
    db.try(&.close)
    File.delete?(path)
  end
end

def account(db : DB::Database) : KemalIdentity::Accounts::Account
  KemalIdentity::SQLite::AccountRepository.new(db).find_by_id("ada").not_nil!
end

def permitted?(rbac, principal, tenant) : Bool
  rbac.decide(principal, "reports.read", KemalIdentity::Authz::Context.new(tenant_id: tenant))
    .permitted?
end

describe "AUT-06 — the tenant binding copied onto the session row" do
  it "is read from the session, not from the account, on every request" do
    with_app do |db, sessions, rbac|
      issued = sessions.start(account(db), KemalIdentity::AssuranceLevel::Password)
      raw = issued.token.reveal

      resolved = sessions.resolve(raw).as(KemalIdentity::Authenticated).principal
      resolved.tenant_id.should be_nil

      permitted?(rbac, resolved, "org-a").should be_true
      permitted?(rbac, resolved, "org-b").should be_true

      # The application confines the account to one organisation. Its own table, its own
      # UPDATE — there is no shard method for this and there should not be.
      db.exec("UPDATE auth_accounts SET tenant_id = 'org-a' WHERE id = 'ada'")
      account(db).tenant_id.should eq("org-a")

      # A session started now is confined.
      fresh = sessions.start(account(db), KemalIdentity::AssuranceLevel::Password)
        .principal
      fresh.tenant_id.should eq("org-a")
      permitted?(rbac, fresh, "org-b").should be_false

      # The session that already existed is not, and no amount of waiting changes it: this is
      # rebuilt from the row on every resolve, so there is no cache to expire.
      CLOCK.advance(1.hour)
      still = sessions.resolve(raw).as(KemalIdentity::Authenticated).principal
      still.tenant_id.should be_nil
      permitted?(rbac, still, "org-b").should be_true
    end
  end

  it "is closed immediately by bump_auth_version, across processes, with no cache involved" do
    with_app do |db, sessions, rbac|
      issued = sessions.start(account(db), KemalIdentity::AssuranceLevel::Password)
      raw = issued.token.reveal

      sessions.resolve(raw).should be_a(KemalIdentity::Authenticated)

      db.exec("UPDATE auth_accounts SET tenant_id = 'org-a' WHERE id = 'ada'")
      KemalIdentity::SQLite::AccountRepository.new(db).bump_auth_version("ada").should eq(2)

      outcome = sessions.resolve(raw)
      outcome.should be_a(KemalIdentity::Failed)
      outcome.as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::StaleAuthVersion)
    end
  end

  it "is closed by revoking the account's sessions, which is the other lever" do
    with_app do |db, sessions, _rbac|
      raw = sessions.start(account(db), KemalIdentity::AssuranceLevel::Password).token.reveal

      db.exec("UPDATE auth_accounts SET tenant_id = 'org-a' WHERE id = 'ada'")
      sessions.revoke_all("ada").should eq(1)

      sessions.resolve(raw).as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::Revoked)
    end
  end

  it "revokes membership promptly with no cache, which is the default" do
    with_app do |db, sessions, rbac|
      raw = sessions.start(account(db), KemalIdentity::AssuranceLevel::Password).token.reveal
      principal = sessions.resolve(raw).as(KemalIdentity::Authenticated).principal

      permitted?(rbac, principal, "org-a").should be_true

      # Another process removes them from the organisation.
      KemalIdentity::SQLite::AuthzRepository.new(db).remove_member("ada", "org-a")

      # The very next decision, no clock movement, no invalidation call.
      permitted?(rbac, principal, "org-a").should be_false
    end
  end
end

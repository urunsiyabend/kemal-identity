require "../spec_helper"
require "../../src/kemal_identity/sqlite"
require "file_utils"

# The SQLite adapters, running the **same** four contract specs the in-memory doubles and the
# PostgreSQL adapters pass.
#
# A third implementation is what turns the contracts from a convention into a constraint. The
# doubles and PostgreSQL were written days apart by the same reasoning; SQLite is a different
# dialect with different types, different placeholders and a different locking model, so
# anything the contracts left implicit shows up here.
#
# Unlike the PostgreSQL specs these need no server, which is the other reason the adapter
# exists: `spec/integration/sqlite_spec.cr` runs anywhere `crystal spec` does.

# A file rather than `:memory:`. Each connection to an in-memory SQLite gets its **own**
# database, so a pool of more than one would silently give every fiber a private empty schema —
# and the concurrency examples would pass while testing nothing.
#
# `journal_mode=wal` and a `busy_timeout` because SQLite serialises writers across the whole
# file: without them the concurrency examples fail with `database is locked` rather than
# queueing, which is contention, not a contract violation.
private SQLITE_PATH = File.join(Dir.tempdir, "kemal_identity_spec_#{Process.pid}.db")
private SQLITE_URL  = "sqlite3://#{SQLITE_PATH}?journal_mode=wal&busy_timeout=5000"

private DATABASE = DB.open(SQLITE_URL)

# `Spec.after_suite`, not `at_exit`. Crystal's spec runner registers its own `at_exit` when
# `spec` is required — before this file's top-level code — and handlers run last-registered
# first, so an `at_exit` here closes the database and deletes the file *before* a single
# example runs. Every example then fails with `no such table`, which is a confusing way to
# discover the ordering.
Spec.after_suite do
  DATABASE.close
  ["-wal", "-shm", ""].each { |suffix| FileUtils.rm_rf("#{SQLITE_PATH}#{suffix}") }
end

private def migrate! : Nil
  Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
    # Plain string splits: Crystal's `m` regex flag means "`.` matches newline", not "`^`
    # matches line starts", so an anchored pattern would not do what it looks like it does.
    up = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last

    up.split(';').each do |statement|
      next if statement.strip.empty?
      DATABASE.exec(statement)
    end
  end
end

private def reset_schema! : Nil
  %w[auth_sessions auth_action_tokens auth_remember_tokens auth_accounts].each do |table|
    DATABASE.exec("DELETE FROM #{table}")
  end
end

private def insert(account : KemalIdentity::Accounts::Account) : Nil
  DATABASE.exec(<<-SQL,
    INSERT INTO auth_accounts (
      id, tenant_id, normalized_login, email_verified_at, disabled_at,
      auth_version, password_digest, password_scheme, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    SQL
    account.id, account.tenant_id, account.normalized_login, account.email_verified_at,
    account.disabled_at, account.auth_version, account.password_digest,
    account.password_scheme, account.created_at, account.updated_at)
end

private def seed_accounts! : Nil
  insert(KemalIdentity::SpecHelper.account(id: "a1", login: "a1@example.com"))
  insert(KemalIdentity::SpecHelper.account(id: "a2", login: "a2@example.com"))
end

migrate!

describe KemalIdentity::SQLite::AccountRepository do
  it_behaves_like_an_account_repository do |accounts|
    reset_schema!
    accounts.each { |account| insert(account) }
    KemalIdentity::SQLite::AccountRepository.new(DATABASE)
  end
end

describe KemalIdentity::SQLite::SessionRepository do
  it_behaves_like_a_session_repository do |accounts|
    reset_schema!
    accounts.each { |account| insert(account) }
    KemalIdentity::SQLite::SessionRepository.new(DATABASE)
  end
end

describe KemalIdentity::SQLite::ActionTokenRepository do
  it_behaves_like_an_action_token_repository do |tokens|
    reset_schema!
    seed_accounts!

    repo = KemalIdentity::SQLite::ActionTokenRepository.new(DATABASE)
    tokens.each { |token| repo.create(token) }
    repo
  end
end

describe KemalIdentity::SQLite::RememberRepository do
  it_behaves_like_a_remember_repository do |tokens|
    reset_schema!
    seed_accounts!

    repo = KemalIdentity::SQLite::RememberRepository.new(DATABASE)
    tokens.each { |token| repo.create(token) }
    repo
  end
end

# Properties of this dialect specifically. The contracts cannot state them, because each
# storage engine reaches them by a different route.
describe "what SQLite enforces that the other adapters emulate" do
  now = KemalIdentity::SpecHelper::FIXED_NOW

  it "rejects a duplicate normalized_login for a null tenant" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com"))

    # The partial unique index. SQLite treats NULLs as distinct in a plain unique index exactly
    # as PostgreSQL does, so without this the single-tenant case admits duplicates.
    #
    # This insert is the spec's own helper rather than an adapter method, so it has no
    # `ON CONFLICT` clause and the driver exception surfaces directly. That is the point: the
    # index is doing the work.
    expect_raises(Exception) do
      insert(KemalIdentity::SpecHelper.account(id: "a2", login: "ada@example.com"))
    end
  end

  it "allows the same login in different tenants" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com", tenant_id: "t1"))
    insert(KemalIdentity::SpecHelper.account(id: "a2", login: "ada@example.com", tenant_id: "t2"))

    KemalIdentity::SQLite::AccountRepository.new(DATABASE)
      .find_by_login("ada@example.com", "t2").or_fail.id.should eq("a2")
  end

  it "stores the session token as a BLOB, not as text" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account)

    digest = KemalIdentity::Secret.new("a-token").digest
    repo = KemalIdentity::SQLite::SessionRepository.new(DATABASE)
    repo.create(session_record(digest, now))

    stored_type = DATABASE.scalar("SELECT typeof(token_digest) FROM auth_sessions").as(String)
    stored_type.should eq("blob")

    repo.find_by_digest(digest).or_fail.session.token_digest.should eq(digest)
  end

  it "round trips the assurance level through an INTEGER" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account)

    digest = KemalIdentity::Secret.new("mfa-token").digest
    repo = KemalIdentity::SQLite::SessionRepository.new(DATABASE)
    repo.create(session_record(digest, now, assurance: KemalIdentity::AssuranceLevel::MFA))

    repo.find_by_digest(digest).or_fail.session.assurance
      .should eq(KemalIdentity::AssuranceLevel::MFA)

    # The numeric value is what is on disk, as in PostgreSQL. Renumbering the enum would
    # silently reclassify every stored row.
    DATABASE.scalar("SELECT assurance FROM auth_sessions").as(Int64).should eq(30)
  end

  # SQLite stores no timezone. The driver writes and reads UTC, and the contracts compare
  # instants exactly, so this is worth pinning rather than assuming.
  it "preserves timestamps to the precision the contracts compare them at" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account)

    digest = KemalIdentity::Secret.new("time-token").digest
    repo = KemalIdentity::SQLite::SessionRepository.new(DATABASE)
    repo.create(session_record(digest, now))

    stored = repo.find_by_digest(digest).or_fail.session
    stored.created_at.should eq(now)
    stored.absolute_expires_at.should eq(now + 12.hours)
  end

  it "raises InfrastructureError rather than a driver error on a duplicate digest" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account)

    digest = KemalIdentity::Secret.new("contested").digest
    repo = KemalIdentity::SQLite::SessionRepository.new(DATABASE)
    repo.create(session_record(digest, now, id: "s1"))

    error = expect_raises(KemalIdentity::InfrastructureError) do
      repo.create(session_record(digest, now, id: "s2"))
    end

    error.message.to_s.should_not contain(digest.hexstring)
  end

  it "increments auth_version atomically under concurrency" do
    reset_schema!
    insert(KemalIdentity::SpecHelper.account)

    repo = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
    results = Channel(Int32?).new

    8.times { spawn { results.send(repo.bump_auth_version("a1")) } }
    returned = Array.new(8) { results.receive }

    returned.compact.sort!.should eq((2..9).to_a)
    repo.find_by_id("a1").or_fail.auth_version.should eq(9)
  end
end

private def session_record(
  digest : Bytes,
  now : Time,
  id : String = "s1",
  assurance : KemalIdentity::AssuranceLevel = KemalIdentity::AssuranceLevel::Password,
) : KemalIdentity::Sessions::Record
  KemalIdentity::Sessions::Record.new(
    id: id,
    account_id: "a1",
    token_digest: digest,
    auth_version: 1,
    assurance: assurance,
    created_at: now,
    authenticated_at: now,
    last_seen_at: now,
    idle_expires_at: now + 30.minutes,
    absolute_expires_at: now + 12.hours,
  )
end

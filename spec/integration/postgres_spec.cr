require "../spec_helper"
require "../../src/kemal_identity/postgres"

# The PostgreSQL adapters, running the **same** contract specs the in-memory doubles pass.
#
# This is the point of the contract layer. A double that quietly behaves differently from
# PostgreSQL turns a green suite into false confidence, and the only way to know it does not is
# to hold both to one specification. Everything asserted here is asserted identically in
# `spec/unit/memory_account_repository_spec.cr` and `spec/unit/memory_session_repository_spec.cr`.
#
# Needs `DATABASE_URL` and a migrated schema. `spec/unit` and `spec/security` deliberately do
# not, so the security regressions still run on every save.

private DATABASE_URL = ENV["DATABASE_URL"]?

# One pool for the whole file. Opened eagerly so that a bad DATABASE_URL fails here, with the
# connection string's own error, rather than inside the first example.
private DATABASE = DATABASE_URL.nil? || DATABASE_URL.to_s.empty? ? nil : DB.open(DATABASE_URL.to_s)

private def database : DB::Database
  DATABASE.or_fail("DATABASE_URL is not set")
end

# Every table the contract touches, emptied between builds.
#
# TRUNCATE rather than DELETE: it is what a test suite wants, and it fails loudly if the schema
# is not there at all, which is a better error than a confusing empty result later.
private def reset_schema! : Nil
  database.exec(
    "TRUNCATE auth_sessions, auth_action_tokens, auth_remember_tokens, auth_api_tokens, " \
    "auth_mfa_factors, auth_mfa_recovery_codes, auth_external_identities, auth_accounts"
  )
rescue error : PQ::PQError
  raise Spec::AssertionFailed.new(
    "the auth_ tables are missing -- run `shards build migrate && bin/migrate up` " \
    "against DATABASE_URL first (#{error.message})",
    __FILE__, __LINE__
  )
end

private def insert(account : KemalIdentity::Accounts::Account) : Nil
  database.exec(<<-SQL,
    INSERT INTO auth_accounts (
      id, tenant_id, normalized_login, email_verified_at, disabled_at,
      auth_version, password_digest, password_scheme, created_at, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    SQL
    account.id, account.tenant_id, account.normalized_login, account.email_verified_at,
    account.disabled_at, account.auth_version, account.password_digest,
    account.password_scheme, account.created_at, account.updated_at)
end

if DATABASE.nil?
  # Reported rather than silently absent: a suite that quietly skips its only test of the real
  # adapter looks exactly like a suite that has one.
  pending "PostgreSQL repositories (set DATABASE_URL to run them)"
else
  describe KemalIdentity::Postgres::AccountRepository do
    it_behaves_like_an_account_repository do |accounts|
      reset_schema!
      accounts.each { |account| insert(account) }
      KemalIdentity::Postgres::AccountRepository.new(database)
    end
  end

  describe KemalIdentity::Postgres::ActionTokenRepository do
    it_behaves_like_an_action_token_repository do |tokens|
      reset_schema!
      # Every token needs an account to belong to, and the contract seeds tokens for a1 and a2.
      insert(KemalIdentity::SpecHelper.account(id: "a1", login: "a1@example.com"))
      insert(KemalIdentity::SpecHelper.account(id: "a2", login: "a2@example.com"))

      repo = KemalIdentity::Postgres::ActionTokenRepository.new(database)
      tokens.each { |token| repo.create(token) }
      repo
    end
  end

  describe KemalIdentity::Postgres::RememberRepository do
    it_behaves_like_a_remember_repository do |tokens|
      reset_schema!
      insert(KemalIdentity::SpecHelper.account(id: "a1", login: "a1@example.com"))
      insert(KemalIdentity::SpecHelper.account(id: "a2", login: "a2@example.com"))

      repo = KemalIdentity::Postgres::RememberRepository.new(database)
      tokens.each { |token| repo.create(token) }
      repo
    end
  end

  describe KemalIdentity::Postgres::ApiTokenRepository do
    it_behaves_like_an_api_token_repository do |accounts|
      reset_schema!
      accounts.each { |account| insert(account) }
      KemalIdentity::Postgres::ApiTokenRepository.new(database)
    end
  end

  describe KemalIdentity::Postgres::MfaRepository do
    it_behaves_like_an_mfa_repository do
      reset_schema!
      KemalIdentity::Postgres::MfaRepository.new(database)
    end
  end

  describe KemalIdentity::Postgres::LinkRepository do
    it_behaves_like_a_link_repository do
      reset_schema!
      KemalIdentity::Postgres::LinkRepository.new(database)
    end
  end

  describe KemalIdentity::Postgres::SessionRepository do
    it_behaves_like_a_session_repository do |accounts|
      reset_schema!
      accounts.each { |account| insert(account) }
      KemalIdentity::Postgres::SessionRepository.new(database)
    end
  end

  # Properties that only exist once a real database is underneath. The contract cannot state
  # them, because the in-memory double reaches them by a different route -- a mutex rather than
  # an index.
  describe "what PostgreSQL enforces that the double emulates" do
    now = KemalIdentity::SpecHelper::FIXED_NOW

    it "rejects a duplicate normalized_login for a null tenant" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com"))

      # The partial unique index from docs/03-data-model.md. Without it, two null-tenant rows
      # with the same login do not collide under a plain UNIQUE (tenant_id, normalized_login),
      # because NULLs are distinct.
      expect_raises(PQ::PQError) do
        insert(KemalIdentity::SpecHelper.account(id: "a2", login: "ada@example.com"))
      end
    end

    it "allows the same login in different tenants" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com", tenant_id: "t1"))
      insert(KemalIdentity::SpecHelper.account(id: "a2", login: "ada@example.com", tenant_id: "t2"))

      KemalIdentity::Postgres::AccountRepository.new(database)
        .find_by_login("ada@example.com", "t2").or_fail.id.should eq("a2")
    end

    it "stores the session token as bytes, not as text" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      digest = KemalIdentity::Secret.new("a-token").digest
      repo = KemalIdentity::Postgres::SessionRepository.new(database)
      repo.create(session_record(digest, now))

      # BYTEA, half the storage of a hex CHAR(64) and with no encoding for two adapters to
      # disagree about.
      column_type = database.scalar(
        "SELECT data_type FROM information_schema.columns " \
        "WHERE table_name = 'auth_sessions' AND column_name = 'token_digest'"
      ).as(String)
      column_type.should eq("bytea")

      repo.find_by_digest(digest).or_fail.session.token_digest.should eq(digest)
    end

    it "round trips the assurance level through a SMALLINT" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      digest = KemalIdentity::Secret.new("mfa-token").digest
      repo = KemalIdentity::Postgres::SessionRepository.new(database)
      repo.create(session_record(digest, now, assurance: KemalIdentity::AssuranceLevel::MFA))

      repo.find_by_digest(digest).or_fail.session.assurance
        .should eq(KemalIdentity::AssuranceLevel::MFA)

      # The numeric value is what is on disk. Renumbering the enum would silently reclassify
      # every session row already stored.
      database.scalar("SELECT assurance FROM auth_sessions").as(Int16).should eq(30_i16)
    end

    it "preserves timestamps to the precision the contract compares them at" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      digest = KemalIdentity::Secret.new("time-token").digest
      repo = KemalIdentity::Postgres::SessionRepository.new(database)
      repo.create(session_record(digest, now))

      stored = repo.find_by_digest(digest).or_fail.session
      stored.created_at.should eq(now)
      stored.absolute_expires_at.should eq(now + 12.hours)
    end

    # The unique index on token_digest, doing the job the double's mutex does in memory.
    it "raises InfrastructureError rather than a driver error on a duplicate digest" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      digest = KemalIdentity::Secret.new("contested").digest
      repo = KemalIdentity::Postgres::SessionRepository.new(database)
      repo.create(session_record(digest, now, id: "s1"))

      error = expect_raises(KemalIdentity::InfrastructureError) do
        repo.create(session_record(digest, now, id: "s2"))
      end

      # An error message must never carry a token or a digest.
      error.message.to_s.should_not contain(digest.hexstring)
    end

    it "leaves the winning row in place when a duplicate is refused" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      digest = KemalIdentity::Secret.new("contested-2").digest
      repo = KemalIdentity::Postgres::SessionRepository.new(database)
      repo.create(session_record(digest, now, id: "s1"))

      begin
        repo.create(session_record(digest, now, id: "s2"))
      rescue KemalIdentity::InfrastructureError
      end

      repo.find_by_digest(digest).or_fail.session.id.should eq("s1")
    end

    # bump_auth_version is a single UPDATE ... RETURNING rather than a read-then-write, so two
    # concurrent password changes cannot both read the same version and write the same
    # increment -- which would leave one of them not invalidating the sessions it was meant to.
    it "increments auth_version atomically under concurrency" do
      reset_schema!
      insert(KemalIdentity::SpecHelper.account)

      repo = KemalIdentity::Postgres::AccountRepository.new(database)
      results = Channel(Int32?).new

      8.times { spawn { results.send(repo.bump_auth_version("a1")) } }
      returned = Array.new(8) { results.receive }

      returned.compact.sort!.should eq((2..9).to_a)
      repo.find_by_id("a1").or_fail.auth_version.should eq(9)
    end
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

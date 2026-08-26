module KemalIdentity::SQLite
  # `Sessions::Repository` over `auth_sessions`, SQLite dialect.
  #
  # ### On translating constraint failures
  #
  # `SQLite3::Exception#code` reports `CONSTRAINT` for every constraint, not specifically for a
  # unique one, so every adapter here checks that broad code. On these tables the distinction
  # does not exist: the only constraints are primary keys and unique indexes, and both mean the
  # same thing to a caller — this row is already there. PostgreSQL's SQLSTATE is narrower,
  # which is why that adapter checks for `23505` exactly.
  class SessionRepository < Sessions::Repository
    SESSION_COLUMNS = <<-SQL
      s.id, s.account_id, s.tenant_id, s.token_digest, s.auth_version, s.assurance,
      s.created_at, s.authenticated_at, s.mfa_verified_at, s.last_seen_at,
      s.idle_expires_at, s.absolute_expires_at, s.revoked_at
      SQL

    # `accounts_table` exists because `auth_accounts` is a reference implementation. An
    # application authenticating against its own `users` table joins against that instead and
    # still satisfies the same contract.
    def initialize(@db : DB::Database, @accounts_table : String = "auth_accounts")
    end

    def create(record : Sessions::Record) : Nil
      # `ON CONFLICT DO NOTHING` plus a row count, rather than catching the driver's exception.
      #
      # crystal-sqlite3 surfaces a constraint failure when the statement is *finalised*, so the
      # error escapes from inside `ensure`-time cleanup rather than from the `exec` call — a
      # `rescue` around the insert never sees it, and the stray exception goes on to poison the
      # connection pool at close. Letting SQLite resolve the conflict is both race-free and
      # entirely within the statement.
      #
      # It covers the primary key as well as the unique index. On these tables that is the same
      # answer either way: the row is already there.
      result = @db.exec(<<-SQL,
        INSERT INTO auth_sessions (
          id, account_id, tenant_id, token_digest, auth_version, assurance,
          created_at, authenticated_at, mfa_verified_at, last_seen_at,
          idle_expires_at, absolute_expires_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
        SQL
        record.id, record.account_id, record.tenant_id, record.token_digest,
        record.auth_version, record.assurance.value.to_i32, record.created_at,
        record.authenticated_at, record.mfa_verified_at, record.last_seen_at,
        record.idle_expires_at, record.absolute_expires_at, record.revoked_at)

      # Names neither the digest nor the id: an error must never carry a token.
      raise InfrastructureError.new("session already exists") if result.rows_affected.zero?
    end

    # One indexed lookup with a join, returning session state and account status together —
    # decision D7, identical in shape to the PostgreSQL adapter. An inner join, so a session
    # pointing at an account that no longer exists resolves to nothing.
    def find_by_digest(digest : Bytes) : Sessions::Lookup?
      @db.query_one?(<<-SQL, digest) { |row| read_lookup(row) }
        SELECT #{SESSION_COLUMNS},
               a.auth_version AS account_auth_version,
               a.disabled_at  AS account_disabled_at
          FROM auth_sessions s
          JOIN #{@accounts_table} a ON a.id = s.account_id
         WHERE s.token_digest = ?
        SQL
    end

    def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
      result = @db.exec(
        "UPDATE auth_sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?",
        last_seen_at, idle_expires_at, id
      )

      result.rows_affected == 1
    end

    def revoke(id : String, at : Time) : Bool
      result = @db.exec(
        "UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", at, id
      )

      result.rows_affected == 1
    end

    def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
      # SQLite has positional `?` rather than PostgreSQL's numbered `$3`, so the optional
      # `except_id` is bound twice rather than referenced twice. No cast is needed: SQLite is
      # dynamically typed and infers nothing from `IS NULL`.
      result = @db.exec(<<-SQL, at, account_id, except_id, except_id)
        UPDATE auth_sessions
           SET revoked_at = ?
         WHERE account_id = ?
           AND revoked_at IS NULL
           AND (? IS NULL OR id <> ?)
        SQL

      result.rows_affected.to_i32
    end

    def delete_revoked_before(before : Time) : Int32
      result = @db.exec(
        "DELETE FROM auth_sessions WHERE revoked_at IS NOT NULL AND revoked_at <= ?", before
      )
      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      # `<=`, matching `SessionService#expired?`'s `>=`, so the sweeper can never delete a row
      # `resolve` still considers live.
      result = @db.exec("DELETE FROM auth_sessions WHERE absolute_expires_at <= ?", before)
      result.rows_affected.to_i32
    end

    private def read_lookup(row : DB::ResultSet) : Sessions::Lookup
      record = Sessions::Record.new(
        id: row.read(String),
        account_id: row.read(String),
        tenant_id: row.read(String?),
        token_digest: row.read(Bytes),
        auth_version: row.read(Int32),
        # Stored as the enum's numeric value in an INTEGER column. SQLite has no SMALLINT, so
        # this reads as Int32 and narrows — the value on disk is the same either way, and
        # renumbering the enum would still silently reclassify every stored row.
        assurance: AssuranceLevel.from_value(row.read(Int32).to_i16),
        created_at: row.read(Time),
        authenticated_at: row.read(Time),
        mfa_verified_at: row.read(Time?),
        last_seen_at: row.read(Time),
        idle_expires_at: row.read(Time),
        absolute_expires_at: row.read(Time),
        revoked_at: row.read(Time?),
      )

      Sessions::Lookup.new(
        session: record,
        account_auth_version: row.read(Int32),
        account_disabled_at: row.read(Time?),
      )
    end
  end
end

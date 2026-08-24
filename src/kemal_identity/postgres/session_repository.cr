module KemalIdentity::Postgres
  # `Sessions::Repository` over `auth_sessions`.
  #
  # The hot path is `#find_by_digest`, and it is the one query whose cost lands on every
  # authenticated request. Everything else runs at login, at logout, or in a background sweep.
  class SessionRepository < Sessions::Repository
    # PostgreSQL's SQLSTATE for a unique violation.
    UNIQUE_VIOLATION = "23505"

    SESSION_COLUMNS = <<-SQL
      s.id, s.account_id, s.tenant_id, s.token_digest, s.auth_version, s.assurance,
      s.created_at, s.authenticated_at, s.mfa_verified_at, s.last_seen_at,
      s.idle_expires_at, s.absolute_expires_at, s.revoked_at
      SQL

    # `accounts_table` exists because `auth_accounts` is a reference implementation. An
    # application authenticating against its own `users` table joins against that instead, and
    # still satisfies the same contract — the contract spec asserts the result shape, never the
    # SQL.
    def initialize(@db : DB::Database, @accounts_table : String = "auth_accounts")
    end

    def create(record : Sessions::Record) : Nil
      @db.exec(<<-SQL,
        INSERT INTO auth_sessions (
          id, account_id, tenant_id, token_digest, auth_version, assurance,
          created_at, authenticated_at, mfa_verified_at, last_seen_at,
          idle_expires_at, absolute_expires_at, revoked_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        SQL
        record.id, record.account_id, record.tenant_id, record.token_digest,
        record.auth_version, record.assurance.value, record.created_at,
        record.authenticated_at, record.mfa_verified_at, record.last_seen_at,
        record.idle_expires_at, record.absolute_expires_at, record.revoked_at)
    rescue error : PQ::PQError
      # The unique index on token_digest exists so that a collision is a loud error rather than
      # two accounts silently sharing a session. Translating it to InfrastructureError keeps
      # that promise while keeping PostgreSQL's exception type out of the contract.
      raise error unless error.field_message(:code) == UNIQUE_VIOLATION

      # The message names neither the digest nor the id: an error must never carry a token or a
      # digest (`src/CLAUDE.md`).
      raise InfrastructureError.new("session already exists")
    end

    # One indexed lookup with a join, returning session state **and** account status together.
    #
    # Decision D7. Fetching the session and then fetching the account is two round trips on
    # every authenticated request, which roughly doubles the fixed cost of every page view for
    # no benefit (`docs/03-data-model.md`).
    #
    # An inner join, so a session pointing at an account that no longer exists resolves to
    # nothing: the failure mode is closed rather than open.
    def find_by_digest(digest : Bytes) : Sessions::Lookup?
      @db.query_one?(<<-SQL, digest) { |row| read_lookup(row) }
        SELECT #{SESSION_COLUMNS},
               a.auth_version AS account_auth_version,
               a.disabled_at  AS account_disabled_at
          FROM auth_sessions s
          JOIN #{@accounts_table} a ON a.id = s.account_id
         WHERE s.token_digest = $1
        SQL
    end

    def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
      # Leaves absolute_expires_at alone: activity moves the idle deadline and can never
      # postpone the absolute one, or a session lives forever through mere use.
      result = @db.exec(
        "UPDATE auth_sessions SET last_seen_at = $1, idle_expires_at = $2 WHERE id = $3",
        last_seen_at, idle_expires_at, id
      )

      result.rows_affected == 1
    end

    def revoke(id : String, at : Time) : Bool
      # `AND revoked_at IS NULL` does two jobs: it reports whether anything actually changed,
      # and it stops a second revocation overwriting the first timestamp — which is the moment
      # an audit trail cares about.
      result = @db.exec(
        "UPDATE auth_sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
        at, id
      )

      result.rows_affected == 1
    end

    def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
      # `$3::text IS NULL OR id <> $3` keeps this a single statement for both callers. The cast
      # is required: PostgreSQL cannot infer a parameter's type from `IS NULL` alone.
      result = @db.exec(<<-SQL, at, account_id, except_id)
        UPDATE auth_sessions
           SET revoked_at = $1
         WHERE account_id = $2
           AND revoked_at IS NULL
           AND ($3::text IS NULL OR id <> $3)
        SQL

      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      # `<=`, matching the `>=` in SessionService#expired?. If the two disagreed about the
      # boundary the sweeper could delete a row `resolve` still considered live, which would
      # make the sweeper a correctness dependency
      # (`blueprints/0006-session-cookie-and-expiry-boundaries.md`).
      result = @db.exec("DELETE FROM auth_sessions WHERE absolute_expires_at <= $1", before)
      result.rows_affected.to_i32
    end

    private def read_lookup(row : DB::ResultSet) : Sessions::Lookup
      record = Sessions::Record.new(
        id: row.read(String),
        account_id: row.read(String),
        tenant_id: row.read(String?),
        token_digest: row.read(Bytes),
        auth_version: row.read(Int32),
        # Stored as the enum's numeric value in a SMALLINT. Never renumber the enum — a
        # renumbering silently reclassifies every session row already on disk.
        assurance: AssuranceLevel.from_value(row.read(Int16)),
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

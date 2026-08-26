module KemalIdentity::SQLite
  # `Accounts::ActionTokenRepository` over `auth_action_tokens`, SQLite dialect.
  #
  # `#consume` is a single conditional `UPDATE ... RETURNING`, exactly as in PostgreSQL, and for
  # the same reason: a read followed by a write lets two concurrent requests both spend one
  # reset link. SQLite serialises writers on the database rather than on the row, which makes
  # the race harder to lose, but the statement shape is what the contract requires and it is
  # what the concurrency example checks.
  class ActionTokenRepository < Accounts::ActionTokenRepository
    COLUMNS = "id, account_id, purpose, token_digest, created_at, expires_at, used_at"

    def initialize(@db : DB::Database)
    end

    def create(token : Accounts::ActionToken) : Nil
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
        INSERT INTO auth_action_tokens (#{COLUMNS})
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
        SQL
        token.id, token.account_id, token.purpose.to_column, token.token_digest,
        token.created_at, token.expires_at, token.used_at)

      # Names neither the digest nor the id: an error must never carry a token.
      raise InfrastructureError.new("action token already exists") if result.rows_affected.zero?
    end

    def consume(digest : Bytes, purpose : Accounts::ActionPurpose, at : Time) : Accounts::ActionToken?
      # Expired, already used, wrong purpose and unknown all update zero rows and so all return
      # nil, indistinguishably. Telling them apart would let somebody probe which links exist.
      @db.query_one?(<<-SQL, at, digest, purpose.to_column, at) { |row| read(row) }
        UPDATE auth_action_tokens
           SET used_at = ?
         WHERE token_digest = ?
           AND purpose = ?
           AND used_at IS NULL
           AND expires_at > ?
        RETURNING #{COLUMNS}
        SQL
    end

    def revoke_all_for_account(account_id : String, purpose : Accounts::ActionPurpose, at : Time) : Int32
      result = @db.exec(<<-SQL, at, account_id, purpose.to_column)
        UPDATE auth_action_tokens
           SET used_at = ?
         WHERE account_id = ? AND purpose = ? AND used_at IS NULL
        SQL

      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      result = @db.exec("DELETE FROM auth_action_tokens WHERE expires_at <= ?", before)
      result.rows_affected.to_i32
    end

    private def read(row : DB::ResultSet) : Accounts::ActionToken
      Accounts::ActionToken.new(
        id: row.read(String),
        account_id: row.read(String),
        purpose: Accounts::ActionPurpose.from_column(row.read(String)),
        token_digest: row.read(Bytes),
        created_at: row.read(Time),
        expires_at: row.read(Time),
        used_at: row.read(Time?),
      )
    end
  end
end

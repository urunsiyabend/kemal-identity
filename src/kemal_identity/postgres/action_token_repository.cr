module KemalIdentity::Postgres
  # `Accounts::ActionTokenRepository` over `auth_action_tokens`.
  #
  # The interesting method is `#consume`, and what makes it correct is that it is a single
  # conditional `UPDATE ... RETURNING` rather than a `SELECT` followed by an `UPDATE`. Two
  # concurrent requests presenting the same reset link both reach the statement; PostgreSQL
  # serialises them on the row, the second finds `used_at IS NULL` no longer true, and updates
  # nothing. Exactly one gets a row back.
  #
  # Written as a read-then-write it would be a race with an account takeover at the end of it.
  class ActionTokenRepository < Accounts::ActionTokenRepository
    UNIQUE_VIOLATION = "23505"

    COLUMNS = "id, account_id, purpose, token_digest, created_at, expires_at, used_at"

    def initialize(@db : DB::Database)
    end

    def create(token : Accounts::ActionToken) : Nil
      @db.exec(<<-SQL,
        INSERT INTO auth_action_tokens (#{COLUMNS})
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        SQL
        token.id, token.account_id, token.purpose.to_column, token.token_digest,
        token.created_at, token.expires_at, token.used_at)
    rescue error : PQ::PQError
      raise error unless error.field_message(:code) == UNIQUE_VIOLATION

      # Names neither the digest nor the account: an error must never carry a token.
      raise InfrastructureError.new("action token already exists")
    end

    def consume(digest : Bytes, purpose : Accounts::ActionPurpose, at : Time) : Accounts::ActionToken?
      # `expires_at > $1` rather than `>=`, so the expiry instant itself is already too late —
      # matching `ActionToken#expired?` and `#delete_expired`.
      #
      # Expired, already used, wrong purpose and unknown all update zero rows and so all return
      # nil. Telling them apart would let somebody probe which links had been issued.
      @db.query_one?(<<-SQL, at, digest, purpose.to_column) { |row| read(row) }
        UPDATE auth_action_tokens
           SET used_at = $1
         WHERE token_digest = $2
           AND purpose = $3
           AND used_at IS NULL
           AND expires_at > $1
        RETURNING #{COLUMNS}
        SQL
    end

    def revoke_all_for_account(account_id : String, purpose : Accounts::ActionPurpose, at : Time) : Int32
      result = @db.exec(<<-SQL, at, account_id, purpose.to_column)
        UPDATE auth_action_tokens
           SET used_at = $1
         WHERE account_id = $2 AND purpose = $3 AND used_at IS NULL
        SQL

      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      result = @db.exec("DELETE FROM auth_action_tokens WHERE expires_at <= $1", before)
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

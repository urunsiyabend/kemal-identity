module KemalIdentity::Postgres
  # `Sessions::RememberRepository` over `auth_remember_tokens`.
  #
  # `#consume` is two statements, and their order is the whole correctness argument.
  #
  # The conditional `UPDATE` goes **first**. It is what makes spending atomic: any number of
  # concurrent callers reach it, PostgreSQL serialises them on the row, and exactly one finds
  # `used_at IS NULL` still true. Only when it changes nothing does the second statement look
  # up why — and by then the answer is stable, because a token that has been spent stays spent.
  #
  # Doing the lookup first would be the read-then-write race that lets two callers both spend
  # one token, which here would mean a stolen cookie working silently instead of being
  # detected.
  class RememberRepository < Sessions::RememberRepository
    UNIQUE_VIOLATION = "23505"

    COLUMNS = "id, account_id, family_id, token_digest, created_at, expires_at, used_at, revoked_at"

    def initialize(@db : DB::Database)
    end

    def create(token : Sessions::RememberToken) : Nil
      @db.exec(<<-SQL,
        INSERT INTO auth_remember_tokens (#{COLUMNS})
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        SQL
        token.id, token.account_id, token.family_id, token.token_digest,
        token.created_at, token.expires_at, token.used_at, token.revoked_at)
    rescue error : PQ::PQError
      raise error unless error.field_message(:code) == UNIQUE_VIOLATION

      raise InfrastructureError.new("remember token already exists")
    end

    def consume(digest : Bytes, at : Time) : Sessions::RememberLookup
      spent = @db.query_one?(<<-SQL, at, digest) { |row| read(row) }
        UPDATE auth_remember_tokens
           SET used_at = $1
         WHERE token_digest = $2
           AND used_at IS NULL
           AND revoked_at IS NULL
           AND expires_at > $1
        RETURNING #{COLUMNS}
        SQL

      return Sessions::RememberAccepted.new(spent) if spent

      # Nothing was spent. Now — and only now — find out whether that was a replay or simply a
      # digest nobody issued.
      existing = @db.query_one?(
        "SELECT #{COLUMNS} FROM auth_remember_tokens WHERE token_digest = $1", digest
      ) { |row| read(row) }

      return Sessions::RememberUnknown.new if existing.nil?

      # Revoked and expired are not evidence of theft. A revoked family already raised its
      # alarm; an expired token is somebody coming back after a month.
      return Sessions::RememberUnknown.new if existing.revoked?
      return Sessions::RememberUnknown.new if existing.expired?(at)

      Sessions::RememberReplayed.new(
        family_id: existing.family_id, account_id: existing.account_id
      )
    end

    def revoke_family(family_id : String, at : Time) : Int32
      # No `used_at IS NULL` condition: the spent token whose replay triggered this must be
      # killed too, or a dead family keeps rows that merely look used.
      result = @db.exec(
        "UPDATE auth_remember_tokens SET revoked_at = $1 WHERE family_id = $2 AND revoked_at IS NULL",
        at, family_id
      )

      result.rows_affected.to_i32
    end

    def revoke_family_by_digest(digest : Bytes, at : Time) : Int32
      # One statement, and pointedly not an UPDATE on the token itself: the row keeps
      # `used_at IS NULL`, so the same cookie presented later reads as revoked rather than as a
      # replay. Logging out must not look like theft.
      result = @db.exec(<<-SQL, at, digest)
        UPDATE auth_remember_tokens
           SET revoked_at = $1
         WHERE revoked_at IS NULL
           AND family_id = (
             SELECT family_id FROM auth_remember_tokens WHERE token_digest = $2
           )
        SQL

      result.rows_affected.to_i32
    end

    def revoke_all_for_account(account_id : String, at : Time) : Int32
      result = @db.exec(
        "UPDATE auth_remember_tokens SET revoked_at = $1 WHERE account_id = $2 AND revoked_at IS NULL",
        at, account_id
      )

      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      result = @db.exec("DELETE FROM auth_remember_tokens WHERE expires_at <= $1", before)
      result.rows_affected.to_i32
    end

    private def read(row : DB::ResultSet) : Sessions::RememberToken
      Sessions::RememberToken.new(
        id: row.read(String),
        account_id: row.read(String),
        family_id: row.read(String),
        token_digest: row.read(Bytes),
        created_at: row.read(Time),
        expires_at: row.read(Time),
        used_at: row.read(Time?),
        revoked_at: row.read(Time?),
      )
    end
  end
end

module KemalIdentity::SQLite
  # `Sessions::RememberRepository` over `auth_remember_tokens`, SQLite dialect.
  #
  # `#consume` is two statements and their order is the whole correctness argument, exactly as
  # in the PostgreSQL adapter: the conditional `UPDATE` goes first so that spending is atomic,
  # and only when it changes nothing does the second statement look up whether that was a
  # replay or a digest nobody issued. Looking first would be the read-then-write race that lets
  # a stolen cookie work silently instead of being detected.
  class RememberRepository < Sessions::RememberRepository
    COLUMNS = "id, account_id, family_id, token_digest, created_at, expires_at, used_at, revoked_at"

    def initialize(@db : DB::Database)
    end

    def create(token : Sessions::RememberToken) : Nil
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
        INSERT INTO auth_remember_tokens (#{COLUMNS})
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
        SQL
        token.id, token.account_id, token.family_id, token.token_digest,
        token.created_at, token.expires_at, token.used_at, token.revoked_at)

      # Names neither the digest nor the id: an error must never carry a token.
      raise InfrastructureError.new("remember token already exists") if result.rows_affected.zero?
    end

    def consume(digest : Bytes, at : Time) : Sessions::RememberLookup
      spent = @db.query_one?(<<-SQL, at, digest, at) { |row| read(row) }
        UPDATE auth_remember_tokens
           SET used_at = ?
         WHERE token_digest = ?
           AND used_at IS NULL
           AND revoked_at IS NULL
           AND expires_at > ?
        RETURNING #{COLUMNS}
        SQL

      return Sessions::RememberAccepted.new(spent) if spent

      existing = @db.query_one?(
        "SELECT #{COLUMNS} FROM auth_remember_tokens WHERE token_digest = ?", digest
      ) { |row| read(row) }

      return Sessions::RememberUnknown.new if existing.nil?

      # Revoked and expired are not evidence of theft: a revoked family already raised its
      # alarm, and an expired token is somebody coming back after a month.
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
        "UPDATE auth_remember_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
        at, family_id
      )

      result.rows_affected.to_i32
    end

    def revoke_family_by_digest(digest : Bytes, at : Time) : Int32
      # Pointedly not an update on the token itself: the row keeps `used_at IS NULL`, so the
      # same cookie presented later reads as revoked rather than as a replay. Logging out must
      # not look like theft.
      result = @db.exec(<<-SQL, at, digest)
        UPDATE auth_remember_tokens
           SET revoked_at = ?
         WHERE revoked_at IS NULL
           AND family_id = (
             SELECT family_id FROM auth_remember_tokens WHERE token_digest = ?
           )
        SQL

      result.rows_affected.to_i32
    end

    def revoke_all_for_account(account_id : String, at : Time) : Int32
      result = @db.exec(
        "UPDATE auth_remember_tokens SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL",
        at, account_id
      )

      result.rows_affected.to_i32
    end

    def delete_expired(before : Time) : Int32
      # Never earlier than expiry: a spent token's row is the evidence of a replay, and
      # deleting it early makes a stolen token coming back look unknown rather than stolen.
      result = @db.exec("DELETE FROM auth_remember_tokens WHERE expires_at <= ?", before)
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

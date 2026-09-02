module KemalIdentity::SQLite
  # `ApiTokens::Repository` over `auth_api_tokens`.
  #
  # The hot path is `#find_by_digest` — one indexed lookup with a join, returning token state and
  # account status together, for the same reason sessions do it: an API's request rate is exactly
  # where a second round trip per request is felt.
  class ApiTokenRepository < ApiTokens::Repository
    TOKEN_COLUMNS = <<-SQL
      t.id, t.account_id, t.name, t.token_digest, t.created_at, t.expires_at,
      t.last_used_at, t.revoked_at, t.scopes
      SQL

    COLUMNS = "id, account_id, name, token_digest, created_at, expires_at, last_used_at, revoked_at, scopes"

    def initialize(@db : DB::Database, @accounts_table : String = "auth_accounts")
    end

    def create(token : ApiTokens::Token) : Nil
      # `ON CONFLICT DO NOTHING` plus a row count rather than catching the driver's exception:
      # crystal-sqlite3 surfaces a constraint failure when the statement is finalised, so a
      # `rescue` around the insert never sees it. See blueprints/0014-sqlite-adapter.md.
      result = @db.exec(<<-SQL,
        INSERT INTO auth_api_tokens (#{COLUMNS})
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
        SQL
        token.id, token.account_id, token.name, token.token_digest,
        token.created_at, token.expires_at, token.last_used_at, token.revoked_at,
        ApiTokens::Token.encode_scopes(token.scopes))

      raise InfrastructureError.new("api token already exists") if result.rows_affected.zero?
    end

    # An inner join, so a token pointing at an account that no longer exists resolves to
    # nothing: the failure mode is closed rather than open.
    def find_by_digest(digest : Bytes) : ApiTokens::Lookup?
      @db.query_one?(<<-SQL, digest) { |row| read_lookup(row) }
        SELECT #{TOKEN_COLUMNS},
               a.auth_version AS account_auth_version,
               a.disabled_at  AS account_disabled_at
          FROM auth_api_tokens t
          JOIN #{@accounts_table} a ON a.id = t.account_id
         WHERE t.token_digest = ?
        SQL
    end

    def touch(id : String, last_used_at : Time) : Bool
      result = @db.exec("UPDATE auth_api_tokens SET last_used_at = ? WHERE id = ?", last_used_at, id)
      result.rows_affected == 1
    end

    def revoke(id : String, at : Time) : Bool
      # `AND revoked_at IS NULL` reports whether anything changed, and stops a second revocation
      # overwriting the first timestamp -- which is the moment an audit trail cares about.
      result = @db.exec(
        "UPDATE auth_api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", at, id
      )
      result.rows_affected == 1
    end

    def expire(id : String, at : Time) : Bool
      # The "never lengthens" rule is in the statement rather than in a read followed by a
      # write, so two callers cannot interleave into a later deadline than either asked for.
      result = @db.exec(<<-SQL, at, id, at)
        UPDATE auth_api_tokens SET expires_at = ?
         WHERE id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
        SQL

      result.rows_affected == 1
    end

    def revoke_all_for_account(account_id : String, at : Time) : Int32
      result = @db.exec(
        "UPDATE auth_api_tokens SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL",
        at, account_id
      )
      result.rows_affected.to_i32
    end

    def list_for_account(account_id : String) : Array(ApiTokens::Token)
      @db.query_all(
        "SELECT #{COLUMNS} FROM auth_api_tokens WHERE account_id = ? ORDER BY created_at DESC, id DESC",
        account_id
      ) { |row| read(row) }
    end

    def delete_expired(before : Time) : Int32
      # `expires_at IS NOT NULL` matters: a token issued without an expiry never expires, and a
      # sweep must never reach a deploy key.
      result = @db.exec(
        "DELETE FROM auth_api_tokens WHERE expires_at IS NOT NULL AND expires_at <= ?", before
      )
      result.rows_affected.to_i32
    end

    private def read_lookup(row : DB::ResultSet) : ApiTokens::Lookup
      ApiTokens::Lookup.new(
        token: read(row),
        account_auth_version: row.read(Int32),
        account_disabled_at: row.read(Time?),
      )
    end

    private def read(row : DB::ResultSet) : ApiTokens::Token
      ApiTokens::Token.new(
        id: row.read(String),
        account_id: row.read(String),
        name: row.read(String),
        token_digest: row.read(Bytes),
        created_at: row.read(Time),
        expires_at: row.read(Time?),
        last_used_at: row.read(Time?),
        revoked_at: row.read(Time?),
        # NULL is unrestricted and '' is attenuated-to-nothing. Coercing one into the other
        # here would be a lockout in one direction and a privilege escalation in the other, so
        # both adapters go through the same codec.
        scopes: ApiTokens::Token.decode_scopes(row.read(String?)),
      )
    end
  end
end

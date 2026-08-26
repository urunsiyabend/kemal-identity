module KemalIdentity::Testing
  # In-memory `ApiTokens::Repository`.
  #
  # Passes the same contract spec as the PostgreSQL and SQLite adapters. Wired to an account
  # repository because `find_by_digest` returns token state and account status together.
  class MemoryApiTokenRepository < KemalIdentity::ApiTokens::Repository
    def initialize(@accounts : MemoryAccountRepository)
      @mutex = Mutex.new
      @tokens = {} of String => KemalIdentity::ApiTokens::Token
      @by_digest = {} of String => String
    end

    def create(token : KemalIdentity::ApiTokens::Token) : Nil
      @mutex.synchronize do
        key = token.token_digest.hexstring

        if @by_digest.has_key?(key)
          raise KemalIdentity::InfrastructureError.new("api token already exists")
        end

        if @tokens.has_key?(token.id)
          raise KemalIdentity::InfrastructureError.new("api token id already exists")
        end

        @tokens[token.id] = token
        @by_digest[key] = token.id
      end
    end

    def find_by_digest(digest : Bytes) : KemalIdentity::ApiTokens::Lookup?
      record = @mutex.synchronize do
        id = @by_digest[digest.hexstring]?
        id.nil? ? nil : @tokens[id]?
      end

      return if record.nil?

      # An inner join: a token whose account has gone resolves to nothing.
      account = @accounts.find_by_id(record.account_id)
      return if account.nil?

      KemalIdentity::ApiTokens::Lookup.new(
        token: record,
        account_auth_version: account.auth_version,
        account_disabled_at: account.disabled_at,
      )
    end

    def touch(id : String, last_used_at : Time) : Bool
      @mutex.synchronize do
        existing = @tokens[id]?
        return false if existing.nil?

        @tokens[id] = replace(existing, last_used_at: last_used_at)
        true
      end
    end

    def revoke(id : String, at : Time) : Bool
      @mutex.synchronize do
        existing = @tokens[id]?
        return false if existing.nil?
        return false if existing.revoked?

        @tokens[id] = replace(existing, revoked_at: at)
        true
      end
    end

    def revoke_all_for_account(account_id : String, at : Time) : Int32
      @mutex.synchronize do
        revoked = 0

        @tokens.each do |id, record|
          next if record.account_id != account_id
          next if record.revoked?

          @tokens[id] = replace(record, revoked_at: at)
          revoked += 1
        end

        revoked
      end
    end

    def list_for_account(account_id : String) : Array(KemalIdentity::ApiTokens::Token)
      @mutex.synchronize do
        @tokens.each_value
          .select { |record| record.account_id == account_id }
          .to_a
          .sort_by! { |record| {record.created_at, record.id} }
          .reverse!
      end
    end

    def delete_expired(before : Time) : Int32
      @mutex.synchronize do
        expired = @tokens.each_value.select(&.expired?(before)).to_a

        expired.each do |record|
          @tokens.delete(record.id)
          @by_digest.delete(record.token_digest.hexstring)
        end

        expired.size
      end
    end

    def size : Int32
      @mutex.synchronize { @tokens.size }
    end

    private def replace(
      record : KemalIdentity::ApiTokens::Token,
      last_used_at : Time? = nil,
      revoked_at : Time? = nil,
    ) : KemalIdentity::ApiTokens::Token
      KemalIdentity::ApiTokens::Token.new(
        id: record.id,
        account_id: record.account_id,
        name: record.name,
        token_digest: record.token_digest,
        created_at: record.created_at,
        expires_at: record.expires_at,
        last_used_at: last_used_at || record.last_used_at,
        revoked_at: revoked_at || record.revoked_at,
      )
    end
  end
end

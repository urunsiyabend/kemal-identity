module KemalIdentity::Testing
  # In-memory `Accounts::ActionTokenRepository`.
  #
  # Passes the same contract spec as the PostgreSQL adapter. The atomicity the contract demands
  # comes from a mutex here and from a conditional update there; the contract does not care
  # which, only that exactly one concurrent caller wins.
  class MemoryActionTokenRepository < KemalIdentity::Accounts::ActionTokenRepository
    def initialize(tokens : Array(KemalIdentity::Accounts::ActionToken) = [] of KemalIdentity::Accounts::ActionToken)
      @mutex = Mutex.new
      @tokens = {} of String => KemalIdentity::Accounts::ActionToken
      # Keyed by hex rather than by `Bytes`, mirroring the unique index on token_digest.
      @by_digest = {} of String => String
      tokens.each { |token| create(token) }
    end

    def create(token : KemalIdentity::Accounts::ActionToken) : Nil
      @mutex.synchronize do
        key = token.token_digest.hexstring

        if @by_digest.has_key?(key)
          raise KemalIdentity::InfrastructureError.new("action token already exists")
        end

        if @tokens.has_key?(token.id)
          raise KemalIdentity::InfrastructureError.new("action token id already exists")
        end

        @tokens[token.id] = token
        @by_digest[key] = token.id
      end
    end

    # The whole lookup, the expiry check, the purpose check and the write happen inside one
    # critical section. Splitting them would let two callers both observe an unused token.
    def consume(digest : Bytes, purpose : KemalIdentity::Accounts::ActionPurpose, at : Time) : KemalIdentity::Accounts::ActionToken?
      @mutex.synchronize do
        id = @by_digest[digest.hexstring]?
        return if id.nil?

        token = @tokens[id]?
        return if token.nil?

        # Expired, already used and wrong purpose all return nil, indistinguishably.
        return if token.used?
        return if token.expired?(at)
        return if token.purpose != purpose

        spent = replace(token, used_at: at)
        @tokens[id] = spent
        spent
      end
    end

    def revoke_all_for_account(account_id : String, purpose : KemalIdentity::Accounts::ActionPurpose, at : Time) : Int32
      @mutex.synchronize do
        spent = 0

        @tokens.each do |id, token|
          next if token.account_id != account_id
          next if token.purpose != purpose
          next if token.used?

          @tokens[id] = replace(token, used_at: at)
          spent += 1
        end

        spent
      end
    end

    def delete_expired(before : Time) : Int32
      @mutex.synchronize do
        expired = @tokens.each_value.select(&.expired?(before)).to_a

        expired.each do |token|
          @tokens.delete(token.id)
          @by_digest.delete(token.token_digest.hexstring)
        end

        expired.size
      end
    end

    def size : Int32
      @mutex.synchronize { @tokens.size }
    end

    private def replace(token : KemalIdentity::Accounts::ActionToken, used_at : Time) : KemalIdentity::Accounts::ActionToken
      KemalIdentity::Accounts::ActionToken.new(
        id: token.id,
        account_id: token.account_id,
        purpose: token.purpose,
        token_digest: token.token_digest,
        created_at: token.created_at,
        expires_at: token.expires_at,
        used_at: used_at,
      )
    end
  end
end

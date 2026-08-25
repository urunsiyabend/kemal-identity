module KemalIdentity::Testing
  # In-memory `Sessions::RememberRepository`.
  #
  # Passes the same contract spec as the PostgreSQL adapter. Atomicity here is a mutex; there
  # it is a conditional update. The contract does not care which, only that exactly one
  # concurrent caller is accepted and the rest see a replay.
  class MemoryRememberRepository < KemalIdentity::Sessions::RememberRepository
    def initialize(tokens : Array(KemalIdentity::Sessions::RememberToken) = [] of KemalIdentity::Sessions::RememberToken)
      @mutex = Mutex.new
      @tokens = {} of String => KemalIdentity::Sessions::RememberToken
      @by_digest = {} of String => String
      tokens.each { |token| create(token) }
    end

    def create(token : KemalIdentity::Sessions::RememberToken) : Nil
      @mutex.synchronize do
        key = token.token_digest.hexstring

        if @by_digest.has_key?(key)
          raise KemalIdentity::InfrastructureError.new("remember token already exists")
        end

        if @tokens.has_key?(token.id)
          raise KemalIdentity::InfrastructureError.new("remember token id already exists")
        end

        @tokens[token.id] = token
        @by_digest[key] = token.id
      end
    end

    def consume(digest : Bytes, at : Time) : KemalIdentity::Sessions::RememberLookup
      @mutex.synchronize do
        id = @by_digest[digest.hexstring]?
        return KemalIdentity::Sessions::RememberUnknown.new if id.nil?

        token = @tokens[id]?
        return KemalIdentity::Sessions::RememberUnknown.new if token.nil?

        # Revoked and expired come before the replay check. Neither is evidence of theft: a
        # revoked family has already raised its alarm, and an expired token is somebody
        # returning after a month.
        return KemalIdentity::Sessions::RememberUnknown.new if token.revoked?
        return KemalIdentity::Sessions::RememberUnknown.new if token.expired?(at)

        if token.used?
          return KemalIdentity::Sessions::RememberReplayed.new(
            family_id: token.family_id, account_id: token.account_id
          )
        end

        spent = replace(token, used_at: at)
        @tokens[id] = spent
        KemalIdentity::Sessions::RememberAccepted.new(spent)
      end
    end

    def revoke_family(family_id : String, at : Time) : Int32
      @mutex.synchronize do
        revoked = 0

        @tokens.each do |id, token|
          next if token.family_id != family_id
          next if token.revoked?

          # Spent tokens are revoked too, including the one whose replay triggered this: a
          # dead family should hold no rows that merely look used.
          @tokens[id] = replace(token, revoked_at: at)
          revoked += 1
        end

        revoked
      end
    end

    def revoke_family_by_digest(digest : Bytes, at : Time) : Int32
      family = @mutex.synchronize do
        id = @by_digest[digest.hexstring]?
        id.nil? ? nil : @tokens[id]?.try(&.family_id)
      end

      family.nil? ? 0 : revoke_family(family, at)
    end

    def revoke_all_for_account(account_id : String, at : Time) : Int32
      @mutex.synchronize do
        revoked = 0

        @tokens.each do |id, token|
          next if token.account_id != account_id
          next if token.revoked?

          @tokens[id] = replace(token, revoked_at: at)
          revoked += 1
        end

        revoked
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

    private def replace(
      token : KemalIdentity::Sessions::RememberToken,
      used_at : Time? = nil,
      revoked_at : Time? = nil,
    ) : KemalIdentity::Sessions::RememberToken
      KemalIdentity::Sessions::RememberToken.new(
        id: token.id,
        account_id: token.account_id,
        family_id: token.family_id,
        token_digest: token.token_digest,
        created_at: token.created_at,
        expires_at: token.expires_at,
        used_at: used_at || token.used_at,
        revoked_at: revoked_at || token.revoked_at,
      )
    end
  end
end

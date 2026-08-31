module KemalIdentity::Testing
  # In-memory `JWT::RevocationStore`, passing the same contract a database-backed one must.
  class MemoryRevocationStore < KemalIdentity::JWT::RevocationStore
    def initialize
      @mutex = Mutex.new
      @entries = {} of String => Time
    end

    def revoked?(jti : String) : Bool
      @mutex.synchronize { @entries.has_key?(jti) }
    end

    def revoke(jti : String, expires_at : Time) : Nil
      @mutex.synchronize do
        # The later expiry wins: an entry must outlive every token that carries this id.
        existing = @entries[jti]?
        @entries[jti] = existing.nil? || expires_at > existing ? expires_at : existing
      end
    end

    def delete_expired(before : Time) : Int32
      @mutex.synchronize do
        expired = @entries.select { |_, expires_at| expires_at <= before }
        expired.each_key { |jti| @entries.delete(jti) }
        expired.size
      end
    end

    def size : Int32
      @mutex.synchronize { @entries.size }
    end
  end
end

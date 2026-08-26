module KemalIdentity::ApiTokens
  # A personal access token: a long-lived credential a person creates deliberately so that a
  # script, a CI job or a CLI can act as them.
  #
  # ### Opaque, not a JWT
  #
  # `docs/06-roadmap.md` puts opaque tokens first on purpose. They reuse the digest-and-revoke
  # machinery sessions already have, and they carry none of JWT's revocation problem: revoking
  # one is an `UPDATE`, and it takes effect on the very next request because validity is read
  # from storage rather than asserted by a signature.
  #
  # ### No scopes
  #
  # A token names an account and nothing else. Scopes are authorization — what this holder may
  # do — and `docs/00-scope.md` puts authorization outside this shard permanently: it answers
  # "who", not "may they". An application that needs scoped tokens stores the scopes against
  # `id` in its own table and consults them itself.
  struct Token
    getter id : String
    getter account_id : String

    # What a person calls this token in a management screen: "laptop", "deploy job". Purely for
    # humans — nothing here reads it.
    getter name : String

    # SHA-256 of the raw token, as raw bytes.
    getter token_digest : Bytes

    getter created_at : Time

    # `nil` means it never expires. That is a real choice for a deploy key and a bad one for a
    # laptop, so it is the application's to make rather than a default this shard imposes.
    getter expires_at : Time?

    # Moved forward as the token is used, but **throttled** the same way sessions throttle
    # `last_seen_at` — otherwise every authenticated API request becomes a write. It answers
    # "is this token still in use?" on a management screen, which does not need to be precise
    # to the second.
    getter last_used_at : Time?

    getter revoked_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @name : String,
      @token_digest : Bytes,
      @created_at : Time,
      @expires_at : Time? = nil,
      @last_used_at : Time? = nil,
      @revoked_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("token_digest must not be empty") if @token_digest.empty?

      expires_at = @expires_at
      if expires_at && expires_at <= @created_at
        raise ArgumentError.new("expires_at must be after created_at")
      end
    end

    def revoked? : Bool
      !@revoked_at.nil?
    end

    # A token with no expiry is never expired.
    def expired?(now : Time) : Bool
      expires_at = @expires_at
      return false if expires_at.nil?

      # `>=`, matching sessions and action tokens: expired *at* the deadline, so every part of
      # the shard agrees about the boundary.
      now >= expires_at
    end

    # Never prints the digest.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::ApiTokens::Token id=" << @id.inspect
      io << " account_id=" << @account_id.inspect
      io << " name=" << @name.inspect
      io << " token_digest=[REDACTED]"
      io << " expires_at=" << @expires_at.inspect
      io << " revoked_at=" << @revoked_at.inspect
      io << '>'
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end

  # A token as it exists exactly once: the raw secret, and the row.
  #
  # The raw value is a `Secret`, so an accidental interpolation redacts. It is the only moment
  # the token is knowable — nothing stores it, and a management screen can never show it again.
  struct Issued
    getter token : Secret
    getter record : Token

    def initialize(@token : Secret, @record : Token)
    end
  end
end

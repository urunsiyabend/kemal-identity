module KemalIdentity::Sessions
  # One link in a remember-me chain.
  #
  # Every token descended from a single login shares a `family_id`. Presenting a token spends
  # it and mints its successor in the same family, so at any moment exactly one token per
  # family is live and the rest are spent history.
  #
  # That history is the point. It is what turns theft from something nobody notices into
  # something the next request detects.
  struct RememberToken
    getter id : String
    getter account_id : String

    # Shared by every token rotated from one original login. Revoking a family ends that
    # browser's remembered state and leaves every other device alone.
    getter family_id : String

    getter token_digest : Bytes
    getter created_at : Time
    getter expires_at : Time

    # Spent normally: the holder presented it and received a successor.
    getter used_at : Time?

    # Killed, rather than spent. Distinct from `used_at` because the difference is exactly what
    # an audit trail needs to tell "this rotated" from "we believe this was stolen".
    getter revoked_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @family_id : String,
      @token_digest : Bytes,
      @created_at : Time,
      @expires_at : Time,
      @used_at : Time? = nil,
      @revoked_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("family_id must not be empty") if @family_id.empty?
      raise ArgumentError.new("token_digest must not be empty") if @token_digest.empty?

      unless @expires_at > @created_at
        raise ArgumentError.new("expires_at must be after created_at")
      end
    end

    def used? : Bool
      !@used_at.nil?
    end

    def revoked? : Bool
      !@revoked_at.nil?
    end

    def expired?(now : Time) : Bool
      now >= @expires_at
    end

    # Never prints the digest.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Sessions::RememberToken id=" << @id.inspect
      io << " account_id=" << @account_id.inspect
      io << " family_id=" << @family_id.inspect
      io << " token_digest=[REDACTED]"
      io << " used_at=" << @used_at.inspect
      io << " revoked_at=" << @revoked_at.inspect
      io << '>'
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end

  # The token was live, and is now spent. Its successor is the caller's to mint.
  struct RememberAccepted
    getter token : RememberToken

    def initialize(@token : RememberToken)
    end
  end

  # An already-spent token was presented again.
  #
  # **This is the theft signal.** A remember-me token is single-use, so the legitimate holder
  # never presents one twice: they hand over their token, get a successor, and forget the old
  # one. A second presentation means two parties hold the same token — which is what a stolen
  # cookie looks like from the server's side.
  #
  # Which of the two is the thief is unknowable, and that is fine. Revoking the whole family
  # ends both, and the real user logs in again with a password. The thief cannot.
  struct RememberReplayed
    getter family_id : String
    getter account_id : String

    def initialize(@family_id : String, @account_id : String)
    end
  end

  # Nothing matched: never issued, expired, or revoked with the rest of its family.
  #
  # Distinct from `RememberReplayed`, because only one of them means somebody should be told
  # their account may have been accessed.
  struct RememberUnknown
  end

  alias RememberLookup = RememberAccepted | RememberReplayed | RememberUnknown
end

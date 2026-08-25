module KemalIdentity::Accounts
  # What an action token authorises its bearer to do, once.
  #
  # Stored as text rather than as an enum value, unlike `AssuranceLevel` — an action token is
  # short-lived, so a row outliving a change to this list is not the concern it is for
  # sessions, and a human reading the table benefits from seeing `reset` rather than `0`.
  enum ActionPurpose
    # Set a new password without knowing the old one.
    Reset

    # Prove control of an email address.
    Confirm

    # Accept an invitation to an account somebody else created. v0.2 ships the value; the flow
    # is later.
    Invite

    def to_column : String
      to_s.downcase
    end

    def self.from_column(value : String) : self
      parse(value)
    end
  end

  # A single-use, expiring grant: password reset, email confirmation, invitation.
  #
  # The bearer holds a random secret; this is the server-side half, and it stores only the
  # digest. Every rule in `KemalIdentity::OpaqueToken` applies, and two more that only a
  # repository can enforce: it expires, and it is consumed **atomically**, so that two
  # concurrent requests cannot both succeed with the same link.
  #
  # ### Why a reset link is not a session
  #
  # A reset token authorises exactly one operation and dies. It never becomes a credential, is
  # never presented twice, and grants nothing beyond its purpose — which is why `purpose` is
  # part of the lookup and not just a label. A token issued to confirm an address must not be
  # redeemable to change a password, or an attacker who can trigger a confirmation email gets
  # an account takeover.
  struct ActionToken
    getter id : String
    getter account_id : String
    getter purpose : ActionPurpose

    # SHA-256 of the raw token, as raw bytes.
    getter token_digest : Bytes

    getter created_at : Time
    getter expires_at : Time

    # When this token was spent. `nil` while it is still redeemable.
    getter used_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @purpose : ActionPurpose,
      @token_digest : Bytes,
      @created_at : Time,
      @expires_at : Time,
      @used_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("token_digest must not be empty") if @token_digest.empty?

      unless @expires_at > @created_at
        raise ArgumentError.new("expires_at must be after created_at")
      end
    end

    def used? : Bool
      !@used_at.nil?
    end

    def expired?(now : Time) : Bool
      # `>=`, matching sessions: a token is expired *at* its deadline, so this and
      # `delete_expired` agree about the boundary.
      now >= @expires_at
    end

    # Never prints the digest.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Accounts::ActionToken id=" << @id.inspect
      io << " account_id=" << @account_id.inspect
      io << " purpose=" << @purpose
      io << " token_digest=[REDACTED]"
      io << " used_at=" << @used_at.inspect
      io << '>'
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end
end

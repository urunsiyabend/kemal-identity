module KemalIdentity::Sessions
  # One row of `auth_sessions`: everything the shard knows about a live session.
  #
  # The browser holds a high-entropy random secret and nothing else. This is the server-side
  # half, and it stores only the **digest** of that secret — so a leaked database backup
  # yields no usable session cookies (`docs/02-security-model.md`).
  struct Record
    getter id : String
    getter account_id : String

    # The account's tenant **as it was when this session was minted**, and the only
    # authorization input this shard copies into a session.
    #
    # `Service#resolve` rebuilds the principal from this row, not from the account, so a change
    # to the account's tenant is not felt by a session that already exists — for the rest of
    # that session's life, which is a longer window than anything else in the authorization
    # path has. Membership and roles are read on every decision; a grants `Cache` bounds itself
    # to a minute; this is bounded only by the session's absolute deadline.
    #
    # It is a copy on purpose: `Lookup` deliberately does not carry the account's tenant, and
    # widening it would put another column of a join on every authenticated request for a value
    # that changes once in an account's lifetime, if ever. The consequence is that **an
    # application that changes an account's tenant must revoke that account's sessions or bump
    # its `auth_version`** — `docs/02-security-model.md` lists it with the other events that
    # require this, and `Accounts::Repository#bump_auth_version` is the one-row way to do it.
    getter tenant_id : String?

    # SHA-256 of the raw token, as raw bytes.
    #
    # `Bytes` rather than a hex string: `BYTEA` is half the storage of a hex `CHAR(64)` and
    # there is no encoding for two adapters to disagree about (`docs/03-data-model.md`).
    getter token_digest : Bytes

    # The account's `auth_version` when this session was minted. A mismatch against the
    # account's current value fails the session.
    getter auth_version : Int32

    getter assurance : AssuranceLevel
    getter created_at : Time

    # When the credential behind `assurance` was verified. Feeds `Principal#fresh?`.
    getter authenticated_at : Time

    getter mfa_verified_at : Time?

    # Moved forward as the user stays active, but **throttled**: only written when
    # `now - last_seen_at` exceeds the configured `touch_interval` (60 s by default).
    # Without that throttle, every authenticated read becomes a write, which is the single
    # biggest performance trap in this design. The cost is that idle expiry is accurate only
    # to within one `touch_interval`, which is part of the contract rather than an
    # implementation accident (`docs/02-security-model.md`).
    getter last_seen_at : Time

    getter idle_expires_at : Time
    getter absolute_expires_at : Time
    getter revoked_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @token_digest : Bytes,
      @auth_version : Int32,
      @assurance : AssuranceLevel,
      @created_at : Time,
      @authenticated_at : Time,
      @last_seen_at : Time,
      @idle_expires_at : Time,
      @absolute_expires_at : Time,
      @tenant_id : String? = nil,
      @mfa_verified_at : Time? = nil,
      @revoked_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("token_digest must not be empty") if @token_digest.empty?
    end

    def revoked? : Bool
      !@revoked_at.nil?
    end

    # Never prints the digest. It is not a password, but it is the value that resolves a
    # session, and `docs/02-security-model.md` forbids logging it.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Sessions::Record id=" << @id.inspect
      io << " account_id=" << @account_id.inspect
      io << " assurance=" << @assurance
      io << " token_digest=[REDACTED]"
      io << " revoked_at=" << @revoked_at.inspect
      io << '>'
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end
end

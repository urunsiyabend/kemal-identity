module KemalIdentity::Accounts
  # The security-relevant facts about an account, and nothing else.
  #
  # No profile, no roles, no email beyond the login used to find it. This is what the
  # authentication path needs; the application loads its own user object when it needs one.
  #
  # ### One identifier
  #
  # `#id` is *the* account identifier. It is what `Principal#subject` carries and what
  # `auth_sessions.account_id` references — there is no second "external subject" to keep in
  # sync with it. An application wanting the shard's identifier to differ from its own user
  # id does that mapping inside its `Repository`, and the shard never learns of it
  # (`docs/01-architecture.md`). See
  # `blueprints/0005-one-account-identifier.md`.
  struct Account
    # Canonical identifier, opaque to the shard. A `String` for the reason given on
    # `Principal#subject`: a type parameter here would propagate through every handler,
    # service and repository in the graph.
    getter id : String

    # Unused in v0.1. Present so that adding tenancy is not a breaking migration.
    getter tenant_id : String?

    # The stored, already-normalised login. Never normalise it again on the way out.
    getter normalized_login : String

    # Bumped to invalidate every session for this account at once, without enumerating
    # rows. The belt to revocation's braces (`docs/02-security-model.md`).
    getter auth_version : Int32

    # `nil` means this account has no password credential — it authenticates through an
    # external identity only. It is not the same as "any password will do", and the
    # authentication path must never treat it as such.
    getter password_digest : String?

    # Which `Hasher` produced `password_digest`, e.g. `bcrypt`. Drives `needs_rehash?` and
    # so the lazy-rehash migration.
    getter password_scheme : String?

    getter email_verified_at : Time?
    getter disabled_at : Time?
    getter created_at : Time
    getter updated_at : Time

    def initialize(
      @id : String,
      @normalized_login : String,
      @created_at : Time,
      @updated_at : Time,
      @tenant_id : String? = nil,
      @auth_version : Int32 = 1,
      @password_digest : String? = nil,
      @password_scheme : String? = nil,
      @email_verified_at : Time? = nil,
      @disabled_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("normalized_login must not be empty") if @normalized_login.empty?
      raise ArgumentError.new("auth_version must be positive") unless @auth_version > 0
    end

    def disabled? : Bool
      !@disabled_at.nil?
    end

    def email_verified? : Bool
      !@email_verified_at.nil?
    end

    # Whether this account can be authenticated by password at all.
    def password_credential? : Bool
      !@password_digest.nil?
    end

    # Redacts the digest. A digest is not a secret in the sense a password is, but it is
    # offline-crackable material and `docs/02-security-model.md` forbids logging it.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Accounts::Account id=" << @id.inspect
      io << " normalized_login=" << @normalized_login.inspect
      io << " tenant_id=" << @tenant_id.inspect
      io << " auth_version=" << @auth_version
      io << " password_digest=" << (@password_digest.nil? ? "nil" : "[REDACTED]")
      io << " disabled_at=" << @disabled_at.inspect
      io << '>'
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end
end

module KemalIdentity
  # Which kind of credential proved a request.
  #
  # **Append only.** A consumer is expected to write `case credential.kind` over these, so
  # renaming or removing a member breaks code that compiled yesterday. New built-in kinds are
  # added at the end.
  #
  # There is no `Remembered` and no `Legacy` member, and their absence is deliberate. Both a
  # restored remember-me login and an adopted legacy session **mint a real session row** and
  # are presented as a session cookie from that point on, so a request one minute later is
  # indistinguishable from any other session. A kind that said `Remembered` on the first
  # request and `Session` on the second would be a worse lie than not saying it: what actually
  # differs is the assurance, and `AssuranceLevel::Remembered` already carries that, durably,
  # on the session row.
  enum CredentialKind
    # A server-side session, presented as a cookie.
    Session

    # An opaque personal access token, presented as a bearer credential.
    ApiToken

    # A signed JWT, presented as a bearer credential.
    Jwt

    # Anything an application's own `RequestAuthenticator` established.
    #
    # The escape hatch that keeps this enum from being a closed world. An application with two
    # custom credential families tells them apart by `CredentialRef#name`, not by this.
    Custom
  end

  # A safe reference to the credential that proved this request.
  #
  # ### Why this exists
  #
  # Without it, two personal access tokens issued to one account produce two `Principal`s that
  # are indistinguishable, so a token created for reading reports can perform a write its owner
  # happens to be permitted. `ApiTokens::Service` has the token id in hand at the moment it
  # authenticates and used to drop it on the floor;
  # `blueprints/0021-credential-reference.md` is why it no longer does.
  #
  # ### What is safe to put here
  #
  # Identifiers and metadata. **Never** the raw token, the digest, the signature, the session
  # token, or any part of a JWT beyond its `jti`. Nothing here needs redacting because nothing
  # secret ever reaches it — which is a stronger property than redacting on the way out
  # (`docs/02-security-model.md`).
  #
  # `name` is for display and for an audit line. Nothing in this shard reads it to make a
  # decision, and an application should not either: it is user-supplied text.
  struct CredentialRef
    getter kind : CredentialKind

    # The credential's stable identifier: a session id, a token id, a JWT's `jti`.
    #
    # Nilable because not every credential has one. A JWT whose issuer omits `jti` cannot be
    # named, and — worth saying out loud — a credential that cannot be named is also one that
    # cannot be revoked individually or attributed in an audit trail.
    getter id : String?

    # A human label, when the credential has one. "deploy-token".
    getter name : String?

    # When the credential stops working, if it says.
    getter expires_at : Time?

    # The permissions this credential is restricted to, or `nil` for no restriction.
    #
    # **`nil` and `[] of String` mean opposite things and must never be conflated.**
    #
    # | Value | Meaning |
    # |---|---|
    # | `nil` | unattenuated — a browser session, or a token issued without scopes |
    # | `["reports:read"]` | attenuated to this set |
    # | `[] of String` | attenuated to nothing; valid, and permits nothing |
    #
    # Reading `nil` as an empty set would deny every session-authenticated request, since a
    # session has no scopes to carry. Reading `[]` as "unset" would hand a deliberately
    # powerless token the run of the application. One is a lockout and the other is a
    # privilege escalation, which is why they are a nilable array rather than an array that is
    # sometimes empty.
    #
    # There is no wildcard. `["*"]` is a scope literally named `*` and matches nothing;
    # unrestricted is `nil`. `blueprints/0018` refuses `*` in a permission for the same
    # reason — it grants permissions that do not exist yet — and a wildcard *scope* is that
    # hazard pointed at tokens.
    getter scopes : Array(String)?

    def initialize(
      @kind : CredentialKind,
      @id : String? = nil,
      @name : String? = nil,
      @expires_at : Time? = nil,
      @scopes : Array(String)? = nil,
    )
    end

    # Whether this credential restricts what its holder may do.
    def unrestricted? : Bool
      @scopes.nil?
    end

    # Whether this credential's attenuation permits `permission`.
    #
    # **This is not an authorization check.** It answers only "does the credential allow it",
    # never "does the account hold it". The account's grant is checked first and separately;
    # effective permission is the intersection of the two, never the union, so a scope can only
    # ever remove. See `blueprints/0021-credential-reference.md` decision 6.
    def permits?(permission : String) : Bool
      scopes = @scopes
      return true if scopes.nil?

      scopes.includes?(permission)
    end
  end
end

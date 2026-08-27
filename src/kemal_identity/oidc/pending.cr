module KemalIdentity::OIDC
  # What the application has to remember between sending somebody to the provider and getting
  # them back.
  #
  # Three secrets and a destination, and each one closes a specific attack:
  #
  # * **`state`** — compared on the callback. Without it, an attacker can hand a victim a
  #    callback URL carrying the attacker's own authorization code, and the victim's browser
  #    silently links the attacker's provider account to the victim's session. That is login
  #    CSRF, and `state` is the only thing that stops it.
  # * **`nonce`** — carried into the ID token by the provider and compared here. It binds the
  #    token to *this* authorization request, so one collected elsewhere cannot be replayed
  #    into this flow.
  # * **`code_verifier`** — the PKCE secret. Only its hash goes to the provider, so an attacker
  #    who intercepts the authorization code still cannot exchange it.
  # * **`return_to`** — where to send the person afterwards, validated on the way *in* rather
  #    than on the way out. See `Client#authorize`.
  #
  # ### Storing it
  #
  # This is short-lived, per-flow state. Two places make sense: a table keyed by `state`, or a
  # signed, `HttpOnly`, `SameSite=Lax` cookie scoped to the callback path. The cookie is what
  # `KemalIdentity::Kemal` does — it needs no schema, and it is exactly as trustworthy as the
  # signing key, which the CSRF layer already depends on.
  #
  # Wherever it goes, it is a **credential**: `code_verifier` is a secret, and this struct
  # redacts itself for the same reason every other secret-holding type here does.
  struct Pending
    getter state : String
    getter nonce : String
    getter code_verifier : Secret

    # Where to go after a successful login. Already validated as a same-site path.
    getter return_to : String?

    getter created_at : Time

    def initialize(
      @state : String,
      @nonce : String,
      @code_verifier : Secret,
      @created_at : Time,
      @return_to : String? = nil,
    )
      raise ArgumentError.new("state must not be empty") if @state.empty?
      raise ArgumentError.new("nonce must not be empty") if @nonce.empty?
      raise ArgumentError.new("code_verifier must not be empty") if @code_verifier.empty?
    end

    # Whether this flow started too long ago to still be completed.
    #
    # A login that has been sitting in a tab for a day is not a login in progress. Expiring it
    # bounds how long a captured `state` cookie is worth anything.
    def expired?(now : Time, within : Time::Span) : Bool
      now - @created_at > within
    end

    # The `code_challenge` sent to the provider: base64url of SHA-256 of the verifier.
    #
    # `S256`, never `plain`. A `plain` challenge *is* the verifier, so it protects against
    # nothing an interceptor of the authorization request could not already do — and a client
    # that offers both can be downgraded to the weaker one by a provider that accepts it.
    def code_challenge : String
      Base64.urlsafe_encode(Digest::SHA256.digest(@code_verifier.reveal), padding: false)
    end

    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::OIDC::Pending [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # What a provider asserted about somebody, once their ID token verified.
  #
  # ### `(issuer, subject)` is the identity. The email is not.
  #
  # `docs/06-roadmap.md`: "The persistent key for an external identity is `(issuer, subject)` —
  # never email." Two reasons, and both bite in production:
  #
  # 1. **Emails change.** People marry, change surname, leave a company and come back. A row
  #    keyed on an address becomes a different person's row, or a stranded orphan.
  # 2. **Emails are claimed, not proved.** A provider that lets somebody set an unverified
  #    address and hands it to you in a token has just let them claim to be whoever owns that
  #    address at *your* service. Matching on it is account takeover with extra steps.
  #
  # `subject` is stable within an issuer and meaningless outside it, which is why both halves
  # are the key. Use `email` to *display*, and to pre-fill a form somebody then confirms —
  # never to look an account up.
  struct Identity
    getter issuer : String
    getter subject : String
    getter email : String?

    # Whether the provider claims to have verified the address. A claim about a claim: false or
    # absent means the address proves nothing at all, and true means only that this provider
    # says so.
    getter? email_verified : Bool

    getter name : String?

    # Every claim the ID token carried, verified but uninterpreted.
    getter claims : Hash(String, ::JSON::Any)

    def initialize(
      @issuer : String,
      @subject : String,
      @claims : Hash(String, ::JSON::Any),
      @email : String? = nil,
      @email_verified : Bool = false,
      @name : String? = nil,
    )
      raise ArgumentError.new("issuer must not be empty") if @issuer.empty?
      raise ArgumentError.new("subject must not be empty") if @subject.empty?
    end
  end
end

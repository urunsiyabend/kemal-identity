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

    # The application's own state, carried through the provider and handed back unchanged.
    #
    # The shard does not know what any of it means. It is here because the *integrity* of it
    # is this codec's job and nothing else in the flow can do it: an account-linking callback
    # has to know that it is a linking flow, whose account started it and from which session,
    # and an application left to invent that ends up with a second signed cookie beside the one
    # already being signed — or an unsigned one, which is the attack.
    #
    # ```
    # client.authorize(
    #   return_to: "/settings/security",
    #   context: {
    #     "flow"       => "link",
    #     "account_id" => principal.subject,
    #     "session_id" => principal.session_id.to_s,
    #   },
    # )
    # ```
    #
    # **Signed, not sealed — so it is not secret.** The browser can read every value, exactly
    # as it can read the PKCE verifier next to it. Provider tokens, credentials and anything
    # else that must not be read do not go here; if the state itself has to stay hidden, it
    # belongs server-side in a table keyed by `state`. ASP.NET Core can put an account id in
    # its equivalent because it *encrypts* it; this one only proves nobody changed it.
    #
    # **Compare it on the callback.** Carrying `session_id` does nothing on its own — the
    # application has to check it against the session presenting the callback, which is how
    # Keycloak binds its own account-linking flows. The shard deliberately does not do that
    # comparison: which account a federated identity may be attached to is the one decision
    # `docs/02-security-model.md` says this shard must never make on an application's behalf.
    #
    # Bounded, because the carrier is a cookie: `PendingCodec` refuses to seal a flow larger
    # than 4 KiB, and an oversized one would otherwise be written by the browser and silently
    # fail to open on the way back — a flow nobody can complete and nothing reports.
    getter context : Hash(String, String)?

    # How many entries a context may hold.
    MAX_CONTEXT_ENTRIES = 8

    # How long one key may be, in bytes.
    MAX_CONTEXT_KEY_BYTES = 64

    # How long one value may be, in bytes.
    MAX_CONTEXT_VALUE_BYTES = 512

    def initialize(
      @state : String,
      @nonce : String,
      @code_verifier : Secret,
      @created_at : Time,
      @return_to : String? = nil,
      @context : Hash(String, String)? = nil,
    )
      raise ArgumentError.new("state must not be empty") if @state.empty?
      raise ArgumentError.new("nonce must not be empty") if @nonce.empty?
      raise ArgumentError.new("code_verifier must not be empty") if @code_verifier.empty?

      validate_context(@context)
    end

    # Refuses a context that cannot survive the round trip, **when the flow starts**.
    #
    # The alternative is a cookie that seals, is written, comes back and does not open, which
    # presents as a login that silently never completes. Failing here puts the error in front
    # of whoever wrote the call rather than in front of their users.
    private def validate_context(context : Hash(String, String)?) : Nil
      return if context.nil?

      if context.size > MAX_CONTEXT_ENTRIES
        raise ArgumentError.new("context must hold at most #{MAX_CONTEXT_ENTRIES} entries")
      end

      context.each do |key, value|
        raise ArgumentError.new("context keys must not be empty") if key.empty?

        if key.bytesize > MAX_CONTEXT_KEY_BYTES
          raise ArgumentError.new("context keys must be at most #{MAX_CONTEXT_KEY_BYTES} bytes")
        end

        if value.bytesize > MAX_CONTEXT_VALUE_BYTES
          raise ArgumentError.new(
            "context values must be at most #{MAX_CONTEXT_VALUE_BYTES} bytes"
          )
        end
      end
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
end

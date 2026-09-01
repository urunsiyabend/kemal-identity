module KemalIdentity::OIDC
  # One OpenID Connect provider, as a **client** of it.
  #
  # `docs/00-scope.md` puts being an authorization server permanently outside this shard. This
  # is the other side: the application redirects somebody to Google or Okta or an internal
  # provider, and gets back an assertion about who they are.
  #
  # ### Authorization Code with PKCE, and nothing else
  #
  # No implicit flow, no hybrid, no resource-owner password grant. The implicit flow puts a
  # token in a URL fragment, where it lands in browser history and in any `Referer` that leaks;
  # the password grant asks your application to handle somebody else's password, which is the
  # thing federating was supposed to avoid. Both are discouraged by the OAuth 2.1 draft and
  # neither is expressible here.
  #
  # PKCE is not optional either, including for a confidential client with a secret. It costs a
  # hash and it closes authorization-code interception, which a client secret does not: the
  # secret proves the *client*, and PKCE proves the request came from the same place the code
  # was issued to.
  struct Provider
    # The `iss` every ID token from this provider must carry, compared exactly.
    #
    # Not a base URL to build others from and not a display name — it is the identity of the
    # party whose assertions you are about to believe, and half of the `(issuer, subject)` pair
    # that names an external account forever.
    getter issuer : String

    getter client_id : String
    getter authorization_endpoint : URI
    getter token_endpoint : URI

    # Where the provider sends the browser back.
    #
    # Registered with the provider and compared by it **exactly**, character for character —
    # which is the check that stops an attacker registering a lookalike path and collecting
    # codes. It is sent again at the token exchange for the same reason.
    getter redirect_uri : String

    getter scopes : Array(String)

    # Where the provider's signing keys come from. Normally a `JWT::JWKS` over its
    # `jwks_uri`, so a rotation is picked up without a restart.
    getter keys : JWT::KeySource

    getter algorithms : Array(String)

    # Extra query parameters to add to the authorization request, for the things a provider wants
    # and no standard names: Google's `hd`, Okta's `login_hint`, Azure's `domain_hint`.
    #
    # ### Allowlisted by exclusion, and refused at boot
    #
    # `RESERVED` below is every parameter `Client#authorize` builds itself, and a key matching one
    # of them raises `ConfigurationError` at construction rather than being silently dropped or
    # silently winning. Four of them — `state`, `nonce`, `code_challenge`, `code_challenge_method`
    # — are the flow's security, and an application that could overwrite them could turn PKCE off
    # by configuration. The rest name the client and where the code comes back to.
    #
    # `prompt` is reserved too, and is not a security value: `Client#authorize(prompt:)` sets it,
    # and two `prompt` parameters in one query string is a request the provider gets to interpret
    # however it likes.
    #
    # Values are escaped by `URI::Params`, so nothing here can inject a separator.
    getter authorization_params : Hash(String, String)?

    # Everything `Client#authorize` puts in the query string itself.
    RESERVED = %w[
      response_type client_id redirect_uri scope
      state nonce code_challenge code_challenge_method prompt
    ]

    def initialize(
      @issuer : String,
      @client_id : String,
      authorization_endpoint : String | URI,
      token_endpoint : String | URI,
      @redirect_uri : String,
      @keys : JWT::KeySource,
      @client_secret : Secret? = nil,
      @scopes : Array(String) = ["openid", "email", "profile"],
      @algorithms : Array(String) = ["RS256"],
      @authorization_params : Hash(String, String)? = nil,
    )
      @authorization_endpoint = Provider.https!(authorization_endpoint, "authorization_endpoint")
      @token_endpoint = Provider.https!(token_endpoint, "token_endpoint")

      raise ConfigurationError.new("issuer must not be empty") if @issuer.blank?
      raise ConfigurationError.new("client_id must not be empty") if @client_id.blank?
      raise ConfigurationError.new("algorithms must not be empty") if @algorithms.empty?

      unless @scopes.includes?("openid")
        raise ConfigurationError.new(
          "scopes must include `openid`, or the provider returns no ID token and there is " \
          "nothing to verify"
        )
      end

      validate_redirect_uri!
      validate_authorization_params!
    end

    private def validate_authorization_params! : Nil
      params = @authorization_params
      return if params.nil?

      params.each_key do |key|
        if key.blank?
          raise ConfigurationError.new("an authorization parameter name must not be empty")
        end

        next unless RESERVED.includes?(key)

        raise ConfigurationError.new(
          "authorization parameter #{key.inspect} is built by the flow and must not be " \
          "overridden; #{key == "prompt" ? "pass prompt: to Client#authorize" : "it is part of what makes the flow safe"}"
        )
      end
    end

    # The client secret, for a confidential client. `nil` for a public one.
    #
    # A public client — a CLI, a desktop application — has nowhere to keep a secret, and PKCE
    # is what protects it. A server-side web application is confidential and should have one.
    def client_secret : Secret?
      @client_secret
    end

    def confidential? : Bool
      !@client_secret.nil?
    end

    # Redacted: a config dump in a crash report must not print a client secret.
    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::OIDC::Provider " << @issuer << ' ' << @client_id << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end

    # A redirect URI must be absolute and exact. A provider matches it character for character,
    # so anything ambiguous here — a wildcard, a fragment, a relative path — is either rejected
    # by the provider later or, worse, matched more loosely than you meant.
    private def validate_redirect_uri! : Nil
      uri = URI.parse(@redirect_uri)

      if uri.scheme.nil? || uri.host.nil?
        raise ConfigurationError.new("redirect_uri must be absolute, got #{@redirect_uri.inspect}")
      end

      unless uri.fragment.nil?
        raise ConfigurationError.new("redirect_uri must not carry a fragment")
      end

      if @redirect_uri.includes?('*')
        raise ConfigurationError.new("redirect_uri must be exact; a wildcard is not a redirect URI")
      end

      # `http://localhost` is the one exception every provider makes, because a loopback
      # redirect never crosses a network.
      return if uri.scheme == "https"
      return if uri.scheme == "http" && {"localhost", "127.0.0.1", "[::1]"}.includes?(uri.host)

      raise ConfigurationError.new(
        "redirect_uri must be https (or http on loopback); a code delivered over plain http is " \
        "a code anybody on the path can take"
      )
    end

    protected def self.https!(endpoint : String | URI, name : String) : URI
      uri = endpoint.is_a?(URI) ? endpoint : URI.parse(endpoint)

      unless uri.scheme == "https"
        raise ConfigurationError.new("#{name} must be https, got #{uri}")
      end

      raise ConfigurationError.new("#{name} must have a host") if uri.host.nil?

      uri
    end
  end
end

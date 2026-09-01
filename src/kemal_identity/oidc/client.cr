require "http/client"
require "json"

module KemalIdentity::OIDC
  # Drives an Authorization Code + PKCE flow against one `Provider`.
  #
  # Two calls, and the application carries `Pending` between them:
  #
  # ```
  # request = client.authorize(return_to: "/dashboard")
  # # store request.pending, then redirect to request.url
  #
  # identity = client.complete(pending, state: ..., code: ...)
  # ```
  #
  # `#complete` returns an `Identity` or a `Failed`, never a raised exception for anything the
  # browser or the provider controls — the callback is a public endpoint reachable by anybody
  # with a URL.
  class Client
    # How long a flow may sit unfinished.
    #
    # A login that has been open in a tab since yesterday is not a login in progress, and the
    # window is how long a captured `state` is worth anything.
    DEFAULT_FLOW_TTL = 15.minutes

    # How long to wait on the token endpoint. Same reasoning as `JWKS::DEFAULT_TIMEOUT`: a
    # provider that accepts connections and never answers must not hold a fiber indefinitely.
    DEFAULT_TIMEOUT = 10.seconds

    # Largest token response accepted, before it is parsed.
    MAX_RESPONSE_BYTES = 256 * 1024

    getter provider : Provider
    getter flow_ttl : Time::Span

    def initialize(
      @provider : Provider,
      @clock : Clock,
      @random : RandomSource,
      @flow_ttl : Time::Span = DEFAULT_FLOW_TTL,
      @timeout : Time::Span = DEFAULT_TIMEOUT,
      @exchanger : Proc(URI, String, HTTP::Headers, Time::Span, String)? = nil,
    )
      raise ConfigurationError.new("flow_ttl must be positive") unless @flow_ttl > Time::Span::ZERO
      raise ConfigurationError.new("timeout must be positive") unless @timeout > Time::Span::ZERO

      @validator = JWT::Validator.new(
        keyring: @provider.keys,
        issuer: @provider.issuer,
        # An ID token's audience is the client it was minted for. This is the check that stops
        # a token issued to a *different* application at the same provider from being replayed
        # here — which is otherwise a complete cross-application account takeover.
        audience: @provider.client_id,
        algorithms: @provider.algorithms,
        clock: @clock,
        # No purpose claim: an OpenID Connect provider does not emit one, and demanding it
        # would mean this shard could not talk to any real provider. The `aud` check above is
        # what does that job here.
        purpose: nil,
        # Providers choose their own ID-token lifetimes and an hour is common but not universal.
        # `exp` is still required and still enforced.
        max_lifetime: nil,
      )
    end

    # Starts a flow: where to send the browser, and what to remember.
    #
    # `return_to` is validated **here**, on the way in, rather than on the callback. That is
    # deliberate: by the callback the value has made a round trip through the provider and back
    # through the browser, and anything checked only then is checked on attacker-influenced
    # input. Checked now and carried in signed state, it cannot be substituted.
    #
    # Only a same-site path is accepted — `/dashboard`, not `https://elsewhere.example.com` and
    # not `//elsewhere.example.com`, which a browser reads as a protocol-relative *absolute*
    # URL and is the open redirect people miss. Anything else is dropped rather than raising:
    # a hostile `?return_to=` in a link is a thing to ignore, not a 500.
    def authorize(return_to : String? = nil, prompt : String? = nil) : AuthorizationRequest
      now = @clock.now

      pending = Pending.new(
        state: @random.token,
        nonce: @random.token,
        # 32 bytes, base64url — comfortably inside RFC 7636's 43-to-128-character range.
        code_verifier: Secret.new(@random.token),
        created_at: now,
        return_to: Client.safe_return_to(return_to),
      )

      params = URI::Params.build do |form|
        form.add("response_type", "code")
        form.add("client_id", @provider.client_id)
        form.add("redirect_uri", @provider.redirect_uri)
        form.add("scope", @provider.scopes.join(' '))
        form.add("state", pending.state)
        form.add("nonce", pending.nonce)
        form.add("code_challenge", pending.code_challenge)
        form.add("code_challenge_method", "S256")
        form.add("prompt", prompt) if prompt

        # Last, and unable to overwrite anything above: `Provider` refuses a reserved name at
        # construction, so by here the keys are known not to collide.
        @provider.authorization_params.try &.each { |key, value| form.add(key, value) }
      end

      uri = @provider.authorization_endpoint.dup
      uri.query = params

      Log.info &.emit("oidc.authorization_started", issuer: @provider.issuer)

      AuthorizationRequest.new(url: uri.to_s, pending: pending)
    end

    # Finishes a flow from the callback's parameters.
    #
    # The order below is the order it has to be in. `state` is compared before anything is sent
    # anywhere, because a mismatched `state` means this callback did not come from a flow this
    # application started, and exchanging its code would be doing an attacker's work.
    def complete(
      pending : Pending,
      state : String?,
      code : String?,
      error : String? = nil,
    ) : Federation::Identity | Failed
      if refusal = refuse_callback(pending, state, code, error)
        return refusal
      end

      body = begin
        exchange(code.to_s, pending)
      rescue error : InfrastructureError | IO::Error | Socket::Error
        Log.warn &.emit("oidc.exchange_failed", issuer: @provider.issuer, error: error.class.name)
        return Failed.new(FailureReason::InvalidCredential)
      end

      id_token = extract_id_token(body)
      return failure(FailureReason::MalformedCredential) if id_token.nil?

      validated = @validator.validate(id_token)
      return validated if validated.is_a?(Failed)

      claims = validated.claims

      if failure = check_token_claims(claims, pending)
        return failure
      end

      identity = Federation::Identity.new(
        issuer: @provider.issuer,
        subject: validated.principal.subject,
        claims: claims,
        email: claims["email"]?.try(&.as_s?),
        # No `|| false`: an absent claim and a claim of `false` are different assertions, and
        # `Federation::Identity#email_verified` keeps them apart. A claim that is present but
        # not a boolean — some issuers send the string `"true"` — reads as nothing said, which
        # `#email_verified?` treats as unverified.
        email_verified: claims["email_verified"]?.try(&.as_bool?),
        name: claims["name"]?.try(&.as_s?),
      )

      # By subject, never by email: an address in a log line outlives the request, and this one
      # belongs to somebody else's directory.
      Log.info &.emit(
        "oidc.identity_asserted", issuer: identity.issuer, subject: identity.subject
      )

      identity
    end

    # Everything that must be refused before a single byte is sent to the provider.
    #
    # Returns `nil` when the callback may proceed. The order is the point: a mismatched `state`
    # means this callback did not come from a flow this application started, and exchanging its
    # code would be doing an attacker's work for them.
    private def refuse_callback(
      pending : Pending,
      state : String?,
      code : String?,
      error : String?,
    ) : Failed?
      # The provider declined — the person pressed "no", or their administrator forbade it.
      # Not an error to investigate, and the reason is the provider's to state, not ours.
      if error
        Log.info &.emit("oidc.declined", issuer: @provider.issuer, error: error)
        return Failed.new(FailureReason::InvalidCredential)
      end

      return failure(FailureReason::MalformedCredential) if state.nil? || state.empty?
      return failure(FailureReason::MalformedCredential) if code.nil? || code.empty?

      # Constant-time, and before any I/O. This is login CSRF's only defence.
      unless Crypto::Subtle.constant_time_compare(state, pending.state)
        Log.warn &.emit("oidc.state_mismatch", issuer: @provider.issuer)
        return Failed.new(FailureReason::InvalidCredential)
      end

      return failure(FailureReason::Expired) if pending.expired?(@clock.now, @flow_ttl)

      nil
    end

    # Whether `value` is somewhere this application may send a browser after login.
    #
    # Only a same-site absolute path. The cases that matter and are easy to miss:
    #
    # * `//evil.example.com` — a browser reads a leading `//` as protocol-relative, so this is
    #   an absolute URL wearing a path's clothes. It is the classic open redirect.
    # * `/\evil.example.com` — some browsers normalise the backslash to a slash, producing the
    #   same thing.
    # * `https://evil.example.com` — an absolute URL, plainly.
    # * A newline or a control character — header splitting, if the value ever reaches a
    #   `Location` unescaped.
    def self.safe_return_to(value : String?) : String?
      return if value.nil? || value.empty?
      return if value.bytesize > 2048
      return unless value.starts_with?('/')
      return if value.starts_with?("//")
      return if value.starts_with?("/\\")
      return if value.includes?('\\')
      return if value.each_char.any?(&.control?)

      value
    end

    # The two claim checks that only matter in a federated flow. The rest is `JWT::Validator`'s.
    private def check_token_claims(
      claims : Hash(String, ::JSON::Any),
      pending : Pending,
    ) : Failed?
      # The nonce binds this token to *this* authorization request. Without it a token collected
      # from another flow can be replayed into this one.
      nonce = claims["nonce"]?.try(&.as_s?)

      if nonce.nil? || !Crypto::Subtle.constant_time_compare(nonce, pending.nonce)
        Log.warn &.emit("oidc.nonce_mismatch", issuer: @provider.issuer)
        return Failed.new(FailureReason::InvalidClaim)
      end

      # `azp` names the party the token was issued to when there is more than one audience. If
      # it is present it must be us, or this token was minted for somebody else.
      if azp = claims["azp"]?.try(&.as_s?)
        return failure(FailureReason::InvalidClaim) unless azp == @provider.client_id
      end

      nil
    end

    private def failure(reason : FailureReason) : Failed
      Log.info &.emit("oidc.rejected", issuer: @provider.issuer, reason: reason.to_s)

      Failed.new(reason)
    end

    private def extract_id_token(body : String) : String?
      document = ::JSON.parse(body).as_h?
      return if document.nil?

      # A provider answering with an OAuth error object rather than a token.
      if oauth_error = document["error"]?.try(&.as_s?)
        Log.warn &.emit("oidc.token_error", issuer: @provider.issuer, error: oauth_error)
        return
      end

      token = document["id_token"]?.try(&.as_s?)
      return if token.nil? || token.empty?

      token
    rescue ::JSON::ParseException
      nil
    end

    # ### The provider's access and refresh tokens are deliberately dropped
    #
    # `docs/06-roadmap.md`: "Provider access and refresh tokens are not stored at all unless the
    # application actually calls the provider's API, and then only encrypted at rest in separate
    # storage."
    #
    # This flow exists to answer "who is this person?", and the ID token answers it. An access
    # token is a credential *for somebody else's service*, and storing one an application never
    # uses turns a breach of this database into a breach of every user's Google account. So the
    # response is read for `id_token` and the rest is discarded.
    #
    # An application that genuinely calls the provider's API should run that exchange itself and
    # keep the result in its own encrypted storage, with its own lifecycle.
    private def exchange(code : String, pending : Pending) : String
      form = URI::Params.build do |params|
        params.add("grant_type", "authorization_code")
        params.add("code", code)
        # Sent again at the exchange, as RFC 6749 §4.1.3 requires: the provider compares it with
        # the one the code was issued for, which is what binds the code to this redirect.
        params.add("redirect_uri", @provider.redirect_uri)
        params.add("client_id", @provider.client_id)
        params.add("code_verifier", pending.code_verifier.reveal)
      end

      headers = HTTP::Headers{
        "Content-Type" => "application/x-www-form-urlencoded",
        "Accept"       => "application/json",
      }

      # `client_secret_basic`, which is the method every provider supports and the one RFC 6749
      # §2.3.1 prefers — a secret in an Authorization header rather than in a body that is more
      # likely to be logged.
      if secret = @provider.client_secret
        credentials = Base64.strict_encode(
          "#{URI.encode_www_form(@provider.client_id)}:#{URI.encode_www_form(secret.reveal)}"
        )
        headers["Authorization"] = "Basic #{credentials}"
      end

      exchanger = @exchanger
      return exchanger.call(@provider.token_endpoint, form, headers, @timeout) if exchanger

      client = HTTP::Client.new(@provider.token_endpoint)
      client.connect_timeout = @timeout
      client.read_timeout = @timeout

      begin
        response = client.post(@provider.token_endpoint.request_target, headers: headers, body: form)

        if response.body.bytesize > MAX_RESPONSE_BYTES
          raise InfrastructureError.new("token response is larger than #{MAX_RESPONSE_BYTES} bytes")
        end

        # A 400 carries an OAuth error object worth reading, so the body is returned either way
        # and `#extract_id_token` decides.
        response.body
      ensure
        client.close
      end
    end
  end

  # Where to send the browser, and what to remember while it is gone.
  struct AuthorizationRequest
    getter url : String
    getter pending : Pending

    def initialize(@url : String, @pending : Pending)
    end

    # The URL carries no secret — only the *hash* of the PKCE verifier — but `pending` does.
    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::OIDC::AuthorizationRequest [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end
end

require "http/client"
require "json"

module KemalIdentity::JWT
  # Fetches a provider's signing keys from a JWKS endpoint.
  #
  # ### The two failure modes this exists to avoid
  #
  # **Fetching on every request.** A JWKS is a network call. Doing one per token turns the
  # identity provider into a hard dependency of every request and hands anybody who can send
  # tokens a way to make you call it — so keys are cached, and the cache is what makes JWT
  # verification local at all.
  #
  # **Never fetching again.** A cache with no expiry is a key set that cannot rotate, and the
  # provider will rotate whether or not you noticed. So the cache has a TTL, and an unknown
  # `kid` triggers one refetch — bounded by `#minimum_refresh_interval`, because otherwise a
  # stream of tokens carrying invented `kid`s is a way to make you hammer the provider.
  #
  # Both bounds are the point. A cache without them is either a denial-of-service amplifier or
  # a key set frozen at boot.
  abstract class KeySource
    # The keys to verify with, fetching or refetching as its own policy dictates.
    abstract def keyring : Keyring

    # Asks for a refresh because a token named a `kid` the current ring does not hold.
    #
    # Returns the ring either way. Implementations must rate-limit this: it is reachable by
    # anybody who can send a token.
    abstract def refresh_for(kid : String?) : Keyring
  end

  # A `KeySource` over a keyring that never changes.
  #
  # What a validator configured with a fixed keyring gets, so the validator has exactly one kind
  # of thing to ask and `JWKS` is not a special case in the hot path.
  class StaticKeySource < KeySource
    def initialize(@keyring : Keyring)
    end

    def keyring : Keyring
      @keyring
    end

    # Nothing to refresh. An unknown `kid` against a fixed ring is a token for somebody else,
    # and it stays refused.
    def refresh_for(kid : String?) : Keyring
      @keyring
    end
  end

  # A `KeySource` over an HTTPS JWKS document.
  class JWKS < KeySource
    # How long a fetched key set is used before it is fetched again.
    #
    # Ten minutes: short enough that a rotation propagates on its own, long enough that the
    # provider is not part of the hot path. Providers publish `Cache-Control` on this endpoint
    # and this deliberately does not read it — a header from the thing being verified is not a
    # good input to how long you trust it.
    DEFAULT_TTL = 10.minutes

    # The floor between two fetches provoked by an unknown `kid`.
    #
    # Without it, a stream of tokens carrying invented `kid`s is a way to make this process
    # hammer the identity provider — a denial of service pointed at somebody else, triggered by
    # unauthenticated traffic.
    DEFAULT_MINIMUM_REFRESH_INTERVAL = 1.minute

    # How long to wait on the provider before giving up.
    #
    # `docs/06-roadmap.md` asks for "a cached JWKS with a timeout", and this is why: without one
    # a provider that accepts connections and never answers holds a fiber per request until
    # something else breaks.
    DEFAULT_TIMEOUT = 5.seconds

    # Largest JWKS document accepted. A key set is a few kilobytes; this is the bound that stops
    # a hostile or broken endpoint from being answered with a stream that never ends.
    MAX_BYTES = 512 * 1024

    getter uri : URI
    getter ttl : Time::Span
    getter minimum_refresh_interval : Time::Span

    @keyring : Keyring?
    @fetched_at : Time?

    # Tracked separately from `@fetched_at`, and only by `#refresh_for`. A scheduled fetch must
    # not spend the budget for the *first* unknown `kid`, or a rotation waits a whole interval
    # for no reason — and every token in that window is rejected.
    @last_refresh_at : Time?

    def initialize(
      uri : String | URI,
      @clock : Clock,
      @algorithms : Array(String) = ["RS256"],
      @ttl : Time::Span = DEFAULT_TTL,
      @minimum_refresh_interval : Time::Span = DEFAULT_MINIMUM_REFRESH_INTERVAL,
      @timeout : Time::Span = DEFAULT_TIMEOUT,
      @fetcher : Proc(URI, Time::Span, String)? = nil,
    )
      @uri = uri.is_a?(URI) ? uri : URI.parse(uri)
      @mutex = Mutex.new

      # A JWKS over plain HTTP is a key set anybody on the path can replace, and replacing it is
      # the whole game: every token then verifies under a key the attacker chose.
      unless @uri.scheme == "https" || @fetcher
        raise ConfigurationError.new(
          "a JWKS must be fetched over https; anybody who can rewrite it can mint your tokens"
        )
      end

      raise ConfigurationError.new("ttl must be positive") unless @ttl > Time::Span::ZERO

      unless @minimum_refresh_interval >= Time::Span::ZERO
        raise ConfigurationError.new("minimum_refresh_interval must not be negative")
      end

      raise ConfigurationError.new("timeout must be positive") unless @timeout > Time::Span::ZERO
    end

    # The current key set, fetching if there is none or the cached one has expired.
    #
    # Raises `InfrastructureError` when there is nothing usable and the provider cannot be
    # reached. A stale-but-present ring is preferred to that: a provider outage should not
    # sign every one of your users out, and a key that verified a minute ago has not become
    # dangerous because a fetch failed.
    def keyring : Keyring
      @mutex.synchronize do
        cached = @keyring
        fetched_at = @fetched_at

        return cached if cached && fetched_at && @clock.now - fetched_at < @ttl

        fetch_locked(fallback: cached)
      end
    end

    # Refetches because a token named a `kid` the ring does not hold — which is what a rotation
    # looks like from here, and also what a hostile stream of invented `kid`s looks like.
    # `minimum_refresh_interval` is what tells them apart cheaply.
    def refresh_for(kid : String?) : Keyring
      @mutex.synchronize do
        cached = @keyring

        # Nothing to refresh for: the ring already answers this `kid`.
        return cached if cached && !cached.find(kid).nil?

        last = @last_refresh_at

        if cached && last && @clock.now - last < @minimum_refresh_interval
          return cached
        end

        @last_refresh_at = @clock.now

        fetch_locked(fallback: cached)
      end
    end

    # Parses a JWKS document into a keyring.
    #
    # Entries this shard cannot use — an unsupported `kty`, an `alg` outside the allow-list, a
    # modulus too short — are **skipped rather than fatal**. A provider publishing one EC key
    # beside three RSA ones is normal, and refusing the whole document over it would take the
    # application down for a key it was never going to use. A document with nothing usable in
    # it *is* fatal, because that is indistinguishable from a document for another service.
    def self.parse(body : String, algorithms : Array(String)) : Keyring
      # `as_h?` before indexing: `JSON::Any#[]?` *raises* on a document that is not an object,
      # and a JWKS endpoint answering `null` or an array is exactly the kind of thing that
      # happens during an outage.
      document = ::JSON.parse(body).as_h?
      entries = document.try(&.["keys"]?).try(&.as_a?)

      raise InfrastructureError.new("JWKS has no `keys` array") if entries.nil?

      keys = [] of Key

      entries.each do |entry|
        key = parse_entry(entry, algorithms)
        keys << key if key
      end

      if keys.empty?
        raise InfrastructureError.new("JWKS contained no usable signing key")
      end

      Keyring.new(keys)
    rescue ::JSON::ParseException
      raise InfrastructureError.new("JWKS is not valid JSON")
    end

    private def self.parse_entry(entry : ::JSON::Any, algorithms : Array(String)) : Key?
      fields = entry.as_h?
      return if fields.nil?

      algorithm = usable_algorithm(fields, algorithms)
      return if algorithm.nil?

      modulus = decode_base64url(fields["n"]?.try(&.as_s?))
      exponent = decode_base64url(fields["e"]?.try(&.as_s?))
      return if modulus.nil? || exponent.nil?

      kid = fields["kid"]?.try(&.as_s?)
      return if kid && kid.empty?

      Key.new(algorithm, RSAPublicKey.new(modulus, exponent), kid)
    rescue ConfigurationError
      # A key too small, or one OpenSSL will not parse. Skipped for the same reason as an
      # unsupported `kty`: one bad entry must not take out a document that also carries good
      # ones.
      nil
    end

    # The algorithm this entry may be used with, or `nil` when this shard cannot use it.
    private def self.usable_algorithm(
      fields : Hash(String, ::JSON::Any),
      algorithms : Array(String),
    ) : Algorithm?
      # Only RSA. EC and OKP would each need their own binding, and skipping what cannot be
      # used is better than failing over a key that was never going to be selected.
      return unless fields["kty"]?.try(&.as_s?) == "RSA"

      # `use` is optional; when present, an encryption key is not a signing key.
      use = fields["use"]?.try(&.as_s?)
      return if use && use != "sig"

      name = fields["alg"]?.try(&.as_s?) || "RS256"
      return unless algorithms.includes?(name)

      case name
      when "RS256" then RS256
      when "RS384" then RS384
      when "RS512" then RS512
      end
    end

    private def self.decode_base64url(value : String?) : Bytes?
      return if value.nil? || value.empty?
      return unless value.matches?(OpaqueToken::PATTERN)

      padded = value.tr("-_", "+/")
      padded += "=" * ((4 - padded.bytesize % 4) % 4)

      Base64.decode(padded)
    rescue Base64::Error
      nil
    end

    # Caller holds the mutex.
    private def fetch_locked(fallback : Keyring?) : Keyring
      body = fetch_body
      ring = JWKS.parse(body, @algorithms)

      @keyring = ring
      @fetched_at = @clock.now

      Log.info &.emit("jwks.fetched", keys: ring.size)

      ring
    rescue error : InfrastructureError | IO::Error | Socket::Error
      # A provider outage must not sign everybody out. The stale ring is what verified a minute
      # ago, and a failed fetch has not made it dangerous.
      if fallback
        Log.warn &.emit("jwks.refresh_failed", error: error.class.name)
        return fallback
      end

      Log.error &.emit("jwks.fetch_failed", error: error.class.name)

      raise InfrastructureError.new("could not fetch the JWKS: #{error.class.name}")
    end

    private def fetch_body : String
      fetcher = @fetcher
      return fetcher.call(@uri, @timeout) if fetcher

      client = HTTP::Client.new(@uri)
      client.connect_timeout = @timeout
      client.read_timeout = @timeout

      begin
        response = client.get(@uri.request_target)

        unless response.status.success?
          raise InfrastructureError.new("JWKS endpoint answered #{response.status_code}")
        end

        body = response.body

        if body.bytesize > MAX_BYTES
          raise InfrastructureError.new("JWKS document is larger than #{MAX_BYTES} bytes")
        end

        body
      ensure
        client.close
      end
    end
  end
end

module KemalIdentity::Kemal
  # Rejects an unsafe request without a valid CSRF token.
  #
  # Registered after `AuthenticationHandler`, because the token binds to the session and this
  # needs to know whether there is one.
  #
  # ### It reads the header before the body, deliberately
  #
  # Touching `env.params.body` on a multipart request makes `Kemal::ParamParser` spool every
  # file part to a temporary file. On Kemal 1.10.0 – 1.12.0 those files were only cleaned up if
  # the request reached the route handler, so a middleware that parses and then rejects leaks
  # them permanently — an unauthenticated client could fill the disk one *rejected* upload at a
  # time. Kemal 1.13.0 moved cleanup into `Kemal::InitHandler`, which runs however the request
  # ends.
  #
  # Checking `X-CSRF-Token` first means a client that sends the header never triggers body
  # parsing at all. A multipart form post still has to be parsed to find the field, so on a
  # Kemal below 1.13.0 that case still leaks — which is a reason to upgrade, and is why the
  # README says so.
  class CSRFHandler < ::Kemal::Handler
    def initialize(@config : CSRFConfig? = nil, @app : Application? = nil)
      # Validated here rather than on first request, so a misconfiguration is a startup
      # failure. `configure` runs before `use` in every documented wiring, so this normally
      # fires at boot.
      resolve_config if @config.nil? && KemalIdentity.configured?
    end

    def call(env : HTTP::Server::Context)
      config = @config || resolve_config

      return call_next(env) unless config.protects?(env.request.method)
      return call_next(env) if config.exempt?(env.request.path)
      return call_next(env) if bearer_only?(env, config)

      unless valid?(env, config)
        Log.info &.emit("csrf.rejected", path: env.request.path, method: env.request.method)
        raise CSRFError.new("CSRF token missing or invalid")
      end

      call_next(env)
    end

    # Whether this request is authenticated by a bearer token **and nothing else**.
    #
    # This is the exemption `docs/02-security-model.md` reserves for v0.4, stated exactly as it
    # is written there: "the exemption applies only to endpoints that accept *nothing but* an
    # `Authorization` header."
    #
    # CSRF exists because a browser attaches cookies to cross-site requests on its own. It does
    # not attach an `Authorization` header on its own — an attacker's page cannot make the
    # victim's browser send one — so a request carrying only a token is not forgeable in that
    # way.
    #
    # The `and nothing else` is the load-bearing half. A request presenting **both** a session
    # cookie and a token is still protected: the cookie alone would authenticate it, so an
    # attacker who can trigger the request cross-site does not need the token at all. Content
    # type is not a defence either, and neither is calling the endpoint an API.
    private def bearer_only?(env : HTTP::Server::Context, config : CSRFConfig) : Bool
      return false unless @app.try(&.bearer) || KemalIdentity.app.bearer

      return false if env.request.headers["Authorization"]?.nil?

      # The session cookie as *presented*, not the resolved outcome: a request carrying an
      # expired cookie still carries a cookie, and exempting it would let one expire its way out
      # of CSRF protection.
      session_cookie = (@app || KemalIdentity.app).cookie
      session_cookie.extract(env.request.cookies).nil?
    end

    private def valid?(env : HTTP::Server::Context, config : CSRFConfig) : Bool
      anchor = env.auth.csrf_anchor
      return false if anchor.nil?

      CSRF.valid?(config.secret, anchor, presented(env, config))
    end

    # Header first — see the note on body parsing above.
    private def presented(env : HTTP::Server::Context, config : CSRFConfig) : String?
      from_header = env.request.headers[config.header_name]?
      return from_header if from_header && !from_header.empty?

      from_body(env, config)
    end

    private def from_body(env : HTTP::Server::Context, config : CSRFConfig) : String?
      value = env.params.body[config.field_name]?
      value.nil? || value.empty? ? nil : value
    rescue ArgumentError
      # A body that cannot be parsed carries no token, which is a rejection rather than a
      # crash. Narrow on purpose: `src/CLAUDE.md` bans the blanket form.
      nil
    end

    private def resolve_config : CSRFConfig
      config = (@app || KemalIdentity.app).csrf

      if config.nil?
        raise ConfigurationError.new(
          "CSRFHandler is registered but no CSRF configuration was given. Pass " \
          "csrf: KemalIdentity::Kemal::CSRFConfig.new(secret: ...) to KemalIdentity.configure, " \
          "or construct the handler with one."
        )
      end

      @config = config
    end
  end
end

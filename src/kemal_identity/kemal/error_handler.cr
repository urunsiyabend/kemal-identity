module KemalIdentity::Kemal
  # Turns the guard exceptions into responses: 401 and 403.
  #
  # `require!` raises `NotAuthenticatedError` — nobody is signed in, so 401. `require_fresh!`
  # raises `FreshAuthenticationRequiredError` — the caller *is* known and simply has to prove
  # it again, so 403 rather than another 401, which would suggest their session had ended.
  #
  # ### Where it goes in the chain
  #
  # Ahead of anything that can raise, which means ahead of `PathGuard` and ahead of
  # `Kemal::RouteHandler` — a route calling `env.auth.require!` raises from inside the route
  # handler, and this must be outside it to catch that. Registering it immediately before
  # `AuthenticationHandler` satisfies both.
  #
  # An application that wants its own behaviour simply does not register this and rescues the
  # two classes itself.
  #
  # ### Why there is no return-to parameter
  #
  # The redirect carries no `?return_to=`. Building one from the request and reflecting it
  # back after login is the standard shape of an open redirect, and getting it right means
  # validating that the target is local — a decision that belongs to the application, which
  # knows its own routes. An application that wants it adds it at its login route, where the
  # validation is one line and visible.
  class ErrorHandler < ::Kemal::Handler
    # What `WWW-Authenticate` announces. `realm` is a label a client may show; it names nothing
    # about the deployment beyond what the application chose.
    DEFAULT_REALM = "api"

    def initialize(@login_path : String? = "/login", @realm : String = DEFAULT_REALM, @app : Application? = nil)
    end

    def call(env : HTTP::Server::Context)
      call_next(env)
    rescue NotAuthenticatedError
      # RFC 6750 §3: "If the request lacks any authentication information … the resource server
      # SHOULD NOT include an error code". A presented credential that did not hold is a
      # different answer, and `invalid_token` is the code for it.
      respond(
        env, status: 401, message: "authentication required", redirect: true,
        challenge_error: bearer_presented?(env) ? "invalid_token" : nil,
      )
    rescue error : FreshAuthenticationRequiredError
      # No redirect: sending somebody to a login page when they are already logged in is
      # confusing, and the application usually wants its own re-authentication prompt.
      #
      # The status stays 403. RFC 9470's examples answer 401 but the document requires no
      # status code, and RFC 6750 asks for 403 on the neighbouring case — so changing it would
      # be a compatibility decision rather than a compliance one. Recorded in
      # `blueprints/0026-bearer-challenges.md`.
      #
      # `insufficient_user_authentication` is only emitted for a request that actually presented
      # a bearer credential: RFC 9470 defines it as the authentication event behind *the access
      # token* being too weak or too old, and a browser session has no access token to say that
      # about.
      #
      # `max_age` says *which* of "too weak" and "too old" it was, and is present only for the
      # recency case, where the caller named a window. `blueprints/0028` is why there is no
      # `acr_values` beside it.
      respond(
        env, status: 403, message: "fresh authentication required", redirect: false,
        challenge_error: bearer_presented?(env) ? "insufficient_user_authentication" : nil,
        max_age: error.max_age,
      )
    rescue error : ForbiddenError
      # 403, no redirect, and one body for every denial reason: whether the caller is not a
      # member of a tenant or a member with no role is an answer the audit log gets and the
      # client does not.
      #
      # `error.challenge_error` is the projection `authorize!` made — `"insufficient_scope"` or
      # nothing. The reason itself never reaches here.
      respond(
        env, status: 403, message: "not permitted", redirect: false,
        challenge_error: error.challenge_error,
      )
    rescue CSRFError
      # 403, and never a redirect: the request was refused on its own merits, and bouncing a
      # rejected POST to a login page would suggest the session had ended when it had not.
      #
      # No challenge: CSRF is not a bearer-credential problem, and a client that re-presented
      # the same token would fail the same way.
      respond(env, status: 403, message: "invalid CSRF token", redirect: false)
    end

    private def respond(
      env : HTTP::Server::Context,
      status : Int32,
      message : String,
      redirect : Bool,
      challenge_error : String? = nil,
      max_age : Time::Span? = nil,
    ) : Nil
      login_path = @login_path

      # A request that presented a bearer credential is never redirected, whatever it sent in
      # `Accept`. Content negotiation is a guess about whether a browser is asking; an
      # `Authorization: Bearer` header is the client saying so outright, and bouncing it to a
      # login page answers an API call with an HTML page it cannot use.
      #
      # Measured before this: a `curl` sending a bearer token and no `Accept` received
      # `302 Location: /login` (blueprints/0025, HTTP-01).
      if redirect && !login_path.nil? && !wants_json?(env) && !bearer_presented?(env)
        env.redirect(login_path, status_code: 302)
        return
      end

      challenge(env, challenge_error, max_age)

      # A generic message. It says what the client must do, and nothing about who exists.
      env.status(status).json({error: message})
    end

    # RFC 6750 §3 makes this header a MUST for a request that carried no credentials or a token
    # that did not grant access — which is every branch above that reaches a status rather than a
    # redirect.
    #
    # It is skipped when the application configured no bearer credential at all. Announcing a
    # scheme the deployment does not accept would be advertising a door that is not there, and a
    # browser-only application has no use for it.
    private def challenge(
      env : HTTP::Server::Context,
      error : String?,
      max_age : Time::Span? = nil,
    ) : Nil
      return unless bearer_configured?

      value = %(Bearer realm="#{@realm}")
      value += %(, error="#{error}") if error

      # RFC 9470 §3: "the allowable elapsed time in seconds since the last active
      # authentication event". Whole seconds, rounded **down**, because a client that
      # re-authenticates within the value it was handed must land inside the window rather
      # than one rounding error outside it.
      #
      # Sent only alongside `insufficient_user_authentication`. The parameter is defined for
      # that challenge, and attaching it to a 401 for a missing credential would be answering
      # a different question.
      if max_age && error == "insufficient_user_authentication"
        value += %(, max_age="#{max_age.total_seconds.to_i}")
      end

      # The `scope` attribute is OPTIONAL in RFC 6750 and deliberately omitted: naming the
      # permission a caller lacks is the one part of a denial this shard keeps to the audit log.
      env.response.headers["WWW-Authenticate"] = value
    end

    private def bearer_configured? : Bool
      app = @app
      return !app.bearer.nil? if app

      # `configured?` rather than `app`, which raises: this handler is the outermost one, so a
      # request that arrives before configuration must still get a response rather than a second
      # exception thrown from the rescue that was handling the first.
      return false unless KemalIdentity.configured?

      !KemalIdentity.app.bearer.nil?
    end

    # Whether this request presented a bearer credential at all, which is what separates
    # "nothing was sent" from "what was sent did not hold".
    private def bearer_presented?(env : HTTP::Server::Context) : Bool
      header = env.request.headers["Authorization"]?
      return false if header.nil?

      scheme, _, credential = header.partition(' ')
      scheme.compare("Bearer", case_insensitive: true).zero? && !credential.strip.empty?
    end

    # Content negotiation, narrowly.
    #
    # An `Accept` header naming JSON, or an `X-Requested-With: XMLHttpRequest`, means a
    # redirect would be answered by code that cannot follow it usefully. Everything else gets
    # the redirect, since a browser is the assumption a session cookie already encodes.
    private def wants_json?(env : HTTP::Server::Context) : Bool
      accept = env.request.headers["Accept"]?
      return true if accept && accept.includes?("application/json")

      env.request.headers["X-Requested-With"]? == "XMLHttpRequest"
    end
  end
end

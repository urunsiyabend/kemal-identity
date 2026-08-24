module KemalIdentity::Kemal
  # Turns the two guard exceptions into responses: 401 and 403.
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
    def initialize(@login_path : String? = "/login")
    end

    def call(env : HTTP::Server::Context)
      call_next(env)
    rescue NotAuthenticatedError
      respond(env, status: 401, message: "authentication required", redirect: true)
    rescue FreshAuthenticationRequiredError
      # No redirect: sending somebody to a login page when they are already logged in is
      # confusing, and the application usually wants its own re-authentication prompt.
      respond(env, status: 403, message: "fresh authentication required", redirect: false)
    rescue CSRFError
      # 403, and never a redirect: the request was refused on its own merits, and bouncing a
      # rejected POST to a login page would suggest the session had ended when it had not.
      respond(env, status: 403, message: "invalid CSRF token", redirect: false)
    end

    private def respond(env : HTTP::Server::Context, status : Int32, message : String, redirect : Bool) : Nil
      login_path = @login_path

      if redirect && !login_path.nil? && !wants_json?(env)
        env.redirect(login_path, status_code: 302)
        return
      end

      # A generic message. It says what the client must do, and nothing about who exists.
      env.status(status).json({error: message})
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

module KemalIdentity::Kemal
  # Resolves the session cookie and populates `env.auth`. Never rejects anything.
  #
  # ### Registered globally, with no scoping
  #
  # No `only`, no `exclude`, no `before_get`, no router-scoped filter. Kemal 1.10.0 – 1.12.0
  # has four defects that each cause a scoped authentication filter to silently not run, and
  # 1.10.0 is the supported floor — so a library whose security depends on the consumer having
  # upgraded to 1.13.0 has a silent failure mode. The defects are listed in
  # `docs/04-kemal-integration.md`; the shortest of them is that `HEAD /admin/users` skipped a
  # `before_get` authentication filter while still running the protected handler.
  #
  # This handler dispatches on nothing at all: it runs for every path and every method,
  # including methods that did not exist when it was written. Kemal 1.13.0 added HTTP QUERY;
  # a handler with a method allowlist would have silently not covered it.
  #
  # ### Resolving is not rejecting
  #
  # It populates and moves on. Rejection is a guard's job — `require!` in a route, or
  # `PathGuard` over a subtree. That separation is what lets a public page render differently
  # for a signed-in visitor, and what stops every stale cookie producing a 401 on the
  # homepage.
  #
  # ### Cost on an anonymous request
  #
  # One cookie-map lookup and nothing else. No digest, no query. Static assets are the common
  # case and they must not pay for authentication.
  #
  # ### Do not register this at position 0
  #
  # `use handler, 0` places a handler ahead of `Kemal::InitHandler`, and since Kemal 1.13.0
  # that position takes over temporary-file cleanup for uploads it parses itself. This handler
  # has no business owning that.
  class AuthenticationHandler < ::Kemal::Handler
    def initialize(@app : Application? = nil)
    end

    def call(env : HTTP::Server::Context)
      app = @app || KemalIdentity.app

      raw = app.cookie.extract(env.request.cookies)
      outcome = app.sessions.resolve(raw)

      env.auth = RequestContext.new(env, app, outcome)

      # A cookie that was presented and did not resolve gets cleared, so the browser stops
      # sending a value that will never work again. `Anonymous` — no cookie at all — needs no
      # response action, which is exactly why the two are distinct outcomes.
      case outcome
      when Failed
        # A cookie that was presented and did not resolve gets cleared, so the browser stops
        # sending a value that will never work again.
        Log.debug &.emit("session.rejected", reason: outcome.reason.to_s)
        env.auth.clear_cookie!
      when Anonymous
        # No session cookie at all. Two credentials can still identify this request, and the
        # order matters: a client presenting `Authorization` is an API client and has no
        # remember-me cookie to restore, while a browser has the reverse.
        unless env.auth.authenticate_bearer!
          # Restoring a remembered login happens here rather than on a *failed* cookie: it keeps
          # logout unambiguous and narrows the window in which parallel requests both present
          # the remember token, which reads as theft. See `blueprints/0012-remember-me.md`.
          env.auth.restore_remembered!
        end
      end

      call_next(env)
    end
  end
end

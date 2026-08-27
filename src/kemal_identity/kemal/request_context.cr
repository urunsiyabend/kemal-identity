module KemalIdentity::Kemal
  # `env.auth`: what the application asks about the current request.
  #
  # Built by `AuthenticationHandler` for **every** request, authenticated or not, so that
  # `env.auth` is never nil and a public page can render differently for a signed-in visitor
  # without a guard rejecting anonymous ones.
  class RequestContext
    # The raw result. Exhaustively matchable, for an application that wants to distinguish
    # "not signed in" from "this cookie is no good".
    getter outcome : Outcome

    @issued_csrf_anchor : String?

    def initialize(@env : HTTP::Server::Context, @app : Application, @outcome : Outcome)
    end

    # The principal, or nil. Prefer `require!` in a guarded route: it makes the principal
    # available only where it exists, with no nil check.
    def principal? : Principal?
      outcome = @outcome
      outcome.is_a?(Authenticated) ? outcome.principal : nil
    end

    def authenticated? : Bool
      @outcome.is_a?(Authenticated)
    end

    # No credential was presented at all.
    def anonymous? : Bool
      @outcome.is_a?(Anonymous)
    end

    # A credential was presented and rejected. Distinct from `anonymous?` because this is the
    # case whose cookie needs clearing.
    def failed? : Bool
      @outcome.is_a?(Failed)
    end

    # Why the presented credential was rejected, for logging. Never for the response: a body
    # that varies with this is an account oracle (`docs/04-kemal-integration.md`).
    def failure_reason : FailureReason?
      outcome = @outcome
      outcome.is_a?(Failed) ? outcome.reason : nil
    end

    # The principal, or `NotAuthenticatedError` — which `ErrorHandler` turns into a 401.
    #
    # Raising is deliberate, and is the one place this shard raises on the authentication
    # path other than `require_fresh!`: it lets a route guard be a single line whose result is
    # the principal, rather than a conditional that has to remember to return.
    def require! : Principal
      principal = principal?
      return principal if principal

      raise NotAuthenticatedError.new("authentication required")
    end

    # The principal, if the credential behind it was verified within `within`.
    #
    # Raises `FreshAuthenticationRequiredError`, which becomes a 403: the caller is known,
    # they simply have to prove it again. The window is the caller's choice rather than a
    # configured global, because "recent enough" for changing an email is not "recent enough"
    # for deleting an account.
    #
    # A session restored from a remember-me cookie is never fresh, however recently it was
    # restored — it proves possession of a stored token, not the presence of the account
    # holder. Step-up therefore always forces a real re-authentication out of `Remembered`.
    #
    # Operations that must call this: changing email, changing password, disabling MFA,
    # generating or revoking API credentials, and any destructive account action.
    def require_fresh!(within : Time::Span) : Principal
      principal = require!
      return principal if principal.fresh?(within: within, now: @app.clock.now)

      raise FreshAuthenticationRequiredError.new("fresh authentication required")
    end

    # The principal, if it reached at least `level`.
    def require_assurance!(level : AssuranceLevel) : Principal
      principal = require!
      return principal if principal.at_least?(level)

      raise FreshAuthenticationRequiredError.new("stronger authentication required")
    end

    # Mints a session for `principal` and sets the cookie.
    #
    # **This is the session fixation defence.** Any session the client held before this call
    # is revoked, so an identifier an attacker planted beforehand is worthless afterwards.
    # The new session is created before the old one is revoked, so a crash in between leaves
    # the user where they were rather than logged out.
    #
    # `docs/04-kemal-integration.md` writes this as `sessions.start!(env, principal)`. It
    # lives here instead: a core service taking an `HTTP::Server::Context` would put HTTP into
    # the layer that is meant not to know HTTP exists. See
    # `blueprints/0008-kemal-layer-owns-the-http-seam.md`.
    def start!(
      principal : Principal,
      assurance : AssuranceLevel? = nil,
      mfa_verified_at : Time? = nil,
    ) : Principal
      account = @app.accounts.find_by_id(principal.subject)

      if account.nil?
        # Verified a credential, then the account vanished. Not an authentication failure —
        # something is wrong underneath.
        raise InfrastructureError.new("account disappeared between authentication and session start")
      end

      previous = principal?.try(&.session_id)
      issued = @app.sessions.start(
        account,
        assurance || principal.assurance,
        mfa_verified_at: mfa_verified_at || principal.mfa_verified_at,
      )

      @app.sessions.revoke(previous) if previous

      @env.response.cookies << @app.cookie.build(issued.token)
      @outcome = Authenticated.new(issued.principal)

      # `Sessions::Service#start` already emitted `session.started`; logging again here would
      # double every login in the trail.

      issued.principal
    end

    # Records that a second factor was proved, and raises this session to `AssuranceLevel::MFA`.
    #
    # Call it after `MFA::Service#verify` or `#redeem_recovery_code` returns `Verified`:
    #
    # ```
    # case KemalIdentity.app.mfa!.verify(env.auth.require!.subject, env.params.body["code"])
    # in KemalIdentity::MFA::Verified then env.auth.mfa_verified!
    # in KemalIdentity::Failed        then render_the_same_error_for_every_reason
    # end
    # ```
    #
    # **This rotates the session**, exactly as login does. `docs/02-security-model.md` lists an
    # assurance increase alongside login among the events that must produce a new identifier:
    # a session id an attacker learned while it was worth `Password` must not silently become
    # one worth `MFA`.
    #
    # `mfa_verified_at` is stamped from the application's clock, so `require_assurance!` and a
    # freshness window both measure from when the factor was actually proved.
    def mfa_verified! : Principal
      start!(require!, assurance: AssuranceLevel::MFA, mfa_verified_at: @app.clock.now)
    end

    # Starts remembering this browser, and writes the cookie.
    #
    # Call it only after a real authentication — `remember` refuses a restored session by
    # taking an account rather than a principal, because chaining remembrance off remembrance
    # would make the thirty days a rolling window that never closes.
    #
    # ```
    # env.auth.start!(result.principal)
    # env.auth.remember! if env.params.body["remember"]?
    # ```
    def remember!(principal : Principal? = nil) : Nil
      subject = (principal || require!).subject
      account = @app.accounts.find_by_id(subject)

      raise InfrastructureError.new("account disappeared before it could be remembered") if account.nil?

      write_remember(@app.remember!.remember(account))
    end

    # Ends the current session and clears the cookie. Safe to call when nobody is signed in.
    #
    # Also forgets this browser's remember-me family. Skipping that would sign the user out and
    # then sign them straight back in on their next request, which is not what a logout button
    # is for.
    def logout! : Bool
      session_id = principal?.try(&.session_id)
      revoked = session_id.nil? ? false : @app.sessions.revoke(session_id)

      forget_remembered_browser

      clear_cookie!
      @outcome = Anonymous.new

      Log.info &.emit("session.ended", session: session_id) if session_id

      revoked
    end

    # Whether this request presented a bearer token that resolved.
    #
    # Returns false when there is no `Authorization: Bearer` header at all, so the caller can go
    # on to try another credential — and **true** when there was one that failed, because a
    # client that sent a token is asking to be authenticated by it. Falling through to a cookie
    # after a rejected token would let a stale credential mask a revoked one.
    protected def authenticate_bearer! : Bool
      service = @app.bearer
      return false if service.nil?

      credential = bearer_credential
      return false if credential.nil?

      @outcome = service.authenticate(credential)
      true
    end

    # The value after the `Bearer` scheme, or nil.
    #
    # The scheme name is matched case-insensitively, as RFC 7235 requires — `bearer`, `Bearer`
    # and `BEARER` are the same scheme, and a client that picks the wrong case is not an
    # attacker.
    private def bearer_credential : String?
      header = @env.request.headers["Authorization"]?
      return if header.nil?

      scheme, _, credential = header.partition(' ')
      return unless scheme.compare("Bearer", case_insensitive: true).zero?

      credential = credential.strip
      credential.empty? ? nil : credential
    end

    # Attempts to restore a remembered login. Called by `AuthenticationHandler`, and only when
    # the request presented no session cookie at all.
    #
    # Restoring on a *failed* session cookie instead would be worse in two ways: it would widen
    # the window in which parallel requests both present the remember token — which reads as
    # theft (`blueprints/0012-remember-me.md`) — and, because logout leaves a revoked session
    # cookie behind, it would race with logout itself. A request with no session cookie is
    # unambiguous, and the handler clears a bad one so the next request qualifies.
    protected def restore_remembered! : Nil
      service = @app.remember
      return if service.nil?

      raw = @app.remember_cookie.extract(@env.request.cookies)
      return if raw.nil?

      case restored = service.restore(raw)
      in Sessions::NotRemembered
        # Expired, revoked, or never issued. Stop the browser sending it again.
        @env.response.cookies << @app.remember_cookie.build_cleared
      in Sessions::ReplayDetected
        # The family and every session are already gone. Clear both cookies so the browser
        # stops presenting credentials that have been deliberately destroyed.
        @env.response.cookies << @app.remember_cookie.build_cleared
        clear_cookie!
        @outcome = Failed.new(FailureReason::ReplayedToken)
      in Sessions::Restored
        # Both cookies, always. Writing the session and not the replacement would leave the
        # browser holding a token the server has already spent, and its next visit would be
        # reported as a replay because of a bug rather than a thief.
        @env.response.cookies << @app.cookie.build(restored.session_token)
        write_remember(restored.remember)
        @outcome = Authenticated.new(restored.principal)
      end
    end

    private def write_remember(issued : Sessions::IssuedRemember) : Nil
      # `max_age`, unlike the session cookie: a remembered login is supposed to survive the
      # browser being closed, which is the whole point of it.
      @env.response.cookies << @app.remember_cookie.build(issued.token, max_age: @app.remember_ttl)
    end

    private def forget_remembered_browser : Nil
      service = @app.remember
      return if service.nil?

      raw = @app.remember_cookie.extract(@env.request.cookies)
      return if raw.nil?

      # Revoked by digest rather than consumed: spending the token would make this browser's
      # next visit look like a replay, so pressing "log out" would warn the user that their
      # cookie may have been stolen.
      service.forget_by_token(raw)

      @env.response.cookies << @app.remember_cookie.build_cleared
    end

    # A CSRF token for this request, minting an anchor if there is not one yet.
    #
    # Call it from whatever renders a form:
    #
    # ```
    # <input type="hidden" name="_csrf" value="<%= env.auth.csrf_token %>">
    # ```
    #
    # For an authenticated request the token binds to the session, so it changes when the
    # session does — including on login, which is what makes a token minted before
    # authentication useless afterwards. For an anonymous one it binds to a dedicated cookie,
    # issued lazily right here: rendering a form is what creates it, so a static asset request
    # never pays for one.
    #
    # The value differs on every call even within a request. That is the mask
    # (`KemalIdentity::Kemal::CSRF`), and it is why a token that repeats in every response
    # cannot be extracted by a compression oracle.
    def csrf_token : String
      config = csrf_config
      CSRF.issue(config.secret, csrf_anchor!(config), @app.random)
    end

    # What the CSRF token is bound to: the session id when signed in, the anchor cookie when
    # not. `nil` when there is neither, which is a rejection rather than a token check against
    # an empty string.
    def csrf_anchor : String?
      session_id = principal?.try(&.session_id)
      return session_id if session_id

      issued = @issued_csrf_anchor
      return issued if issued

      value = @env.request.cookies[csrf_config.cookie_name]?.try(&.value)
      value.nil? || value.empty? ? nil : value
    end

    # Whether `token` is valid for this request. For an application checking by hand rather
    # than through `CSRFHandler`.
    def csrf_valid?(token : String?) : Bool
      anchor = csrf_anchor
      return false if anchor.nil?

      CSRF.valid?(csrf_config.secret, anchor, token)
    end

    private def csrf_anchor!(config : CSRFConfig) : String
      existing = csrf_anchor
      return existing if existing

      value = @app.random.token
      @issued_csrf_anchor = value
      @env.response.cookies << config.build_cookie(value)
      value
    end

    private def csrf_config : CSRFConfig
      config = @app.csrf
      return config if config

      raise ConfigurationError.new(
        "CSRF is not configured. Pass csrf: KemalIdentity::Kemal::CSRFConfig.new(secret: ...) " \
        "to KemalIdentity.configure."
      )
    end

    # Tells the browser to stop sending a cookie that no longer resolves.
    #
    # Same name, path and domain as the one that was set: a browser matches on all three, so a
    # clearing cookie that differs in any of them leaves the original in place.
    def clear_cookie! : Nil
      @env.response.cookies << @app.cookie.build_cleared
    end
  end
end

class HTTP::Server::Context
  @kemal_identity_auth : KemalIdentity::Kemal::RequestContext?

  # The authentication context for this request.
  #
  # Raises `ConfigurationError` rather than returning nil when
  # `KemalIdentity::Kemal::AuthenticationHandler` is not installed: a route reaching for
  # `env.auth` in an application that forgot to register the handler is asking a question
  # nothing has answered, and silently treating that as "anonymous" would turn a wiring
  # mistake into an authentication bypass.
  def auth : KemalIdentity::Kemal::RequestContext
    context = @kemal_identity_auth
    return context if context

    raise KemalIdentity::ConfigurationError.new(
      "env.auth is unavailable: add `use KemalIdentity::Kemal::AuthenticationHandler.new` " \
      "to the handler chain, ahead of any route that reads it"
    )
  end

  # :nodoc:
  def auth=(context : KemalIdentity::Kemal::RequestContext)
    @kemal_identity_auth = context
  end

  # Whether authentication has run for this request.
  def auth? : Bool
    !@kemal_identity_auth.nil?
  end
end

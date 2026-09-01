module KemalIdentity
  # Everything the shard needs, wired together once at boot.
  #
  # Built at startup and never mutated afterwards (`docs/01-architecture.md`): no request can
  # widen a session window or swap a hasher. Adapters must be safe for concurrent use from
  # multiple fibers on multiple threads, which since Crystal 1.21 may genuinely mean multiple
  # threads.
  #
  # The repositories go in; the services come out. `sessions` takes a
  # `Sessions::Repository` and gives back a `Sessions::Service`, because an application
  # configures storage and calls behaviour.
  class Application
    # The account store. Abstract on purpose — an application with its own `users` table
    # implements this and creates no `auth_accounts` table at all.
    getter accounts : Accounts::Repository

    getter sessions : Sessions::Service
    getter passwords : Passwords::Authenticator
    getter hasher : Passwords::Hasher

    # Throttling for the password verification path. `NullRateLimiter` by default, which
    # allows everything — see its documentation, and the README.
    getter rate_limiter : RateLimiter
    getter cookie : Sessions::CookieConfig
    getter clock : Clock
    getter random : RandomSource

    # The account lifecycle service: password reset and email confirmation.
    #
    # `nil` unless the application supplied both an `ActionTokenRepository` and a `Notifier` —
    # neither has a sensible default. A reset flow with nowhere to store its tokens, or with
    # nobody to send the link, would be a flow that silently never works.
    getter accounts_service : Accounts::Service?

    # Remember-me, or `nil` unless a `RememberRepository` was supplied.
    getter remember : Sessions::RememberService?

    # The cookie remember-me tokens ride in. Separate from the session cookie: different name,
    # different lifetime, and it carries a `max-age` because it is meant to outlive the browser
    # being closed, which is the entire point of it.
    getter remember_cookie : Sessions::CookieConfig

    getter remember_ttl : Time::Span

    # What counts as an acceptable password when one is being *set*. Defaults to a length floor
    # whose ceiling comes from this application's hasher.
    getter password_policy : Passwords::Policy

    # CSRF configuration, or `nil` when the application has not set one up.
    #
    # Nilable rather than defaulted: a default signing key would be shared by every deployment
    # that forgot to set one, which is the same as having no protection while appearing to have
    # some. `CSRFHandler` raises at construction when this is missing.
    getter csrf : CSRFConfig?

    # The session store, exposed for a sweeper or a "list my devices" screen. The hot path
    # goes through `sessions` instead.
    getter session_repository : Sessions::Repository

    # The stores behind the account lifecycle and remember-me services, exposed for the
    # sweeper. Nil when the application configured neither, in which case there is nothing of
    # theirs to sweep.
    getter action_tokens : Accounts::ActionTokenRepository?
    getter remember_tokens : Sessions::RememberRepository?
    getter api_tokens : ApiTokens::Repository?

    # Opaque personal access tokens, or `nil` unless an `ApiTokens::Repository` was supplied.
    getter api : ApiTokens::Service?

    # The factor store, exposed so an application can run its own reports over it.
    getter mfa_factors : MFA::Repository?

    # Second factors, or `nil` unless an `MFA::Repository`, a secret-box key and an issuer were
    # all supplied. Half of an MFA setup is worse than none: a service with nowhere to store a
    # factor, or no key to seal it with, would accept an enrolment and lose it.
    getter mfa : MFA::Service?

    # JWT validation, or `nil` — which it is unless an application passed a `JWT::Validator`.
    # Off by default on purpose: a JWT cannot be revoked before its `exp`, and
    # `JWT::RevocationStore` sets out what that costs.
    getter jwt : JWT::Validator?

    # What resolves an `Authorization: Bearer` header, whichever kind of token it holds.
    #
    # One authenticator when only one is configured, and an `AuthenticatorChain` when several
    # are: the header does not say which kind it carries, so they are tried in turn on shape. Nil
    # when the application accepts no bearer credential at all.
    #
    # An application's own authenticators arrive through `bearer_authenticators:` and are part of
    # this. That matters beyond the resolution itself: this is also the signal
    # `Kemal::ErrorHandler` uses to decide whether to send an RFC 6750 challenge, and
    # `Kemal::CSRFHandler` uses to decide whether a token-only request is exempt. An application
    # whose only bearer credential is its own — a gateway-issued key, a legacy token — used to
    # get neither, because there was nowhere to put it (`blueprints/0025`, TOK-04).
    getter bearer : RequestAuthenticator?

    # What decides whether a principal may perform an action, or `nil` when the application has
    # not configured authorization at all.
    #
    # Nil rather than a permissive default, and `Authz::DenyAll` rather than "allow" when
    # something is half-configured: an authorizer that permitted everything would turn a wiring
    # mistake into an open application, and a nil is what makes `env.auth.authorize!` say so
    # loudly instead of guessing.
    #
    # Built by the application rather than assembled from parameters here — `Authz::RBAC.new`
    # takes a role catalog, and a catalog is code that belongs next to the routes it guards.
    getter authorizer : Authz::Authorizer?

    def initialize(
      @accounts : Accounts::Repository,
      sessions : Sessions::Repository,
      @hasher : Passwords::Hasher = Passwords::BcryptHasher.new,
      @clock : Clock = SystemClock.new,
      @random : RandomSource = SecureRandomSource.new,
      @rate_limiter : RateLimiter = NullRateLimiter.new,
      session_config : Sessions::Config = Sessions::Config.new,
      @cookie : Sessions::CookieConfig = Sessions::CookieConfig.new,
      @csrf : CSRFConfig? = nil,
      @action_tokens : Accounts::ActionTokenRepository? = nil,
      @remember_tokens : Sessions::RememberRepository? = nil,
      @api_tokens : ApiTokens::Repository? = nil,
      api_token_prefix : String = ApiTokens::Service::DEFAULT_PREFIX,
      @jwt : JWT::Validator? = nil,
      bearer_authenticators : Array(RequestAuthenticator) = [] of RequestAuthenticator,
      @authorizer : Authz::Authorizer? = nil,
      @mfa_factors : MFA::Repository? = nil,
      mfa_secret_key : Secret? = nil,
      mfa_issuer : String? = nil,
      mfa_drift : Int32 = 1,
      notifier : Accounts::Notifier? = nil,
      password_policy : Passwords::Policy? = nil,
      @remember_cookie : Sessions::CookieConfig = Sessions::CookieConfig.new(
        name: "__Host-kemal_identity_remember"
      ),
      @remember_ttl : Time::Span = 30.days,
      reset_ttl : Time::Span = 1.hour,
      confirmation_ttl : Time::Span = 1.day,
    )
      @session_repository = sessions

      @sessions = Sessions::Service.new(
        sessions: sessions, clock: @clock, random: @random, config: session_config
      )

      @passwords = Passwords::Authenticator.new(
        accounts: @accounts, hasher: @hasher, clock: @clock, rate_limiter: @rate_limiter
      )

      @password_policy = password_policy || Passwords::LengthPolicy.for(@hasher)

      if api_tokens = @api_tokens
        @api = ApiTokens::Service.new(
          tokens: api_tokens, clock: @clock, random: @random, prefix: api_token_prefix
        )
      end

      # Opaque tokens first: they are the credential this shard recommends, and their shape
      # check is exact rather than a bound, so the fall-through to JWT costs a comparison.
      #
      # An application's own authenticators come after both, in the order it listed them.
      # Measured rather than chosen: with every family checking shape exactly, inserting a
      # consumer's authenticator at any position among the built-ins produces an identical answer
      # for every credential — so "last, in order" is deterministic without an interleaving API,
      # and it means a loose shape check in a consumer's authenticator cannot shadow a credential
      # this shard issued.
      candidates = ([@api, @jwt].compact.map(&.as(RequestAuthenticator)) + bearer_authenticators)

      @bearer =
        case candidates.size
        when 0 then nil
        when 1 then candidates.first
        else        AuthenticatorChain.new(candidates)
        end

      if remember_tokens
        @remember = Sessions::RememberService.new(
          remember: remember_tokens,
          accounts: @accounts,
          sessions: @sessions,
          clock: @clock,
          random: @random,
          notifier: notifier,
          ttl: @remember_ttl,
        )
      end

      @mfa = build_mfa(mfa_secret_key, mfa_issuer, mfa_drift)

      # Built only when everything they need is present. Half a reset flow is worse than none:
      # it would accept a request and quietly drop it.
      if action_tokens && notifier
        @accounts_service = Accounts::Service.new(
          accounts: @accounts,
          tokens: action_tokens,
          notifier: notifier,
          sessions: @sessions,
          hasher: @hasher,
          policy: @password_policy,
          clock: @clock,
          random: @random,
          rate_limiter: @rate_limiter,
          remember: @remember,
          reset_ttl: reset_ttl,
          confirmation_ttl: confirmation_ttl,
        )
      end
    end

    # The account lifecycle service, or a clear error rather than a nil.
    def accounts_service! : Accounts::Service
      service = @accounts_service
      return service if service

      raise ConfigurationError.new(
        "password reset and email confirmation are not configured. Pass action_tokens: and " \
        "notifier: to KemalIdentity.configure."
      )
    end

    # Opaque personal access tokens, or a clear error rather than a nil.
    def api! : ApiTokens::Service
      service = @api
      return service if service

      raise ConfigurationError.new(
        "API tokens are not configured. Pass api_tokens: to KemalIdentity.configure."
      )
    end

    # Same rule as the reset flow: built only when everything it needs is present, because half
    # an MFA setup would accept an enrolment and then have nowhere to put it.
    private def build_mfa(key : Secret?, issuer : String?, drift : Int32) : MFA::Service?
      factors = @mfa_factors

      if factors.nil? || key.nil? || issuer.nil?
        if factors || key || issuer
          raise ConfigurationError.new(
            "MFA needs all three of mfa_factors:, mfa_secret_key: and mfa_issuer:. Configuring " \
            "some of them would accept an enrolment and then have nowhere to put it."
          )
        end

        return
      end

      MFA::Service.new(
        factors: factors,
        secret_box: MFA::AesSecretBox.new(key, @random),
        clock: @clock,
        random: @random,
        issuer: issuer,
        rate_limiter: @rate_limiter,
        # So that redeeming a recovery code ends the account's other sessions, which
        # `docs/02-security-model.md` requires.
        sessions: @sessions,
        drift: drift,
      )
    end

    # Second factors, or a clear error rather than a nil.
    def mfa! : MFA::Service
      service = @mfa
      return service if service

      raise ConfigurationError.new(
        "MFA is not configured. Pass mfa_factors:, mfa_secret_key: and mfa_issuer: to " \
        "KemalIdentity.configure."
      )
    end

    # The authorizer, or a clear error rather than a nil.
    def authorizer! : Authz::Authorizer
      authorizer = @authorizer
      return authorizer if authorizer

      raise ConfigurationError.new(
        "authorization is not configured. Pass authorizer: KemalIdentity::Authz::RBAC.new(...) " \
        "to KemalIdentity.configure."
      )
    end

    # Remember-me, or a clear error rather than a nil.
    def remember! : Sessions::RememberService
      service = @remember
      return service if service

      raise ConfigurationError.new(
        "remember-me is not configured. Pass remember_tokens: to KemalIdentity.configure."
      )
    end

    # A policy whose ceiling comes from this application's hasher rather than from a number
    # copied out of a document. v0.1 has no flow that calls it — there is no registration and
    # no password change — so it is built on demand rather than held.
    def password_policy(
      min_length : Int32 = Passwords::LengthPolicy::DEFAULT_MIN_LENGTH,
      breach_check : Passwords::BreachCheck = Passwords::NullBreachCheck.new,
    ) : Passwords::LengthPolicy
      Passwords::LengthPolicy.for(@hasher, min_length: min_length, breach_check: breach_check)
    end
  end

  @@app : Application?

  # Builds the application and installs it as the process-wide one.
  #
  # Called once, at boot, before any request is served. The handlers reach for
  # `KemalIdentity.app`, so an application that never calls this gets a clear error rather
  # than a nil.
  def self.configure(
    accounts : Accounts::Repository,
    sessions : Sessions::Repository,
    hasher : Passwords::Hasher = Passwords::BcryptHasher.new,
    clock : Clock = SystemClock.new,
    random : RandomSource = SecureRandomSource.new,
    rate_limiter : RateLimiter = NullRateLimiter.new,
    session_config : Sessions::Config = Sessions::Config.new,
    cookie : Sessions::CookieConfig = Sessions::CookieConfig.new,
    csrf : CSRFConfig? = nil,
    action_tokens : Accounts::ActionTokenRepository? = nil,
    remember_tokens : Sessions::RememberRepository? = nil,
    api_tokens : ApiTokens::Repository? = nil,
    api_token_prefix : String = ApiTokens::Service::DEFAULT_PREFIX,
    jwt : JWT::Validator? = nil,
    bearer_authenticators : Array(RequestAuthenticator) = [] of RequestAuthenticator,
    authorizer : Authz::Authorizer? = nil,
    mfa_factors : MFA::Repository? = nil,
    mfa_secret_key : Secret? = nil,
    mfa_issuer : String? = nil,
    mfa_drift : Int32 = 1,
    notifier : Accounts::Notifier? = nil,
    password_policy : Passwords::Policy? = nil,
    remember_cookie : Sessions::CookieConfig = Sessions::CookieConfig.new(
      name: "__Host-kemal_identity_remember"
    ),
    remember_ttl : Time::Span = 30.days,
    reset_ttl : Time::Span = 1.hour,
    confirmation_ttl : Time::Span = 1.day,
  ) : Application
    self.app = Application.new(
      accounts: accounts,
      sessions: sessions,
      hasher: hasher,
      clock: clock,
      random: random,
      rate_limiter: rate_limiter,
      session_config: session_config,
      cookie: cookie,
      csrf: csrf,
      action_tokens: action_tokens,
      remember_tokens: remember_tokens,
      api_tokens: api_tokens,
      jwt: jwt,
      bearer_authenticators: bearer_authenticators,
      authorizer: authorizer,
      mfa_factors: mfa_factors,
      mfa_secret_key: mfa_secret_key,
      mfa_issuer: mfa_issuer,
      mfa_drift: mfa_drift,
      api_token_prefix: api_token_prefix,
      notifier: notifier,
      password_policy: password_policy,
      remember_cookie: remember_cookie,
      remember_ttl: remember_ttl,
      reset_ttl: reset_ttl,
      confirmation_ttl: confirmation_ttl,
    )
  end

  # Installs an already-built application. Useful when the application object is assembled
  # elsewhere, and in specs.
  def self.app=(app : Application) : Application
    @@app = app
  end

  # The configured application.
  #
  # Raises `ConfigurationError` rather than returning nil: reaching this unconfigured means a
  # handler is about to authenticate a request against nothing, and that must be a loud
  # startup-shaped failure rather than a nil check at every call site.
  def self.app : Application
    app = @@app
    return app if app

    raise ConfigurationError.new(
      "KemalIdentity is not configured. Call KemalIdentity.configure(accounts: ..., sessions: ...) at boot."
    )
  end

  # Whether an application has been installed. For a handler that wants to fail helpfully.
  def self.configured? : Bool
    !@@app.nil?
  end
end

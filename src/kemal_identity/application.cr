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
      action_tokens : Accounts::ActionTokenRepository? = nil,
      remember_tokens : Sessions::RememberRepository? = nil,
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

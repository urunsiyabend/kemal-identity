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
    )
      @session_repository = sessions

      @sessions = Sessions::Service.new(
        sessions: sessions, clock: @clock, random: @random, config: session_config
      )

      @passwords = Passwords::Authenticator.new(
        accounts: @accounts, hasher: @hasher, clock: @clock, rate_limiter: @rate_limiter
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

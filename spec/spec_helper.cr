require "spec"
require "../src/kemal_identity"

require "./support/fiber_join"
require "./support/or_fail"
require "./support/outcome_matchers"
require "./support/test_clock"
require "./support/deterministic_random"
require "./support/fast_test_hasher"
require "./support/legacy_password_doubles"
require "./support/memory_account_repository"
require "./support/memory_session_repository"
require "./support/memory_action_token_repository"
require "./support/recording_notifier"
require "./support/memory_remember_repository"
require "./support/memory_api_token_repository"
require "./support/memory_revocation_store"
require "./support/memory_mfa_repository"
require "./support/memory_link_repository"
require "./support/memory_authz_repository"
require "./support/rsa_test_key"
require "./support/jwt_forge"

require "./contract/clock_contract"
require "./contract/random_source_contract"
require "./contract/hasher_contract"
require "./contract/account_repository_contract"
require "./contract/session_repository_contract"
require "./contract/rate_limiter_contract"
require "./contract/action_token_repository_contract"
require "./contract/remember_repository_contract"
require "./contract/api_token_repository_contract"
require "./contract/mfa_repository_contract"
require "./contract/oidc_link_repository_contract"
require "./contract/authz_repository_contract"

module KemalIdentity::SpecHelper
  # A fixed instant every spec can anchor on, so no spec depends on the wall clock.
  FIXED_NOW = Time.utc(2026, 8, 24, 12, 0, 0)

  # A service wired entirely to test doubles: a clock that only moves when a spec moves it,
  # a seeded RNG, and in-memory repositories that pass the same contracts as PostgreSQL.
  record Harness,
    clock : KemalIdentity::Testing::TestClock,
    random : KemalIdentity::Testing::DeterministicRandom,
    accounts : KemalIdentity::Testing::MemoryAccountRepository,
    sessions : KemalIdentity::Testing::MemorySessionRepository,
    service : KemalIdentity::Sessions::Service

  def self.harness(
    config : KemalIdentity::Sessions::Config = KemalIdentity::Sessions::Config.new,
    accounts : Array(KemalIdentity::Accounts::Account) = [] of KemalIdentity::Accounts::Account,
    now : Time = FIXED_NOW,
    seed : Int32 = 1,
  ) : Harness
    clock = KemalIdentity::Testing::TestClock.new(now)
    random = KemalIdentity::Testing::DeterministicRandom.new(seed: seed)
    account_repo = KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
    session_repo = KemalIdentity::Testing::MemorySessionRepository.new(account_repo)

    Harness.new(
      clock: clock,
      random: random,
      accounts: account_repo,
      sessions: session_repo,
      service: KemalIdentity::Sessions::Service.new(
        sessions: session_repo, clock: clock, random: random, config: config
      ),
    )
  end

  # A fully wired account service, on doubles throughout.
  record AccountHarness,
    clock : KemalIdentity::Testing::TestClock,
    accounts : KemalIdentity::Testing::MemoryAccountRepository,
    tokens : KemalIdentity::Testing::MemoryActionTokenRepository,
    sessions : KemalIdentity::Testing::MemorySessionRepository,
    session_service : KemalIdentity::Sessions::Service,
    remember_service : KemalIdentity::Sessions::RememberService,
    notifier : KemalIdentity::Testing::RecordingNotifier,
    hasher : KemalIdentity::Testing::FastTestHasher,
    service : KemalIdentity::Accounts::Service

  def self.account_harness(
    accounts : Array(KemalIdentity::Accounts::Account)? = nil,
    rate_limiter : KemalIdentity::RateLimiter = KemalIdentity::NullRateLimiter.new,
    reset_ttl : Time::Span = 1.hour,
    now : Time = FIXED_NOW,
    seed : Int32 = 1,
  ) : AccountHarness
    clock = KemalIdentity::Testing::TestClock.new(now)
    random = KemalIdentity::Testing::DeterministicRandom.new(seed: seed)
    hasher = KemalIdentity::Testing::FastTestHasher.new
    notifier = KemalIdentity::Testing::RecordingNotifier.new

    account_repo = KemalIdentity::Testing::MemoryAccountRepository.new(accounts || [account])
    token_repo = KemalIdentity::Testing::MemoryActionTokenRepository.new
    session_repo = KemalIdentity::Testing::MemorySessionRepository.new(account_repo)

    session_service = KemalIdentity::Sessions::Service.new(
      sessions: session_repo, clock: clock, random: random
    )

    remember_service = KemalIdentity::Sessions::RememberService.new(
      remember: KemalIdentity::Testing::MemoryRememberRepository.new,
      accounts: account_repo, sessions: session_service,
      clock: clock, random: random, notifier: notifier
    )

    AccountHarness.new(
      clock: clock,
      accounts: account_repo,
      tokens: token_repo,
      sessions: session_repo,
      session_service: session_service,
      remember_service: remember_service,
      notifier: notifier,
      hasher: hasher,
      service: KemalIdentity::Accounts::Service.new(
        accounts: account_repo,
        tokens: token_repo,
        notifier: notifier,
        sessions: session_service,
        hasher: hasher,
        policy: KemalIdentity::Passwords::LengthPolicy.for(hasher),
        clock: clock,
        random: random,
        rate_limiter: rate_limiter,
        remember: remember_service,
        reset_ttl: reset_ttl,
      ),
    )
  end

  def self.account(
    id : String = "a1",
    login : String = "ada@example.com",
    tenant_id : String? = nil,
    auth_version : Int32 = 1,
    disabled_at : Time? = nil,
    password_digest : String? = "digest",
    now : Time = FIXED_NOW,
  ) : KemalIdentity::Accounts::Account
    KemalIdentity::Accounts::Account.new(
      id: id,
      normalized_login: login,
      tenant_id: tenant_id,
      auth_version: auth_version,
      disabled_at: disabled_at,
      password_digest: password_digest,
      password_scheme: password_digest.nil? ? nil : "test",
      created_at: now,
      updated_at: now,
    )
  end

  def self.principal(
    subject : String = "account-1",
    assurance : KemalIdentity::AssuranceLevel = KemalIdentity::AssuranceLevel::Password,
    authenticated_at : Time = FIXED_NOW,
    session_id : String? = "session-1",
    mfa_verified_at : Time? = nil,
    tenant_id : String? = nil,
  ) : KemalIdentity::Principal
    KemalIdentity::Principal.new(
      subject: subject,
      assurance: assurance,
      authenticated_at: authenticated_at,
      session_id: session_id,
      mfa_verified_at: mfa_verified_at,
      tenant_id: tenant_id,
    )
  end
end

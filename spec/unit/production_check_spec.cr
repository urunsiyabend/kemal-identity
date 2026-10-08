require "../spec_helper"

# The opt-in production check. Every gap it names is a default, or an easy configuration, that
# turns a login or second-factor protection off without anything saying so. Nothing here
# changes what `configure` accepts: an application that never asks sees exactly v0.12.
private def build_app(
  rate_limiter : KemalIdentity::RateLimiter = KemalIdentity::NullRateLimiter.new,
  cookie : KemalIdentity::Sessions::CookieConfig = KemalIdentity::Sessions::CookieConfig.new,
  mfa : Bool = false,
  mfa_max_consecutive_failures : Int32? = 100,
  mfa_recovery_rate_limiter : KemalIdentity::RateLimiter? = nil,
) : KemalIdentity::Application
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new

  KemalIdentity::Application.new(
    accounts: accounts,
    sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
    hasher: KemalIdentity::Testing::FastTestHasher.new,
    rate_limiter: rate_limiter,
    cookie: cookie,
    mfa_factors: mfa ? KemalIdentity::Testing::MemoryMfaRepository.new : nil,
    mfa_secret_key: mfa ? KemalIdentity::Secret.new("mfa-secret-box-key-of-32-bytes!!") : nil,
    mfa_issuer: mfa ? "Example" : nil,
    mfa_max_consecutive_failures: mfa_max_consecutive_failures,
    mfa_recovery_rate_limiter: mfa_recovery_rate_limiter,
  )
end

# What an application writes over its own store. The check cannot see inside it, so it trusts it.
private class ApplicationOwnLimiter < KemalIdentity::RateLimiter
  def consume(key : String) : KemalIdentity::Verdict
    KemalIdentity::Verdict.allow
  end

  def reset(key : String) : Nil
  end
end

private def window : KemalIdentity::FixedWindowRateLimiter
  KemalIdentity::FixedWindowRateLimiter.new(limit: 10, window: 5.minutes)
end

describe "KemalIdentity production check" do
  it "names the unthrottled login of a default configuration" do
    build_app.production_gaps.should eq([KemalIdentity::ProductionGap::UnthrottledLogin])
  end

  it "names an in-memory limiter as process-local" do
    build_app(rate_limiter: window).production_gaps
      .should eq([KemalIdentity::ProductionGap::ProcessLocalRateLimiter])

    backoff = KemalIdentity::ExponentialBackoffRateLimiter.new
    build_app(rate_limiter: backoff).production_gaps
      .should eq([KemalIdentity::ProductionGap::ProcessLocalRateLimiter])
  end

  it "names a fail-open login, and still sees what it wraps" do
    gaps = build_app(rate_limiter: KemalIdentity::FailOpenRateLimiter.new(window)).production_gaps

    gaps.should contain(KemalIdentity::ProductionGap::FailOpenLogin)
    gaps.should contain(KemalIdentity::ProductionGap::ProcessLocalRateLimiter)
  end

  it "names a fail-open wrapper around nothing at all as unthrottled too" do
    limiter = KemalIdentity::FailOpenRateLimiter.new(KemalIdentity::NullRateLimiter.new)
    gaps = build_app(rate_limiter: limiter).production_gaps

    gaps.should contain(KemalIdentity::ProductionGap::UnthrottledLogin)
    gaps.should contain(KemalIdentity::ProductionGap::FailOpenLogin)
  end

  it "trusts a limiter the application wrote" do
    build_app(rate_limiter: ApplicationOwnLimiter.new).production_gaps.should be_empty
  end

  it "names an MFA setup with no lifetime bound on guessing" do
    build_app(rate_limiter: ApplicationOwnLimiter.new, mfa: true, mfa_max_consecutive_failures: nil)
      .production_gaps.should eq([KemalIdentity::ProductionGap::UnboundedMfaGuessing])
  end

  it "names a recovery path that was explicitly left unthrottled" do
    build_app(
      rate_limiter: ApplicationOwnLimiter.new, mfa: true,
      mfa_recovery_rate_limiter: KemalIdentity::NullRateLimiter.new
    ).production_gaps.should eq([KemalIdentity::ProductionGap::UnthrottledMfaRecovery])
  end

  it "sees an unthrottled recovery path through a fail-open wrapper" do
    recovery = KemalIdentity::FailOpenRateLimiter.new(KemalIdentity::NullRateLimiter.new)

    build_app(rate_limiter: ApplicationOwnLimiter.new, mfa: true, mfa_recovery_rate_limiter: recovery)
      .production_gaps.should eq([KemalIdentity::ProductionGap::UnthrottledMfaRecovery])
  end

  it "names an in-memory recovery limiter as process-local, even beside a shared login limiter" do
    build_app(rate_limiter: ApplicationOwnLimiter.new, mfa: true, mfa_recovery_rate_limiter: window)
      .production_gaps.should eq([KemalIdentity::ProductionGap::ProcessLocalRateLimiter])
  end

  # Recovery inherits `rate_limiter:` unless given its own, so the default configuration with MFA
  # leaves both unthrottled — and the fix is the login limiter, not a recovery argument nobody
  # passed.
  it "names an inherited unthrottled recovery path, and says where it was inherited from" do
    gaps = build_app(mfa: true).production_gaps
    gaps.should eq([KemalIdentity::ProductionGap::UnthrottledLogin, KemalIdentity::ProductionGap::UnthrottledMfaRecovery])
    KemalIdentity::ProductionGap::UnthrottledMfaRecovery.remedy.should contain("rate_limiter:")
  end

  it "says nothing about MFA when MFA is not configured" do
    build_app(rate_limiter: ApplicationOwnLimiter.new, mfa_max_consecutive_failures: nil)
      .production_gaps.should be_empty
  end

  it "names a session cookie that travels over plain HTTP" do
    cookie = KemalIdentity::Sessions::CookieConfig.new(
      name: "dev_session", secure: false, allow_insecure: true
    )

    build_app(rate_limiter: ApplicationOwnLimiter.new, cookie: cookie).production_gaps
      .should eq([KemalIdentity::ProductionGap::InsecureSessionCookie])
  end

  describe ".validate_production!" do
    it "names every gap in one error, with its fix" do
      app = build_app(rate_limiter: KemalIdentity::FailOpenRateLimiter.new(window), mfa: true,
        mfa_max_consecutive_failures: nil)

      error = expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity.validate_production!(app)
      end

      message = error.message.to_s
      message.should contain("FailOpenLogin")
      message.should contain("ProcessLocalRateLimiter")
      message.should contain("UnboundedMfaGuessing")
      message.should contain("mfa_max_consecutive_failures")
    end

    it "accepts a gap the deployment has decided to live with" do
      app = build_app(rate_limiter: window)

      KemalIdentity.validate_production!(
        app, accept: [KemalIdentity::ProductionGap::ProcessLocalRateLimiter]
      ).should be_nil
    end

    it "still refuses the gaps that were not accepted" do
      app = build_app(rate_limiter: window, mfa: true, mfa_max_consecutive_failures: nil)

      error = expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity.validate_production!(
          app, accept: [KemalIdentity::ProductionGap::ProcessLocalRateLimiter]
        )
      end

      error.message.to_s.should_not contain("ProcessLocalRateLimiter")
      error.message.to_s.should contain("UnboundedMfaGuessing")
    end

    it "passes a configuration with every protection on" do
      KemalIdentity.validate_production!(build_app(rate_limiter: ApplicationOwnLimiter.new, mfa: true))
        .should be_nil
    end
  end
end

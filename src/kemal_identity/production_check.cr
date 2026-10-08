module KemalIdentity
  # A protection that is off, or weaker than it looks, in a configuration that boots fine.
  #
  # Every one of these is either a default or one argument away from one, and each was chosen
  # for a reason the shard still stands by: it cannot pick a login limit on an application's
  # behalf, and disabling a factor after N failures would lock out people carrying years of
  # typos. What was missing is a way to *ask* — so that "rate limiting is off" is something a
  # deployment finds out at boot rather than from an incident review.
  enum ProductionGap
    # `rate_limiter:` is a `NullRateLimiter`, the default: every login, reset and second-factor
    # attempt is allowed, so bcrypt is a CPU lever and guessing is unmetered.
    UnthrottledLogin

    # `rate_limiter:` is a `FailOpenRateLimiter`: while its store is down the login path runs
    # unmetered, which is what an attacker gets by overwhelming the store
    # (`blueprints/0023-rate-limiter-store-failure.md`).
    FailOpenLogin

    # `rate_limiter:` is one of the in-memory limiters. Each process counts on its own, so the
    # effective limit is the configured one times the number of processes — 2.2× with six
    # workers, measured (`blueprints/0025`, OPS-01). Correct for exactly one process.
    ProcessLocalRateLimiter

    # MFA is configured with no `mfa_max_consecutive_failures:`, so a factor is never disabled
    # however long it is guessed at, and NIST SP 800-63B's SHALL is unmet
    # (`blueprints/0029-second-factor-rate-limiting.md`).
    UnboundedMfaGuessing

    # MFA is configured and `mfa_recovery_rate_limiter:` is a `NullRateLimiter`, so recovery
    # codes can be guessed without limit while the TOTP path is throttled.
    UnthrottledMfaRecovery

    # The session cookie, or the remember-me cookie when remember-me is on, is not `Secure`.
    # The `allow_insecure: true` escape hatch is for local HTTP development and nothing else.
    InsecureSessionCookie

    # What to change, for the error message. Kept beside the members so a new one cannot be
    # added without saying how to close it.
    def remedy : String
      case self
      in UnthrottledLogin
        "pass rate_limiter: — KemalIdentity::Postgres::FixedWindowRateLimiter is shared " \
        "across processes"
      in FailOpenLogin
        "keep the login limiter fail-closed; wrap only less sensitive call sites in " \
        "FailOpenRateLimiter"
      in ProcessLocalRateLimiter
        "use a shared limiter such as KemalIdentity::Postgres::FixedWindowRateLimiter, or " \
        "accept this gap if the deployment is genuinely one process"
      in UnboundedMfaGuessing
        "pass mfa_max_consecutive_failures: (NIST SP 800-63B allows at most 100)"
      in UnthrottledMfaRecovery
        "drop mfa_recovery_rate_limiter: to reuse rate_limiter:, or pass a real limiter"
      in InsecureSessionCookie
        "use the default Secure cookie; secure: false with allow_insecure: true is for " \
        "local HTTP only"
      end
    end
  end

  class Application
    # Every `ProductionGap` in this configuration, in declaration order. Empty when none.
    #
    # Only limiters this shard ships are recognised. An application's own limiter is trusted,
    # because nothing here can see whether its store is shared — which is also why the
    # `FailOpenRateLimiter` is unwrapped: the wrapper is ours, and so may be what it wraps.
    def production_gaps : Array(ProductionGap)
      gaps = [] of ProductionGap

      limiter = @rate_limiter
      inner = limiter.is_a?(FailOpenRateLimiter) ? limiter.inner : limiter

      gaps << ProductionGap::UnthrottledLogin if inner.is_a?(NullRateLimiter)
      gaps << ProductionGap::FailOpenLogin if limiter.is_a?(FailOpenRateLimiter)
      gaps << ProductionGap::ProcessLocalRateLimiter if process_local?(inner)

      if mfa = @mfa
        gaps << ProductionGap::UnboundedMfaGuessing if mfa.max_consecutive_failures.nil?
        gaps << ProductionGap::UnthrottledMfaRecovery if mfa.recovery_rate_limiter.is_a?(NullRateLimiter)
      end

      insecure = !@cookie.secure? || (!@remember.nil? && !@remember_cookie.secure?)
      gaps << ProductionGap::InsecureSessionCookie if insecure

      gaps
    end

    private def process_local?(limiter : RateLimiter) : Bool
      limiter.is_a?(FixedWindowRateLimiter) || limiter.is_a?(ExponentialBackoffRateLimiter)
    end
  end

  # Raises `ConfigurationError` naming every `ProductionGap` in `app` that `accept` does not.
  #
  # Opt in by calling it at boot, next to `Kemal.validate_middleware_order!`:
  #
  # ```
  # KemalIdentity.configure(...)
  # KemalIdentity.validate_production!
  # ```
  #
  # ### Why it is not run by `configure`
  #
  # Every gap it names is a configuration that boots today, and some of them are right for
  # somebody — a single-process deployment is well served by `FixedWindowRateLimiter`. Running
  # this automatically would turn a working deployment into one that fails to start on upgrade,
  # which is the breakage a minor release must not cause. So it is a question an application
  # asks, as `blueprints/0034` decided for the handler chain.
  #
  # ### Why there is an `accept`
  #
  # The handler-chain check has no silencing list, because an application that disagrees with
  # it simply does not ask. That does not carry over: these gaps are independent, and declining
  # the whole check to live with one of them would hide the other five. `accept` names the one
  # decision, in code, where a reviewer can see it.
  def self.validate_production!(
    app : Application = KemalIdentity.app,
    accept : Enumerable(ProductionGap) = [] of ProductionGap,
  ) : Nil
    gaps = app.production_gaps.reject { |gap| accept.includes?(gap) }
    return if gaps.empty?

    raise ConfigurationError.new(
      "this KemalIdentity configuration leaves protections off for production:\n" \
      "  - #{gaps.map { |gap| "#{gap}: #{gap.remedy}" }.join("\n  - ")}\n" \
      "Fix them, or pass accept: [KemalIdentity::ProductionGap::...] for a gap this " \
      "deployment has decided to live with."
    )
  end
end

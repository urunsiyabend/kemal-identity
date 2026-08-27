module KemalIdentity::MFA
  # Enrolling, proving and removing second factors.
  #
  # ### What makes TOTP safe is here, not in `TOTP`
  #
  # `TOTP` computes and compares six digits. Six digits is one of a million, a code is valid
  # for its whole period plus the drift either side, and neither of those facts is a problem
  # until you notice that nothing so far stops an attacker submitting codes in a loop. Three
  # things do, and all three live in this class:
  #
  # 1. **A rate limit on every attempt**, consumed before the code is checked. Without it, a
  #    million guesses against a 90-second window is a few minutes of traffic.
  # 2. **Single use.** A counter that verified once is spent, atomically, so a code read over
  #    somebody's shoulder is worthless by the time it is typed a second time.
  # 3. **Confirmation before the factor counts.** A secret that was generated but never proved
  #    is a secret nobody may actually hold, and treating it as a factor is how a person locks
  #    themselves out of their own account.
  #
  # ### Freshness is the caller's to enforce
  #
  # `docs/06-roadmap.md` requires fresh authentication for disabling MFA, replacing a factor
  # and using a recovery code. That check belongs at the route — `env.auth.require_fresh!` —
  # and not here, because this class takes an account id and has no request to inspect. The
  # methods that need it say so, and `examples/` shows the guard.
  class Service
    # Attempts allowed before the limiter is consulted for a verdict, per account.
    DEFAULT_QUOTA_PREFIX = "mfa"

    # How many recovery codes to issue at once.
    #
    # Ten is the usual number, and the trade-off is real in both directions: too few and the
    # person runs out at the worst moment, too many and the printed list is a long-lived
    # bypass sitting in somebody's downloads folder.
    DEFAULT_RECOVERY_CODES = 10

    # Bytes of entropy per recovery code.
    #
    # The full `RandomSource::TOKEN_BYTES`, which is the floor `docs/02-security-model.md` sets
    # for any secret handed to a browser. A recovery code skips the second factor outright, so
    # it is the last thing that should be granted an exception to that rule — and the usual
    # argument for a shorter one, that people type these by hand, is answered by printing them
    # in groups: `#redeem_recovery_code` strips the spacing back out.
    RECOVERY_CODE_BYTES = RandomSource::TOKEN_BYTES

    getter drift : Int32

    def initialize(
      @factors : Repository,
      @secret_box : SecretBox,
      @clock : Clock,
      @random : RandomSource,
      @issuer : String,
      @rate_limiter : RateLimiter = NullRateLimiter.new,
      @sessions : Sessions::Service? = nil,
      @drift : Int32 = 1,
      @digits : Int32 = TOTP::DEFAULT_DIGITS,
      @period : Time::Span = TOTP::DEFAULT_PERIOD,
      @algorithm : TOTP::Algorithm = TOTP::Algorithm::SHA1,
      @recovery_code_count : Int32 = DEFAULT_RECOVERY_CODES,
      @quota_prefix : String = DEFAULT_QUOTA_PREFIX,
    )
      raise ConfigurationError.new("issuer must not be empty") if @issuer.blank?
      raise ConfigurationError.new("issuer must not contain a colon") if @issuer.includes?(':')
      raise ConfigurationError.new("drift must not be negative") if @drift < 0

      unless TOTP::PERMITTED_DIGITS.includes?(@digits)
        raise ConfigurationError.new(
          "digits must be one of #{TOTP::PERMITTED_DIGITS.join(", ")}, got #{@digits}"
        )
      end

      raise ConfigurationError.new("period must be positive") unless @period > Time::Span::ZERO

      if @recovery_code_count < 1
        raise ConfigurationError.new("recovery_code_count must be positive")
      end

      # Each step of tolerance multiplies the number of codes valid at any moment, and a wide
      # window is an authentication bypass with a limit on it rather than a convenience.
      if @drift > 2
        raise ConfigurationError.new(
          "drift must not exceed 2; a wider window multiplies the codes valid at any moment"
        )
      end
    end

    # Generates a secret and stores it unconfirmed, returning what to show the person.
    #
    # Nothing is protected yet. The factor does not count until `#confirm` proves that whoever
    # asked for it can actually produce a code from it.
    #
    # `label` is what the person will see in their authenticator app next to the six digits,
    # so the login is the usual choice.
    def enrol(account : Accounts::Account, label : String) : PendingEnrolment
      raise ArgumentError.new("cannot enrol a disabled account") if account.disabled?
      raise ArgumentError.new("label must not be empty") if label.blank?
      raise ArgumentError.new("label must not contain a colon") if label.includes?(':')

      secret = @random.bytes(RandomSource::TOKEN_BYTES)

      factor = Factor.new(
        id: @random.token,
        account_id: account.id,
        sealed_secret: @secret_box.seal(secret),
        created_at: @clock.now,
        label: label,
        digits: @digits,
        period: @period,
        algorithm: @algorithm,
      )

      @factors.create_factor(factor)

      Log.info &.emit("mfa.enrolment_started", subject: account.id, factor: factor.id)

      PendingEnrolment.new(
        factor: factor,
        provisioning_uri: TOTP.provisioning_uri(
          secret,
          issuer: @issuer,
          label: label,
          period: @period,
          digits: @digits,
          algorithm: @algorithm,
        ),
      )
    end

    # Finishes enrolment by checking a code from the new factor.
    #
    # Returns `nil` when the code does not verify, and `Confirmed` when it does — carrying
    # recovery codes if this is what turned MFA on for the account. Rate limited like any other
    # code submission: an unconfirmed factor is still a guessable secret.
    def confirm(factor_id : String, code : String) : Confirmed?
      factor = @factors.find_factor(factor_id)
      return if factor.nil?
      return if factor.confirmed?

      verdict = @rate_limiter.consume(quota_key(factor.account_id))
      return unless verdict.allowed?

      counter = match(factor, code)

      if counter.nil?
        Log.info &.emit("mfa.confirmation_failed", subject: factor.account_id, factor: factor.id)
        return
      end

      return unless @factors.confirm_factor(factor.id, counter, @clock.now)

      @rate_limiter.reset(quota_key(factor.account_id))

      confirmed = @factors.find_factor(factor.id) || factor

      Log.info &.emit("mfa.enabled", subject: factor.account_id, factor: factor.id)

      # Only when this is what turned MFA on. Re-enrolling a second device must not silently
      # void the codes the person already wrote down.
      codes =
        if @factors.unused_recovery_codes(factor.account_id).zero?
          issue_recovery_codes(factor.account_id)
        else
          [] of Secret
        end

      Confirmed.new(factor: confirmed, recovery_codes: codes)
    end

    # Checks a code against every confirmed factor on the account.
    #
    # The attempt is counted **before** any code is checked, for the reason `RateLimiter`
    # gives: counting afterwards means a wrong guess that times out is a free guess.
    #
    # Every confirmed factor is tried, because a person with two devices should be able to use
    # either, and only the factor that actually matched has its counter spent.
    def verify(account_id : String, code : String) : VerificationResult
      verdict = @rate_limiter.consume(quota_key(account_id))

      unless verdict.allowed?
        Log.warn &.emit("mfa.throttled", subject: account_id)
        return Failed.new(FailureReason::RateLimited, verdict.retry_after)
      end

      confirmed = @factors.factors_for_account(account_id).select(&.confirmed?)
      return failure(account_id, FailureReason::InvalidCredential) if confirmed.empty?

      confirmed.each do |factor|
        counter = match(factor, code)
        next if counter.nil?

        # The code was right. Whether it may be *used* is a separate question, and the answer
        # is no if this counter has already been spent — which is the replay an attacker who
        # watched somebody type it is attempting.
        unless @factors.consume_counter(factor.id, counter, @clock.now)
          return failure(account_id, FailureReason::ReplayedToken, factor.id)
        end

        @rate_limiter.reset(quota_key(account_id))

        Log.info &.emit("mfa.verified", subject: account_id, factor: factor.id)

        return Verified.new(factor: factor)
      end

      failure(account_id, FailureReason::InvalidCredential)
    end

    # Spends a recovery code.
    #
    # The way back in when the phone is gone, and therefore a full bypass of the second factor:
    # rate limited like `#verify`, consumed atomically so two requests cannot both spend it,
    # and audited at **warning** level. A recovery code being used is either somebody's worst
    # day or an attacker's best one, and it is worth an alert either way.
    #
    # `docs/06-roadmap.md` requires fresh authentication for this; enforce it at the route.
    #
    # ### It signs the account's other sessions out
    #
    # `docs/02-security-model.md` lists MFA recovery among the events that revoke **all** of an
    # account's sessions, and the reason is the situation that produces one: somebody is
    # redeeming a code because they have lost the device, and "lost" and "taken" look identical
    # from here. Anything already signed in elsewhere is exactly what needs ending.
    #
    # `except_session_id` spares the session doing the redeeming, which is normally the one
    # half-way through a login. Pass it, or the person is signed out by their own recovery.
    # Requires a `Sessions::Service`; with none configured the codes still work and nothing is
    # revoked, which is a weaker arrangement and one an application has to choose deliberately.
    def redeem_recovery_code(
      account_id : String,
      code : String,
      except_session_id : String? = nil,
    ) : VerificationResult
      verdict = @rate_limiter.consume(quota_key(account_id))

      unless verdict.allowed?
        Log.warn &.emit("mfa.throttled", subject: account_id)
        return Failed.new(FailureReason::RateLimited, verdict.retry_after)
      end

      # Shape before hashing and before any I/O, as with every other bearer secret here.
      normalised = normalise_recovery_code(code)
      return failure(account_id, FailureReason::MalformedCredential) if normalised.nil?

      unless @factors.consume_recovery_code(account_id, normalised.digest, @clock.now)
        return failure(account_id, FailureReason::InvalidCredential)
      end

      @rate_limiter.reset(quota_key(account_id))

      remaining = @factors.unused_recovery_codes(account_id)

      Log.warn &.emit("mfa.recovery_code_used", subject: account_id, remaining: remaining)

      @sessions.try(&.revoke_all(account_id, except_id: except_session_id))

      Verified.new(by_recovery_code: true)
    end

    # Whether this account has at least one factor that has been proved.
    #
    # Unconfirmed factors deliberately do not count: a half-finished enrolment must not make
    # the login screen start demanding a code nobody can produce.
    def enrolled?(account_id : String) : Bool
      @factors.factors_for_account(account_id).any?(&.confirmed?)
    end

    # Every factor on the account, for a management screen. Unconfirmed ones included, since
    # that screen has to show what is half-finished.
    def factors(account_id : String) : Array(Factor)
      @factors.factors_for_account(account_id)
    end

    def unused_recovery_codes(account_id : String) : Int32
      @factors.unused_recovery_codes(account_id)
    end

    # Removes one factor. Requires fresh authentication at the route.
    #
    # Recovery codes are left alone: removing one of two devices is not "MFA is off", and
    # voiding the codes would be a surprise in the direction of locking somebody out.
    def remove(factor_id : String) : Bool
      factor = @factors.find_factor(factor_id)
      return false if factor.nil?
      return false unless @factors.delete_factor(factor_id)

      Log.info &.emit("mfa.factor_removed", subject: factor.account_id, factor: factor_id)

      true
    end

    # Turns MFA off for an account: every factor, and every recovery code with them.
    #
    # This lowers the account's security, so it is exactly the operation
    # `docs/06-roadmap.md` requires fresh authentication for. Audited at **warning** level —
    # an attacker who has hijacked a session will try this before anything else.
    def disable(account_id : String) : Int32
      removed = @factors.delete_factors_for_account(account_id)

      # Codes that outlive the factors they were issued alongside are a bypass of a control
      # that no longer exists.
      @factors.replace_recovery_codes(account_id, [] of RecoveryCode)

      Log.warn &.emit("mfa.disabled", subject: account_id, factors: removed) if removed > 0

      removed
    end

    # Issues a fresh set of recovery codes, voiding whatever was there.
    #
    # Voiding is the point: this is what somebody calls when they think the old list leaked.
    # Requires fresh authentication at the route.
    def regenerate_recovery_codes(account_id : String) : Array(Secret)
      issue_recovery_codes(account_id)
    end

    private def issue_recovery_codes(account_id : String) : Array(Secret)
      now = @clock.now
      secrets = Array.new(@recovery_code_count) { Secret.new(@random.token(RECOVERY_CODE_BYTES)) }

      records = secrets.map do |secret|
        RecoveryCode.new(
          id: @random.token,
          account_id: account_id,
          code_digest: secret.digest,
          created_at: now,
        )
      end

      @factors.replace_recovery_codes(account_id, records)

      Log.info &.emit("mfa.recovery_codes_issued", subject: account_id, count: records.size)

      secrets
    end

    # The counter `code` matches for this factor, or `nil`.
    #
    # Returns `nil` rather than raising when the stored secret will not open: a row sealed
    # under a key the application no longer has is a data problem, and it must not become a
    # 500 on the login path. It is logged, because a factor that can never verify again is
    # something somebody has to be told about.
    private def match(factor : Factor, code : String) : Int64?
      secret = @secret_box.open?(factor.sealed_secret)

      if secret.nil?
        Log.error &.emit(
          "mfa.secret_unreadable", subject: factor.account_id, factor: factor.id
        )
        return
      end

      TOTP.match(
        secret,
        code,
        at: @clock.now,
        period: factor.period,
        digits: factor.digits,
        algorithm: factor.algorithm,
        drift: @drift,
      )
    end

    # Recovery codes are shown grouped and in one case; a person typing one back will not
    # reproduce the spacing, so it is stripped before hashing rather than being a reason to
    # reject them.
    private def normalise_recovery_code(code : String) : Secret?
      cleaned = code.delete { |char| char.ascii_whitespace? || char == '-' }

      return if cleaned.empty?
      return if cleaned.bytesize != RandomSource.token_length(RECOVERY_CODE_BYTES)
      return unless cleaned.matches?(OpaqueToken::PATTERN)

      Secret.new(cleaned)
    end

    private def failure(
      account_id : String,
      reason : FailureReason,
      factor_id : String? = nil,
    ) : Failed
      Log.info &.emit(
        "mfa.rejected", subject: account_id, reason: reason.to_s, factor: factor_id
      )

      Failed.new(reason)
    end

    # Keyed by account rather than by login: by the time a second factor is being asked for,
    # the account is known, and an attacker guessing codes is guessing against one account.
    private def quota_key(account_id : String) : String
      "#{@quota_prefix}:#{account_id}"
    end
  end
end

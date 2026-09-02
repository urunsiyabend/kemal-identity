module KemalIdentity::MFA
  # What kind of second factor a row holds.
  #
  # One member today. It exists so that adding WebAuthn is a new member and a new branch
  # rather than a new table and a second lookup on the verification path — the same reason
  # `AssuranceLevel` has gaps in it. Persisted as a `SMALLINT`: **append only, never
  # renumber**.
  enum FactorKind : Int16
    TOTP = 1
  end

  # One enrolled second factor.
  #
  # ### The parameters travel with the factor
  #
  # `digits`, `period` and `algorithm` are stored per row rather than read from configuration
  # at verification time. An application that later moves from six digits to eight, or from
  # SHA-1 to SHA-256, would otherwise break every already-enrolled authenticator at once — the
  # app on the phone keeps computing what it was given at enrolment, and nothing tells it
  # otherwise. Stored per row, a default change applies to new enrolments and leaves existing
  # ones working.
  struct Factor
    getter id : String
    getter account_id : String
    getter kind : FactorKind

    # What the person calls it, for a list of "your second factors". Never a secret.
    getter label : String

    # The TOTP shared secret, encrypted. See `SecretBox` for why this one is not a digest.
    getter sealed_secret : Bytes

    getter digits : Int32
    getter period : Time::Span
    getter algorithm : TOTP::Algorithm
    getter created_at : Time

    # When a code from this factor first verified, or `nil` while enrolment is unfinished.
    #
    # Enrolment is two steps on purpose. A secret that was generated but never proved is a
    # secret nobody may actually hold: a mis-scanned QR code, a clock two minutes out, an app
    # that silently failed to save. Treating it as a factor immediately is how a person locks
    # themselves out of their own account, so an unconfirmed factor never authenticates and
    # never counts towards "this account has MFA".
    getter confirmed_at : Time?

    # The highest TOTP counter this factor has been used at, or `nil` if never.
    #
    # The replay defence. Without it a code stays usable for its whole window plus the drift
    # either side, which is precisely the window an attacker who watched someone type it is
    # working in.
    getter last_used_counter : Int64?

    # How many times in a row a code has been offered for this factor and been wrong.
    #
    # Per factor rather than per account, because that is the thing NIST SP 800-63B bounds:
    # *"the verifier SHALL limit consecutive failed authentication attempts using a specific
    # authenticator on a single subscriber account to no more than 100 by disabling that
    # authenticator."* A rate limiter cannot answer this — it is keyed by account, it is
    # usually a window that resets, and in this shard's default it lives in one process's
    # memory. So the count belongs on the row, which is also where django-otp keeps it
    # (`throttling_failure_count`).
    #
    # Reset to zero by a successful verification, not by the passage of time. "Consecutive"
    # means since the last success.
    getter consecutive_failures : Int32

    # When the most recent wrong code was offered for this factor, or `nil` if never.
    #
    # The other half of django-otp's pair: the count alone cannot tell an operator whether a
    # factor is failing right now or failed months ago, and a deployment that wants its own
    # per-factor delay curve computes it from this.
    getter last_failure_at : Time?

    # When this factor was disabled for having failed too many times in a row, or `nil`.
    #
    # A disabled factor never authenticates and never counts towards "this account has MFA",
    # exactly like an unconfirmed one — but it is a different state and stays visible in a
    # management listing, because the person needs to be told which device stopped working and
    # why. Re-enabling is deliberately not an operation on this contract: what a deployment
    # does about it — support ticket, re-enrolment, an unlock e-mail — is policy, and the two
    # available answers are already there (`Service#remove` then a fresh enrolment).
    getter disabled_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @sealed_secret : Bytes,
      @created_at : Time,
      @label : String = "authenticator",
      @kind : FactorKind = FactorKind::TOTP,
      @digits : Int32 = TOTP::DEFAULT_DIGITS,
      @period : Time::Span = TOTP::DEFAULT_PERIOD,
      @algorithm : TOTP::Algorithm = TOTP::Algorithm::SHA1,
      @confirmed_at : Time? = nil,
      @last_used_counter : Int64? = nil,
      @consecutive_failures : Int32 = 0,
      @last_failure_at : Time? = nil,
      @disabled_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("sealed_secret must not be empty") if @sealed_secret.empty?
    end

    # Whether enrolment finished.
    def confirmed? : Bool
      !@confirmed_at.nil?
    end

    # Whether this factor was disabled for consecutive failures.
    def disabled? : Bool
      !@disabled_at.nil?
    end

    # Whether a code from this factor may authenticate anything: enrolment finished and it has
    # not been disabled. This is what the verification path and `Service#enrolled?` ask.
    def usable? : Bool
      confirmed? && !disabled?
    end

    # Redacted. `sealed_secret` is ciphertext rather than a secret, and printing it in a crash
    # report would still be handing an attacker half of what they need.
    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::MFA::Factor " << @id << ' ' << @kind << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # One single-use recovery code.
  #
  # Unlike the TOTP secret, this *is* an ordinary bearer secret — the server only has to
  # recognise it — so it follows the token discipline in `docs/02-security-model.md` exactly:
  # generated from a CSPRNG, stored as a SHA-256 digest, and consumed atomically so that two
  # simultaneous requests cannot both spend it.
  struct RecoveryCode
    getter id : String
    getter account_id : String
    getter code_digest : Bytes
    getter created_at : Time
    getter used_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @code_digest : Bytes,
      @created_at : Time,
      @used_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("code_digest must not be empty") if @code_digest.empty?
    end

    def used? : Bool
      !@used_at.nil?
    end

    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::MFA::RecoveryCode " << @id << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # A factor that has been created but not yet proved.
  #
  # `provisioning_uri` contains the secret in plain text, and this is the only moment it exists
  # outside the person's own possession: render it as a QR code and let it go. It is a
  # credential — never log it, never put it in a URL that leaves the machine, and never store
  # it beside the ciphertext it came from.
  struct PendingEnrolment
    getter factor : Factor
    getter provisioning_uri : String

    def initialize(@factor : Factor, @provisioning_uri : String)
    end

    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::MFA::PendingEnrolment " << @factor.id << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # A factor that has now been proved, and any recovery codes issued along with it.
  #
  # `recovery_codes` is non-empty only when this confirmation is what turned MFA on for the
  # account — issuing them at that moment rather than leaving it to the application is
  # deliberate: an account with a second factor and no way around it is one lost phone from
  # being unrecoverable, and "the app was supposed to call `regenerate_recovery_codes`" is not
  # a defence anybody can offer the person locked out.
  #
  # The codes are plain text and are stored only as digests. Same rule as above: show them once.
  struct Confirmed
    getter factor : Factor
    getter recovery_codes : Array(Secret)

    def initialize(@factor : Factor, @recovery_codes : Array(Secret))
    end

    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::MFA::Confirmed " << @factor.id << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # A second factor was proved.
  struct Verified
    # Which factor answered, or `nil` when a recovery code was spent — a recovery code belongs
    # to the account rather than to any one device, which is the point of having them.
    getter factor : Factor?

    # True when a single-use recovery code was spent rather than a code from an authenticator.
    # Worth surfacing: it is the signal that somebody has lost their device, and the moment to
    # prompt for re-enrolment.
    getter? by_recovery_code : Bool

    def initialize(@factor : Factor? = nil, @by_recovery_code : Bool = false)
    end
  end

  # The result of presenting a second factor.
  #
  # `Failed` is the same struct a password or a bearer token produces, so `RateLimited` carries
  # a `retry_after` here exactly as it does there, and every reason stays out of the response
  # for the same reason: which of "wrong code", "already used" and "no such factor" it was is
  # for the audit log, not for whoever is guessing.
  alias VerificationResult = Verified | Failed
end

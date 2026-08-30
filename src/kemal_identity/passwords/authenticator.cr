module KemalIdentity::Passwords
  # Verifies a login and a password, and answers who — if anyone — that proves.
  #
  # A `CredentialAuthenticator`, not a `RequestAuthenticator`: it runs at login only, takes an
  # identifier and a secret, and *establishes* an identity rather than reading one that was
  # already established. Passport.js is the cautionary example of forcing both into one
  # abstraction (`docs/01-architecture.md`).
  #
  # It does not create a session. It returns a `Principal` with no `session_id`, and the
  # caller passes the account to `Sessions::Service#start`, which is what makes rotation on
  # login — the session fixation defence — the session layer's decision rather than this
  # one's.
  #
  # ### Two ways this class avoids being an account oracle
  #
  # **Every failure is one failure.** `reason` distinguishes them for the audit log; the
  # response must not. `DisabledAccount` and `InvalidCredential` rendering differently tells
  # an attacker which logins exist (`docs/04-kemal-integration.md`).
  #
  # **Every path costs the same.** The naive implementation returns early when no account
  # matches, having done no hashing, and the response arrives a hundred-odd milliseconds
  # sooner — a reliable oracle no matter how identical the body is. So an unknown login is
  # verified against `Hasher#dummy_digest`, and the disabled check happens *after* the
  # verification rather than in front of it, so that disabled accounts are not distinguishable
  # by timing either.
  class Authenticator
    def initialize(
      @accounts : Accounts::Repository,
      @hasher : Hasher,
      @clock : Clock,
      @rate_limiter : RateLimiter = NullRateLimiter.new,
    )
    end

    # Verifies `password` against the account identified by `login`.
    #
    # `ip` keys the source-address half of the rate limit, and is recorded in the audit event.
    def authenticate(
      login : String,
      password : String,
      tenant_id : String? = nil,
      ip : String? = nil,
    ) : Outcome
      secret = Secret.new(password)
      normalized = Accounts::Login.normalize(login)

      # Before the lookup and before any hashing. Bcrypt is tens of milliseconds of CPU by
      # design, so an endpoint that verifies a hash before deciding whether it should have is
      # a denial-of-service lever that no amount of later penalising takes away.
      verdict = consume_quota(normalized, tenant_id, ip)

      # Fail closed, and loudly. A limiter that cannot answer is not a limiter, and running
      # the login path unmetered is precisely what an attacker gets by overwhelming whatever
      # stores the counts. An application that would rather stay up wraps its limiter in
      # `FailOpenRateLimiter` — per endpoint, since each service takes its own.
      if verdict.unavailable?
        Log.error &.emit("rate_limiter.unavailable", endpoint: "login", ip: ip)

        return failure(FailureReason::RateLimiterUnavailable, subject: nil, ip: ip)
      end

      unless verdict.allowed?
        return failure(
          FailureReason::RateLimited, subject: nil, ip: ip, retry_after: verdict.retry_after
        )
      end

      # Normalised at write time and compared by equality, so the index is used and the
      # uniqueness constraint agrees with the lookup (`docs/02-security-model.md`).
      account = @accounts.find_by_login(normalized, tenant_id)

      # The timing equalisation, and the reason `dummy_digest` exists. Note that this runs
      # for an account with no password credential too: `password_digest` is nil for an
      # external-identity-only account, and falling through to the dummy digest means such an
      # account cannot be told apart from a nonexistent one, and cannot be logged into by
      # accident.
      digest = account.try(&.password_digest) || @hasher.dummy_digest
      verified = @hasher.verify(secret, digest)

      if account.nil? || !verified
        return failure(FailureReason::InvalidCredential, subject: account.try(&.id), ip: ip)
      end

      # After verification, never before: an early return here would make a disabled account
      # answer faster than a live one.
      if account.disabled?
        return failure(FailureReason::DisabledAccount, subject: account.id, ip: ip)
      end

      rehash_if_stale(account, secret, digest)

      # Proving you are the account holder clears the count, so a person who mistypes their
      # password four times and then gets it right is not left throttled.
      reset_quota(normalized, tenant_id, ip)

      Log.info &.emit("authentication.succeeded", subject: account.id, ip: ip)

      Authenticated.new(
        Principal.new(
          subject: account.id,
          assurance: AssuranceLevel::Password,
          authenticated_at: @clock.now,
          # No credential yet, and none is coming from here. Verifying a password *proves* an
          # identity; it does not hand back something to present on the next request.
          # `Sessions::Service#start` is what mints that, and doing it there is what makes
          # login rotate the session identifier.
          credential: nil,
          tenant_id: account.tenant_id,
        )
      )
    end

    # Re-hashes a correct password whose digest is at outdated parameters.
    #
    # This is what lets an application raise its bcrypt cost, or migrate off a legacy
    # algorithm, without forcing a global password reset: old digests disappear as people
    # sign in (`docs/06-roadmap.md`, migration step 2). `Hasher#needs_rehash?` reports true
    # for a digest it cannot even parse, which is precisely the legacy digest being retired.
    #
    # A failure to write must never fail the login. The user typed the right password; the
    # worst outcome of a failed rehash is that it is attempted again next time.
    private def rehash_if_stale(account : Accounts::Account, secret : Secret, digest : String) : Nil
      return unless @hasher.needs_rehash?(digest)

      updated = @accounts.update_password_digest(
        account.id, @hasher.hash_secret(secret), @hasher.scheme, @clock.now
      )

      if updated
        Log.info &.emit("password.rehashed", subject: account.id, scheme: @hasher.scheme)
      else
        Log.warn &.emit("password.rehash_failed", subject: account.id)
      end
    rescue error : InfrastructureError
      Log.warn &.emit("password.rehash_failed", subject: account.id, error: error.class.name)
    end

    # Counts this attempt against both keys, and denies if either says so.
    #
    # Both are consumed even when the first denies: an attacker must not be able to spend
    # somebody else's quota while preserving their own, and short-circuiting would make the
    # order of the checks observable.
    private def consume_quota(normalized : String, tenant_id : String?, ip : String?) : Verdict
      verdicts = quota_keys(normalized, tenant_id, ip).map { |key| @rate_limiter.consume(key) }

      # An unavailable store outranks a denial: the two need different responses from whoever
      # is on call, and reporting the denial would hide the incident behind something that
      # looks like the system working.
      verdicts.find(&.unavailable?) || verdicts.find { |verdict| !verdict.allowed? } || Verdict.allow
    end

    private def reset_quota(normalized : String, tenant_id : String?, ip : String?) : Nil
      quota_keys(normalized, tenant_id, ip).each { |key| @rate_limiter.reset(key) }
    end

    # Two dimensions, and both matter.
    #
    # The **login** key is what survives an attacker rotating addresses: credential stuffing is
    # distributed by nature, so an address-keyed limit alone barely touches it. The **address**
    # key is what catches one host spraying many logins.
    #
    # The login is hashed rather than used directly, so a limiter's storage can answer "is this
    # login under attack" without retaining the address somebody typed
    # (`blueprints/0007-audit-events-omit-the-login.md`). It is scoped by tenant, since the same
    # login in two tenants is two accounts.
    private def quota_keys(normalized : String, tenant_id : String?, ip : String?) : Array(String)
      keys = ["login:#{Digest::SHA256.hexdigest("#{tenant_id}\u0000#{normalized}")}"]
      keys << "ip:#{ip}" if ip && !ip.empty?
      keys
    end

    private def failure(
      reason : FailureReason,
      subject : String?,
      ip : String?,
      retry_after : Time::Span? = nil,
    ) : Failed
      # The reason is recorded here and nowhere else. Whatever renders the response gets one
      # message for every reason.
      Log.info &.emit("authentication.failed", reason: reason.to_s, subject: subject, ip: ip)
      Failed.new(reason, retry_after: retry_after)
    end
  end
end

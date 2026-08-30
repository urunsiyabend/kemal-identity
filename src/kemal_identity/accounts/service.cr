module KemalIdentity::Accounts
  # A password was set from a valid reset link.
  struct PasswordWasReset
    getter account_id : String

    # How many sessions were ended. A credential change evicts whoever knew the old one.
    getter revoked_sessions : Int32

    def initialize(@account_id : String, @revoked_sessions : Int32)
    end
  end

  # An address was proved.
  struct EmailWasConfirmed
    getter account_id : String

    def initialize(@account_id : String)
    end
  end

  # The link did not work, or the new password was not acceptable.
  #
  # Unlike a failed *login*, this is safe to render specifically. The person holding a reset
  # link already has it; telling them their new password is too short reveals nothing about who
  # exists, and refusing without saying why makes the form unusable.
  struct ActionRejected
    enum Reason
      # Expired, already used, for a different purpose, or never issued. Deliberately one
      # reason for all four -- separating them would let somebody probe which links exist.
      InvalidToken

      # The new password failed the application's `Policy`.
      PasswordUnacceptable
    end

    getter reason : Reason
    getter policy_violations : Array(Passwords::PolicyViolation)

    def initialize(
      @reason : Reason,
      @policy_violations : Array(Passwords::PolicyViolation) = [] of Passwords::PolicyViolation,
    )
    end
  end

  alias ActionOutcome = PasswordWasReset | EmailWasConfirmed | ActionRejected

  # The account lifecycle flows that surround a password: reset it, and prove an address.
  #
  # Both are built from the same two pieces -- a single-use `ActionToken` and a `Notifier` --
  # and both are shaped by the same constraint: **asking must reveal nothing**.
  class Service
    def initialize(
      @accounts : Repository,
      @tokens : ActionTokenRepository,
      @notifier : Notifier,
      @sessions : Sessions::Service,
      @hasher : Passwords::Hasher,
      @policy : Passwords::Policy,
      @clock : Clock,
      @random : RandomSource,
      @rate_limiter : RateLimiter = NullRateLimiter.new,
      # Optional, and its absence is a real hole rather than a missing convenience: without it
      # a password reset revokes sessions but leaves remember-me families alive, so a stolen
      # remember cookie keeps working after the victim resets their password. See
      # `#reset_password`.
      @remember : Sessions::RememberService? = nil,
      @reset_ttl : Time::Span = 1.hour,
      @confirmation_ttl : Time::Span = 1.day,
    )
      raise ConfigurationError.new("reset_ttl must be positive") unless @reset_ttl > Time::Span::ZERO

      unless @confirmation_ttl > Time::Span::ZERO
        raise ConfigurationError.new("confirmation_ttl must be positive")
      end
    end

    # Starts a password reset, if there is an account to start one for.
    #
    # **Returns nothing, always, and takes the same time either way.** The caller cannot tell
    # whether the address exists, and neither can whoever is watching the response -- which is
    # the whole point, because a forgot-password form is the easiest place in an application to
    # enumerate a customer list.
    #
    # What is equalised here is everything this method controls: a token is minted and digested
    # on both paths, and the branch that has no account throws its token away. What is *not*
    # controlled here is `Notifier#deliver`, which is why its contract says it must return
    # promptly -- an implementation that waits on an SMTP server puts a network round trip on
    # one path and not the other, and hands the oracle back.
    #
    # Rate limited per address, so the endpoint cannot be turned into a way to flood somebody's
    # inbox. A denial is silent, for the same reason everything else here is.
    def request_password_reset(login : String, tenant_id : String? = nil, ip : String? = nil) : Nil
      normalized = Login.normalize(login)

      verdict = @rate_limiter.consume(quota_key("reset", normalized, tenant_id))

      # Same fail-closed default as login, and the same escape hatch. This endpoint sends mail
      # to an address somebody else chose, so running it unmetered turns it into a way to flood
      # a stranger's inbox.
      if verdict.unavailable?
        Log.error &.emit("rate_limiter.unavailable", endpoint: "password_reset", ip: ip)
        return
      end

      unless verdict.allowed?
        Log.info &.emit("password_reset.throttled", ip: ip)
        return
      end

      account = @accounts.find_by_login(normalized, tenant_id)

      # Minted before the branch, so both paths pay for it. Discarded below when there is
      # nobody to send it to.
      token = OpaqueToken.generate(@random)
      expires_at = @clock.now + @reset_ttl

      if account.nil?
        Log.info &.emit("password_reset.requested", known: false, ip: ip)
        return
      end

      # A disabled account gets no reset link. Silently -- saying so would confirm the address.
      if account.disabled?
        Log.info &.emit("password_reset.refused", subject: account.id, reason: "disabled")
        return
      end

      # Issuing a new link invalidates the old ones, so a link sitting in a mailbox somebody
      # else now controls stops working the moment the real owner asks for a fresh one.
      @tokens.revoke_all_for_account(account.id, ActionPurpose::Reset, @clock.now)

      store(account, token, ActionPurpose::Reset, expires_at)

      @notifier.deliver(
        PasswordResetRequested.new(
          account_id: account.id, login: account.normalized_login,
          token: token, expires_at: expires_at
        )
      )

      Log.info &.emit("password_reset.requested", known: true, subject: account.id, ip: ip)
    end

    # Spends a reset link and sets a new password.
    #
    # The token is consumed **before** the password is checked against the policy, and stays
    # consumed even when the policy then rejects it -- `docs/02-security-model.md`, token rule
    # five. Leaving it spendable would turn one emailed link into unlimited attempts; the user
    # simply asks for another link, which costs them one email and costs an attacker a
    # foothold.
    def reset_password(raw_token : String, new_password : String) : ActionOutcome
      consumed = consume(raw_token, ActionPurpose::Reset)
      return ActionRejected.new(ActionRejected::Reason::InvalidToken) if consumed.nil?

      secret = Secret.new(new_password)
      violations = @policy.violations(secret)

      unless violations.empty?
        Log.info &.emit("password_reset.rejected", subject: consumed.account_id, reason: "policy")
        return ActionRejected.new(ActionRejected::Reason::PasswordUnacceptable, violations)
      end

      now = @clock.now
      account_id = consumed.account_id

      @accounts.update_password_digest(account_id, @hasher.hash_secret(secret), @hasher.scheme, now)

      # A credential change, so every session dies. Nobody should be left holding a session
      # obtained by proving they knew the *old* password, and somebody resetting a password
      # they had forgotten is often somebody who suspects a compromise.
      revoked = @sessions.revoke_all(account_id)

      # Belt as well as braces: revocation handles the sessions that exist, the version bump
      # handles anything created concurrently with this call.
      @accounts.bump_auth_version(account_id)

      # And every remembered browser.
      #
      # Revoking sessions alone would be a hole with an attacker in it: a remember-me cookie
      # outlives any session, so somebody holding a stolen one would simply be signed back in
      # on their next request -- after the victim had reset their password specifically to
      # evict them. Resetting a password is the single strongest "get everyone out" signal an
      # account holder can send, and it has to mean it.
      @remember.try(&.forget_all(account_id))

      account = @accounts.find_by_id(account_id)

      if account
        # Unsolicited on purpose. It is how somebody learns that an attacker who reached their
        # mailbox has taken the account.
        @notifier.deliver(
          PasswordChanged.new(account_id: account_id, login: account.normalized_login, at: now)
        )
      end

      Log.info &.emit("password_reset.completed", subject: account_id, revoked_sessions: revoked)

      PasswordWasReset.new(account_id: account_id, revoked_sessions: revoked)
    end

    # Sends a confirmation link for an account that already exists.
    #
    # Takes an account id rather than a login: confirmation is triggered by the application
    # after it creates an account or changes an address, so there is no untrusted identifier to
    # enumerate with, and no reason to be silent about an unknown one.
    def request_email_confirmation(account_id : String) : Bool
      account = @accounts.find_by_id(account_id)
      return false if account.nil?

      token = OpaqueToken.generate(@random)
      expires_at = @clock.now + @confirmation_ttl

      @tokens.revoke_all_for_account(account.id, ActionPurpose::Confirm, @clock.now)
      store(account, token, ActionPurpose::Confirm, expires_at)

      @notifier.deliver(
        EmailConfirmationRequested.new(
          account_id: account.id, login: account.normalized_login,
          token: token, expires_at: expires_at
        )
      )

      Log.info &.emit("email_confirmation.requested", subject: account.id)
      true
    end

    # Spends a confirmation link.
    #
    # Deliberately does **not** touch sessions or `auth_version`. Proving an address is not a
    # credential change: nobody's password altered, so logging everybody out would be a
    # surprise with no security benefit.
    def confirm_email(raw_token : String) : ActionOutcome
      consumed = consume(raw_token, ActionPurpose::Confirm)
      return ActionRejected.new(ActionRejected::Reason::InvalidToken) if consumed.nil?

      @accounts.mark_email_verified(consumed.account_id, @clock.now)

      Log.info &.emit("email_confirmation.completed", subject: consumed.account_id)
      EmailWasConfirmed.new(account_id: consumed.account_id)
    end

    # Shape check before hashing, then one atomic consume.
    #
    # A malformed token never reaches the database, and expired, used, wrong-purpose and
    # unknown all come back the same way.
    private def consume(raw_token : String, purpose : ActionPurpose) : ActionToken?
      return unless OpaqueToken.valid_shape?(raw_token)

      @tokens.consume(OpaqueToken.digest(Secret.new(raw_token)), purpose, @clock.now)
    end

    private def store(account : Account, token : Secret, purpose : ActionPurpose, expires_at : Time) : Nil
      @tokens.create(
        ActionToken.new(
          id: @random.token,
          account_id: account.id,
          purpose: purpose,
          token_digest: OpaqueToken.digest(token),
          created_at: @clock.now,
          expires_at: expires_at,
        )
      )
    end

    # Hashed and tenant-scoped, like the login path's: a limiter should be able to answer "is
    # this address being hammered" without retaining the address.
    private def quota_key(prefix : String, normalized : String, tenant_id : String?) : String
      "#{prefix}:#{Digest::SHA256.hexdigest("#{tenant_id}/#{normalized}")}"
    end
  end
end

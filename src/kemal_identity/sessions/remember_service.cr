module KemalIdentity::Sessions
  # A remember-me cookie was issued. Both values go to the browser; neither is stored raw.
  struct IssuedRemember
    getter token : Secret
    getter family_id : String
    getter expires_at : Time

    def initialize(@token : Secret, @family_id : String, @expires_at : Time)
    end
  end

  # A remembered login was restored: a session exists again, and the remember cookie has
  # rotated.
  #
  # Both tokens must reach the browser. Writing one cookie and not the other leaves the client
  # holding a remember token the server has already spent, which the next request reports as a
  # replay — the user is signed out and told their cookie may have been stolen, because of a
  # bug rather than a thief.
  struct Restored
    getter principal : Principal
    getter session_token : Secret
    getter remember : IssuedRemember

    def initialize(@principal : Principal, @session_token : Secret, @remember : IssuedRemember)
    end
  end

  # An already-spent token was presented. The family is dead and so are the account's sessions.
  struct ReplayDetected
    getter account_id : String
    getter family_id : String
    getter revoked_tokens : Int32
    getter revoked_sessions : Int32

    def initialize(@account_id : String, @family_id : String, @revoked_tokens : Int32, @revoked_sessions : Int32)
    end
  end

  # No usable remember cookie. Never issued, expired, revoked, or the account is gone.
  struct NotRemembered
  end

  alias RestoreOutcome = Restored | ReplayDetected | NotRemembered

  # "Keep me signed in", done so that theft is detectable.
  #
  # ### Not a long-lived session
  #
  # `docs/02-security-model.md` is explicit that this must not be "an ordinary session with a
  # 30-day expiry". That would be a bearer secret sitting in a browser for a month with no way
  # to notice it had been copied.
  #
  # Instead every token is single-use and rotates on presentation, and every token descended
  # from one login shares a family. After a thief uses a stolen cookie the token is spent, so
  # when the real user next presents their copy it is a replay — and the reverse if the user
  # gets there first. Either way somebody presents a spent token, and that is the signal.
  #
  # ### Restored sessions are weaker on purpose
  #
  # A session restored here sits at `AssuranceLevel::Remembered`, below `Password`, and
  # `Principal#fresh?` returns false for it however recently it was restored. Possession of a
  # cookie is not the presence of the account holder. Anything sensitive calls
  # `require_fresh!` and gets a real re-authentication.
  class RememberService
    def initialize(
      @remember : RememberRepository,
      @accounts : Accounts::Repository,
      @sessions : Service,
      @clock : Clock,
      @random : RandomSource,
      @notifier : Accounts::Notifier? = nil,
      @ttl : Time::Span = 30.days,
    )
      raise ConfigurationError.new("ttl must be positive") unless @ttl > Time::Span::ZERO
    end

    # Starts remembering this browser, after a real authentication.
    #
    # Called only when somebody has just proved who they are with a password. Never from a
    # restored session: chaining remembrance off remembrance would make the thirty days a
    # rolling window that never closes.
    def remember(account : Accounts::Account) : IssuedRemember
      raise ArgumentError.new("cannot remember a disabled account") if account.disabled?

      issue(account_id: account.id, family_id: @random.token)
    end

    # Restores a remembered login, rotating the cookie.
    #
    # Returns `NotRemembered` for anything unusable, `ReplayDetected` when a spent token comes
    # back, and `Restored` on success — with a **new** remember token that the caller must
    # write alongside the session cookie.
    def restore(raw_token : String?) : RestoreOutcome
      return NotRemembered.new if raw_token.nil? || raw_token.empty?

      # Shape before hashing, before any query.
      return NotRemembered.new unless OpaqueToken.valid_shape?(raw_token)

      digest = OpaqueToken.digest(Secret.new(raw_token))

      case outcome = @remember.consume(digest, @clock.now)
      in RememberUnknown  then NotRemembered.new
      in RememberReplayed then handle_replay(outcome)
      in RememberAccepted then rotate(outcome.token)
      end
    end

    # Stops remembering one browser. What a "log out" button should call alongside ending the
    # session, or the next visit signs the user straight back in.
    def forget(family_id : String) : Int32
      @remember.revoke_family(family_id, @clock.now)
    end

    # Stops remembering the browser holding this token, without spending it.
    #
    # What logging out calls. Consuming the token would mark it used, and the same cookie
    # arriving later would read as a replay — so a user who pressed "log out" would be told
    # their cookie may have been stolen.
    def forget_by_token(raw_token : String) : Int32
      return 0 unless OpaqueToken.valid_shape?(raw_token)

      @remember.revoke_family_by_digest(OpaqueToken.digest(Secret.new(raw_token)), @clock.now)
    end

    # Stops remembering every browser. The right response to a password change.
    def forget_all(account_id : String) : Int32
      @remember.revoke_all_for_account(account_id, @clock.now)
    end

    # Disk reclamation. Correctness never depends on it — but note that sweeping *early* would
    # break replay detection, since a spent token's row is the evidence.
    def delete_expired : Int32
      @remember.delete_expired(@clock.now)
    end

    private def rotate(spent : RememberToken) : RestoreOutcome
      account = @accounts.find_by_id(spent.account_id)

      # The account went away or was disabled since the cookie was issued. Kill the family
      # rather than leaving tokens that resolve to nothing.
      if account.nil? || account.disabled?
        @remember.revoke_family(spent.family_id, @clock.now)
        return NotRemembered.new
      end

      issued = @sessions.start(account, AssuranceLevel::Remembered)

      # Same family, so the chain of custody survives the rotation and a replay of any earlier
      # link still names this family.
      replacement = issue(account_id: account.id, family_id: spent.family_id)

      Log.info &.emit("remember.restored", subject: account.id, family: spent.family_id)

      Restored.new(
        principal: issued.principal,
        session_token: issued.token,
        remember: replacement,
      )
    end

    private def handle_replay(replay : RememberReplayed) : RestoreOutcome
      now = @clock.now

      revoked_tokens = @remember.revoke_family(replay.family_id, now)

      # More than `docs/02-security-model.md` literally asks for, and deliberately.
      #
      # Killing the family alone would leave any session the thief already minted with the
      # stolen cookie alive for its full lifetime — the detection would fire and the intruder
      # would stay signed in. A replay is a strong signal that this account is compromised, so
      # every session ends and the account holder signs in again with a password. The thief
      # cannot. See `blueprints/0012-remember-me.md`.
      revoked_sessions = @sessions.revoke_all(replay.account_id)

      notify_replay(replay, now)

      Log.warn &.emit(
        "remember.replay_detected",
        subject: replay.account_id, family: replay.family_id,
        revoked_tokens: revoked_tokens, revoked_sessions: revoked_sessions
      )

      ReplayDetected.new(
        account_id: replay.account_id,
        family_id: replay.family_id,
        revoked_tokens: revoked_tokens,
        revoked_sessions: revoked_sessions,
      )
    end

    private def notify_replay(replay : RememberReplayed, at : Time) : Nil
      notifier = @notifier
      return if notifier.nil?

      account = @accounts.find_by_id(replay.account_id)
      return if account.nil?

      notifier.deliver(
        Accounts::RememberTokenReplayed.new(
          account_id: account.id, login: account.normalized_login,
          family_id: replay.family_id, at: at
        )
      )
    end

    private def issue(account_id : String, family_id : String) : IssuedRemember
      token = OpaqueToken.generate(@random)
      expires_at = @clock.now + @ttl

      @remember.create(
        RememberToken.new(
          id: @random.token,
          account_id: account_id,
          family_id: family_id,
          token_digest: OpaqueToken.digest(token),
          created_at: @clock.now,
          expires_at: expires_at,
        )
      )

      IssuedRemember.new(token: token, family_id: family_id, expires_at: expires_at)
    end
  end
end

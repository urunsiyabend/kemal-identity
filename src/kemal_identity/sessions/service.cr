module KemalIdentity::Sessions
  # A freshly issued session: the raw secret for the browser, the row that was stored, and the
  # principal it resolves to.
  #
  # The raw token is a `Secret`, so it redacts itself in logs and crash reports. It exists
  # only long enough to be written into a `Set-Cookie` — nothing persists it, and
  # `spec/security/token_storage_spec.cr` asserts it never reaches a row.
  struct Issued
    getter token : Secret
    getter record : Record
    getter principal : Principal

    def initialize(@token : Secret, @record : Record, @principal : Principal)
    end
  end

  # Creating, resolving, rotating and revoking sessions.
  #
  # This is where the session lifecycle rules live. The repository reports facts; this decides
  # what they mean.
  class Service
    def initialize(
      @sessions : Repository,
      @clock : Clock,
      @random : RandomSource,
      @config : Config = Config.new,
    )
    end

    # Starts a new session for an account.
    #
    # Raises `ArgumentError` for a disabled account. That is a caller bug rather than an
    # authentication failure: whoever calls this has already verified a credential, and the
    # disabled check belongs in front of that. Failing loudly here stops a caller from
    # accidentally minting a session the very next request would reject.
    def start(
      account : Accounts::Account,
      assurance : AssuranceLevel,
      mfa_verified_at : Time? = nil,
    ) : Issued
      raise ArgumentError.new("cannot start a session for a disabled account") if account.disabled?

      issued = issue(
        account: account,
        assurance: assurance,
        mfa_verified_at: mfa_verified_at,
      )

      # Emitted here rather than in the Kemal layer, so an application driving the service
      # directly gets the same trail as one going through `env.auth`. Rotation has its own
      # event and does not also emit this one: it did not start a session so much as replace
      # one, and an investigator wants those distinguishable.
      Log.info &.emit(
        "session.started",
        subject: account.id, session: issued.record.id, assurance: assurance.to_s
      )

      issued
    end

    # Resolves a raw cookie value.
    #
    # Returns `Anonymous` when there is no credential to check, and `Failed` when there was
    # one and it did not hold — the caller needs that distinction to know whether to clear
    # the cookie (`docs/02-security-model.md`).
    #
    # The order of the checks below is the order in `docs/02-security-model.md` and is not
    # arbitrary: shape before any I/O, then revocation, then expiry, then account status.
    # Expiry is evaluated **here, on every read**, never deferred to the sweeper. That is the
    # direct lesson of kemal-session issue #116, where a timeout only marked a session for
    # deletion at the next GC pass, and a read could refresh its access time before any
    # expiry check — reviving it.
    def resolve(raw : String?) : Outcome
      return Anonymous.new if raw.nil? || raw.empty?

      # Before hashing, before querying. An oversized or malformed value dies here.
      return Failed.new(FailureReason::MalformedCredential) unless Token.valid_shape?(raw)

      token = Secret.new(raw)
      lookup = @sessions.find_by_digest(Token.digest(token))

      # Unknown digest: an expired session already swept, a cookie from a previous
      # deployment, or a guess. One reason for all three.
      return Failed.new(FailureReason::InvalidCredential) if lookup.nil?

      record = lookup.session
      now = @clock.now

      return Failed.new(FailureReason::Revoked) if record.revoked?
      return Failed.new(FailureReason::Expired) if expired?(record, now)
      return Failed.new(FailureReason::DisabledAccount) if lookup.account_disabled?
      return Failed.new(FailureReason::StaleAuthVersion) if lookup.stale_auth_version?

      touched = touch_if_due(record, now)
      Authenticated.new(principal_for(touched))
    end

    # Issues a new secret and a new row, revoking the old one.
    #
    # Called on successful login — this is the session fixation defence, and it is why the
    # identifier a client held before authenticating is worthless afterwards — and on an
    # assurance increase or a credential change.
    #
    # Both windows restart. Re-authentication legitimately begins a new session lifetime,
    # which is a different thing from activity: activity moves `idle_expires_at` only, and can
    # never postpone the absolute deadline.
    def rotate(
      record : Record,
      account : Accounts::Account,
      assurance : AssuranceLevel? = nil,
      mfa_verified_at : Time? = nil,
    ) : Issued
      raise ArgumentError.new("cannot rotate into a disabled account") if account.disabled?

      issued = issue(
        account: account,
        assurance: assurance || record.assurance,
        mfa_verified_at: mfa_verified_at || record.mfa_verified_at,
      )

      # Revoked after the new row exists. The other order would leave a window in which a
      # crash logs the user out instead of leaving them where they were.
      @sessions.revoke(record.id, @clock.now)

      # `docs/02-security-model.md` names session rotation among the events that must reach the
      # audit trail: it is how an investigator sees that a login replaced an identifier a client
      # was already holding, which is the session fixation defence actually firing.
      Log.info &.emit(
        "session.rotated",
        subject: account.id, from: record.id, to: issued.record.id,
        assurance: issued.record.assurance.to_s
      )

      issued
    end

    # Ends one session. Returns false if it did not exist or was already revoked.
    def revoke(session_id : String) : Bool
      revoked = @sessions.revoke(session_id, @clock.now)

      # Only when something changed. Revoking an already-revoked session is not an event, and
      # logging it would put a line in the trail for every double-submitted logout.
      Log.info &.emit("session.revoked", session: session_id) if revoked

      revoked
    end

    # Ends every session for an account, returning how many it ended.
    def revoke_all(account_id : String, except_id : String? = nil) : Int32
      revoked = @sessions.revoke_all_for_account(account_id, @clock.now, except_id: except_id)

      # Bulk revocation is on `docs/02-security-model.md`'s list of events that must be
      # recorded, and the count is the part that matters: "revoked 4 sessions" tells an
      # investigator four people were signed out, which is why the repository contract insists
      # the number counts only sessions actually ended.
      Log.info &.emit(
        "session.revoked_all", subject: account_id, count: revoked, spared: except_id
      ) if revoked > 0

      revoked
    end

    # Ends the sessions that a password change or MFA recovery must invalidate.
    #
    # Every *other* session dies unconditionally — evicting whoever knew the old credential is
    # the entire point. Whether the session performing the change dies too is
    # `Config#revoke_current_on_credential_change`, and defaults to false so that changing
    # your own password does not log you out of the tab you changed it in
    # (`docs/02-security-model.md`).
    #
    # This is the revocation half. The caller pairs it with
    # `Accounts::Repository#bump_auth_version`, which invalidates sessions without
    # enumerating rows — belt as well as braces, since a session created concurrently with
    # this call would otherwise survive it.
    def revoke_after_credential_change(account_id : String, current_session_id : String? = nil) : Int32
      except = @config.revoke_current_on_credential_change? ? nil : current_session_id
      revoke_all(account_id, except_id: except)
    end

    # Deletes rows past their absolute deadline. Disk reclamation only — correctness never
    # depends on this having run.
    def delete_expired : Int32
      @sessions.delete_expired(@clock.now)
    end

    private def issue(
      account : Accounts::Account,
      assurance : AssuranceLevel,
      mfa_verified_at : Time?,
    ) : Issued
      now = @clock.now
      token = Token.generate(@random)

      record = Record.new(
        id: @random.token,
        account_id: account.id,
        tenant_id: account.tenant_id,
        token_digest: Token.digest(token),
        # Stamped from the account as it is right now, so a bump that happens later
        # invalidates this session.
        auth_version: account.auth_version,
        assurance: assurance,
        created_at: now,
        authenticated_at: now,
        mfa_verified_at: mfa_verified_at,
        last_seen_at: now,
        idle_expires_at: now + @config.idle_timeout,
        absolute_expires_at: now + @config.absolute_timeout,
      )

      @sessions.create(record)

      Issued.new(token: token, record: record, principal: principal_for(record))
    end

    # A session is expired *at* its deadline, not one instant after.
    #
    # `>=` rather than `>` so that this and `Repository#delete_expired` — which removes rows
    # at or before the instant it is given — agree about the boundary. If they disagreed, the
    # sweeper could delete a row this method still considered valid, which would make the
    # sweeper a correctness dependency. See
    # `blueprints/0006-session-cookie-and-expiry-boundaries.md`.
    private def expired?(record : Record, now : Time) : Bool
      now >= record.absolute_expires_at || now >= record.idle_expires_at
    end

    # Moves the idle deadline forward, but only once per `touch_interval`.
    #
    # Returns the record as it now stands, so the principal reflects the write. Not writing is
    # the common case and costs nothing.
    private def touch_if_due(record : Record, now : Time) : Record
      return record if now - record.last_seen_at <= @config.touch_interval

      idle_expires_at = now + @config.idle_timeout
      @sessions.touch(record.id, now, idle_expires_at)

      Record.new(
        id: record.id,
        account_id: record.account_id,
        token_digest: record.token_digest,
        auth_version: record.auth_version,
        assurance: record.assurance,
        created_at: record.created_at,
        authenticated_at: record.authenticated_at,
        last_seen_at: now,
        idle_expires_at: idle_expires_at,
        absolute_expires_at: record.absolute_expires_at,
        tenant_id: record.tenant_id,
        mfa_verified_at: record.mfa_verified_at,
        revoked_at: record.revoked_at,
      )
    end

    private def principal_for(record : Record) : Principal
      Principal.new(
        subject: record.account_id,
        assurance: record.assurance,
        authenticated_at: record.authenticated_at,
        # A session is unattenuated: scopes are a token concept, and reading their absence as
        # "permits nothing" would deny every signed-in browser. `CredentialRef#scopes` says
        # why `nil` and `[]` are not the same answer.
        credential: CredentialRef.new(
          kind: CredentialKind::Session,
          id: record.id,
          expires_at: record.absolute_expires_at,
        ),
        mfa_verified_at: record.mfa_verified_at,
        tenant_id: record.tenant_id,
      )
    end
  end
end

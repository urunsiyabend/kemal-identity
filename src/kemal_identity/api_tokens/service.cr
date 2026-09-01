module KemalIdentity::ApiTokens
  # Issues, resolves and revokes personal access tokens.
  #
  # A `RequestAuthenticator`: it answers "who is making this request?" from the value after the
  # `Bearer` scheme, and returns the same `Outcome` union a session cookie does. Everything
  # downstream — `require!`, `PathGuard`, `env.auth` — works unchanged, because the whole point
  # of that union is that the credential type stops mattering once it has been resolved.
  #
  # ### Opaque, and therefore revocable
  #
  # `docs/06-roadmap.md` puts opaque tokens ahead of JWT deliberately. Validity is read from
  # storage on every request, so revoking a token takes effect on the next one. A stateless JWT
  # cannot make that promise without server-side state, at which point it is not stateless.
  class Service < RequestAuthenticator
    # Prepended to every token, before the random part.
    #
    # Not decoration. A fixed, searchable prefix is what lets secret scanners — GitHub's, a
    # pre-commit hook, a log scrubber — recognise one of these in a commit or a paste and
    # report it. A bare base64 blob is indistinguishable from any other base64 blob.
    #
    # An application should change this to something identifying itself, so a scanner can tell
    # *whose* token it found.
    DEFAULT_PREFIX = "ki_"

    # How stale `last_used_at` may get before a read is allowed to write.
    #
    # The same throttle sessions use, for the same reason: without it every authenticated API
    # request becomes a write, and an API's request rate is exactly where that hurts most. The
    # cost is that "last used" is accurate only to within one interval, which is fine for the
    # management screen it exists to feed.
    DEFAULT_TOUCH_INTERVAL = 5.minutes

    getter prefix : String

    def initialize(
      @tokens : Repository,
      @clock : Clock,
      @random : RandomSource,
      @prefix : String = DEFAULT_PREFIX,
      @touch_interval : Time::Span = DEFAULT_TOUCH_INTERVAL,
    )
      raise ConfigurationError.new("prefix must not be empty") if @prefix.empty?

      unless @prefix.matches?(/\A[A-Za-z0-9_-]+\z/)
        raise ConfigurationError.new(
          "prefix must be url-safe (letters, digits, underscore, hyphen), got #{@prefix.inspect}"
        )
      end

      unless @touch_interval >= Time::Span::ZERO
        raise ConfigurationError.new("touch_interval must not be negative")
      end
    end

    # Mints a token for an account. The raw value is returned exactly once and never again.
    #
    # `expires_at` of `nil` means it never expires — a real choice for a deploy key and a poor
    # one for a laptop, so it is the caller's to make.
    #
    # `scopes` of `nil` means the token is not attenuated: it carries whatever its owner holds,
    # which is what every token issued before v0.8 does. An empty array means it permits
    # nothing — valid, and not the same answer. There is no wildcard; unrestricted is `nil`.
    def issue(
      account : Accounts::Account,
      name : String,
      expires_at : Time? = nil,
      scopes : Array(String)? = nil,
    ) : Issued
      raise ArgumentError.new("cannot issue a token for a disabled account") if account.disabled?
      raise ArgumentError.new("name must not be empty") if name.blank?

      now = @clock.now

      if expires_at && expires_at <= now
        raise ArgumentError.new("expires_at must be in the future")
      end

      secret = Secret.new("#{@prefix}#{@random.token}")

      record = Token.new(
        id: @random.token,
        account_id: account.id,
        name: name,
        token_digest: OpaqueToken.digest(secret),
        created_at: now,
        expires_at: expires_at,
        scopes: scopes,
      )

      @tokens.create(record)

      Log.info &.emit(
        "api_token.issued",
        subject: account.id,
        # The token's id, under the field name every other event uses for a credential id. Named
        # `token:` until v0.8.2, which read as though the secret itself were in the log line.
        credential: record.id,
        expires_at: expires_at.to_s,
        # How wide the credential is, for whoever reviews what was handed out. The scope names
        # themselves are permission names, not secrets.
        scopes: scopes.try(&.join(' ')),
      )

      Issued.new(token: secret, record: record)
    end

    # Resolves the value after the `Bearer` scheme.
    #
    # The order of the checks below mirrors `Sessions::Service#resolve`, and for the same
    # reasons: shape before any I/O, then revocation, then expiry, then account status.
    #
    # Returns `Anonymous` when nothing was presented and `Failed` when something was — a caller
    # needs that difference to decide between "this is a public endpoint" and "answer 401".
    def authenticate(credential : String?) : Outcome
      return Anonymous.new if credential.nil? || credential.empty?

      # Before hashing, before querying. An oversized header dies on a length comparison.
      return Failed.new(FailureReason::MalformedCredential) unless valid_shape?(credential)

      secret = Secret.new(credential)
      lookup = @tokens.find_by_digest(OpaqueToken.digest(secret))

      return Failed.new(FailureReason::InvalidCredential) if lookup.nil?

      record = lookup.token
      now = @clock.now

      return Failed.new(FailureReason::Revoked) if record.revoked?
      return Failed.new(FailureReason::Expired) if record.expired?(now)
      return Failed.new(FailureReason::DisabledAccount) if lookup.account_disabled?

      # `auth_version` is deliberately *not* compared. A password change should not silently
      # break a deploy key: the token was created separately and on purpose, and its holder may
      # be a machine with no way to notice. An application that wants otherwise revokes tokens
      # explicitly — `revoke_all_for_account` exists for exactly that.

      touch_if_due(record, now)

      Authenticated.new(
        Principal.new(
          subject: record.account_id,
          # Below `Password`, so `require_fresh!` refuses a token outright. An automated client
          # cannot re-authenticate interactively, so a destructive action should not be
          # reachable with a token in the first place.
          assurance: AssuranceLevel::ApiToken,
          authenticated_at: now,
          # The token that proved this request, named. `record` is already in hand from the
          # lookup above, so this costs no second query — which is the whole point, since
          # rediscovering the token id from the header would mean digesting and querying
          # again on every authenticated request.
          #
          # No session id: a bearer token is presented per request and establishes nothing.
          credential: CredentialRef.new(
            kind: CredentialKind::ApiToken,
            id: record.id,
            name: record.name,
            expires_at: record.expires_at,
            # Carried, not consulted. Whether a scope permits the action is the authorizer's
            # question, and it asks it after the account's own grant — a scope can only ever
            # narrow (`blueprints/0021-credential-reference.md`).
            scopes: record.scopes,
          ),
        )
      )
    end

    # Ends one token. Takes effect on the very next request, because validity is read from
    # storage rather than asserted by a signature.
    #
    # **Revokes by id alone, so it is an administrative call.** A route that lets a client name
    # the token to revoke — `DELETE /tokens/:id` — must use the two-argument form below, or it
    # will happily end a token belonging to somebody else. A token id is not secret material:
    # it appears in `api_token.revoked` and `api_token.issued` audit lines, in a management
    # listing, and in whatever an operator exports from either.
    def revoke(token_id : String) : Bool
      revoked = @tokens.revoke(token_id, @clock.now)

      Log.info &.emit("api_token.revoked", credential: token_id) if revoked

      revoked
    end

    # Ends one token **only if it belongs to `account_id`**, which is what a "revoke this token"
    # button in a user's own settings needs.
    #
    # Answers `false` for a token that exists and belongs to somebody else, and for one that does
    # not exist at all — the same answer, so a caller cannot use it to discover whether an id is
    # real. Costs one extra read; this is a management action, not a request-path one.
    def revoke(token_id : String, account_id : String) : Bool
      owned = @tokens.list_for_account(account_id).any? { |token| token.id == token_id }

      unless owned
        Log.info &.emit(
          "api_token.revoke_refused", subject: account_id, credential: token_id, reason: "not_owned"
        )
        return false
      end

      revoke(token_id)
    end

    # Ends every token for an account, returning how many. The right response to a compromised
    # account, and what a "revoke all my tokens" button calls.
    def revoke_all(account_id : String) : Int32
      revoked = @tokens.revoke_all_for_account(account_id, @clock.now)

      Log.info &.emit("api_token.revoked_all", subject: account_id, count: revoked) if revoked > 0

      revoked
    end

    # Every token for an account, newest first, for a management screen. Revoked ones included:
    # "when did I revoke that?" is a question such a screen exists to answer.
    def list(account_id : String) : Array(Token)
      @tokens.list_for_account(account_id)
    end

    # Disk reclamation. A token with no expiry is never swept.
    def delete_expired : Int32
      @tokens.delete_expired(@clock.now)
    end

    # Exact prefix, then exactly the alphabet and length `RandomSource#token` emits.
    private def valid_shape?(credential : String) : Bool
      return false unless credential.starts_with?(@prefix)

      OpaqueToken.valid_shape?(credential[@prefix.size..])
    end

    private def touch_if_due(record : Token, now : Time) : Nil
      last_used_at = record.last_used_at

      return if last_used_at && now - last_used_at <= @touch_interval

      @tokens.touch(record.id, now)
    end
  end
end

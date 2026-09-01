require "json"

module KemalIdentity::JWT
  # A token that passed every check, and the claims it carried.
  #
  # `Principal` carries a subject and nothing else by design. An OpenID Connect callback needs
  # the rest — that is where the provider's assertions about a person live — so `#validate`
  # hands back both rather than making a caller re-parse a token already verified here.
  struct Validated
    getter principal : Principal

    # Every claim in the token, including ones this shard does not interpret.
    #
    # **Verified, not trusted.** The signature says the issuer wrote these; it says nothing
    # about whether `email_verified` is true or whether `groups` should mean anything to your
    # application. Read `Federation::Identity` before using any of them as an identifier.
    getter claims : Hash(String, ::JSON::Any)

    def initialize(@principal : Principal, @claims : Hash(String, ::JSON::Any))
    end
  end

  # Validates a JSON Web Token presented as a bearer credential.
  #
  # ### Off by default, and second on purpose
  #
  # `docs/06-roadmap.md` puts opaque tokens first and this second, because a JWT buys one
  # thing — verification without a lookup — and pays for it with the property that matters
  # most in an authentication system: **you cannot take it back**. Nothing here is wired
  # into `Application` unless an application asks for it by constructing a `Validator`.
  # Read `RevocationStore` before you do; it states the trade-off in full.
  #
  # This validator *verifies* tokens minted elsewhere — an identity provider, an API
  # gateway, another service in the estate. It does not mint them. If you are about to
  # issue JWTs to your own clients, `ApiTokens::Service` is the credential this shard
  # recommends, and it revokes.
  #
  # ### What "strict" means here
  #
  # Every one of these is a documented, exploited JWT failure, and none of them is
  # optional:
  #
  # | Attack | What stops it |
  # |---|---|
  # | `alg: none` | no `Algorithm` can express it; the allow-list refuses the string at boot; `alg` is compared against the key's |
  # | algorithm confusion (RS256 verified as HS256) | the *key* names its algorithm; the token's `alg` selects nothing |
  # | a retired key still accepted | an unknown `kid` is rejected, never retried against the ring |
  # | a token from another service replayed here | `iss` and `aud` are required and compared |
  # | a token that never expires | `exp` is required, and `max_lifetime` bounds how far away it may be |
  # | a reset-link token used as an access token | `purpose` is required and compared |
  # | clock skew widened into an expiry bypass | `leeway` is bounded at `MAX_LEEWAY` |
  # | a signature over re-encoded claims | verification runs over the received bytes |
  # | a multi-megabyte header | size and shape are checked before any parsing |
  #
  # ### What it deliberately does not check
  #
  # `auth_version` is not compared, exactly as in `ApiTokens::Service`: a password change
  # must not silently break a machine client that has no way to notice. The difference is
  # that a JWT gives you no way to change your mind later either — which is the whole point
  # of the paragraph above.
  class Validator < RequestAuthenticator
    # Largest token accepted, before anything is decoded or parsed.
    #
    # A JWT carrying a real claim set is a few hundred bytes. This bound exists so that a
    # hostile `Authorization` header costs one integer comparison instead of a base64 decode
    # and a JSON parse — the same "shape before I/O" rule the opaque tokens follow.
    DEFAULT_MAX_BYTESIZE = 8192

    # Default tolerance for the two clocks disagreeing.
    DEFAULT_LEEWAY = 30.seconds

    # The most skew that may be configured.
    #
    # Leeway extends the life of every expired token by its own width, so it is an expiry
    # bypass with a limit on it. Thirty seconds covers NTP-synchronised hosts; anything
    # approaching an hour means the clocks are broken and should be fixed rather than
    # tolerated.
    MAX_LEEWAY = 5.minutes

    # Default ceiling on how long a token may claim to be valid for.
    #
    # This is the "very short TTL" half of the revocation trade-off. A token is a standing
    # grant that cannot be withdrawn, so its lifetime *is* the exposure window for a
    # stolen one.
    DEFAULT_MAX_LIFETIME = 1.hour

    # Claim carrying what the token is for, and the value an access token must have.
    DEFAULT_PURPOSE_CLAIM = "purpose"
    DEFAULT_PURPOSE       = "access"

    getter issuer : String
    getter audience : String
    getter algorithms : Array(String)
    getter leeway : Time::Span
    getter max_lifetime : Time::Span?
    getter purpose : String?
    getter purpose_claim : String

    # The `jti` denylist, when one was configured. Exposed so `Sweeper` can drop entries whose
    # tokens have expired; see `RevocationStore`.
    getter revocations : RevocationStore?

    # A `JWKS` has not been fetched at boot, so the boot-time check against the algorithm
    # allow-list applies only when a fixed keyring was supplied.
    @static_keyring : Keyring?
    @keys : KeySource

    # `algorithms` is an allow-list of `alg` header values, checked before a key is even
    # selected. It is separate from the keyring's algorithms on purpose: two independent
    # gates on the same value, so that one misconfigured keyring is not enough.
    #
    # `purpose` may be set to `nil` to accept tokens carrying no purpose claim — an
    # explicit decision at the call site, for an issuer you do not control that does not
    # emit one. Understand what it costs: without it, any validly signed token from that
    # issuer authenticates a request, including one minted for a password reset or an
    # email confirmation.
    #
    # `accounts`, when given, turns "is this account still allowed in?" back into a lookup:
    # a disabled account stops authenticating immediately instead of at `exp`. That is a
    # read from storage on every request, which is the cost a JWT was chosen to avoid — the
    # honest accounting is in `RevocationStore`.
    # `keyring` may be a fixed `Keyring` or a `KeySource` such as `JWKS`. The difference is
    # visible in exactly one place — an unknown `kid` asks a `JWKS` to refetch once, because
    # that is what a key rotation looks like from here.
    def initialize(
      keyring : Keyring | KeySource,
      @issuer : String,
      @audience : String,
      @algorithms : Array(String),
      @clock : Clock,
      @leeway : Time::Span = DEFAULT_LEEWAY,
      @max_lifetime : Time::Span? = DEFAULT_MAX_LIFETIME,
      @purpose : String? = DEFAULT_PURPOSE,
      @purpose_claim : String = DEFAULT_PURPOSE_CLAIM,
      @revocations : RevocationStore? = nil,
      @accounts : Accounts::Repository? = nil,
      @max_bytesize : Int32 = DEFAULT_MAX_BYTESIZE,
    )
      @keys = keyring.is_a?(Keyring) ? StaticKeySource.new(keyring) : keyring
      @static_keyring = keyring.is_a?(Keyring) ? keyring : nil

      raise ConfigurationError.new("issuer must not be empty") if @issuer.blank?
      raise ConfigurationError.new("audience must not be empty") if @audience.blank?

      validate_algorithms!
      validate_timing!
      validate_claim_checks!
    end

    private def validate_algorithms! : Nil
      raise ConfigurationError.new("algorithms must not be empty") if @algorithms.empty?

      # Belt to the braces in `Algorithm`: `none` cannot be constructed, and it also cannot
      # be named. Case-insensitively, since `None` is the same bypass.
      if @algorithms.any? { |name| name.compare(NONE, case_insensitive: true).zero? }
        raise ConfigurationError.new(
          "`none` is not an algorithm; a token that says it is unsigned is a token an attacker wrote"
        )
      end

      if @algorithms.any?(&.blank?)
        raise ConfigurationError.new("an algorithm name must not be empty")
      end

      # Only for a fixed keyring: a `JWKS` has not been fetched yet at boot, and its own parser
      # already drops entries the allow-list does not permit.
      #
      # The keyring can only ever prove tokens the allow-list would refuse anyway, which is
      # a configuration mistake rather than a hole — but it is the kind that hides a typo in
      # an algorithm name until the day rotation needs it.
      if static = @static_keyring
        static.keys.each do |key|
          unless @algorithms.includes?(key.algorithm.name)
            raise ConfigurationError.new(
              "keyring holds a #{key.algorithm.name} key, which the algorithm allow-list " \
              "does not permit"
            )
          end
        end
      end
    end

    private def validate_timing! : Nil
      unless @leeway >= Time::Span::ZERO
        raise ConfigurationError.new("leeway must not be negative")
      end

      if @leeway > MAX_LEEWAY
        raise ConfigurationError.new(
          "leeway must not exceed #{MAX_LEEWAY.total_seconds.to_i}s; it extends the life of every " \
          "expired token by its own width"
        )
      end

      if (lifetime = @max_lifetime) && lifetime <= Time::Span::ZERO
        raise ConfigurationError.new("max_lifetime must be positive")
      end
    end

    private def validate_claim_checks! : Nil
      if (expected = @purpose) && expected.blank?
        raise ConfigurationError.new("purpose must not be blank; pass nil to accept any purpose")
      end

      raise ConfigurationError.new("purpose_claim must not be empty") if @purpose_claim.blank?

      if @max_bytesize <= 0
        raise ConfigurationError.new("max_bytesize must be positive")
      end
    end

    # Resolves the value after the `Bearer` scheme.
    #
    # Returns `Anonymous` when nothing was presented, `Failed` for everything else, and
    # never raises: every byte here is attacker-controlled.
    #
    # The order is shape, then signature, then claims, then storage. A token is not parsed
    # for meaning until it has been proven to come from a key we hold — reading claims out
    # of an unverified token is how a validator ends up trusting an attacker's `kid`.
    def authenticate(credential : String?) : Outcome
      result = authenticate_and_keep_claims(credential)

      case result
      in Validated then Authenticated.new(result.principal)
      in Failed    then result
      in Anonymous then result
      end
    end

    # Shared by `#authenticate` and `#validate`. `Anonymous` only ever escapes through the
    # first: a caller asking for claims presented a token on purpose.
    private def authenticate_and_keep_claims(credential : String?) : Validated | Failed | Anonymous
      return Anonymous.new if credential.nil? || credential.empty?
      return Failed.new(FailureReason::MalformedCredential) if credential.bytesize > @max_bytesize

      parts = credential.split('.')

      # Exactly three. Five means a JWE, which this shard does not decrypt and must not
      # mistake for a signed token.
      return Failed.new(FailureReason::MalformedCredential) unless parts.size == 3
      return Failed.new(FailureReason::MalformedCredential) if parts.any?(&.empty?)

      header = decode_json(parts[0])
      return Failed.new(FailureReason::MalformedCredential) if header.nil?

      signature = decode_segment(parts[2])
      return Failed.new(FailureReason::MalformedCredential) if signature.nil?

      key = select_key(header)
      return Failed.new(FailureReason::InvalidCredential) if key.nil?

      # Over the bytes exactly as they arrived, per RFC 7515 §5.2. Re-encoding the parsed
      # header and payload would verify a signature over something nobody signed.
      signing_input = "#{parts[0]}.#{parts[1]}"

      unless key.verify(signing_input, signature)
        return Failed.new(FailureReason::InvalidCredential)
      end

      claims = decode_json(parts[1])
      return Failed.new(FailureReason::MalformedCredential) if claims.nil?

      check_claims(claims)
    end

    # The same validation as `#authenticate`, keeping the claims.
    #
    # `Principal` deliberately carries nothing but a subject, an assurance and a time — no
    # email, no name, no groups (`docs/03-architecture.md` on why). An OpenID Connect callback
    # genuinely needs the rest of the claim set, though, because that is where the provider's
    # assertions live, so this returns both rather than making `OIDC::Client` re-parse a token
    # this class has already verified.
    #
    # Everything `#authenticate` refuses, this refuses identically. It is the same code path.
    def validate(credential : String?) : Validated | Failed
      result = authenticate_and_keep_claims(credential)

      # Nothing presented is a rejection here rather than a state: a caller asking for claims
      # is holding a token it believes in.
      return Failed.new(FailureReason::MalformedCredential) if result.is_a?(Anonymous)

      result
    end

    private NONE = "none"

    # Header handling, all of it before any signature is checked and none of it trusting
    # what it reads for anything except selecting a key we already hold.
    private def select_key(header : Hash(String, ::JSON::Any)) : Key?
      alg = header["alg"]?.try(&.as_s?)
      return if alg.nil?

      # Redundant given the boot-time check, and kept because the cost of being wrong here
      # is every token forged.
      return if alg.compare(NONE, case_insensitive: true).zero?
      return unless @algorithms.includes?(alg)
      return unless acceptable_header?(header)

      kid = select_kid(header)
      key = @keys.keyring.find(kid)

      # An unknown `kid` is what a key rotation looks like from here, so a `JWKS` gets one
      # chance to refetch. It rate-limits itself, because this path is reachable by anybody who
      # can send a token — see `JWKS#minimum_refresh_interval`.
      key = @keys.refresh_for(kid).find(kid) if key.nil?
      return if key.nil?

      # The token said how it wanted to be verified; the key says how it may be. Only the
      # second one decides, and a disagreement is a forgery attempt.
      return unless key.algorithm.name == alg

      key
    end

    # `crit` and `typ`: the two header parameters that can say "this is not what you think".
    private def acceptable_header?(header : Hash(String, ::JSON::Any)) : Bool
      # RFC 7515 §4.1.11: an extension the verifier does not understand must be rejected.
      # This shard understands none, so any `crit` at all is a refusal.
      return false if header.has_key?("crit")

      # `typ` is optional; when present it must not claim to be something else.
      typ = header["typ"]?
      return true if typ.nil?

      value = typ.as_s?
      return false if value.nil?

      normalised = value.downcase
      normalised == "jwt" || normalised.ends_with?("+jwt")
    end

    # `nil` when the header names no key, which an unambiguous ring can still answer. An
    # unusable `kid` returns `""`, which no ring holds, rather than being read as absent.
    private def select_kid(header : Hash(String, ::JSON::Any)) : String?
      raw = header["kid"]?
      return if raw.nil?

      kid = raw.as_s?
      kid.nil? || kid.empty? ? "" : kid
    end

    private def check_claims(claims : Hash(String, ::JSON::Any)) : Validated | Failed
      now = @clock.now

      # `exp` is mandatory. A token with no expiry is a permanent grant that cannot be
      # withdrawn, which is the one thing this design cannot survive.
      expires_at = numeric_date(claims["exp"]?)
      return Failed.new(FailureReason::InvalidClaim) if expires_at.nil?

      issued_at = numeric_date(claims["iat"]?)
      return Failed.new(FailureReason::InvalidClaim) if issued_at.nil? && claims.has_key?("iat")

      if failure = check_timing(claims, now, expires_at, issued_at)
        return failure
      end

      if failure = check_identity(claims)
        return failure
      end

      subject = claims["sub"]?.try(&.as_s?)
      return Failed.new(FailureReason::InvalidClaim) if subject.nil? || subject.empty?

      if failure = check_stored_state(claims, subject)
        return failure
      end

      principal = Principal.new(
        subject: subject,
        # The same level an opaque token gets, and for the same reason: possession of a
        # secret, not the presence of a person. Never fresh, so `require_fresh!` refuses it.
        assurance: AssuranceLevel::ApiToken,
        # `iat` when the issuer stated one — it is when the credential behind this principal
        # was actually verified, and it is what `Principal#fresh?` measures.
        authenticated_at: issued_at || now,
        # `jti` when the issuer stated one, and `nil` otherwise — this shard requires `jti`
        # only when a revocation store is configured, so an unnamed token is a legitimate
        # configuration rather than an error here. Worth knowing what `nil` costs: a
        # credential that cannot be named is one an audit line cannot attribute and an
        # operator cannot revoke on its own.
        #
        # No session id: a bearer token is presented per request and establishes nothing.
        credential: CredentialRef.new(
          kind: CredentialKind::Jwt,
          id: claims["jti"]?.try(&.as_s?),
          expires_at: expires_at,
        ),
      )

      Validated.new(principal: principal, claims: claims)
    end

    # When the token is valid, and for how long it claims to be. Returns `nil` when every
    # check passes.
    private def check_timing(
      claims : Hash(String, ::JSON::Any),
      now : Time,
      expires_at : Time,
      issued_at : Time?,
    ) : Failed?
      return Failed.new(FailureReason::Expired) if now > expires_at + @leeway

      if not_before = numeric_date(claims["nbf"]?)
        return Failed.new(FailureReason::InvalidClaim) if now < not_before - @leeway
      elsif claims.has_key?("nbf")
        return Failed.new(FailureReason::InvalidClaim)
      end

      if issued_at && issued_at - @leeway > now
        # Issued in the future: either the clocks are further apart than `leeway` admits, or
        # somebody is extending a lifetime by moving its start.
        return Failed.new(FailureReason::InvalidClaim)
      end

      if lifetime = @max_lifetime
        # Measured from `iat` when the token states one, and from now when it does not —
        # otherwise omitting `iat` would be a way around the ceiling.
        start = issued_at || now
        return Failed.new(FailureReason::InvalidClaim) if expires_at - start > lifetime + @leeway
      end

      nil
    end

    # Who issued it, who it is for, and what it is for. Returns `nil` when every check passes.
    private def check_identity(claims : Hash(String, ::JSON::Any)) : Failed?
      return Failed.new(FailureReason::InvalidClaim) unless claims["iss"]?.try(&.as_s?) == @issuer
      return Failed.new(FailureReason::InvalidClaim) unless audience_matches?(claims["aud"]?)

      if expected = @purpose
        unless claims[@purpose_claim]?.try(&.as_s?) == expected
          return Failed.new(FailureReason::InvalidClaim)
        end
      end

      nil
    end

    # The two checks that cost a lookup, and are therefore the two that are off by default.
    # `JWT::RevocationStore` sets out what turning them on buys and what it costs.
    private def check_stored_state(claims : Hash(String, ::JSON::Any), subject : String) : Failed?
      if revocations = @revocations
        # A revocation store you cannot key is a revocation store that does nothing, so an
        # issuer that omits `jti` is a configuration failure surfaced as a rejection rather
        # than a silently unenforced control.
        jti = claims["jti"]?.try(&.as_s?)
        return Failed.new(FailureReason::InvalidClaim) if jti.nil? || jti.empty?
        return Failed.new(FailureReason::Revoked) if revocations.revoked?(jti)
      end

      if accounts = @accounts
        account = accounts.find_by_id(subject)
        return Failed.new(FailureReason::InvalidCredential) if account.nil?
        return Failed.new(FailureReason::DisabledAccount) if account.disabled?
      end

      nil
    end

    # RFC 7519 §4.1.3: `aud` is a string, or an array of strings when the token is meant
    # for several recipients. Both forms are required to *name us*; a missing or empty
    # `aud` is a token anybody may replay anywhere.
    private def audience_matches?(value : ::JSON::Any?) : Bool
      return false if value.nil?

      if single = value.as_s?
        return single == @audience
      end

      if many = value.as_a?
        return many.any? { |entry| entry.as_s? == @audience }
      end

      false
    end

    # Largest value `Time.unix` accepts here: 9999-12-31T23:59:59Z. A token claiming to
    # expire past it is refused rather than allowed to raise.
    private MAX_NUMERIC_DATE = 253_402_300_799_i64

    private def numeric_date(value : ::JSON::Any?) : Time?
      return if value.nil?

      if seconds = value.as_i64?
        return if seconds < 0 || seconds > MAX_NUMERIC_DATE
        return Time.unix(seconds)
      end

      # RFC 7519 allows a non-integer NumericDate. Bounded before conversion, since a
      # float outside Int64's range raises on `to_i64`.
      if seconds = value.as_f?
        return if seconds.nan? || seconds < 0 || seconds > MAX_NUMERIC_DATE
        return Time.unix(seconds.to_i64)
      end

      nil
    end

    private def decode_json(segment : String) : Hash(String, ::JSON::Any)?
      Validator.decode_json(segment)
    end

    private def decode_segment(segment : String) : Bytes?
      Validator.decode_segment(segment)
    end

    # Class-level so that `JWT.unverified_issuer` can reuse exactly this discipline rather than
    # reimplementing it. Neither reads instance state, and a second decoder that agreed *almost*
    # with this one is how a token means two things to one application.
    def self.decode_json(segment : String) : Hash(String, ::JSON::Any)?
      bytes = decode_segment(segment)
      return if bytes.nil?

      parsed = ::JSON.parse(String.new(bytes))
      parsed.as_h?
    rescue ::JSON::ParseException
      nil
    end

    # Base64url, unpadded, per RFC 7515 §2.
    #
    # Strict about the alphabet rather than lenient: standard-base64 `+` and `/`, and `=`
    # padding, are all rejected. A decoder that accepts several encodings of one token is
    # a decoder two systems can disagree about, and disagreement is where signature-
    # stripping bugs live.
    def self.decode_segment(segment : String) : Bytes?
      return unless segment.matches?(OpaqueToken::PATTERN)

      # No valid base64 has this length; `Base64.decode` would otherwise accept it.
      return if segment.bytesize % 4 == 1

      padded = segment.tr("-_", "+/")
      padded += "=" * ((4 - padded.bytesize % 4) % 4)

      Base64.decode(padded)
    rescue Base64::Error
      nil
    end
  end

  # The `iss` a token *claims*, read without verifying anything at all.
  #
  # ### What this is for
  #
  # One `Validator` holds one issuer, so an API accepting tokens from several customer identity
  # providers has one validator each — and has to decide which one to ask. It cannot ask them in
  # turn: every JWT is three base64url segments, so `AuthenticatorChain` routes them all to the
  # first validator, which fails the signature and stops the chain. Measured, in both orders, in
  # `blueprints/0025-maturity-validation-results.md` (JWT-01): whichever issuer is registered
  # second has its customers refused.
  #
  # So the choice has to be made from the token, before any validation, and this is that read —
  # bounded and strict, so an application does not write its own.
  #
  # ```
  # issuer = KemalIdentity::JWT.unverified_issuer(credential)
  # validator = issuer.try { |i| VALIDATORS[i]? }
  # outcome = validator.try(&.authenticate(credential)) ||
  #           KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidClaim)
  # ```
  #
  # ### What it is not for, and the name says so
  #
  # **The return value is attacker-controlled.** Nothing has been verified — not the signature,
  # not `exp`, not `aud`. Two rules follow, and both are load-bearing:
  #
  # 1. **Never treat it as an identity.** It selects a validator and nothing else. The trustworthy
  #    issuer is the one on `Validator`, after `authenticate` succeeded — that one was compared
  #    against a configured value.
  # 2. **Never build a URL from it.** Fetching JWKS from the issuer a token names is
  #    server-side request forgery with extra steps: the attacker chooses the host. Look the
  #    validator up in a map the application configured at boot, by exact string equality, and
  #    refuse anything not in it.
  #
  # ### Bounded, like the validator itself
  #
  # `max_bytesize` defaults to what `Validator` uses, and is checked before anything is decoded,
  # so a two-megabyte `Authorization` header costs one integer comparison. The segment alphabet is
  # the strict base64url of RFC 7515 §2 — the same decoder the validator uses, not a second one
  # that might disagree with it.
  #
  # Answers `nil` for anything that is not a well-formed JWT carrying a non-empty string `iss`.
  # A `nil` means "no validator can be chosen", which the caller must treat as a refusal rather
  # than as permission to pick a default.
  def self.unverified_issuer(
    credential : String?,
    max_bytesize : Int32 = Validator::DEFAULT_MAX_BYTESIZE,
  ) : String?
    return if credential.nil? || credential.empty?
    return if credential.bytesize > max_bytesize

    parts = credential.split('.')
    return unless parts.size == 3

    claims = Validator.decode_json(parts[1])
    return if claims.nil?

    issuer = claims["iss"]?.try(&.as_s?)
    return if issuer.nil? || issuer.empty?

    issuer
  end
end

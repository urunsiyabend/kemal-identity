require "openssl/hmac"

module KemalIdentity
  # Cross-site request forgery protection.
  #
  # ### Why a token at all, when the cookie is already `SameSite=Lax`
  #
  # `SameSite` is defence in depth, not a replacement. It is a browser-side control with
  # inconsistent behaviour across clients, it does nothing for a request the browser considers
  # same-site, and `Lax` — which this shard defaults to, because `Strict` breaks
  # return-from-OAuth navigation — permits top-level cross-site `GET`s
  # (`docs/02-security-model.md`).
  #
  # ### The scheme: a signed, session-bound, masked token
  #
  # No server-side token store, and no plain double-submit either.
  #
  # Plain double-submit — compare a cookie to a form field — fails the requirement that *a
  # token from another session is rejected*: anyone who can set the cookie can also set the
  # field, and the two would agree. So the token is an HMAC the application alone can compute:
  #
  # ```
  # raw    = HMAC-SHA256(secret, anchor)
  # pad    = 32 random bytes
  # token  = base64url(pad + (raw XOR pad))
  # ```
  #
  # `anchor` is the **session id** for an authenticated request, and the value of a dedicated
  # `__Host-` prefixed cookie for an anonymous one. An attacker cannot compute `raw` without
  # the secret, and cannot read the victim's anchor — so a token minted for their own session
  # fails against the victim's.
  #
  # The mask exists because `raw` is otherwise constant for the lifetime of a session, and a
  # value that repeats in every response is what BREACH-style compression oracles extract. The
  # pad changes per issue, so the rendered token changes with it while still verifying.
  #
  # ### The anonymous anchor, and why login CSRF is covered
  #
  # `docs/02-security-model.md` calls login CSRF "the case most implementations miss": without
  # a token on the login form, an attacker logs the victim into the **attacker's** account and
  # then observes whatever the victim does under it — anything typed, uploaded or purchased
  # lands in an account the attacker controls.
  #
  # The login form is anonymous, so it has no session to bind to. It binds to the anchor
  # cookie instead, which is issued lazily the first time a token is asked for. The `__Host-`
  # prefix is doing real work here: it forbids a `Domain` attribute, so a compromised sibling
  # subdomain cannot plant an anchor the attacker knows.
  module CSRF
    # SHA-256, so 32 bytes of signature and 32 of pad.
    DIGEST_BYTES = 32
    TOKEN_BYTES  = DIGEST_BYTES * 2

    # base64url of 64 bytes, unpadded.
    TOKEN_LENGTH = 86

    PATTERN = /\A[A-Za-z0-9_-]+\z/

    # Mints a token for `anchor`.
    def self.issue(secret : Secret, anchor : String, random : RandomSource) : String
      raw = sign(secret, anchor)
      pad = random.bytes(DIGEST_BYTES)

      masked = Bytes.new(TOKEN_BYTES)
      pad.copy_to(masked)
      DIGEST_BYTES.times { |i| masked[DIGEST_BYTES + i] = raw[i] ^ pad[i] }

      Base64.urlsafe_encode(masked, padding: false)
    end

    # Whether `presented` is a token this application issued for `anchor`.
    #
    # Returns false for anything malformed rather than raising: the input is whatever a client
    # chose to send, and a hostile value must be a rejection, not a 500.
    def self.valid?(secret : Secret, anchor : String, presented : String?) : Bool
      return false if presented.nil? || anchor.empty?

      # Shape before decoding, so an oversized value costs a length comparison.
      return false unless presented.bytesize == TOKEN_LENGTH && presented.matches?(PATTERN)

      masked = decode(presented)
      return false if masked.nil? || masked.size != TOKEN_BYTES

      pad = masked[0, DIGEST_BYTES]
      unmasked = Bytes.new(DIGEST_BYTES)
      DIGEST_BYTES.times { |i| unmasked[i] = masked[DIGEST_BYTES + i] ^ pad[i] }

      Crypto::Subtle.constant_time_compare(unmasked, sign(secret, anchor))
    end

    private def self.sign(secret : Secret, anchor : String) : Bytes
      OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, secret.reveal, anchor)
    end

    private def self.decode(value : String) : Bytes?
      Base64.decode(value)
    rescue Base64::Error
      nil
    end
  end

  # How CSRF protection is named and scoped. Boot-time and immutable.
  struct CSRFConfig
    # Anything not on this list is protected. A denylist of `POST`/`PUT`/`PATCH`/`DELETE`
    # would leave every method nobody thought of unprotected — `PROPFIND` mutates in WebDAV,
    # and HTTP QUERY did not exist when this shard was designed. Safe-by-name, protected
    # otherwise.
    #
    # `QUERY` is here because RFC 10008 defines it as safe and idempotent. It carries a request
    # body, which makes it easy to mistake for a mutation; it is not one, and a spec asserts
    # that its body does not get it treated as one.
    SAFE_METHODS = %w[GET HEAD OPTIONS TRACE QUERY]

    # Minimum signing key length. A short key is a weak signature, and this is the one place a
    # weak default would be invisible.
    MIN_SECRET_BYTES = 32

    getter secret : Secret
    getter cookie_name : String
    getter header_name : String
    getter field_name : String
    getter exempt_prefixes : Array(String)
    getter? secure : Bool

    def initialize(
      secret : String,
      @cookie_name : String = "__Host-kemal_identity_csrf",
      @header_name : String = "X-CSRF-Token",
      @field_name : String = "_csrf",
      # Mirrors `Sessions::CookieConfig`: the anchor cookie is `Secure` unless an application
      # deliberately says otherwise, which is only ever right in local development.
      @secure : Bool = true,
      # Prefixes exempted from protection.
      #
      # Exempting a path is a promise that it accepts **no** session cookie. An endpoint that
      # accepts a cookie is subject to CSRF regardless of whether it also accepts a bearer
      # token, and regardless of being labelled an API — content type is not a defence
      # (`docs/02-security-model.md`). When bearer tokens land in v0.4 the exemption applies
      # only to endpoints that accept nothing but an `Authorization` header.
      @exempt_prefixes : Array(String) = [] of String,
    )
      if secret.bytesize < MIN_SECRET_BYTES
        raise ConfigurationError.new(
          "CSRF secret must be at least #{MIN_SECRET_BYTES} bytes, got #{secret.bytesize}"
        )
      end

      if @cookie_name.starts_with?("__Host-") && !@secure
        raise ConfigurationError.new("a __Host- CSRF cookie must be Secure")
      end

      raise ConfigurationError.new("CSRF cookie name must not be empty") if @cookie_name.empty?

      # Wrapped immediately, so a configuration dump in a crash report cannot leak the
      # signing key (`docs/02-security-model.md`).
      @secret = Secret.new(secret)
    end

    # The anchor cookie.
    #
    # `HttpOnly`, because nothing client-side needs to read it: the token itself is rendered
    # into the page, and the anchor is only ever compared server-side. `__Host-` by default,
    # which forbids a `Domain` attribute — so a compromised sibling subdomain cannot plant an
    # anchor value the attacker knows, which is what makes the anonymous login-form case hold.
    def build_cookie(value : String) : HTTP::Cookie
      HTTP::Cookie.new(
        name: @cookie_name,
        value: value,
        path: "/",
        secure: @secure,
        http_only: true,
        samesite: HTTP::Cookie::SameSite::Lax,
      )
    end

    def protects?(method : String) : Bool
      !SAFE_METHODS.includes?(method.upcase)
    end

    def exempt?(path : String) : Bool
      @exempt_prefixes.any? do |prefix|
        next false unless path.starts_with?(prefix)
        rest = path[prefix.size..]
        rest.empty? || rest.starts_with?('/')
      end
    end

    # Never prints the secret.
    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Kemal::CSRFConfig cookie_name=" << @cookie_name.inspect
      io << " secret=[REDACTED]>"
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end
  end
end

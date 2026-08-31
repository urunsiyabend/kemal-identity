require "openssl/hmac"

module KemalIdentity::Testing
  # Mints JSON Web Tokens, including ones no honest issuer would produce.
  #
  # The shard validates tokens and deliberately does not issue them, so this lives in
  # `spec/support/` rather than `src/`. It exists to *attack* the validator: every knob a
  # forger would want — the algorithm, the `kid`, an unsigned token, a header that lies
  # about what the signature covers, arbitrary bytes in any segment — is reachable from
  # here, because a validator spec that can only produce well-formed tokens tests nothing
  # an attacker would ever send.
  module JWTForge
    DIGESTS = {"HS256" => ::OpenSSL::Algorithm::SHA256,
               "HS384" => ::OpenSSL::Algorithm::SHA384,
               "HS512" => ::OpenSSL::Algorithm::SHA512}

    # A key long enough for every HMAC variant this shard ships.
    SECRET = KemalIdentity::Secret.new("k" * 64)

    ISSUER   = "https://issuer.example.com"
    AUDIENCE = "https://api.example.com"

    def self.claims(
      now : Time = KemalIdentity::Testing::FIXED_NOW,
      subject : String = "a1",
      expires_in : Time::Span? = 15.minutes,
      issuer : String? = ISSUER,
      audience : ::JSON::Any? = ::JSON::Any.new(AUDIENCE),
      purpose : String? = "access",
      issued_at : Time? = nil,
      jti : String? = nil,
    ) : Hash(String, ::JSON::Any)
      claims = {} of String => ::JSON::Any

      claims["sub"] = ::JSON::Any.new(subject)
      claims["iss"] = ::JSON::Any.new(issuer) if issuer
      claims["aud"] = audience if audience
      claims["purpose"] = ::JSON::Any.new(purpose) if purpose
      claims["jti"] = ::JSON::Any.new(jti) if jti
      claims["exp"] = ::JSON::Any.new((now + expires_in).to_unix) if expires_in

      at = issued_at || now
      claims["iat"] = ::JSON::Any.new(at.to_unix)

      claims
    end

    # A signed token. `algorithm` names the `alg` header *and* selects the digest, so
    # passing one the key was not meant for produces exactly the confusion attack.
    def self.encode(
      claims : Hash(String, ::JSON::Any),
      secret : KemalIdentity::Secret = SECRET,
      algorithm : String = "HS256",
      kid : String? = nil,
      header : Hash(String, ::JSON::Any) = {} of String => ::JSON::Any,
    ) : String
      full = {"alg" => ::JSON::Any.new(algorithm), "typ" => ::JSON::Any.new("JWT")}
      full["kid"] = ::JSON::Any.new(kid) if kid
      full.merge!(header)

      signing_input = "#{segment(full.to_json)}.#{segment(claims.to_json)}"
      digest = DIGESTS[algorithm]? || ::OpenSSL::Algorithm::SHA256
      signature = ::OpenSSL::HMAC.digest(digest, secret.reveal, signing_input)

      "#{signing_input}.#{encode_bytes(signature)}"
    end

    # A token whose header claims one algorithm while the signature was made with another.
    def self.encode_lying(
      claims : Hash(String, ::JSON::Any),
      claimed : String,
      signed_with : String,
      secret : KemalIdentity::Secret = SECRET,
      kid : String? = nil,
    ) : String
      header = {"alg" => ::JSON::Any.new(claimed), "typ" => ::JSON::Any.new("JWT")}
      header["kid"] = ::JSON::Any.new(kid) if kid

      signing_input = "#{segment(header.to_json)}.#{segment(claims.to_json)}"
      signature = ::OpenSSL::HMAC.digest(DIGESTS[signed_with], secret.reveal, signing_input)

      "#{signing_input}.#{encode_bytes(signature)}"
    end

    # The `alg: none` token: a real header, real claims, and an empty signature segment.
    # Also produced with a non-empty junk signature, since some libraries only check that
    # the segment is present.
    def self.unsigned(
      claims : Hash(String, ::JSON::Any),
      signature : String = "",
      algorithm : String = "none",
    ) : String
      header = {"alg" => ::JSON::Any.new(algorithm), "typ" => ::JSON::Any.new("JWT")}

      "#{segment(header.to_json)}.#{segment(claims.to_json)}.#{signature}"
    end

    # Replaces the claims of an already-signed token, leaving its signature untouched.
    def self.swap_claims(token : String, claims : Hash(String, ::JSON::Any)) : String
      parts = token.split('.')

      "#{parts[0]}.#{segment(claims.to_json)}.#{parts[2]}"
    end

    # An RS256/384/512 token signed by the fixed test key.
    def self.encode_rsa(
      claims : Hash(String, ::JSON::Any),
      algorithm : String = "RS256",
      kid : String? = nil,
      header : Hash(String, ::JSON::Any) = {} of String => ::JSON::Any,
    ) : String
      full = {"alg" => ::JSON::Any.new(algorithm), "typ" => ::JSON::Any.new("JWT")}
      full["kid"] = ::JSON::Any.new(kid) if kid
      full.merge!(header)

      signing_input = "#{segment(full.to_json)}.#{segment(claims.to_json)}"

      "#{signing_input}.#{encode_bytes(RSATestKey.sign(signing_input, algorithm))}"
    end

    def self.segment(json : String) : String
      encode_bytes(json.to_slice)
    end

    def self.encode_bytes(bytes : Bytes) : String
      Base64.strict_encode(bytes).tr("+/", "-_").rstrip('=')
    end
  end
end

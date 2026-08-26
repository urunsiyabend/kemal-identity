require "openssl/hmac"

module KemalIdentity::JWT
  # A signature scheme a token may be verified with.
  #
  # ### `none` cannot be expressed here
  #
  # RFC 7519 defines an `alg` of `none`, meaning "this token is unsigned", and it is the
  # single most reliably exploited flaw in JWT deployments: a library that honours it turns
  # any token the attacker writes into a valid one. This shard has no way to say it. There
  # is no `None` subclass, `Validator` refuses an allow-list containing `"none"` at boot,
  # and the header's `alg` is checked against the *key's* algorithm besides — three
  # independent places, because one place is one mistake away from none of them.
  #
  # ### Verification, not signing
  #
  # Only `#verify` is abstract. This shard validates tokens issued elsewhere — an identity
  # provider, a gateway, another service — and minting them is deliberately out of scope,
  # so there is no signing key to be careless with. `ApiTokens::Service` is what issues a
  # credential here.
  #
  # ### Adding an algorithm
  #
  # Only HMAC is shipped, because Crystal's OpenSSL bindings expose `HMAC` and not the
  # `EVP` interface that RSA and ECDSA verification need. RS256 and ES256 are therefore a
  # subclass plus a C binding away rather than built in — implement `#verify` against
  # whichever binding you already have. Everything else, `kid` selection included, is
  # unchanged, since the keyring names the algorithm rather than trusting the token to.
  abstract class Algorithm
    # The `alg` header value that selects this scheme, exactly as it appears in the token.
    abstract def name : String

    # Whether `signature` is a valid signature over `signing_input` under `key`.
    #
    # `signing_input` is the base64url header and payload joined by a dot, per RFC 7515 —
    # the bytes as they arrived, never a re-encoding of the parsed claims. Re-encoding
    # would mean verifying a signature over something the sender never signed.
    #
    # Implementations must be constant-time and must not raise: everything here is
    # attacker-supplied.
    abstract def verify(signing_input : String, signature : Bytes, key : Secret) : Bool
  end

  # HMAC over SHA-2: `HS256`, `HS384` and `HS512`.
  #
  # A symmetric scheme, so every party that can verify a token can also mint one. That is
  # fine when the issuer and the verifier are the same deployment and the secret never
  # leaves it, and it is the wrong choice for a token from a third party — there, an
  # asymmetric algorithm is what stops your verifier's copy of the key from being a
  # forging key.
  class HMAC < Algorithm
    getter name : String

    # Minimum key length in bytes, per RFC 7518 §3.2: "A key of the same size as the hash
    # output or larger MUST be used". A 6-character HMAC secret is brute-forceable offline
    # from a single captured token, so this is enforced rather than recommended.
    getter minimum_key_bytes : Int32

    protected def initialize(@name : String, @digest : ::OpenSSL::Algorithm, @minimum_key_bytes : Int32)
    end

    def verify(signing_input : String, signature : Bytes, key : Secret) : Bool
      expected = ::OpenSSL::HMAC.digest(@digest, key.reveal, signing_input)

      # Length first — `constant_time_compare` on differing lengths is not meaningful — and
      # the length of a signature is not a secret.
      return false if signature.size != expected.size

      Crypto::Subtle.constant_time_compare(signature, expected)
    end
  end

  # HMAC-SHA-256. The default choice for a token minted and verified by one deployment.
  HS256 = HMAC.new("HS256", ::OpenSSL::Algorithm::SHA256, 32)

  # HMAC-SHA-384.
  HS384 = HMAC.new("HS384", ::OpenSSL::Algorithm::SHA384, 48)

  # HMAC-SHA-512.
  HS512 = HMAC.new("HS512", ::OpenSSL::Algorithm::SHA512, 64)
end

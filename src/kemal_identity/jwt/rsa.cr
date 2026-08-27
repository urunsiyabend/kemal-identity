require "openssl"

# Bindings Crystal's standard library does not provide.
#
# `OpenSSL::HMAC` is bound; the `EVP_PKEY` interface that public-key verification needs is not,
# and neither is `d2i_PUBKEY`. Reopening the lib is how a shard adds the handful of functions it
# needs without vendoring the rest, and these five are the whole of it.
#
# `EVP_DigestVerify` is the one-shot form, present since OpenSSL 1.1.1 and not deprecated in
# 3.x. The low-level `RSA_*` API would be the other way to do this and is deprecated in 3.0, so
# the key is assembled as DER and handed to `d2i_PUBKEY` instead — see `JWT::RSAPublicKey`.
lib LibCrypto
  # Named for the C type, as Crystal's own `EVP_MD_CTX` and `EVP_MD` are. A binding that
  # renames what it binds is a binding nobody can check against the header.
  # ameba:disable Naming/TypeNames
  alias EVP_PKEY = Void*

  fun d2i_pubkey = d2i_PUBKEY(a : EVP_PKEY*, pp : UInt8**, length : Long) : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(pkey : EVP_PKEY)
  fun evp_pkey_base_id = EVP_PKEY_base_id(pkey : EVP_PKEY) : Int32

  fun evp_digestverifyinit = EVP_DigestVerifyInit(
    ctx : EVP_MD_CTX, pctx : Void**, type : EVP_MD, e : Void*, pkey : EVP_PKEY,
  ) : Int32

  fun evp_digestverify = EVP_DigestVerify(
    ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT,
  ) : Int32
end

module KemalIdentity::JWT
  # An RSA public key, held as a live `EVP_PKEY`.
  #
  # ### Why the key is built as DER
  #
  # A JWKS gives a modulus and an exponent as two base64url integers, and OpenSSL has no
  # "assemble a key from these two numbers" call that survives 3.x: the `RSA_new` /
  # `RSA_set0_key` route is deprecated there, and `EVP_PKEY_fromdata` is 3.0-only, which would
  # make this shard refuse to build against 1.1.1. What *is* stable in both is `d2i_PUBKEY`, so
  # the two integers are encoded into a DER SubjectPublicKeyInfo — about forty lines of ASN.1 —
  # and parsed back by OpenSSL itself. OpenSSL validates the structure; this code only writes it.
  class RSAPublicKey
    # DER for `AlgorithmIdentifier { rsaEncryption, NULL }`, which is the same bytes for every
    # RSA key: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }.
    RSA_ALGORITHM_IDENTIFIER = Bytes[
      0x30, 0x0d,
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
      0x05, 0x00,
    ]

    # Smallest modulus accepted, in bytes.
    #
    # 2048 bits. Anything smaller is not a key an issuer should still be signing with, and
    # accepting one means the weakest key in a rotating JWKS sets the security of the whole
    # thing.
    MINIMUM_MODULUS_BYTES = 256

    @pkey : LibCrypto::EVP_PKEY

    # Builds a key from a JWKS `n` and `e`, already base64url-decoded.
    #
    # Raises `ConfigurationError` for anything OpenSSL will not accept, so a malformed JWKS
    # entry is a loud failure at fetch time rather than a key that silently verifies nothing.
    def initialize(modulus : Bytes, exponent : Bytes)
      if modulus.size < MINIMUM_MODULUS_BYTES
        raise ConfigurationError.new(
          "RSA modulus must be at least #{MINIMUM_MODULUS_BYTES * 8} bits, " \
          "got #{modulus.size * 8}"
        )
      end

      raise ConfigurationError.new("RSA exponent must not be empty") if exponent.empty?

      der = RSAPublicKey.encode_subject_public_key_info(modulus, exponent)

      pkey = der.to_unsafe.as(UInt8*)
      parsed = LibCrypto.d2i_pubkey(nil, pointerof(pkey), der.size.to_i64)

      raise ConfigurationError.new("could not parse the RSA public key") if parsed.null?

      @pkey = parsed
    end

    # Whether `signature` is a PKCS#1 v1.5 signature over `data` under this key.
    #
    # Returns `false` for anything that does not verify, including a malformed signature:
    # everything reaching here is attacker-supplied, so nothing about it may raise.
    def verify(data : String, signature : Bytes, digest : ::OpenSSL::Algorithm) : Bool
      return false if signature.empty?

      md = LibCrypto.evp_get_digestbyname(digest.to_s)
      return false if md.null?

      ctx = LibCrypto.evp_md_ctx_new
      return false if ctx.null?

      begin
        return false unless LibCrypto.evp_digestverifyinit(ctx, nil, md, nil, @pkey) == 1

        # Exactly 1 means verified. 0 means "did not verify" and anything else is an error, and
        # both of those are the same answer to the caller.
        LibCrypto.evp_digestverify(
          ctx, signature.to_unsafe, signature.size.to_u64,
          data.to_unsafe, data.bytesize.to_u64
        ) == 1
      ensure
        LibCrypto.evp_md_ctx_free(ctx)
      end
    end

    def finalize
      LibCrypto.evp_pkey_free(@pkey) unless @pkey.null?
    end

    # DER `SubjectPublicKeyInfo` for an RSA key:
    #
    # ```text
    # SEQUENCE {
    #   SEQUENCE { OID rsaEncryption, NULL }
    #   BIT STRING { SEQUENCE { INTEGER n, INTEGER e } }
    # }
    # ```
    protected def self.encode_subject_public_key_info(modulus : Bytes, exponent : Bytes) : Bytes
      rsa_key = sequence(integer(modulus) + integer(exponent))

      # A BIT STRING is preceded by a count of unused trailing bits, which is zero for anything
      # byte-aligned.
      bit_string = tagged(0x03, Bytes[0x00] + rsa_key)

      sequence(RSA_ALGORITHM_IDENTIFIER + bit_string)
    end

    # ASN.1 INTEGER. A leading zero is prepended when the top bit is set, because DER integers
    # are signed and a modulus is not.
    private def self.integer(value : Bytes) : Bytes
      trimmed = value

      while trimmed.size > 1 && trimmed[0] == 0
        trimmed = trimmed[1..]
      end

      body = trimmed[0] >= 0x80 ? Bytes[0x00] + trimmed : trimmed

      tagged(0x02, body)
    end

    private def self.sequence(body : Bytes) : Bytes
      tagged(0x30, body)
    end

    # Tag, DER length, body. Definite-length only, which is all a key needs.
    private def self.tagged(tag : UInt8, body : Bytes) : Bytes
      io = IO::Memory.new
      io.write_byte(tag)
      write_length(io, body.size)
      io.write(body)
      io.to_slice
    end

    private def self.write_length(io : IO, length : Int32) : Nil
      if length < 0x80
        io.write_byte(length.to_u8)
        return
      end

      bytes = [] of UInt8
      remaining = length

      while remaining > 0
        bytes.unshift((remaining & 0xff).to_u8)
        remaining >>= 8
      end

      io.write_byte((0x80 | bytes.size).to_u8)
      bytes.each { |byte| io.write_byte(byte) }
    end
  end

  # RSASSA-PKCS1-v1_5: `RS256`, `RS384` and `RS512`.
  #
  # The algorithms an OpenID Connect provider actually signs ID tokens with. Asymmetric, so the
  # key this shard holds verifies and cannot forge — which is what makes a token from a third
  # party meaningfully different from an `HS256` one, where the verifier's copy of the key is
  # also a signing key.
  #
  # A `Key` built with one of these takes an `RSAPublicKey` in place of a `Secret`, so the same
  # keyring, the same `kid` selection and the same allow-list apply unchanged.
  class RSA < Algorithm
    getter name : String

    protected def initialize(@name : String, @digest : ::OpenSSL::Algorithm)
    end

    # Not reachable through `Key`, which routes an RSA key to `#verify_with`. Present because
    # `Algorithm` demands it, and refusing outright is better than quietly treating a public
    # key as an HMAC secret — which is the algorithm-confusion attack itself.
    def verify(signing_input : String, signature : Bytes, key : Secret) : Bool
      false
    end

    def verify_with(signing_input : String, signature : Bytes, key : RSAPublicKey) : Bool
      key.verify(signing_input, signature, @digest)
    end
  end

  # RSASSA-PKCS1-v1_5 over SHA-256. What almost every OIDC provider uses.
  RS256 = RSA.new("RS256", ::OpenSSL::Algorithm::SHA256)

  # :ditto:
  RS384 = RSA.new("RS384", ::OpenSSL::Algorithm::SHA384)

  # :ditto:
  RS512 = RSA.new("RS512", ::OpenSSL::Algorithm::SHA512)
end

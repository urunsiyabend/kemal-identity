require "openssl"

# Signing bindings, for the spec suite only.
#
# `src/kemal_identity/jwt/rsa.cr` binds verification, because that is all the shard does. To
# *attack* an RS256 validator a spec has to be able to mint tokens, so signing is bound here —
# in `spec/support/`, where it cannot become part of the published API by accident. A shard that
# can sign is a shard someone will use to issue tokens, and issuing is deliberately out of scope.
lib LibCrypto
  fun d2i_autoprivatekey = d2i_AutoPrivateKey(
    a : EVP_PKEY*, pp : UInt8**, length : Long,
  ) : EVP_PKEY

  fun evp_digestsigninit = EVP_DigestSignInit(
    ctx : EVP_MD_CTX, pctx : Void**, type : EVP_MD, e : Void*, pkey : EVP_PKEY,
  ) : Int32

  fun evp_digestsign = EVP_DigestSign(
    ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT,
  ) : Int32
end

module KemalIdentity::Testing
  # A fixed 2048-bit RSA key pair, and the JWKS numbers that describe its public half.
  #
  # Fixed rather than generated per run, for the reason `spec/CLAUDE.md` gives about
  # determinism: a key generated at spec time makes every RS256 example depend on a keygen that
  # takes an unpredictable amount of time, and gives a failure nobody can reproduce from the
  # spec file alone. It is a test key, published in a public repository, and it protects
  # nothing.
  module RSATestKey
    # PKCS#8 DER, base64. The private half.
    PRIVATE_DER_BASE64 = <<-KEY.gsub('\n', "")
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7fizguscSkMLV0AIH9Ahk+PAJcyfSNLOglapr5N
      zIEM4DHdtkt2ikibD5ekVAPs9QtRDjC6w/T7A5K+mXzQEzM2V8ZDFvkg/KYuWu15v7h+9Ms7v/qEt1GAEvjPXxjGZe
      cy9S/HUHd41m1KAW/QTBCnEL66Iv0jrWvIO8Fr66CJyNQW80vtr2J1TXvQostFqNjM170gIeKvsp5R8XLMQmwAOmlg
      QR3m8KOLVckN2qSLpS58lq27HvlKzmt4PrvbytFqsuuEY/y2Yub4KRVN9UyXctdSRJ2CIJXlMoYQZ5jCU5quxql0jD
      53GRCCn/Tmox0O2ESopuU9qacqIZUlZXAgMBAAECggEAVUG91H76URXkkudgVQ+B1bBhLlrf67UtTUNhWGicgJkrpL
      0p63V/Lvqxr/AKl3k4OmHriOLg83UgFA9EzFNbTVX8uwCwfiRz67rm6IeAlXMtvLoqLcnwbhF5UI8Ps0P9tMs55MmJ
      ydhyQyVCmtF5HPLLjvkaKha1zLmySZAqMFs8ex6iKAvOBp5JW0LhtWFRij/j8E8eRxDwyEa8y+hgbWGG7CHCOvAHas
      209Hj2ygDqAXrzA3xHgpxGi6S0hbfDHgCYFMoXxKIud+Maq5ej0vsvy3dlvLRc9LkEIuCNJ3joKV27IToFgwGVWpWv
      +n3CcGrlaJtEsgEoQjP6X9ts2QKBgQDpIGn56f6AWgeu43cjo0n1RejliULC3rftar8tUmymQ4MqE+nXXAiDrxSUxI
      yHhqT9INMIRz9Igj+oshNWSO6kfPCwJVGZgkw/iTNgAJMvTQo+X1wFw3bHIOpC+yn3Tp+4OEFlemW8OX2XI6OCuxvM
      bE9ljBOMMBipfGVKoT0mLQKBgQDN44zbhP56flRpAoFR7AykQCVTfOopc9/O8xkVhkWHsleN+PXOxx37ABvFYVuCPf
      9LZ6jFGqYVpYyIx9n195NkqT1sQPhnmV/1aewlU1d9lSS6HAce61DN8uQObNQ8aaQSnamSfhqxQWUd64QOA303FwZz
      WTgtDtb3ZV3sJtQlEwKBgQCShgv1xstuEqf3lQIhxRTL8zexZTcv0doaf9hO/RpK2e4LuV5lPHQhiB5QbsTAvbDfZA
      0fi+BLi4nFVr9uoQJVIi4JGDuUV1/jIzHGKjZYKXzBvR/Sg4sZFygGF2TGCoW6vKjlxitBRYUZRI4VsdKEBqNUeNkk
      aGpnxEbJxFPxtQKBgAMOhs/XiKOu7nfkpqDdvU5O+X7k0uEsrDz5VP0B0lRybGRaNuQMBsDsPn1OtboYS4sGDfZnL+
      IQZCa/uNezBkgvTw8lY8q99zPAj9X6B8mAhlwRAHYQDlIQchxYt0nyU5JHLvZS0vigvOyVy48dtCU2PU1HHNNmbgCc
      S6mu5eVrAoGBALFFejgzwA9RHrw9pTuFJ9oC00AY3MSnaEqawCDLnwKb7iRrHWCMedGJ97j9DUKdjARidKc4Hun4Xw
      KGSj9ieZOuHt1XlGZyoeZwR9k6bEvtwpxQA0OlGqw0EASqSHOQ0o1ECsq8EapUeRqjKPfUHhTDAeFaBblTrQpgktT8
      pSHs
      KEY

    # The JWKS `n`, base64url. The modulus of the key above.
    MODULUS_BASE64URL = <<-N.gsub('\n', "")
      u34s4LrHEpDC1dACB_QIZPjwCXMn0jSzoJWqa-TcyBDOAx3bZLdopImw-XpFQD7PULUQ4wusP0-wOSvpl80BMzNlfG
      Qxb5IPymLlrteb-4fvTLO7_6hLdRgBL4z18YxmXnMvUvx1B3eNZtSgFv0EwQpxC-uiL9I61ryDvBa-ugicjUFvNL7a
      9idU170KLLRajYzNe9ICHir7KeUfFyzEJsADppYEEd5vCji1XJDdqki6UufJatux75Ss5reD6728rRarLrhGP8tmLm
      -CkVTfVMl3LXUkSdgiCV5TKGEGeYwlOarsapdIw-dxkQgp_05qMdDthEqKblPamnKiGVJWVw
      N

    # The JWKS `e`, base64url. 65537, as every RSA key in practice.
    EXPONENT_BASE64URL = "AQAB"

    DIGESTS = {"RS256" => ::OpenSSL::Algorithm::SHA256,
               "RS384" => ::OpenSSL::Algorithm::SHA384,
               "RS512" => ::OpenSSL::Algorithm::SHA512}

    def self.modulus : Bytes
      decode(MODULUS_BASE64URL)
    end

    def self.exponent : Bytes
      decode(EXPONENT_BASE64URL)
    end

    def self.public_key : KemalIdentity::JWT::RSAPublicKey
      KemalIdentity::JWT::RSAPublicKey.new(modulus, exponent)
    end

    # A PKCS#1 v1.5 signature over `data`, for minting a token to attack the validator with.
    def self.sign(data : String, algorithm : String = "RS256") : Bytes
      der = Base64.decode(PRIVATE_DER_BASE64)
      pointer = der.to_unsafe.as(UInt8*)
      pkey = LibCrypto.d2i_autoprivatekey(nil, pointerof(pointer), der.size.to_i64)

      raise "could not load the test private key" if pkey.null?

      begin
        md = LibCrypto.evp_get_digestbyname(DIGESTS[algorithm].to_s)
        ctx = LibCrypto.evp_md_ctx_new

        begin
          raise "EVP_DigestSignInit failed" unless LibCrypto.evp_digestsigninit(ctx, nil, md, nil, pkey) == 1

          # Called twice: once with a null buffer to learn the length, then to fill it.
          length = LibC::SizeT.new(0)
          raise "EVP_DigestSign sizing failed" unless LibCrypto.evp_digestsign(ctx, nil, pointerof(length), data.to_unsafe, data.bytesize.to_u64) == 1

          signature = Bytes.new(length.to_i32)
          raise "EVP_DigestSign failed" unless LibCrypto.evp_digestsign(
                                                 ctx, signature.to_unsafe, pointerof(length), data.to_unsafe, data.bytesize.to_u64
                                               ) == 1

          signature[0, length.to_i32]
        ensure
          LibCrypto.evp_md_ctx_free(ctx)
        end
      ensure
        LibCrypto.evp_pkey_free(pkey)
      end
    end

    private def self.decode(value : String) : Bytes
      padded = value.tr("-_", "+/")
      padded += "=" * ((4 - padded.bytesize % 4) % 4)

      Base64.decode(padded)
    end
  end
end

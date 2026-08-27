require "openssl/cipher"
require "openssl/hmac"

module KemalIdentity::MFA
  # Reversible encryption for the one secret in this shard that cannot be hashed.
  #
  # ### Why this exists at all
  #
  # Every other secret here is stored as a SHA-256 digest, because the server only ever has to
  # *recognise* it. A TOTP secret is different in kind: the server has to recompute the code
  # from it on every verification, so it must be able to read the secret back. Hashing is not
  # an option, and pretending otherwise would mean shipping something that does not work.
  #
  # What is left is the next-best property: a stolen database is not enough. Sealed secrets are
  # useless without a key that lives in the application's configuration rather than in the
  # table beside them, so a dump, a backup or a read-only SQL injection yields ciphertext. An
  # attacker who has *both* has the second factor, and there is no arrangement of software that
  # changes that.
  #
  # Contrast recovery codes, which are ordinary bearer secrets and are stored as digests like
  # everything else.
  #
  # ### The contract
  #
  # `#seal` must be non-deterministic: sealing the same secret twice produces different blobs,
  # so that equal ciphertexts do not reveal equal secrets. `#open?` returns `nil` rather than
  # raising for a blob that does not authenticate — a truncated column, a row from a different
  # key, a value someone edited — because that is a data problem the caller has to handle, not
  # an exception on the verification path.
  abstract class SecretBox
    # Encrypts `secret`, returning an opaque blob to store.
    abstract def seal(secret : Bytes) : Bytes

    # The secret inside `sealed`, or `nil` if it does not authenticate under this key.
    abstract def open?(sealed : Bytes) : Bytes?
  end

  # AES-256-CBC with an HMAC-SHA-256 tag over the ciphertext: encrypt-then-MAC.
  #
  # ### Why not GCM
  #
  # It would be the obvious choice, and Crystal's `OpenSSL::Cipher` does not expose the
  # authentication tag — there is no `auth_tag` accessor and no `EVP_CIPHER_CTX_ctrl` binding,
  # so a GCM tag cannot be read out or supplied back without binding libcrypto directly. That
  # is a dependency this shard will not take for one table. Encrypt-then-MAC over CBC is the
  # classical construction it replaced, it is secure when done in this order, and every piece
  # of it is in the standard library.
  #
  # The order matters and is not a detail: **MAC over the ciphertext, verified before
  # decrypting**. MAC-then-encrypt invites a padding oracle, because the padding is checked on
  # data that has not been authenticated yet. Here a blob that fails the tag is never fed to
  # the cipher at all.
  #
  # ### The blob
  #
  # ```text
  # version (1) | iv (16) | tag (32) | ciphertext (16n)
  # ```
  #
  # The version byte is covered by the tag and exists so a future scheme can be added without
  # a migration: a reader that meets a version it does not know refuses the row rather than
  # guessing at its layout.
  class AesSecretBox < SecretBox
    VERSION    = 1_u8
    IV_BYTES   =   16
    TAG_BYTES  =   32
    KEY_BYTES  =   32
    CIPHER     = "aes-256-cbc"
    MIN_LENGTH = 1 + IV_BYTES + TAG_BYTES + 16

    # Domain separation. One master key, two derived keys that must never be interchangeable:
    # a construction where the same bytes both encrypt and authenticate is one where an
    # attacker who breaks one has broken both.
    ENCRYPTION_CONTEXT = "kemal_identity/mfa/secret-box/v1/encryption"
    MAC_CONTEXT        = "kemal_identity/mfa/secret-box/v1/authentication"

    # `key` is the application's master key, and it is the whole of the protection: it belongs
    # in configuration or a secrets manager, never in the database this box writes to, and
    # never in the repository.
    #
    # At least 32 bytes, because the derived keys are only as strong as what they came from.
    # Generate one with `Random::Secure.hex(32)` and treat losing it as losing every enrolled
    # factor — see `#reseal`.
    def initialize(key : Secret, @random : RandomSource)
      if key.bytesize < KEY_BYTES
        raise ConfigurationError.new(
          "secret box key must be at least #{KEY_BYTES} bytes, got #{key.bytesize}"
        )
      end

      @encryption_key = ::OpenSSL::HMAC.digest(
        ::OpenSSL::Algorithm::SHA256, key.reveal, ENCRYPTION_CONTEXT
      )
      @mac_key = ::OpenSSL::HMAC.digest(
        ::OpenSSL::Algorithm::SHA256, key.reveal, MAC_CONTEXT
      )
    end

    def seal(secret : Bytes) : Bytes
      raise ArgumentError.new("secret must not be empty") if secret.empty?

      iv = @random.bytes(IV_BYTES)

      cipher = ::OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = @encryption_key
      cipher.iv = iv

      ciphertext = IO::Memory.new
      ciphertext.write(cipher.update(secret))
      ciphertext.write(cipher.final)
      body = ciphertext.to_slice

      authenticated = Bytes.new(1 + IV_BYTES + body.size)
      authenticated[0] = VERSION
      iv.copy_to(authenticated + 1)
      body.copy_to(authenticated + 1 + IV_BYTES)

      tag = ::OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, @mac_key, authenticated)

      sealed = Bytes.new(1 + IV_BYTES + TAG_BYTES + body.size)
      sealed[0] = VERSION
      iv.copy_to(sealed + 1)
      tag.copy_to(sealed + 1 + IV_BYTES)
      body.copy_to(sealed + 1 + IV_BYTES + TAG_BYTES)

      sealed
    end

    def open?(sealed : Bytes) : Bytes?
      # Length and version before any cryptography, and before any allocation proportional to
      # what was handed in.
      return if sealed.size < MIN_LENGTH
      return unless sealed[0] == VERSION

      iv = sealed[1, IV_BYTES]
      tag = sealed[1 + IV_BYTES, TAG_BYTES]
      body = sealed[(1 + IV_BYTES + TAG_BYTES)..]

      # CBC produces whole blocks; anything else was truncated or edited.
      return unless body.size % 16 == 0

      authenticated = Bytes.new(1 + IV_BYTES + body.size)
      authenticated[0] = VERSION
      iv.copy_to(authenticated + 1)
      body.copy_to(authenticated + 1 + IV_BYTES)

      expected = ::OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, @mac_key, authenticated)

      # Verified *before* decrypting. This is the line that is not a padding oracle.
      return unless Crypto::Subtle.constant_time_compare(tag, expected)

      cipher = ::OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key = @encryption_key
      cipher.iv = iv

      plain = IO::Memory.new
      plain.write(cipher.update(body))
      plain.write(cipher.final)

      plain.to_slice
    rescue ::OpenSSL::Cipher::Error
      # Unreachable through the tag check above for anything an attacker produced, and kept
      # because "the library raised" must not become a 500 on the verification path.
      nil
    end

    # Re-encrypts a blob under this box, given the one it was sealed with.
    #
    # Key rotation, in the only form this design supports: read every factor, `reseal`, write
    # it back. That is an offline job over a small table, not a migration, and it is deliberate
    # — carrying several keys and a key id inside the blob would make the common path pay for
    # a rotation that happens once.
    #
    # Returns `nil` when `previous` cannot open the blob, so a partly-rotated table is visible
    # rather than silently re-sealed as garbage.
    def reseal(sealed : Bytes, previous : SecretBox) : Bytes?
      secret = previous.open?(sealed)
      return if secret.nil?

      seal(secret)
    end

    # Redacted: the derived keys are the whole protection, and a config dump in a crash report
    # must not print them.
    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::MFA::AesSecretBox [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end
end

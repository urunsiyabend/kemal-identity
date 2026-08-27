require "openssl/hmac"

module KemalIdentity::MFA
  # Time-based one-time passwords, RFC 6238.
  #
  # The whole algorithm is HOTP (RFC 4226) with a counter derived from the clock: divide the
  # seconds since the epoch by a step, HMAC the counter under a shared secret, and truncate the
  # result to a few digits. That is all a second factor is — proof that the holder has the
  # secret, sampled at a moment both sides can agree on.
  #
  # ### This module decides nothing
  #
  # It computes and compares codes. It does not know which account a secret belongs to, whether
  # a code was already used, or how many attempts have been made — those are `MFA::Service`'s
  # job, and they are the parts that actually make TOTP safe. A six-digit code is one of a
  # million, and an unlimited number of guesses against a window that never closes is not a
  # second factor at all.
  module TOTP
    # Digest used to derive codes. SHA-1 is the default, and not because it is the best of
    # these: it is what authenticator apps overwhelmingly implement, and a second factor
    # nobody can enrol in protects nothing. HMAC-SHA-1 is not affected by the SHA-1 collision
    # results — this is a keyed MAC over a counter, not a signature over attacker-chosen text.
    enum Algorithm
      SHA1
      SHA256
      SHA512

      # The spelling the `otpauth://` URI uses.
      def to_s(io : IO) : Nil
        io << case self
        in Algorithm::SHA1   then "SHA1"
        in Algorithm::SHA256 then "SHA256"
        in Algorithm::SHA512 then "SHA512"
        end
      end

      def digest : ::OpenSSL::Algorithm
        case self
        in Algorithm::SHA1   then ::OpenSSL::Algorithm::SHA1
        in Algorithm::SHA256 then ::OpenSSL::Algorithm::SHA256
        in Algorithm::SHA512 then ::OpenSSL::Algorithm::SHA512
        end
      end
    end

    # Seconds per code. Thirty is what every authenticator app assumes.
    DEFAULT_PERIOD = 30.seconds

    # Digits per code. Six is the universal default; eight is permitted by RFC 6238 and
    # supported here, and anything else is refused rather than silently truncated.
    DEFAULT_DIGITS = 6

    # Digit counts a client can actually display and a person can actually read back.
    PERMITTED_DIGITS = {6, 7, 8}

    # The RFC 4226 counter for `at`: whole steps since the Unix epoch.
    def self.counter(at : Time, period : Time::Span = DEFAULT_PERIOD) : Int64
      raise ArgumentError.new("period must be positive") unless period > Time::Span::ZERO

      at.to_unix // period.total_seconds.to_i64
    end

    # The code for one counter value.
    #
    # Returned as a zero-padded string rather than an integer, because `042311` and `42311`
    # are the same number and only one of them is the code.
    def self.code(
      secret : Bytes,
      counter : Int64,
      digits : Int32 = DEFAULT_DIGITS,
      algorithm : Algorithm = Algorithm::SHA1,
    ) : String
      raise ArgumentError.new("secret must not be empty") if secret.empty?

      unless PERMITTED_DIGITS.includes?(digits)
        raise ArgumentError.new("digits must be one of #{PERMITTED_DIGITS.join(", ")}, got #{digits}")
      end

      message = Bytes.new(8)
      IO::ByteFormat::BigEndian.encode(counter, message)

      mac = ::OpenSSL::HMAC.digest(algorithm.digest, secret, message)

      # RFC 4226 §5.3 dynamic truncation: the low nibble of the last byte picks where to read
      # four bytes from, and the top bit is masked off so the result is positive on every
      # platform's signed integer.
      offset = (mac[mac.size - 1] & 0x0f).to_i
      binary = ((mac[offset].to_u32 & 0x7f) << 24) |
               (mac[offset + 1].to_u32 << 16) |
               (mac[offset + 2].to_u32 << 8) |
               mac[offset + 3].to_u32

      modulus = 10_u32 ** digits

      (binary % modulus).to_s.rjust(digits, '0')
    end

    # The counter a `candidate` matches within `drift` steps either side of `at`, or `nil`.
    #
    # Returning the counter rather than a boolean is what lets the caller refuse a code it has
    # already seen. Without that, every code stays valid for its whole window and a shoulder-
    # surfed six digits can be replayed for the next thirty seconds — which is exactly the
    # window an attacker who watched someone type it is working in.
    #
    # `drift` exists because the two clocks are never identical, and it is a cost: each step of
    # tolerance multiplies the number of codes valid at any moment. One step either side is the
    # usual compromise and the default.
    def self.match(
      secret : Bytes,
      candidate : String,
      at : Time,
      period : Time::Span = DEFAULT_PERIOD,
      digits : Int32 = DEFAULT_DIGITS,
      algorithm : Algorithm = Algorithm::SHA1,
      drift : Int32 = 1,
    ) : Int64?
      raise ArgumentError.new("drift must not be negative") if drift < 0

      # Shape before any HMAC: a two-megabyte "code" costs a length comparison.
      return unless candidate.bytesize == digits
      return unless candidate.each_char.all?(&.ascii_number?)

      current = counter(at, period)
      matched = nil.as(Int64?)

      # Every candidate counter is checked even after a match, so that the time this takes does
      # not reveal which step matched — and with it, the offset between the two clocks.
      (-drift..drift).each do |offset|
        expected = code(secret, current + offset, digits, algorithm)

        matched = current + offset if Crypto::Subtle.constant_time_compare(candidate, expected)
      end

      matched
    end

    # The `otpauth://` URI an authenticator app scans.
    #
    # `issuer` names the service and `label` names the account within it — usually the login,
    # since it is what the person will recognise in a list of six-digit codes. Both appear in
    # the path *and* `issuer` again in the query, which is redundant and is what the apps
    # actually parse.
    #
    # The result contains the secret. It is a credential: render it to a QR code and never log
    # it, put it in a URL that leaves the machine, or store it beside the ciphertext it came
    # from.
    def self.provisioning_uri(
      secret : Bytes,
      issuer : String,
      label : String,
      period : Time::Span = DEFAULT_PERIOD,
      digits : Int32 = DEFAULT_DIGITS,
      algorithm : Algorithm = Algorithm::SHA1,
    ) : String
      raise ArgumentError.new("issuer must not be empty") if issuer.blank?
      raise ArgumentError.new("label must not be empty") if label.blank?

      # A colon separates issuer from label in the path, so one inside either would produce a
      # URI that parses to something else.
      if issuer.includes?(':') || label.includes?(':')
        raise ArgumentError.new("issuer and label must not contain a colon")
      end

      path = URI.encode_path_segment("#{issuer}:#{label}")

      params = URI::Params.build do |form|
        form.add("secret", Base32.encode(secret))
        form.add("issuer", issuer)
        form.add("algorithm", algorithm.to_s)
        form.add("digits", digits.to_s)
        form.add("period", period.total_seconds.to_i.to_s)
      end

      "otpauth://totp/#{path}?#{params}"
    end
  end
end

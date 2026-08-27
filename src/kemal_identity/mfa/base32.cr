module KemalIdentity::MFA
  # RFC 4648 base32, because every authenticator app expects a TOTP secret in it.
  #
  # Not a general-purpose codec and not exported as one: it exists because `otpauth://` URIs
  # and the "type this code in by hand" fallback both speak base32, and Crystal's stdlib ships
  # base64 only. The alphabet is case-insensitive on the way in — a person reading a secret off
  # a screen types it in whatever case they like — and upper-case on the way out.
  module Base32
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    # Base32 of `bytes`, unpadded.
    #
    # Padding is dropped because `otpauth://` secrets are conventionally unpadded and because
    # `=` would have to be percent-escaped in the query string it lands in.
    def self.encode(bytes : Bytes) : String
      return "" if bytes.empty?

      String.build do |io|
        buffer = 0_u32
        bits = 0

        bytes.each do |byte|
          buffer = (buffer << 8) | byte
          bits += 8

          while bits >= 5
            bits -= 5
            io << ALPHABET[(buffer >> bits) & 0x1f]
          end
        end

        # The trailing partial group, left-aligned with zero bits, per RFC 4648 §6.
        io << ALPHABET[(buffer << (5 - bits)) & 0x1f] if bits > 0
      end
    end

    # The bytes `value` encodes, or `nil` when it is not base32.
    #
    # Returns `nil` rather than raising: the input is usually something a person typed, so
    # "that is not a valid secret" is an expected answer and not an exceptional one. Spaces and
    # hyphens are ignored, since secrets are printed in groups of four to be readable, and `=`
    # padding is accepted although never produced.
    def self.decode?(value : String) : Bytes?
      cleaned = value.delete { |char| char.ascii_whitespace? || char == '-' }.rstrip('=').upcase
      return Bytes.new(0) if cleaned.empty?

      # 1, 3 and 6 characters cannot be the tail of any byte-aligned group.
      return if {1, 3, 6}.includes?(cleaned.bytesize % 8)

      io = IO::Memory.new
      buffer = 0_u32
      bits = 0

      cleaned.each_char do |char|
        index = ALPHABET.index(char)
        return if index.nil?

        buffer = (buffer << 5) | index
        bits += 5

        if bits >= 8
          bits -= 8
          io.write_byte(((buffer >> bits) & 0xff).to_u8)
        end
      end

      # Whatever is left is padding, and RFC 4648 §3.5 requires it to be zero. A non-zero
      # remainder means two different strings would decode to the same bytes.
      return if bits > 0 && (buffer & ((1_u32 << bits) - 1)) != 0

      io.to_slice
    end
  end
end

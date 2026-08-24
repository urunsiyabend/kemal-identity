module KemalIdentity
  # A string that must never be printed.
  #
  # Wrapping a raw credential in this type means a crash report, a `Log` call or an
  # accidental interpolation prints `#<KemalIdentity::Secret [REDACTED]>` instead of the
  # password, the session token or the cookie signing key. `docs/02-security-model.md`
  # requires that every type holding a secret redacts itself, the configuration object
  # included.
  #
  # This is a safety net, not a licence to log. Nothing on the authentication path should
  # be logging a `Secret` at all.
  struct Secret
    def initialize(@value : String)
    end

    # The raw value. Every call site is a place a secret can escape, so keep them few and
    # obvious: hashing, digesting, and constant-time comparison.
    def reveal : String
      @value
    end

    # Length in characters, for a policy that counts what a person typed. Distinct from
    # `#bytesize`, which is what an algorithm's limit is measured in.
    def size : Int32
      @value.size
    end

    # Length of the underlying value. Safe to log; used by the shape checks that run
    # before any hashing or I/O.
    def bytesize : Int32
      @value.bytesize
    end

    def empty? : Bool
      @value.empty?
    end

    # Constant-time equality.
    #
    # `==` on `String` short-circuits at the first differing byte, which leaks the length
    # of the matching prefix. Secrets are compared here and nowhere else.
    def ==(other : Secret) : Bool
      Crypto::Subtle.constant_time_compare(@value, other.reveal)
    end

    def ==(other : String) : Bool
      Crypto::Subtle.constant_time_compare(@value, other)
    end

    # SHA-256 of the value, as raw bytes.
    #
    # Raw bytes rather than hex: `BYTEA` is half the storage of a hex `CHAR(64)` and there
    # is no encoding for two adapters to disagree about (`docs/03-data-model.md`).
    def digest : Bytes
      Digest::SHA256.digest(@value)
    end

    def to_s(io : IO) : Nil
      io << "[REDACTED]"
    end

    def inspect(io : IO) : Nil
      io << "#<KemalIdentity::Secret [REDACTED]>"
    end
  end
end

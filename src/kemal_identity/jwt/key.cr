module KemalIdentity::JWT
  # One verification key, and the single algorithm it may be used with.
  #
  # ### Why the key names the algorithm
  #
  # Binding the two together is what defeats algorithm confusion, the second classic JWT
  # attack after `alg: none`. The attack: a service verifies RS256 tokens with a public
  # key, an attacker re-signs the payload as HS256 using that public key *as an HMAC
  # secret*, and a library that reads `alg` from the token and then asks "what key do I
  # have?" verifies it happily. The token got to choose how it would be checked.
  #
  # Here it cannot. The keyring decides which key applies, the key states its algorithm,
  # and the token's `alg` header is only ever compared against that — it selects nothing.
  # `Validator`'s allow-list is a second, independent gate on the same value.
  struct Key
    # The `kid` this key answers to, or `nil` for a keyring holding exactly one key.
    #
    # Not a secret and not a credential: it is a public label that says *which* key was
    # used, so publishing it in a token header costs nothing. Naming keys is what makes
    # rotation possible — see `Keyring`.
    getter id : String?

    # The scheme this key may be used with, and the only one.
    getter algorithm : Algorithm

    def initialize(@algorithm : Algorithm, @secret : Secret, @id : String? = nil)
      if (id = @id) && id.empty?
        raise ConfigurationError.new("key id must not be empty; use nil for an unnamed key")
      end

      if @secret.empty?
        raise ConfigurationError.new("key secret must not be empty")
      end

      if (algorithm = @algorithm).is_a?(HMAC) && @secret.bytesize < algorithm.minimum_key_bytes
        raise ConfigurationError.new(
          "#{algorithm.name} requires a key of at least #{algorithm.minimum_key_bytes} bytes, " \
          "got #{@secret.bytesize}"
        )
      end
    end

    # Whether `signature` verifies over `signing_input` under this key.
    def verify(signing_input : String, signature : Bytes) : Bool
      @algorithm.verify(signing_input, signature, @secret)
    end

    # Redacted: a config dump in a crash report must not print a verification key, which
    # for HMAC is also a *signing* key and therefore forges tokens.
    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::JWT::Key " << (@id || "(unnamed)") << ' ' << @algorithm.name
      io << " [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end

  # The keys a validator will consider, indexed by `kid`.
  #
  # ### Rotation
  #
  # Rotating a signing key means both keys have to verify for a while, since tokens minted
  # under the old one are still in flight until their `exp`. That window is what `kid` is
  # for: the issuer stamps each token with the name of the key that signed it, both keys
  # sit in the ring, and the old one is dropped once nothing can still be carrying it.
  # Without `kid` the verifier's only option is to try every key in turn, which turns key
  # retirement into guesswork and makes a compromised key impossible to withdraw cleanly.
  #
  # ### Selection is strict on purpose
  #
  # * A token naming a `kid` the ring does not hold is **rejected**, never retried against
  #   the other keys. A withdrawn key must stay withdrawn.
  # * A token naming no `kid` resolves only when the ring holds exactly one key. With two
  #   or more the request is ambiguous, and guessing is how a retired key gets used again.
  class Keyring
    getter keys : Array(Key)

    @by_id : Hash(String?, Key)

    def initialize(@keys : Array(Key))
      raise ConfigurationError.new("keyring must hold at least one key") if @keys.empty?

      ids = @keys.map(&.id)

      if ids.size != ids.uniq.size
        raise ConfigurationError.new("keyring must not hold two keys with the same id")
      end

      if @keys.size > 1 && ids.any?(Nil)
        raise ConfigurationError.new(
          "every key in a keyring of more than one must have an id, so that `kid` can select it"
        )
      end

      @by_id = @keys.to_h { |key| {key.id, key} }
    end

    # Convenience for the common single-key case.
    def self.new(algorithm : Algorithm, secret : Secret, id : String? = nil) : Keyring
      new([Key.new(algorithm, secret, id)])
    end

    # The key `kid` names, or `nil` when none applies.
    #
    # Returning `nil` rather than raising keeps this on the failure-is-a-value path: `kid`
    # arrives from the client, so an unknown one is an authentication failure, not a bug.
    def find(kid : String?) : Key?
      return @by_id[kid]? unless kid.nil?

      # No `kid`: only an unambiguous ring can answer.
      @keys.size == 1 ? @keys.first : nil
    end

    def size : Int32
      @keys.size
    end

    def to_s(io : IO) : Nil
      io << "#<KemalIdentity::JWT::Keyring " << @keys.size << " key(s) [REDACTED]>"
    end

    # :ditto:
    def inspect(io : IO) : Nil
      to_s(io)
    end
  end
end

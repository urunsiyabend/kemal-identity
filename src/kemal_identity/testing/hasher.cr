module KemalIdentity::Testing
  # A hasher fast enough to run in every login spec.
  #
  # Real bcrypt at cost 12 is tens of milliseconds per verification, so a suite that used it
  # everywhere would take minutes and nobody would run it on save. This satisfies the same
  # `Hasher` contract — the contract spec is what stops it drifting into false confidence —
  # and is unreachable from a production build because it lives in `spec/support`.
  #
  # **Not a password hasher.** A single SHA-256 pass is exactly what a password hasher must
  # not be: it is fast, which is the property that makes offline cracking cheap. The
  # `rounds` parameter stands in for bcrypt's cost so `needs_rehash?` has something to
  # compare, and buys no real work.
  class FastTestHasher < KemalIdentity::Passwords::Hasher
    SCHEME = "test"

    # Matches bcrypt's usable limit so specs written against the double keep meaning
    # something against the real hasher.
    MAX_SECRET_BYTESIZE = 71

    getter rounds : Int32

    @dummy_digest : String

    def initialize(
      @rounds : Int32 = 2,
      @random : KemalIdentity::RandomSource = KemalIdentity::SecureRandomSource.new,
    )
      # A random secret rather than a fixed one, for the reason given on
      # `Hasher#dummy_digest`: a constant would be a value an attacker could submit.
      @dummy_digest = hash_secret(KemalIdentity::Secret.new(@random.token))
    end

    def scheme : String
      SCHEME
    end

    def max_secret_bytesize : Int32
      MAX_SECRET_BYTESIZE
    end

    def hash_secret(secret : KemalIdentity::Secret) : String
      validate!(secret)
      # Salt comes from the injected source, not `Random.new`: spec/CLAUDE.md requires that
      # nothing in the suite reach for real randomness, so a `DeterministicRandom` makes
      # this hasher reproducible end to end.
      salt = @random.bytes(8).hexstring
      "$#{SCHEME}$#{@rounds}$#{salt}$#{derive(secret, salt, @rounds)}"
    end

    def verify(secret : KemalIdentity::Secret, digest : String) : Bool
      return false unless usable?(secret)

      parts = digest.split('$')
      return false unless parts.size == 5 && parts[1] == SCHEME

      rounds = parts[2].to_i?
      return false if rounds.nil?

      Crypto::Subtle.constant_time_compare(parts[4], derive(secret, parts[3], rounds))
    end

    def needs_rehash?(digest : String) : Bool
      parts = digest.split('$')
      return true unless parts.size == 5 && parts[1] == SCHEME

      rounds = parts[2].to_i?
      return true if rounds.nil?

      rounds < @rounds
    end

    def dummy_digest : String
      @dummy_digest
    end

    private def derive(secret : KemalIdentity::Secret, salt : String, rounds : Int32) : String
      digest = "#{salt}#{secret.reveal}"
      rounds.times { digest = Digest::SHA256.hexdigest(digest) }
      digest
    end

    private def usable?(secret : KemalIdentity::Secret) : Bool
      !secret.empty? && secret.bytesize <= MAX_SECRET_BYTESIZE
    end

    private def validate!(secret : KemalIdentity::Secret) : Nil
      raise ArgumentError.new("secret must not be empty") if secret.empty?

      if secret.bytesize > MAX_SECRET_BYTESIZE
        raise ArgumentError.new(
          "secret is #{secret.bytesize} bytes; #{SCHEME} accepts at most #{MAX_SECRET_BYTESIZE}"
        )
      end
    end
  end
end

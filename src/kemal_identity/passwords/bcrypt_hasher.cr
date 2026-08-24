require "crypto/bcrypt/password"

module KemalIdentity::Passwords
  # bcrypt, via Crystal's standard library. The default hasher.
  #
  # Argon2id is the better algorithm and ships as `kemal_identity_argon2`, separately,
  # because it needs a C binding — the only real reason to split a shard
  # (`docs/00-scope.md`). bcrypt is the default because it is in the standard library, so
  # the default path has no native dependency at all.
  #
  # ### Cost
  #
  # `DEFAULT_COST` here is 12, above the standard library's 11. It is a starting point, not
  # a recommendation: the right cost is the highest one that keeps p95 login latency inside
  # budget **on the deployment target**, which is what `bench/` measures. Crystal's own
  # bcrypt documentation makes the same point, and adds the other half — rate-limit every
  # endpoint that verifies a hash, because deliberately slow work is a denial-of-service
  # lever (`docs/04-kemal-integration.md`).
  #
  # Verification is CPU-bound for tens of milliseconds. Run on a request fiber it occupies a
  # scheduler thread for that whole time, so a burst of logins queues unrelated requests
  # behind it. Keeping this class synchronous is deliberate: the fix is to dispatch it to a
  # dedicated execution context, and that belongs in a wrapper around this contract rather
  # than in the contract itself, so introducing it later changes one call site instead of
  # the `Hasher` API (`docs/06-roadmap.md`, step 10).
  class BcryptHasher < Hasher
    SCHEME = "bcrypt"

    DEFAULT_COST = 12

    # bcrypt's limit is 72 bytes *including* the trailing NUL the algorithm appends, which
    # leaves 71 for the secret. Crystal's `Crypto::Bcrypt` enforces
    # `PASSWORD_RANGE = 1..72` against `bytesize + 1`, so 71 is exactly where it starts
    # raising.
    MAX_SECRET_BYTESIZE = 71

    getter cost : Int32

    @dummy_digest : String

    def initialize(
      @cost : Int32 = DEFAULT_COST,
      random : KemalIdentity::RandomSource = SecureRandomSource.new,
    )
      unless Crypto::Bcrypt::COST_RANGE.includes?(@cost)
        raise ConfigurationError.new(
          "bcrypt cost #{@cost} is outside the supported range #{Crypto::Bcrypt::COST_RANGE}"
        )
      end

      # Computed once, here, so the unknown-login path costs no more than a real
      # verification and costs it no later. The secret is random rather than a documented
      # constant — see `Hasher#dummy_digest`.
      @dummy_digest = hash_secret(Secret.new(random.token))
    end

    def scheme : String
      SCHEME
    end

    def max_secret_bytesize : Int32
      MAX_SECRET_BYTESIZE
    end

    def hash_secret(secret : Secret) : String
      validate!(secret)
      Crypto::Bcrypt::Password.create(secret.reveal, cost: @cost).to_s
    end

    def verify(secret : Secret, digest : String) : Bool
      # Checked before parsing, and never by handing an over-length secret to the standard
      # library: `Crypto::Bcrypt` raises on one, and this is the request path.
      return false unless usable?(secret)

      parsed = parse(digest)
      return false if parsed.nil?

      parsed.verify(secret.reveal)
    end

    def needs_rehash?(digest : String) : Bool
      parsed = parse(digest)

      # Unparseable, or produced by something that is not bcrypt: exactly the legacy digest
      # the lazy-rehash migration exists to retire.
      return true if parsed.nil?

      parsed.cost < @cost
    end

    def dummy_digest : String
      @dummy_digest
    end

    # `Crypto::Bcrypt::Password.new` raises on anything it does not recognise, and a foreign
    # digest is an expected input here rather than an error — an application mid-migration
    # has a table full of them. Rescuing the one specific class it raises turns that into a
    # value; `src/CLAUDE.md` bans the blanket form, not this.
    private def parse(digest : String) : Crypto::Bcrypt::Password?
      return if digest.empty?
      Crypto::Bcrypt::Password.new(digest)
    rescue Crypto::Bcrypt::Error
      nil
    end

    private def usable?(secret : Secret) : Bool
      !secret.empty? && secret.bytesize <= MAX_SECRET_BYTESIZE
    end

    private def validate!(secret : Secret) : Nil
      raise ArgumentError.new("secret must not be empty") if secret.empty?

      if secret.bytesize > MAX_SECRET_BYTESIZE
        raise ArgumentError.new(
          "secret is #{secret.bytesize} bytes; bcrypt accepts at most #{MAX_SECRET_BYTESIZE}"
        )
      end
    end
  end
end

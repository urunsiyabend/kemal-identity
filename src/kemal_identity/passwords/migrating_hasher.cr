module KemalIdentity::Passwords
  # The current hasher, plus the ability to verify digests from the system being migrated off.
  #
  # `docs/06-roadmap.md`'s migration step 2, made expressible:
  #
  # ```
  # login
  #   ├─ current hasher verifies         → done
  #   └─ legacy verifier succeeds        → rehash with the current hasher, immediately
  # ```
  #
  # Nobody is forced through a password reset, and old digests disappear as people sign in. The
  # rehash is not this class's doing — `Passwords::Authenticator` already rehashes whenever
  # `#needs_rehash?` says so, and `Hasher#needs_rehash?` is documented to return true for a
  # digest it cannot parse, which is exactly the legacy one. All that was missing was a way to
  # *verify* it, and this is that.
  #
  # ```
  # KemalIdentity.configure(
  #   accounts: accounts,
  #   sessions: sessions,
  #   hasher: KemalIdentity::Passwords::MigratingHasher.new(
  #     KemalIdentity::Passwords::BcryptHasher.new,
  #     [DeviseVerifier.new.as(KemalIdentity::Passwords::LegacyVerifier)]
  #   ),
  # )
  # ```
  #
  # ### It never writes a legacy digest
  #
  # `#hash_secret` and `#scheme` are the current hasher's, always. Verification is the only
  # thing the legacy side is allowed to do, so the count of old digests can only go down.
  #
  # ### One verifier runs, not all of them
  #
  # Digests are routed by `LegacyVerifier#handles?`, which looks at shape and never at the
  # secret. Trying every verifier in turn would make a login cost the sum of every legacy
  # scheme, and would make that cost depend on which scheme the account uses.
  #
  # ### The timing hole this closes, which is not the usual one
  #
  # The enumeration oracle — unknown logins answering faster than real ones — is already closed
  # by `Hasher#dummy_digest`. This introduces a *different* one. Legacy schemes are usually
  # fast, because being fast is why they are being retired; bcrypt is deliberately slow. So a
  # failed login against an un-migrated account would return in microseconds while a failed
  # login against a migrated one takes tens of milliseconds, and an attacker learns **which
  # accounts have not been migrated yet** — precisely the accounts whose digests are cheapest
  # to attack if the database ever leaks.
  #
  # So a failed legacy verification is followed by a throwaway verification against the current
  # hasher's dummy digest, and the two paths cost the same. A *successful* one is not, because
  # the caller rehashes immediately and that rehash is the same cost — see
  # `blueprints/0019-migrating-an-existing-application.md`.
  class MigratingHasher < Hasher
    getter current : Hasher
    getter legacy : Array(LegacyVerifier)

    def initialize(@current : Hasher, legacy : Enumerable(LegacyVerifier))
      @legacy = legacy.to_a

      if @legacy.empty?
        raise ConfigurationError.new(
          "MigratingHasher needs at least one LegacyVerifier; use the hasher directly otherwise"
        )
      end

      names = @legacy.map(&.name)

      if names.uniq.size != names.size
        raise ConfigurationError.new("two legacy verifiers share a name: #{names.sort!.join(", ")}")
      end
    end

    # The **current** scheme. What gets written to `password_scheme` on every rehash, so that
    # the query counting what is left to migrate keeps working.
    def scheme : String
      @current.scheme
    end

    def max_secret_bytesize : Int32
      @current.max_secret_bytesize
    end

    # Always the current hasher. A migration that can still write the old format is not one.
    def hash_secret(secret : Secret) : String
      @current.hash_secret(secret)
    end

    def dummy_digest : String
      @current.dummy_digest
    end

    # The current hasher's answer, which is already `true` for anything it cannot parse — every
    # legacy digest, by construction.
    def needs_rehash?(digest : String) : Bool
      @current.needs_rehash?(digest)
    end

    def verify(secret : Secret, digest : String) : Bool
      verifier = @legacy.find(&.handles?(digest))
      return @current.verify(secret, digest) if verifier.nil?

      # The migration hazard nobody expects, and it is worth being loud about. Legacy schemes
      # are usually unsalted digests with no input limit, so an old table can hold accounts
      # whose password is longer than bcrypt's 71 bytes. Verifying one would succeed and then
      # the immediate rehash would raise, because `Hasher#hash_secret` refuses a secret the
      # algorithm cannot represent rather than truncating it.
      #
      # So it is refused here, which is what `Hasher#verify` is documented to do for a secret
      # the algorithm cannot represent. Those accounts have to go through a password reset, and
      # this warning is how an operator finds out that some exist — the login itself is
      # indistinguishable from a wrong password, deliberately.
      if secret.bytesize > @current.max_secret_bytesize
        Log.warn &.emit(
          "password.legacy_secret_too_long",
          scheme: verifier.name, bytes: secret.bytesize, limit: @current.max_secret_bytesize
        )

        return false
      end

      return true if verifier.verify(secret, digest)

      # Equalises the failure path against a current-scheme login. Without it, the response
      # time says whether this account has been migrated. The result is deliberately discarded:
      # the dummy digest verifies against nothing, and the point is the work, not the answer.
      @current.verify(secret, @current.dummy_digest)

      false
    end

    # The legacy scheme names, for a migration-progress report.
    def legacy_schemes : Array(String)
      @legacy.map(&.name)
    end

    # Which verifier would handle `digest`, or nil for one the current hasher owns. For a
    # script that wants to count what is left without a password in hand.
    def legacy_scheme_for(digest : String) : String?
      @legacy.find(&.handles?(digest)).try(&.name)
    end
  end
end

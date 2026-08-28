module KemalIdentity::Testing
  # A stand-in for the password scheme an application is migrating off.
  #
  # A single unsalted SHA-256 pass, which is what a legacy scheme usually turns out to be and
  # is exactly why it is being retired. It lives in `spec/support` and not in `src` on purpose:
  # this shard ships the `LegacyVerifier` contract and no implementations, because a published
  # `Sha256Verifier` is a published working SHA-256 password check and the first thing somebody
  # does with a class that exists is use it for something new.
  class LegacyTestVerifier < KemalIdentity::Passwords::LegacyVerifier
    PREFIX = "legacy$"

    def self.digest_for(password : String) : String
      "#{PREFIX}#{::Digest::SHA256.hexdigest(password)}"
    end

    def initialize(@name : String = "legacy-sha256", @prefix : String = PREFIX)
    end

    def name : String
      @name
    end

    def handles?(digest : String) : Bool
      digest.starts_with?(@prefix)
    end

    def verify(secret : KemalIdentity::Secret, digest : String) : Bool
      expected = "#{@prefix}#{::Digest::SHA256.hexdigest(secret.reveal)}"

      Crypto::Subtle.constant_time_compare(expected, digest)
    end
  end

  # Counts what the hasher underneath it was asked to do.
  #
  # The timing equalisation in `MigratingHasher` is a *cost*, and a spec that asserted it by
  # measuring elapsed time would be a spec that flakes on a loaded runner. Counting the work
  # instead is deterministic and says the same thing: the failure path did the same amount of
  # hashing as a current-scheme login.
  class CountingHasher < KemalIdentity::Passwords::Hasher
    getter verifications : Int32 = 0
    getter hashes : Int32 = 0

    def initialize(@inner : KemalIdentity::Passwords::Hasher)
    end

    def scheme : String
      @inner.scheme
    end

    def max_secret_bytesize : Int32
      @inner.max_secret_bytesize
    end

    def hash_secret(secret : KemalIdentity::Secret) : String
      @hashes += 1
      @inner.hash_secret(secret)
    end

    def verify(secret : KemalIdentity::Secret, digest : String) : Bool
      @verifications += 1
      @inner.verify(secret, digest)
    end

    def needs_rehash?(digest : String) : Bool
      @inner.needs_rehash?(digest)
    end

    def dummy_digest : String
      @inner.dummy_digest
    end

    def reset_counts : Nil
      @verifications = 0
      @hashes = 0
    end
  end
end

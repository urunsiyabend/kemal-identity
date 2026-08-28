module KemalIdentity::Passwords
  # Verifies a digest produced by the system this application is migrating **off**.
  #
  # ### Why this is verify-only
  #
  # There is no `hash_secret` here, and there never will be. A legacy verifier exists so that
  # people can log in with the password they already have; the digest it produces is then
  # immediately replaced by one from the current `Hasher`. Giving it the ability to *write* a
  # digest would make it possible to keep creating them, and a migration that can still create
  # rows in the old format is not a migration.
  #
  # ### Do not go looking for a library of these
  #
  # This shard ships the contract and no implementations, deliberately. A ready-made
  # `Sha1Verifier` would be this project publishing a working SHA-1 password check, and the
  # first thing somebody does with a class that exists is use it for something new. Yours is
  # five lines and looks like this:
  #
  # ```
  # class DeviseVerifier < KemalIdentity::Passwords::LegacyVerifier
  #   def name : String
  #     "devise"
  #   end
  #
  #   def handles?(digest : String) : Bool
  #     digest.starts_with?("$2a$")
  #   end
  #
  #   def verify(secret : KemalIdentity::Secret, digest : String) : Bool
  #     Crypto::Bcrypt::Password.new(digest).verify(secret.reveal + PEPPER)
  #   end
  # end
  # ```
  #
  # ### The rules an implementation has to keep
  #
  # * **Never raise.** This runs on the request path against whatever is in the column. A
  #   digest written by a system nobody remembers is an expected input, not an error.
  # * **Never truncate.** The same rule `Hasher` states: if the algorithm cuts at *n* bytes,
  #   two different passwords sharing a prefix open the same account.
  # * **Compare in constant time** if the comparison is yours to make. `Crypto::Subtle`.
  abstract class LegacyVerifier
    # Names the scheme, for the audit trail and for the "how many are left" query. It ends up
    # in a log line, so it is a short identifier and not a sentence.
    abstract def name : String

    # Whether this verifier recognises `digest` **by its shape alone**, with no secret
    # involved.
    #
    # `MigratingHasher` uses this to route a digest to exactly one verifier, which is what
    # stops a login paying for every legacy scheme in turn. Getting it wrong in the permissive
    # direction — claiming a digest that belongs to the current hasher — makes `verify` the
    # thing that decides, so it fails closed; getting it wrong in the other direction leaves
    # those accounts unable to log in, which is loud.
    abstract def handles?(digest : String) : Bool

    # Whether `secret` produced `digest` under the old scheme. Returns false rather than
    # raising, for anything at all.
    abstract def verify(secret : Secret, digest : String) : Bool
  end
end

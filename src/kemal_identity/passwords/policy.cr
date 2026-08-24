module KemalIdentity::Passwords
  # Why a password was refused.
  #
  # Unlike `FailureReason`, these *are* safe to show a user: they arise when someone is
  # choosing a password, not when someone is proving they know one, so there is no account to
  # enumerate and a specific message is what makes the requirement followable.
  enum PolicyViolation
    TooShort
    TooLong
    Breached
  end

  # Whether a password is acceptable to *set*. Nothing to do with verifying one.
  #
  # Separate from `Hasher` on purpose: hashing is the shard's business, and deciding what
  # counts as an acceptable password is the application's. This contract is the seam.
  #
  # **No composition rules ship, and none will.** "One uppercase, one lowercase, one digit,
  # one symbol" is not supported by current guidance, and hard-coding it in a library forces
  # it on every consumer — `docs/02-security-model.md` names a competing shard that documents
  # exactly such a rule as a feature. Mandatory rotation is likewise absent. An application
  # that must have either writes its own `Policy`; that is what the contract is for.
  abstract class Policy
    # Every reason this password is unacceptable. Empty means acceptable.
    #
    # All of them, not the first one: telling somebody their password is too short, and then
    # after they fix it that it is also breached, is a worse experience than saying both at
    # once.
    abstract def violations(password : Secret) : Array(PolicyViolation)

    def acceptable?(password : Secret) : Bool
      violations(password).empty?
    end
  end

  # Whether a password is known to have been breached.
  #
  # A hook, defaulting to doing nothing, because the useful implementations all involve a
  # network call — and an auth library that silently makes one during a password change is a
  # library that fails when the third party does.
  abstract class BreachCheck
    abstract def breached?(password : Secret) : Bool
  end

  # The default: never reports a breach.
  class NullBreachCheck < BreachCheck
    def breached?(password : Secret) : Bool
      false
    end
  end

  # The shipped policy: a length floor, the algorithm's ceiling, and a breach hook.
  #
  # ### Two units, deliberately
  #
  # The minimum is in **characters** and the maximum in **bytes**. They measure different
  # things. The floor is about how much a person chose to type, and counting a two-byte
  # character as two would punish a passphrase in Greek for being in Greek. The ceiling is
  # the algorithm's hard limit, which is a byte count, and pretending otherwise is how a
  # password gets silently truncated (`blueprints/0004-hasher-over-length-behaviour.md`).
  class LengthPolicy < Policy
    # `docs/02-security-model.md`: length is the requirement that actually correlates with
    # strength, so it is the one that ships.
    DEFAULT_MIN_LENGTH = 12

    getter min_length : Int32
    getter max_bytesize : Int32

    def initialize(
      @max_bytesize : Int32,
      @min_length : Int32 = DEFAULT_MIN_LENGTH,
      @breach_check : BreachCheck = NullBreachCheck.new,
    )
      raise ConfigurationError.new("min_length must be positive") unless @min_length > 0

      if @min_length > @max_bytesize
        raise ConfigurationError.new(
          "min_length (#{@min_length}) exceeds max_bytesize (#{@max_bytesize}), " \
          "so no password could satisfy this policy"
        )
      end
    end

    # Builds a policy whose ceiling is the hasher's actual limit, rather than a number copied
    # from a document and left to drift when the hasher changes.
    def self.for(hasher : Hasher, min_length : Int32 = DEFAULT_MIN_LENGTH, breach_check : BreachCheck = NullBreachCheck.new) : self
      new(max_bytesize: hasher.max_secret_bytesize, min_length: min_length, breach_check: breach_check)
    end

    def violations(password : Secret) : Array(PolicyViolation)
      found = [] of PolicyViolation

      found << PolicyViolation::TooShort if password.size < @min_length
      found << PolicyViolation::TooLong if password.bytesize > @max_bytesize

      # Only asked once the password is plausible: a breach check is usually a network call,
      # and there is no point spending it on a password that is already refused.
      found << PolicyViolation::Breached if found.empty? && @breach_check.breached?(password)

      found
    end
  end
end

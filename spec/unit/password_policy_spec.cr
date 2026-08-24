require "../spec_helper"

private def policy(min_length : Int32 = 12, max_bytesize : Int32 = 71, breach : KemalIdentity::Passwords::BreachCheck? = nil)
  KemalIdentity::Passwords::LengthPolicy.new(
    max_bytesize: max_bytesize,
    min_length: min_length,
    breach_check: breach || KemalIdentity::Passwords::NullBreachCheck.new,
  )
end

private def secret(value : String)
  KemalIdentity::Secret.new(value)
end

describe KemalIdentity::Passwords::LengthPolicy do
  it "defaults to a twelve character minimum" do
    KemalIdentity::Passwords::LengthPolicy::DEFAULT_MIN_LENGTH.should eq(12)
  end

  it "accepts a password of sufficient length" do
    policy.acceptable?(secret("correct horse battery")).should be_true
    policy.violations(secret("correct horse battery")).should be_empty
  end

  it "rejects one that is too short" do
    policy.violations(secret("short")).should eq([KemalIdentity::Passwords::PolicyViolation::TooShort])
  end

  it "accepts a password exactly at the minimum" do
    policy.acceptable?(secret("a" * 12)).should be_true
  end

  it "rejects one that exceeds the algorithm's limit" do
    policy.violations(secret("a" * 72)).should eq([KemalIdentity::Passwords::PolicyViolation::TooLong])
  end

  it "accepts a password exactly at the limit" do
    policy.acceptable?(secret("a" * 71)).should be_true
  end

  # The minimum counts characters and the maximum counts bytes, because they measure
  # different things: what a person chose to type, versus what the algorithm can represent.
  describe "the two units" do
    it "counts the minimum in characters, so a passphrase is not punished for its script" do
      # Twelve characters, twenty-four bytes.
      greek = secret("κωδικόςμυστι")
      greek.size.should eq(12)
      greek.bytesize.should eq(24)
      policy.acceptable?(greek).should be_true
    end

    it "counts the maximum in bytes, because that is what the algorithm limits" do
      # Thirty-six characters, seventy-two bytes: comfortably short, one byte too long.
      over = secret("é" * 36)
      over.size.should eq(36)
      over.bytesize.should eq(72)
      policy.violations(over).should eq([KemalIdentity::Passwords::PolicyViolation::TooLong])
    end
  end

  # Telling someone their password is too short, and only afterwards that it is also
  # breached, is worse than saying both at once.
  #
  # Both bounds can be violated at once precisely because they count different things: six
  # four-byte characters is too *few* characters and too *many* bytes simultaneously. A
  # single-unit policy could never produce this pair, which is the clearest demonstration
  # that the two units are not interchangeable.
  it "reports every violation rather than the first" do
    heavy = secret("\u{1F600}" * 6)
    heavy.size.should eq(6)
    heavy.bytesize.should eq(24)

    policy(min_length: 12, max_bytesize: 20).violations(heavy).should eq([
      KemalIdentity::Passwords::PolicyViolation::TooShort,
      KemalIdentity::Passwords::PolicyViolation::TooLong,
    ])
  end

  describe "the breach hook" do
    it "does nothing by default" do
      policy.acceptable?(secret("correct horse battery")).should be_true
    end

    it "reports a breached password" do
      policy(breach: AlwaysBreached.new)
        .violations(secret("correct horse battery"))
        .should eq([KemalIdentity::Passwords::PolicyViolation::Breached])
    end

    # A breach check is usually a network call. Spending it on a password that is already
    # refused is waste, and on a hot path it would be a denial-of-service lever.
    it "is not consulted for a password that already failed on length" do
      check = CountingBreachCheck.new
      policy(breach: check).violations(secret("short"))
      check.calls.should eq(0)
    end

    it "is consulted for a password that passed on length" do
      check = CountingBreachCheck.new
      policy(breach: check).violations(secret("correct horse battery"))
      check.calls.should eq(1)
    end
  end

  describe "boot-time validation" do
    it "refuses a minimum above the maximum, which nothing could satisfy" do
      expect_raises(KemalIdentity::ConfigurationError) { policy(min_length: 100, max_bytesize: 71) }
    end

    it "refuses a non-positive minimum" do
      expect_raises(KemalIdentity::ConfigurationError) { policy(min_length: 0) }
    end
  end

  describe ".for" do
    # The ceiling comes from the hasher rather than from a number copied out of a document
    # and left to drift when the hasher changes.
    it "takes its ceiling from the hasher's actual limit" do
      hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
      KemalIdentity::Passwords::LengthPolicy.for(hasher).max_bytesize.should eq(hasher.max_secret_bytesize)
    end
  end
end

class AlwaysBreached < KemalIdentity::Passwords::BreachCheck
  def breached?(password : KemalIdentity::Secret) : Bool
    true
  end
end

class CountingBreachCheck < KemalIdentity::Passwords::BreachCheck
  getter calls : Int32 = 0

  def breached?(password : KemalIdentity::Secret) : Bool
    @calls += 1
    false
  end
end

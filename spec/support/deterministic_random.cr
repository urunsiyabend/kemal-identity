module KemalIdentity::Testing
  # A reproducible byte source.
  #
  # Not secure and not meant to be: a spec that asserts two logins produce distinct
  # session digests needs the bytes to be distinct and reproducible, not unpredictable.
  # Passes the same `RandomSource` contract spec as `SecureRandomSource`.
  class DeterministicRandom < KemalIdentity::RandomSource
    getter calls : Int32 = 0

    def initialize(seed : Int32 = 1)
      @random = Random.new(seed)
    end

    def bytes(count : Int32) : Bytes
      raise ArgumentError.new("count must be positive") unless count > 0
      @calls += 1
      @random.random_bytes(count)
    end
  end
end

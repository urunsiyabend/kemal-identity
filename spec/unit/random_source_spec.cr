require "../spec_helper"

describe KemalIdentity::SecureRandomSource do
  it_behaves_like_a_random_source { KemalIdentity::SecureRandomSource.new }
end

describe KemalIdentity::Testing::DeterministicRandom do
  it_behaves_like_a_random_source { KemalIdentity::Testing::DeterministicRandom.new }

  it "replays the same sequence for the same seed" do
    a = KemalIdentity::Testing::DeterministicRandom.new(seed: 7)
    b = KemalIdentity::Testing::DeterministicRandom.new(seed: 7)
    a.bytes(32).should eq(b.bytes(32))
  end

  it "diverges for a different seed" do
    a = KemalIdentity::Testing::DeterministicRandom.new(seed: 1)
    b = KemalIdentity::Testing::DeterministicRandom.new(seed: 2)
    a.bytes(32).should_not eq(b.bytes(32))
  end
end

describe KemalIdentity::RandomSource do
  describe ".token_length" do
    it "matches the encoded length for the default token size" do
      KemalIdentity::RandomSource.token_length.should eq(43)
    end

    it "matches the encoded length for a larger token" do
      source = KemalIdentity::Testing::DeterministicRandom.new
      KemalIdentity::RandomSource.token_length(64).should eq(source.token(64).size)
    end
  end
end

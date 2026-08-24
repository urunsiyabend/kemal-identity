require "../spec_helper"

describe KemalIdentity::Testing::FastTestHasher do
  # The double runs the same contract as the real hasher. That is the whole reason the
  # contract exists.
  it_behaves_like_a_hasher do
    [
      KemalIdentity::Testing::FastTestHasher.new(rounds: 2),
      KemalIdentity::Testing::FastTestHasher.new(rounds: 1),
    ] of KemalIdentity::Passwords::Hasher
  end

  it "is fast enough to use in every login spec" do
    hasher = KemalIdentity::Testing::FastTestHasher.new
    secret = KemalIdentity::Secret.new("correct horse")
    digest = hasher.hash_secret(secret)

    elapsed = Time.measure { 50.times { hasher.verify(secret, digest) } }
    elapsed.should be < 250.milliseconds
  end
end

describe "KemalIdentity::Testing::FastTestHasher determinism" do
  # spec/CLAUDE.md: no real randomness anywhere in the suite. Seeded identically, the
  # double must be reproducible end to end — that is what makes a failing spec a bug rather
  # than a coin toss.
  it "produces identical digests for identical seeds" do
    a = KemalIdentity::Testing::FastTestHasher.new(
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 42)
    )
    b = KemalIdentity::Testing::FastTestHasher.new(
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 42)
    )

    secret = KemalIdentity::Secret.new("correct horse")
    a.hash_secret(secret).should eq(b.hash_secret(secret))
    a.dummy_digest.should eq(b.dummy_digest)
  end

  it "diverges for different seeds, so the dummy digest is not a shared constant" do
    a = KemalIdentity::Testing::FastTestHasher.new(
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 1)
    )
    b = KemalIdentity::Testing::FastTestHasher.new(
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 2)
    )

    a.dummy_digest.should_not eq(b.dummy_digest)
  end
end

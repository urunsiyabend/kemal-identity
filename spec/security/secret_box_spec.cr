require "../spec_helper"

# The one secret in this shard that is encrypted rather than hashed, because the server has to
# read it back to compute a code. Named for what an attacker holding the table would try.

private KEY       = KemalIdentity::Secret.new("k" * 32)
private OTHER_KEY = KemalIdentity::Secret.new("z" * 32)
private PLAINTEXT = "12345678901234567890".to_slice

private def box(key : KemalIdentity::Secret = KEY)
  KemalIdentity::MFA::AesSecretBox.new(key, KemalIdentity::Testing::DeterministicRandom.new)
end

describe KemalIdentity::MFA::AesSecretBox do
  it "round trips a secret" do
    sealed = box.seal(PLAINTEXT)

    box.open?(sealed).should eq(PLAINTEXT)
  end

  it "round trips secrets of every length, including ones that fill a block exactly" do
    (1..64).each do |size|
      secret = Bytes.new(size) { |i| ((i * 5 + 3) % 256).to_u8 }

      box.open?(box.seal(secret)).should eq(secret)
    end
  end

  # A sealed blob must not be a fingerprint. Two accounts with the same secret — which happens,
  # because people restore backups — must not be visibly the same row.
  it "produces a different blob every time, so equal secrets do not look equal" do
    sealer = box
    sealed = Array.new(5) { sealer.seal(PLAINTEXT) }

    sealed.map(&.hexstring).uniq!.size.should eq(5)
  end

  it "never contains the secret it sealed" do
    sealed = box.seal(PLAINTEXT)

    sealed.hexstring.should_not contain(PLAINTEXT.hexstring)
  end

  # The whole point: the table alone is not enough.
  it "cannot be opened with a different key" do
    box(OTHER_KEY).open?(box(KEY).seal(PLAINTEXT)).should be_nil
  end

  # Encrypt-then-MAC, verified before decrypting. A blob that fails the tag never reaches the
  # cipher, which is what stops the padding oracle this construction is famous for.
  it "refuses a blob whose ciphertext was edited" do
    sealed = box.seal(PLAINTEXT)
    sealed[sealed.size - 1] ^= 0x01

    box.open?(sealed).should be_nil
  end

  it "refuses a blob whose IV was edited" do
    sealed = box.seal(PLAINTEXT)
    sealed[3] ^= 0x01

    box.open?(sealed).should be_nil
  end

  it "refuses a blob whose tag was edited" do
    sealed = box.seal(PLAINTEXT)
    sealed[20] ^= 0x01

    box.open?(sealed).should be_nil
  end

  # The version byte is covered by the tag, so it cannot be changed to select another layout.
  it "refuses a blob claiming a version it does not know" do
    sealed = box.seal(PLAINTEXT)
    sealed[0] = 99_u8

    box.open?(sealed).should be_nil
  end

  it "refuses a truncated blob rather than raising" do
    sealed = box.seal(PLAINTEXT)

    (0...sealed.size).each do |size|
      box.open?(sealed[0, size]).should be_nil
    end
  end

  # Two blobs from the same key, spliced. Each half authenticates on its own and the join
  # does not.
  it "refuses a blob assembled from two others" do
    first = box.seal(PLAINTEXT)
    second = box.seal("09876543210987654321".to_slice)

    spliced = first.dup
    second[(1 + 16 + 32)..].copy_to(spliced + (1 + 16 + 32))

    box.open?(spliced).should be_nil
  end

  it "never raises for arbitrary bytes" do
    [Bytes.new(0), Bytes.new(1), Bytes.new(64), Bytes.new(65) { 0xff_u8 },
     Bytes.new(1000) { |i| (i % 256).to_u8 }].each do |candidate|
      box.open?(candidate).should be_nil
    end
  end

  it "refuses an empty secret, which would seal nothing" do
    expect_raises(ArgumentError) { box.seal(Bytes.new(0)) }
  end

  # The derived keys are the whole protection.
  it "refuses at boot a key too short to derive from" do
    expect_raises(KemalIdentity::ConfigurationError, /at least 32 bytes/) do
      box(KemalIdentity::Secret.new("short"))
    end
  end

  it "redacts itself, so a config dump is not the key" do
    box.inspect.should contain("[REDACTED]")
    box.inspect.should_not contain(KEY.reveal)
    box.to_s.should_not contain(KEY.reveal)
  end
end

describe "rotating the key" do
  it "re-seals a blob under the new key" do
    old = box(KEY)
    new = box(OTHER_KEY)
    sealed = old.seal(PLAINTEXT)

    rotated = new.reseal(sealed, old).or_fail

    new.open?(rotated).should eq(PLAINTEXT)
    old.open?(rotated).should be_nil
  end

  # So that a half-rotated table is visible rather than silently re-sealed as garbage.
  it "reports a blob the previous key cannot open, rather than sealing nonsense" do
    box(OTHER_KEY).reseal(box(KEY).seal(PLAINTEXT), box(OTHER_KEY)).should be_nil
  end
end

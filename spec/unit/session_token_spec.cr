require "../spec_helper"

describe KemalIdentity::Sessions::Token do
  random = KemalIdentity::Testing::DeterministicRandom.new

  describe ".generate" do
    it "produces a token of the expected shape" do
      KemalIdentity::Sessions::Token.valid_shape?(
        KemalIdentity::Sessions::Token.generate(random).reveal
      ).should be_true
    end

    it "produces a Secret, so an accidental interpolation redacts" do
      token = KemalIdentity::Sessions::Token.generate(random)
      "cookie=#{token}".should_not contain(token.reveal)
    end

    it "does not repeat itself" do
      Array.new(50) { KemalIdentity::Sessions::Token.generate(random).reveal }.uniq!.size.should eq(50)
    end

    it "carries at least 32 bytes of entropy" do
      # RandomSource#token refuses anything less; the session path is where it matters most.
      KemalIdentity::Sessions::Token.generate(random).reveal.size.should eq(43)
    end
  end

  describe ".valid_shape?" do
    it "accepts a token this shard minted" do
      KemalIdentity::Sessions::Token.valid_shape?(
        KemalIdentity::Sessions::Token.generate(random).reveal
      ).should be_true
    end

    it "rejects anything of the wrong length" do
      KemalIdentity::Sessions::Token.valid_shape?("").should be_false
      KemalIdentity::Sessions::Token.valid_shape?("a" * 42).should be_false
      KemalIdentity::Sessions::Token.valid_shape?("a" * 44).should be_false
    end

    it "rejects characters outside base64url" do
      # Standard base64 (+ /) and padding (=) are rejected too: our tokens are urlsafe and
      # unpadded, so anything else was not minted here.
      ["+", "/", "=", "!", " ", "\n", "\t", "\u0000"].each do |char|
        KemalIdentity::Sessions::Token.valid_shape?("a" * 42 + char).should be_false
      end
    end

    # The check is a byte comparison, so a multi-byte character cannot sneak past a length
    # measured in characters.
    it "measures length in bytes" do
      KemalIdentity::Sessions::Token.valid_shape?("\u00e9" * 43).should be_false
    end

    it "rejects an oversized value" do
      KemalIdentity::Sessions::Token.valid_shape?("a" * 2_000_000).should be_false
    end
  end

  describe ".digest" do
    it "produces the SHA-256 of the raw token" do
      token = KemalIdentity::Secret.new("some-token")
      KemalIdentity::Sessions::Token.digest(token).should eq(Digest::SHA256.digest("some-token"))
    end

    it "produces 32 bytes" do
      KemalIdentity::Sessions::Token.digest(KemalIdentity::Secret.new("x")).size.should eq(32)
    end

    it "is stable, so a lookup finds what a write stored" do
      token = KemalIdentity::Sessions::Token.generate(random)
      KemalIdentity::Sessions::Token.digest(token).should eq(KemalIdentity::Sessions::Token.digest(token))
    end

    it "differs for different tokens" do
      a = KemalIdentity::Sessions::Token.generate(random)
      b = KemalIdentity::Sessions::Token.generate(random)
      KemalIdentity::Sessions::Token.digest(a).should_not eq(KemalIdentity::Sessions::Token.digest(b))
    end
  end
end

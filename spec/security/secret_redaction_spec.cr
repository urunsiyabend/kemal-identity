require "../spec_helper"

# docs/02-security-model.md, "Logging": never log passwords, raw tokens, session cookies,
# digests or Set-Cookie values. `Secret` is the safety net that makes an accidental
# interpolation harmless rather than a disclosure.
describe "secret disclosure through interpolation" do
  secret = KemalIdentity::Secret.new("correct horse battery staple")

  it "does not appear in to_s" do
    secret.to_s.should eq("[REDACTED]")
  end

  it "does not appear in inspect" do
    secret.inspect.should_not contain("correct horse")
  end

  it "does not appear in string interpolation" do
    "password=#{secret}".should eq("password=[REDACTED]")
  end

  it "does not appear when written to an IO" do
    io = IO::Memory.new
    io << secret
    io.to_s.should_not contain("correct horse")
  end

  it "does not appear inside a collection's inspect" do
    {password: secret}.inspect.should_not contain("correct horse")
  end

  it "is still retrievable where a call site deliberately reveals it" do
    secret.reveal.should eq("correct horse battery staple")
  end
end

describe "secret comparison" do
  it "matches an identical secret" do
    KemalIdentity::Secret.new("s3cret").should eq(KemalIdentity::Secret.new("s3cret"))
  end

  it "rejects a differing secret" do
    KemalIdentity::Secret.new("s3cret").should_not eq(KemalIdentity::Secret.new("s3crat"))
  end

  it "rejects a secret sharing a prefix" do
    KemalIdentity::Secret.new("s3cret").should_not eq(KemalIdentity::Secret.new("s3cretx"))
  end

  it "compares against a raw string" do
    (KemalIdentity::Secret.new("s3cret") == "s3cret").should be_true
    (KemalIdentity::Secret.new("s3cret") == "other").should be_false
  end
end

describe "secret digesting" do
  it "produces a 32-byte SHA-256 digest" do
    KemalIdentity::Secret.new("token").digest.size.should eq(32)
  end

  it "produces the same digest for the same input" do
    KemalIdentity::Secret.new("token").digest.should eq(KemalIdentity::Secret.new("token").digest)
  end

  it "produces a different digest for a different input" do
    KemalIdentity::Secret.new("token").digest.should_not eq(KemalIdentity::Secret.new("tokem").digest)
  end

  it "does not leak the raw value into the digest" do
    String.new(KemalIdentity::Secret.new("token").digest).should_not contain("token")
  end
end

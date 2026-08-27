require "../spec_helper"

private alias Base32 = KemalIdentity::MFA::Base32
private alias TOTP = KemalIdentity::MFA::TOTP

# RFC 4648 §10. A codec with no published vectors behind it is a codec that agrees with
# whatever this shard happens to do, which is not the same as agreeing with an authenticator
# app.
private BASE32_VECTORS = {
  ""       => "",
  "f"      => "MY",
  "fo"     => "MZXQ",
  "foo"    => "MZXW6",
  "foob"   => "MZXW6YQ",
  "fooba"  => "MZXW6YTB",
  "foobar" => "MZXW6YTBOI",
}

describe KemalIdentity::MFA::Base32 do
  it "matches the RFC 4648 vectors, unpadded" do
    BASE32_VECTORS.each do |plain, encoded|
      Base32.encode(plain.to_slice).should eq(encoded)
    end
  end

  it "round trips them" do
    BASE32_VECTORS.each do |plain, encoded|
      String.new(Base32.decode?(encoded).or_fail).should eq(plain)
    end
  end

  # The padded spelling is what RFC 4648 actually prints, and what a person pasting from a
  # provider's setup page may well have.
  it "accepts the padded spelling it never produces" do
    String.new(Base32.decode?("MZXW6YTBOI======").or_fail).should eq("foobar")
  end

  # Secrets are printed in groups of four to be readable, and a person typing one back will
  # include whatever separators they saw.
  it "ignores the spacing a person reads off a screen" do
    String.new(Base32.decode?("MZXW 6YTB-OI").or_fail).should eq("foobar")
    String.new(Base32.decode?("mzxw6ytboi").or_fail).should eq("foobar")
  end

  it "returns nil for anything outside the alphabet, rather than raising" do
    ["MZXW6YTB!", "0189", "MZXW6YTBOI==!", "×"].each do |candidate|
      Base32.decode?(candidate).should be_nil
    end
  end

  it "returns nil for a length no byte-aligned group can produce" do
    ["A", "ABC", "ABCDEF"].each { |candidate| Base32.decode?(candidate).should be_nil }
  end

  # Otherwise two different strings decode to the same bytes, and a secret has more than one
  # spelling.
  it "returns nil when the trailing bits are not zero" do
    Base32.decode?("MZXW6YTBOJ").should be_nil
  end

  it "round trips arbitrary bytes at every length that matters" do
    (0..40).each do |size|
      bytes = Bytes.new(size) { |i| ((i * 7 + 13) % 256).to_u8 }

      Base32.decode?(Base32.encode(bytes)).should eq(bytes)
    end
  end
end

# RFC 6238 Appendix B. These are the vectors every implementation is checked against, and
# getting them right is the difference between "our codes match Google Authenticator" and "our
# codes match our own bug".
private SHA1_SECRET   = "12345678901234567890".to_slice
private SHA256_SECRET = "12345678901234567890123456789012".to_slice
private SHA512_SECRET = "1234567890123456789012345678901234567890123456789012345678901234".to_slice

private TIMES = [59_i64, 1_111_111_109_i64, 1_111_111_111_i64,
                 1_234_567_890_i64, 2_000_000_000_i64, 20_000_000_000_i64]

describe KemalIdentity::MFA::TOTP do
  it "matches the RFC 6238 SHA-1 vectors" do
    expected = %w[94287082 07081804 14050471 89005924 69279037 65353130]

    TIMES.zip(expected) do |seconds, code|
      counter = TOTP.counter(Time.unix(seconds))

      TOTP.code(SHA1_SECRET, counter, digits: 8).should eq(code)
    end
  end

  it "matches the RFC 6238 SHA-256 vectors" do
    expected = %w[46119246 68084774 67062674 91819424 90698825 77737706]

    TIMES.zip(expected) do |seconds, code|
      counter = TOTP.counter(Time.unix(seconds))

      TOTP.code(SHA256_SECRET, counter, digits: 8, algorithm: TOTP::Algorithm::SHA256)
        .should eq(code)
    end
  end

  it "matches the RFC 6238 SHA-512 vectors" do
    expected = %w[90693936 25091201 99943326 93441116 38618901 47863826]

    TIMES.zip(expected) do |seconds, code|
      counter = TOTP.counter(Time.unix(seconds))

      TOTP.code(SHA512_SECRET, counter, digits: 8, algorithm: TOTP::Algorithm::SHA512)
        .should eq(code)
    end
  end

  # `042311` and `42311` are the same number and only one of them is the code.
  it "zero-pads a code to its full width" do
    # Found by search: this counter produces a code below 100000 under the RFC's own secret.
    counter = (1..100_000).find { |i| TOTP.code(SHA1_SECRET, i.to_i64).to_i < 100_000 }

    counter.should_not be_nil
    TOTP.code(SHA1_SECRET, counter.or_fail.to_i64).size.should eq(6)
  end

  it "advances the counter once per period" do
    # Aligned to a step boundary, so that "29 seconds later" is unambiguously the same step.
    start = Time.unix(TOTP.counter(Time.unix(1_000_000_000)) * 30)

    TOTP.counter(start).should eq(TOTP.counter(start + 29.seconds))
    TOTP.counter(start + 30.seconds).should eq(TOTP.counter(start) + 1)
  end

  # The boundary itself: a code minted at :29 and submitted at :31 belongs to the previous
  # step, which is the entire reason `drift` exists.
  it "puts the two sides of a boundary in different steps" do
    boundary = Time.unix(TOTP.counter(Time.unix(1_000_000_000)) * 30 + 30)

    TOTP.counter(boundary - 1.second).should eq(TOTP.counter(boundary) - 1)
  end

  it "refuses a digit count no client can display" do
    [4, 5, 9, 0, -1].each do |digits|
      expect_raises(ArgumentError, /digits/) { TOTP.code(SHA1_SECRET, 1_i64, digits: digits) }
    end
  end

  it "refuses an empty secret" do
    expect_raises(ArgumentError, /secret/) { TOTP.code(Bytes.new(0), 1_i64) }
  end
end

private MATCH_NOW = Time.unix(1_111_111_111)

describe "matching a submitted code" do
  it "returns the counter the code belongs to" do
    counter = TOTP.counter(MATCH_NOW)

    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter), at: MATCH_NOW).should eq(counter)
  end

  # Returning the counter rather than a boolean is what lets the caller refuse a code it has
  # already seen — without it, a shoulder-surfed six digits stays usable for its whole window.
  it "identifies which step matched, so the caller can refuse a replay" do
    counter = TOTP.counter(MATCH_NOW)

    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter - 1), at: MATCH_NOW).should eq(counter - 1)
    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter + 1), at: MATCH_NOW).should eq(counter + 1)
  end

  # Each step of tolerance multiplies the number of codes valid at any moment.
  it "accepts exactly the configured drift and no more" do
    counter = TOTP.counter(MATCH_NOW)

    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter + 2), at: MATCH_NOW, drift: 1).should be_nil
    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter + 2), at: MATCH_NOW, drift: 2).should eq(counter + 2)
  end

  it "accepts only the current code when drift is zero" do
    counter = TOTP.counter(MATCH_NOW)

    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter), at: MATCH_NOW, drift: 0).should eq(counter)
    TOTP.match(SHA1_SECRET, TOTP.code(SHA1_SECRET, counter - 1), at: MATCH_NOW, drift: 0).should be_nil
  end

  it "rejects a code from another secret" do
    other = "09876543210987654321".to_slice

    TOTP.match(SHA1_SECRET, TOTP.code(other, TOTP.counter(MATCH_NOW)), at: MATCH_NOW).should be_nil
  end

  # Shape before any HMAC: a hostile "code" must cost a length comparison.
  it "rejects anything that is not exactly the right number of digits" do
    ["", "12345", "1234567", "12345 ", "abcdef", "12345a", "1" * 2_000_000]
      .each { |candidate| TOTP.match(SHA1_SECRET, candidate, at: MATCH_NOW).should be_nil }
  end

  it "never raises for anything a client controls" do
    ["", "      ", "\u0661\u0662\u0663\u0664\u0665\u0666", "------"].each do |candidate|
      TOTP.match(SHA1_SECRET, candidate, at: MATCH_NOW).should be_nil
    end
  end

  it "refuses a negative drift" do
    expect_raises(ArgumentError, /drift/) { TOTP.match(SHA1_SECRET, "123456", at: MATCH_NOW, drift: -1) }
  end
end

describe "the provisioning URI" do
  it "carries everything an authenticator app needs to agree with us" do
    uri = TOTP.provisioning_uri(SHA1_SECRET, issuer: "Acme", label: "ada@example.com")

    uri.should start_with("otpauth://totp/Acme%3Aada%40example.com?")
    uri.should contain("secret=#{Base32.encode(SHA1_SECRET)}")
    uri.should contain("issuer=Acme")
    uri.should contain("algorithm=SHA1")
    uri.should contain("digits=6")
    uri.should contain("period=30")
  end

  it "reflects a non-default algorithm, digit count and period" do
    uri = TOTP.provisioning_uri(
      SHA1_SECRET, issuer: "Acme", label: "ada", algorithm: TOTP::Algorithm::SHA256,
      digits: 8, period: 60.seconds
    )

    uri.should contain("algorithm=SHA256")
    uri.should contain("digits=8")
    uri.should contain("period=60")
  end

  # A colon inside either half produces a URI that parses to a different account.
  it "refuses an issuer or label that would change how the URI parses" do
    expect_raises(ArgumentError, /colon/) do
      TOTP.provisioning_uri(SHA1_SECRET, issuer: "Acme:Corp", label: "ada")
    end

    expect_raises(ArgumentError, /colon/) do
      TOTP.provisioning_uri(SHA1_SECRET, issuer: "Acme", label: "a:b")
    end
  end

  it "refuses a blank issuer or label" do
    expect_raises(ArgumentError) { TOTP.provisioning_uri(SHA1_SECRET, issuer: " ", label: "ada") }
    expect_raises(ArgumentError) { TOTP.provisioning_uri(SHA1_SECRET, issuer: "Acme", label: "") }
  end

  # The URI is a credential, and this is the round trip that proves the app will agree with us.
  it "encodes a secret an app can decode back to the same bytes" do
    uri = TOTP.provisioning_uri(SHA1_SECRET, issuer: "Acme", label: "ada")
    encoded = URI.parse(uri).query_params["secret"]

    Base32.decode?(encoded).should eq(SHA1_SECRET)
  end
end

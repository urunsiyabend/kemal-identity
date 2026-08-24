require "../spec_helper"

private def config(
  secret : String = "a" * 32,
  cookie_name : String = "__Host-kemal_identity_csrf",
  secure : Bool = true,
  exempt : Array(String) = [] of String,
)
  KemalIdentity::CSRFConfig.new(
    secret: secret, cookie_name: cookie_name, secure: secure, exempt_prefixes: exempt
  )
end

private def random
  KemalIdentity::Testing::DeterministicRandom.new
end

describe KemalIdentity::CSRF do
  secret = KemalIdentity::Secret.new("a" * 32)
  other_secret = KemalIdentity::Secret.new("b" * 32)

  describe ".issue and .valid?" do
    it "accepts a token it issued for the same anchor" do
      token = KemalIdentity::CSRF.issue(secret, "session-1", random)
      KemalIdentity::CSRF.valid?(secret, "session-1", token).should be_true
    end

    # The blocker from docs/05-testing.md: a token from another session is rejected. This is
    # what plain double-submit cannot do -- anyone able to set the cookie could set the field
    # too, and the two would agree.
    it "rejects a token issued for a different anchor" do
      token = KemalIdentity::CSRF.issue(secret, "session-1", random)
      KemalIdentity::CSRF.valid?(secret, "session-2", token).should be_false
    end

    it "rejects a token signed with a different secret" do
      token = KemalIdentity::CSRF.issue(other_secret, "session-1", random)
      KemalIdentity::CSRF.valid?(secret, "session-1", token).should be_false
    end

    it "rejects an empty anchor rather than validating against nothing" do
      token = KemalIdentity::CSRF.issue(secret, "session-1", random)
      KemalIdentity::CSRF.valid?(secret, "", token).should be_false
    end

    it "rejects a missing token" do
      KemalIdentity::CSRF.valid?(secret, "session-1", nil).should be_false
    end
  end

  # The mask. `HMAC(secret, anchor)` is constant for the life of a session, and a value
  # repeated in every response is what a BREACH-style compression oracle extracts. The pad
  # changes per issue, so the rendered token changes with it and still verifies.
  describe "masking" do
    it "issues a different string every time for the same anchor" do
      source = random
      tokens = Array.new(20) { KemalIdentity::CSRF.issue(secret, "session-1", source) }
      tokens.uniq!.size.should eq(20)
    end

    it "accepts every one of those differing tokens" do
      source = random
      Array.new(10) { KemalIdentity::CSRF.issue(secret, "session-1", source) }.each do |token|
        KemalIdentity::CSRF.valid?(secret, "session-1", token).should be_true
      end
    end

    it "produces a token of a fixed length, so the shape check is exact" do
      KemalIdentity::CSRF.issue(secret, "session-1", random).size
        .should eq(KemalIdentity::CSRF::TOKEN_LENGTH)
    end
  end

  # Whatever a client chose to send. A hostile value must be a rejection, never a 500.
  describe "malformed input" do
    it "rejects values of the wrong length without raising" do
      ["", "a", "a" * 85, "a" * 87, "a" * 100_000].each do |value|
        KemalIdentity::CSRF.valid?(secret, "session-1", value).should be_false
      end
    end

    it "rejects characters outside base64url" do
      ["+", "/", "=", "!", " ", "	"].each do |char|
        candidate = "a" * (KemalIdentity::CSRF::TOKEN_LENGTH - 1) + char
        KemalIdentity::CSRF.valid?(secret, "session-1", candidate).should be_false
      end
    end

    it "rejects a well-shaped value that decodes to nothing meaningful" do
      KemalIdentity::CSRF.valid?(secret, "session-1", "a" * KemalIdentity::CSRF::TOKEN_LENGTH)
        .should be_false
    end

    it "rejects a token whose signature half has been altered" do
      token = KemalIdentity::CSRF.issue(secret, "session-1", random)
      tampered = token[0...-1] + (token[-1] == 'A' ? "B" : "A")
      KemalIdentity::CSRF.valid?(secret, "session-1", tampered).should be_false
    end
  end
end

describe KemalIdentity::CSRFConfig do
  describe "which methods it protects" do
    # A denylist of POST/PUT/PATCH/DELETE would leave every method nobody thought of
    # unprotected. PROPFIND mutates in WebDAV, and HTTP QUERY did not exist when this shard
    # was designed. Safe by name, protected otherwise.
    it "protects everything not named safe" do
      %w[POST PUT PATCH DELETE PROPFIND MKCOL LOCK PURGE].each do |method|
        config.protects?(method).should be_true
      end
    end

    it "leaves the safe methods alone" do
      %w[GET HEAD OPTIONS TRACE].each do |method|
        config.protects?(method).should be_false
      end
    end

    # RFC 10008 defines QUERY as safe and idempotent. It carries a request body, which makes
    # it easy to mistake for a mutation; it is not one.
    it "treats QUERY as safe despite it carrying a body" do
      config.protects?("QUERY").should be_false
    end

    it "is case-insensitive about the method name" do
      config.protects?("get").should be_false
      config.protects?("post").should be_true
    end
  end

  describe "exemptions" do
    it "exempts a path under an exempt prefix" do
      c = config(exempt: ["/api/webhook"])
      c.exempt?("/api/webhook").should be_true
      c.exempt?("/api/webhook/stripe").should be_true
    end

    # The same boundary rule as PathGuard: a naive starts_with? would exempt a path that
    # merely shares the prefix, which is the wrong direction for a security control.
    it "does not exempt a path that merely shares the prefix" do
      config(exempt: ["/api/webhook"]).exempt?("/api/webhooks-admin").should be_false
    end

    it "exempts nothing by default" do
      config.exempt?("/anything").should be_false
    end
  end

  describe "boot-time validation" do
    it "refuses a short signing key" do
      expect_raises(KemalIdentity::ConfigurationError) { config(secret: "too short") }
    end

    it "accepts a key at the minimum length" do
      config(secret: "a" * KemalIdentity::CSRFConfig::MIN_SECRET_BYTES).should_not be_nil
    end

    it "refuses a __Host- cookie that is not Secure" do
      expect_raises(KemalIdentity::ConfigurationError) { config(secure: false) }
    end

    it "refuses an empty cookie name" do
      expect_raises(KemalIdentity::ConfigurationError) { config(cookie_name: "") }
    end
  end

  describe "the anchor cookie" do
    it "is HttpOnly, Secure and path-scoped to the root" do
      header = config.build_cookie("anchor-value").to_set_cookie_header
      header.should contain("HttpOnly")
      header.should contain("Secure")
      header.should contain("path=/")
      header.should contain("SameSite=Lax")
    end

    it "sets no domain, so a sibling subdomain cannot plant an anchor" do
      config.build_cookie("anchor-value").to_set_cookie_header.should_not contain("domain")
    end
  end

  # docs/02-security-model.md: a configuration dump in a crash report must not leak the
  # signing key.
  describe "redaction" do
    it "keeps the signing key out of inspect and interpolation" do
      c = config(secret: "sup3rs3cr3t-signing-key-at-least-32")
      c.inspect.should_not contain("sup3rs3cr3t")
      c.to_s.should_not contain("sup3rs3cr3t")
      "csrf=#{c}".should_not contain("sup3rs3cr3t")
    end

    it "keeps it out of the wrapped secret too" do
      config(secret: "sup3rs3cr3t-signing-key-at-least-32").secret.inspect
        .should_not contain("sup3rs3cr3t")
    end
  end
end

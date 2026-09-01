require "../spec_helper"

# `JWT.unverified_issuer` reads an attacker-controlled claim out of an unverified token, so its
# specs are about what it refuses at least as much as what it returns.
private def token_claiming(issuer : String?, extra : Hash(String, ::JSON::Any) = {} of String => ::JSON::Any)
  claims = KemalIdentity::Testing::JWTForge.claims(
    now: KemalIdentity::Testing::FIXED_NOW, issuer: issuer
  )
  extra.each { |k, v| claims[k] = v }
  KemalIdentity::Testing::JWTForge.encode(claims)
end

describe "KemalIdentity::JWT.unverified_issuer" do
  it "reads the issuer a token claims" do
    KemalIdentity::JWT.unverified_issuer(token_claiming("https://alpha.example.com"))
      .should eq("https://alpha.example.com")
  end

  # The point of the whole helper: it works on a token this application cannot verify, because
  # choosing the validator is what has to happen before verification can.
  it "reads it from a token signed with a key nobody here holds" do
    forged = KemalIdentity::Testing::JWTForge.encode(
      KemalIdentity::Testing::JWTForge.claims(
        now: KemalIdentity::Testing::FIXED_NOW, issuer: "https://beta.example.com"
      ),
      secret: KemalIdentity::Secret.new("z" * 64)
    )

    KemalIdentity::JWT.unverified_issuer(forged).should eq("https://beta.example.com")
  end

  describe "what it refuses" do
    it "refuses nil and empty" do
      KemalIdentity::JWT.unverified_issuer(nil).should be_nil
      KemalIdentity::JWT.unverified_issuer("").should be_nil
    end

    it "refuses anything that is not three segments" do
      KemalIdentity::JWT.unverified_issuer("not-a-jwt").should be_nil
      KemalIdentity::JWT.unverified_issuer("two.segments").should be_nil
      KemalIdentity::JWT.unverified_issuer("a.b.c.d").should be_nil
    end

    # Bounded before anything is decoded, so a hostile header costs one integer comparison
    # rather than a megabyte of base64.
    it "refuses a token past the byte limit without decoding it" do
      oversized = "#{"a" * 9000}.#{"b" * 9000}.#{"c" * 9000}"

      KemalIdentity::JWT.unverified_issuer(oversized).should be_nil
      KemalIdentity::JWT.unverified_issuer(oversized, max_bytesize: 40_000).should be_nil
    end

    # The same strict base64url the validator uses, not a second decoder that might disagree.
    it "refuses standard-base64 and padded segments" do
      valid = token_claiming("https://alpha.example.com")
      header, payload, signature = valid.split('.')

      KemalIdentity::JWT.unverified_issuer("#{header}.#{payload}=.#{signature}").should be_nil
      KemalIdentity::JWT.unverified_issuer("#{header}.#{payload}+#{payload}.#{signature}")
        .should be_nil
    end

    it "refuses a payload that is not a JSON object" do
      encoded = Base64.urlsafe_encode(%(["not", "an", "object"]), padding: false)

      KemalIdentity::JWT.unverified_issuer("aaaa.#{encoded}.bbbb").should be_nil
    end

    it "refuses a missing, empty or non-string issuer" do
      KemalIdentity::JWT.unverified_issuer(token_claiming(nil)).should be_nil
      KemalIdentity::JWT.unverified_issuer(token_claiming("")).should be_nil

      numeric = KemalIdentity::Testing::JWTForge.encode(
        KemalIdentity::Testing::JWTForge.claims(
          now: KemalIdentity::Testing::FIXED_NOW, issuer: nil
        ).tap { |claims| claims["iss"] = ::JSON::Any.new(42_i64) }
      )
      KemalIdentity::JWT.unverified_issuer(numeric).should be_nil
    end
  end

  # The routing this exists for, end to end: two issuers, each with its own validator, both
  # accepted — which chaining the validators cannot do.
  it "makes two issuers reachable through one entry point" do
    alpha_secret = KemalIdentity::Secret.new("alpha-hmac-key-of-32-bytes-plus!!")
    beta_secret = KemalIdentity::Secret.new("beta-hmac-key-of-32-bytes-plus!!!")

    build = ->(issuer : String, secret : KemalIdentity::Secret) do
      KemalIdentity::JWT::Validator.new(
        keyring: KemalIdentity::JWT::Keyring.new([
          KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, secret),
        ]),
        issuer: issuer, audience: "consumer-app", algorithms: ["HS256"],
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
      )
    end

    validators = {
      "https://alpha.example.com" => build.call("https://alpha.example.com", alpha_secret),
      "https://beta.example.com"  => build.call("https://beta.example.com", beta_secret),
    }

    mint = ->(issuer : String, secret : KemalIdentity::Secret) do
      KemalIdentity::Testing::JWTForge.encode(
        KemalIdentity::Testing::JWTForge.claims(
          now: KemalIdentity::Testing::FIXED_NOW, issuer: issuer,
          audience: ::JSON::Any.new("consumer-app")
        ),
        secret
      )
    end

    route = ->(credential : String) do
      issuer = KemalIdentity::JWT.unverified_issuer(credential)
      validator = issuer.try { |i| validators[i]? }

      if validator
        validator.authenticate(credential)
      else
        # A `nil` is a refusal, never permission to pick a default.
        KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidClaim).as(KemalIdentity::Outcome)
      end
    end

    route.call(mint.call("https://alpha.example.com", alpha_secret))
      .should be_a(KemalIdentity::Authenticated)
    route.call(mint.call("https://beta.example.com", beta_secret))
      .should be_a(KemalIdentity::Authenticated)

    # An issuer nobody configured is refused without any validator being consulted.
    route.call(mint.call("https://gamma.example.com", alpha_secret))
      .should be_a(KemalIdentity::Failed)

    # And a token whose claimed issuer is configured but whose signature is somebody else's is
    # still refused -- by the validator, because selection proves nothing.
    route.call(mint.call("https://alpha.example.com", beta_secret))
      .should be_a(KemalIdentity::Failed)
  end
end

require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# JWT-01 to JWT-04, from the consumer side. A B2B API accepting tokens from two customer
# identity providers, each with its own keys, audience and claim shapes.

private ISSUER_A = "https://alpha.example.com"
private ISSUER_B = "https://beta.example.com"
private SECRET_A = KemalIdentity::Secret.new("alpha-hmac-key-of-32-bytes-plus!!")
private SECRET_B = KemalIdentity::Secret.new("beta-hmac-key-of-32-bytes-plus!!!")

private def validator_for(
  issuer : String,
  secret : KemalIdentity::Secret,
  audience : String = "consumer-app",
  revocations : KemalIdentity::JWT::RevocationStore? = nil,
  clock : KemalIdentity::Clock? = nil,
)
  KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new([
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, secret),
    ]),
    issuer: issuer,
    audience: audience,
    algorithms: ["HS256"],
    clock: clock || KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW),
    revocations: revocations,
  )
end

private def token_from(
  issuer : String,
  secret : KemalIdentity::Secret,
  audience : String = "consumer-app",
  subject : String = "a1",
  jti : String? = nil,
  extra : Hash(String, ::JSON::Any) = {} of String => ::JSON::Any,
)
  claims = KemalIdentity::Testing::JWTForge.claims(
    now: KemalIdentity::SpecHelper::FIXED_NOW,
    subject: subject,
    issuer: issuer,
    audience: ::JSON::Any.new(audience),
    jti: jti,
  )
  extra.each { |k, v| claims[k] = v }
  KemalIdentity::Testing::JWTForge.encode(claims, secret)
end


# The routing a consumer has to write themselves: read `iss` from an unverified token, pick the
# validator, and only then validate. Every bound on that parse is the consumer's problem.
private def resolve
  ->(credential : String, validators : Hash(String, KemalIdentity::JWT::Validator)) do
    segments = credential.split('.')
    if segments.size != 3
      KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential).as(KemalIdentity::Outcome)
    else
      payload = begin
        padded = segments[1] + "=" * ((4 - segments[1].size % 4) % 4)
        ::JSON.parse(Base64.decode_string(padded))
      rescue
        nil
      end

      issuer = payload.try { |p| p["iss"]?.try(&.as_s?) }
      validator = issuer.try { |i| validators[i]? }

      if payload.nil?
        KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential).as(KemalIdentity::Outcome)
      elsif validator.nil?
        KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidClaim).as(KemalIdentity::Outcome)
      else
        validator.authenticate(credential)
      end
    end
  end
end

describe "JWT-01: two issuers selected at runtime" do
  # Each validator alone works. That much is not in question.
  it "validates each issuer's token against its own validator" do
    validator_for(ISSUER_A, SECRET_A).authenticate(token_from(ISSUER_A, SECRET_A))
      .should be_a(KemalIdentity::Authenticated)
    validator_for(ISSUER_B, SECRET_B).authenticate(token_from(ISSUER_B, SECRET_B))
      .should be_a(KemalIdentity::Authenticated)
  end

  # And each refuses the other's, which is the security property. The reason is worth noting:
  # the *signature* fails first, because each issuer signs with its own key and neither key is
  # in the other's ring. `iss` never gets compared.
  it "refuses a token minted for the other issuer, on the signature" do
    outcome = validator_for(ISSUER_A, SECRET_A).authenticate(token_from(ISSUER_B, SECRET_B))

    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason.should eq(
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # And when the two *do* share a key, so the signature verifies, `iss` is what refuses.
  it "refuses a wrong issuer on the claim when the signature happens to verify" do
    outcome = validator_for(ISSUER_A, SECRET_A).authenticate(token_from(ISSUER_B, SECRET_A))

    outcome.as(KemalIdentity::Failed).reason.should eq(
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  # The obvious way to accept both: register both validators in the chain the shard ships for
  # exactly this ("One header, two credentials").
  it "cannot accept both issuers by chaining the two validators" do
    chain = KemalIdentity::AuthenticatorChain.new([
      validator_for(ISSUER_A, SECRET_A).as(KemalIdentity::RequestAuthenticator),
      validator_for(ISSUER_B, SECRET_B).as(KemalIdentity::RequestAuthenticator),
    ])

    # Issuer A's token: the first validator answers, so this works.
    chain.authenticate(token_from(ISSUER_A, SECRET_A)).should be_a(KemalIdentity::Authenticated)

    # Issuer B's token: validator A recognises the *shape* — every JWT has the same shape — and
    # rejects it on its merits, so the chain stops rather than giving a rejected credential a
    # second opinion. Validator B is never asked, and a legitimate customer's token is refused.
    outcome = chain.authenticate(token_from(ISSUER_B, SECRET_B))
    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason.should eq(
      KemalIdentity::FailureReason::InvalidCredential
    )
  end

  # Reversing the order moves the problem rather than solving it, which is what makes this
  # structural rather than a configuration mistake.
  it "fails whichever issuer is registered second" do
    reversed = KemalIdentity::AuthenticatorChain.new([
      validator_for(ISSUER_B, SECRET_B).as(KemalIdentity::RequestAuthenticator),
      validator_for(ISSUER_A, SECRET_A).as(KemalIdentity::RequestAuthenticator),
    ])

    reversed.authenticate(token_from(ISSUER_B, SECRET_B)).should be_a(KemalIdentity::Authenticated)
    reversed.authenticate(token_from(ISSUER_A, SECRET_A)).should be_a(KemalIdentity::Failed)
  end

  # So the consumer has to route on `iss` before validating — which means reading an
  # unverified claim out of an unverified token. There is no public helper for that.
  it "has no public way to read iss before validation" do
    KemalIdentity::JWT::Validator.responds_to?(:peek_issuer).should be_false
    KemalIdentity::JWT.responds_to?(:unverified_issuer).should be_false
  end

  # What a consumer ends up writing: their own base64url decode of segment 1.
  it "works only once the consumer parses the token themselves" do
    validators = {
      ISSUER_A => validator_for(ISSUER_A, SECRET_A),
      ISSUER_B => validator_for(ISSUER_B, SECRET_B),
    }

    resolve.call(token_from(ISSUER_A, SECRET_A), validators).should be_a(KemalIdentity::Authenticated)
    resolve.call(token_from(ISSUER_B, SECRET_B), validators).should be_a(KemalIdentity::Authenticated)

    # An unknown issuer is refused without any validator being consulted, and without network.
    resolve.call(token_from("https://gamma.example.com", SECRET_A), validators)
      .should be_a(KemalIdentity::Failed)
  end
end

describe "JWT-02: claim mapping without weakening validation" do
  # Pass condition: "Mapping cannot skip signature, issuer, audience, expiry or purpose checks."
  it "hands the consumer every claim, but only after validation" do
    validator = validator_for(ISSUER_A, SECRET_A)
    token = token_from(
      ISSUER_A, SECRET_A,
      extra: {"uid" => ::JSON::Any.new("legacy-4711"), "tenant" => ::JSON::Any.new("acme")}
    )

    validated = validator.validate(token)
    validated.should be_a(KemalIdentity::JWT::Validated)

    claims = validated.as(KemalIdentity::JWT::Validated).claims
    claims["uid"].as_s.should eq("legacy-4711")
    claims["tenant"].as_s.should eq("acme")

    # The mapping step is the consumer's, and it runs on already-verified claims.
    mapped = KemalIdentity::Principal.new(
      subject: claims["uid"].as_s,
      assurance: KemalIdentity::AssuranceLevel::ApiToken,
      authenticated_at: KemalIdentity::SpecHelper::FIXED_NOW,
      tenant_id: claims["tenant"].as_s,
    )
    mapped.subject.should eq("legacy-4711")
    mapped.tenant_id.should eq("acme")
  end

  it "gives the consumer nothing to map when validation failed" do
    validator_for(ISSUER_A, SECRET_A)
      .validate(token_from(ISSUER_B, SECRET_B))
      .should be_a(KemalIdentity::Failed)
  end

  # Pass condition: "local identity linking uses issuer plus subject rather than email."
  it "exposes issuer and subject together" do
    claims = validator_for(ISSUER_A, SECRET_A)
      .validate(token_from(ISSUER_A, SECRET_A))
      .as(KemalIdentity::JWT::Validated).claims

    claims["iss"].as_s.should eq(ISSUER_A)
    claims["sub"].as_s.should eq("a1")
  end
end

describe "JWT-03: audience-specific validation" do
  # One process, two APIs. A token minted for billing must not authenticate against admin.
  it "refuses a token minted for another audience" do
    billing = validator_for(ISSUER_A, SECRET_A, audience: "billing")
    admin = validator_for(ISSUER_A, SECRET_A, audience: "admin")

    for_billing = token_from(ISSUER_A, SECRET_A, audience: "billing")

    billing.authenticate(for_billing).should be_a(KemalIdentity::Authenticated)

    outcome = admin.authenticate(for_billing)
    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason.should eq(
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  # Pass condition: "multi-audience tokens have explicit semantics". RFC 7519 lets `aud` be an
  # array, and what a verifier does with one it is only *one of* is the subtle part.
  it "accepts a token whose aud array contains this audience" do
    claims = KemalIdentity::Testing::JWTForge.claims(
      now: KemalIdentity::SpecHelper::FIXED_NOW,
      subject: "a1", issuer: ISSUER_A,
      audience: ::JSON::Any.new([::JSON::Any.new("billing"), ::JSON::Any.new("admin")]),
    )
    token = KemalIdentity::Testing::JWTForge.encode(claims, SECRET_A)

    validator_for(ISSUER_A, SECRET_A, audience: "billing").authenticate(token)
      .should be_a(KemalIdentity::Authenticated)
    validator_for(ISSUER_A, SECRET_A, audience: "admin").authenticate(token)
      .should be_a(KemalIdentity::Authenticated)
  end

  it "refuses a token whose aud array does not contain this audience" do
    claims = KemalIdentity::Testing::JWTForge.claims(
      now: KemalIdentity::SpecHelper::FIXED_NOW,
      subject: "a1", issuer: ISSUER_A,
      audience: ::JSON::Any.new([::JSON::Any.new("billing")]),
    )
    token = KemalIdentity::Testing::JWTForge.encode(claims, SECRET_A)

    validator_for(ISSUER_A, SECRET_A, audience: "admin").authenticate(token)
      .as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::InvalidClaim)
  end

  # Pass condition: "route policy cannot accidentally use a global validator with a broader
  # audience". There is no global validator to reach for: a validator is a value the route holds.
  it "has no ambient validator a route could pick up by accident" do
    KemalIdentity.responds_to?(:jwt).should be_false
  end
end

describe "JWT-04: revocation policy per issuer" do
  it "denylists a jti for one issuer without touching the other" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    store_a = KemalIdentity::Testing::MemoryRevocationStore.new

    alpha = validator_for(ISSUER_A, SECRET_A, revocations: store_a, clock: clock)
    beta = validator_for(ISSUER_B, SECRET_B, clock: clock)   # expiry only, no denylist

    token_a = token_from(ISSUER_A, SECRET_A, jti: "jti-a")
    token_b = token_from(ISSUER_B, SECRET_B, jti: "jti-b")

    alpha.authenticate(token_a).should be_a(KemalIdentity::Authenticated)
    beta.authenticate(token_b).should be_a(KemalIdentity::Authenticated)

    store_a.revoke("jti-a", KemalIdentity::SpecHelper::FIXED_NOW + 1.hour)

    outcome = alpha.authenticate(token_a)
    outcome.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::Revoked)

    # Beta's policy is unchanged: it has no store, so nothing to consult.
    beta.authenticate(token_b).should be_a(KemalIdentity::Authenticated)
  end
end

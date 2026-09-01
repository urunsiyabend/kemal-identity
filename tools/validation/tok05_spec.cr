require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# TOK-05 — four bearer credential families in one application: an opaque personal token, an
# internal gateway JWT, a partner JWT, and a legacy credential kept alive during a migration.
#
# The question is whether the chain is the *consumer's*, or whether it is assembled from named
# built-ins with the consumer's authenticators bolted on the side.

CLOCK5 = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

# Family 3: partner JWTs, a second issuer with its own key. Two `JWT::Validator`s cannot be
# chained on shape (JWT-01), so routing on `iss` is the consumer's job — `JWT.unverified_issuer`
# is the bounded read that makes it possible without a hand-rolled parser.
class PartnerRouter < KemalIdentity::RequestAuthenticator
  getter io_calls = 0

  def initialize(@validators : Hash(String, KemalIdentity::JWT::Validator))
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    issuer = KemalIdentity::JWT.unverified_issuer(credential)
    # Not a JWT at all, or a JWT from an issuer this application does not know. Both are "not
    # mine" — and the second deliberately reads the same as the first from outside, so a probe
    # cannot enumerate which issuers are configured.
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential) if issuer.nil?
    validator = @validators[issuer]?
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential) if validator.nil?

    @io_calls += 1
    validator.authenticate(credential)
  end
end

# Family 4: the legacy credential. Fixed prefix, fixed length, and it counts its own I/O so the
# "no I/O before the shape decides" condition can be measured rather than asserted.
class LegacyCredential < KemalIdentity::RequestAuthenticator
  PREFIX = "legacy-"
  getter io_calls = 0

  def initialize(@subjects : Hash(String, String), @now : Time)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    unless credential.starts_with?(PREFIX) && credential.bytesize == PREFIX.bytesize + 8
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    @io_calls += 1
    subject = @subjects[credential.lchop(PREFIX)]?
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential) if subject.nil?

    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: subject,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: @now,
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::Custom, id: "legacy", name: "legacy token"
        ),
      )
    )
  end
end

private INTERNAL_SECRET = KemalIdentity::Secret.new("internal-gateway-secret-32-bytes")
private PARTNER_SECRET  = KemalIdentity::Secret.new("partner-issuer-secret-32-bytes!!")

private def validator(secret : KemalIdentity::Secret, issuer : String) : KemalIdentity::JWT::Validator
  KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new(KemalIdentity::JWT::HS256, secret),
    issuer: issuer,
    audience: "monolith",
    algorithms: ["HS256"],
    clock: CLOCK5,
  )
end

private def jwt_for(secret : KemalIdentity::Secret, issuer : String, subject : String) : String
  KemalIdentity::Testing::JWTForge.encode(
    KemalIdentity::Testing::JWTForge.claims(
      subject: subject, issuer: issuer, audience: ::JSON::Any.new("monolith")
    ),
    secret: secret,
  )
end

describe "TOK-05 — four bearer families" do
  # First attempt, and it fails: `jwt:` is configured *and* a JWT-shaped authenticator of the
  # application's own is passed. The shard's validator sees the partner token first, recognises
  # the shape, rejects it on `iss` — which is not `MalformedCredential`, so the chain stops and
  # the application's router never runs.
  it "cannot put a JWT-shaped authenticator of its own behind the shipped one" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    partner = PartnerRouter.new({"https://partner.example" => validator(PARTNER_SECRET, "https://partner.example")})

    chain = KemalIdentity::AuthenticatorChain.new([
      validator(INTERNAL_SECRET, "https://internal.example").as(KemalIdentity::RequestAuthenticator),
      partner.as(KemalIdentity::RequestAuthenticator),
    ])

    outcome = chain.authenticate(jwt_for(PARTNER_SECRET, "https://partner.example", "a1"))

    outcome.should be_a(KemalIdentity::Failed)
    # `InvalidCredential`, not `InvalidClaim`: the signature fails before `iss` is ever compared,
    # because each issuer signs with a key the other's ring does not hold (JWT-01's first row).
    # Either way it is not `MalformedCredential`, so the chain stops.
    outcome.as(KemalIdentity::Failed).reason.invalid_credential?.should be_true
    partner.io_calls.should eq(0)
  end

  # Second attempt: the application owns the JWT shape entirely. No `jwt:` — its router holds
  # both validators and routes on `iss` itself, which is what `JWT.unverified_issuer` is for.
  it "works when the application owns the shape it shares with the shard" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    partner = PartnerRouter.new({
      "https://internal.example" => validator(INTERNAL_SECRET, "https://internal.example"),
      "https://partner.example"  => validator(PARTNER_SECRET, "https://partner.example"),
    })
    legacy = LegacyCredential.new({"abcdefgh" => "legacy-user"}, KemalIdentity::Testing::FIXED_NOW)

    app = KemalIdentity.configure(
      accounts: accounts,
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: CLOCK5,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 9),
      api_tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      bearer_authenticators: [
        partner.as(KemalIdentity::RequestAuthenticator),
        legacy.as(KemalIdentity::RequestAuthenticator),
      ],
    )

    chain = app.bearer.as(KemalIdentity::AuthenticatorChain)
    chain.authenticators.size.should eq(3)

    issued = app.api.not_nil!.issue(account: KemalIdentity::Testing.account, name: "ci")

    # Family 1: the opaque personal token.
    chain.authenticate(issued.token.reveal)
      .as(KemalIdentity::Authenticated).principal.credential.not_nil!.kind
      .should eq(KemalIdentity::CredentialKind::ApiToken)

    # Families 2 and 3: two issuers, same shape, the application's router deciding.
    chain.authenticate(jwt_for(INTERNAL_SECRET, "https://internal.example", "a1"))
      .as(KemalIdentity::Authenticated).principal.subject.should eq("a1")
    chain.authenticate(jwt_for(PARTNER_SECRET, "https://partner.example", "a1"))
      .as(KemalIdentity::Authenticated).principal.subject.should eq("a1")

    # Family 4: the legacy credential.
    chain.authenticate("legacy-abcdefgh")
      .as(KemalIdentity::Authenticated).principal.subject.should eq("legacy-user")
  end

  it "fails closed on an ambiguous shape rather than trying it against every backend" do
    partner = PartnerRouter.new({"https://partner.example" => validator(PARTNER_SECRET, "https://partner.example")})
    legacy = LegacyCredential.new({"abcdefgh" => "legacy-user"}, KemalIdentity::Testing::FIXED_NOW)
    chain = KemalIdentity::AuthenticatorChain.new([
      partner.as(KemalIdentity::RequestAuthenticator),
      legacy.as(KemalIdentity::RequestAuthenticator),
    ])

    # A JWT from an issuer nobody knows: three segments, so it *looks* like families 2 and 3.
    unknown = jwt_for(PARTNER_SECRET, "https://stranger.example", "a1")
    chain.authenticate(unknown).as(KemalIdentity::Failed).reason.malformed_credential?.should be_true

    # A partner JWT with a signature made by the wrong key: recognised, then rejected. The chain
    # must stop here rather than offer it to the legacy authenticator.
    forged = jwt_for(INTERNAL_SECRET, "https://partner.example", "a1")
    chain.authenticate(forged).as(KemalIdentity::Failed).reason.invalid_credential?.should be_true
  end

  it "performs no I/O before the shape has decided the credential could be its own" do
    partner = PartnerRouter.new({"https://partner.example" => validator(PARTNER_SECRET, "https://partner.example")})
    legacy = LegacyCredential.new({"abcdefgh" => "legacy-user"}, KemalIdentity::Testing::FIXED_NOW)
    chain = KemalIdentity::AuthenticatorChain.new([
      partner.as(KemalIdentity::RequestAuthenticator),
      legacy.as(KemalIdentity::RequestAuthenticator),
    ])

    ["", "not-a-credential", "ki_#{"a" * 43}", "legacy-short", "legacy-#{"x" * 40}"].each do |raw|
      chain.authenticate(raw)
    end

    partner.io_calls.should eq(0)
    legacy.io_calls.should eq(0)
  end

  it "answers a maliciously oversized credential without decoding it" do
    partner = PartnerRouter.new({"https://partner.example" => validator(PARTNER_SECRET, "https://partner.example")})
    legacy = LegacyCredential.new(Hash(String, String).new, KemalIdentity::Testing::FIXED_NOW)
    chain = KemalIdentity::AuthenticatorChain.new([
      partner.as(KemalIdentity::RequestAuthenticator),
      legacy.as(KemalIdentity::RequestAuthenticator),
    ])

    two_megabytes = "a.#{"b" * 2_000_000}.c"
    elapsed = Time.measure { chain.authenticate(two_megabytes) }

    chain.authenticate(two_megabytes).as(KemalIdentity::Failed).reason.malformed_credential?.should be_true
    partner.io_calls.should eq(0)
    elapsed.should be < 50.milliseconds
  end

  it "does not reveal which families exist" do
    partner = PartnerRouter.new({"https://partner.example" => validator(PARTNER_SECRET, "https://partner.example")})
    legacy = LegacyCredential.new({"abcdefgh" => "legacy-user"}, KemalIdentity::Testing::FIXED_NOW)
    chain = KemalIdentity::AuthenticatorChain.new([
      partner.as(KemalIdentity::RequestAuthenticator),
      legacy.as(KemalIdentity::RequestAuthenticator),
    ])

    # An unknown issuer and a plain string are indistinguishable from outside: same reason, and
    # the reason names no backend.
    a = chain.authenticate(jwt_for(PARTNER_SECRET, "https://stranger.example", "a1")).as(KemalIdentity::Failed)
    b = chain.authenticate("nonsense").as(KemalIdentity::Failed)

    a.reason.should eq(b.reason)
    a.reason.to_s.downcase.should_not contain("partner")
    a.reason.to_s.downcase.should_not contain("legacy")
    a.reason.to_s.downcase.should_not contain("jwt")
  end
end

# An authenticator of the application's own whose credentials share the *opaque token* shape,
# rather than the JWT shape. Same collision, different family — measured rather than assumed by
# analogy.
class ShapeCollider < KemalIdentity::RequestAuthenticator
  getter io_calls = 0

  def initialize(@now : Time)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?
    unless credential.starts_with?("ki_") && credential.bytesize == 46
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    @io_calls += 1
    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: "collider", assurance: KemalIdentity::AssuranceLevel::ApiToken, authenticated_at: @now
      )
    )
  end
end

describe "TOK-05 — one owner per shape" do
  it "cannot share the opaque-token shape with the shipped service either" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    collider = ShapeCollider.new(KemalIdentity::Testing::FIXED_NOW)

    app = KemalIdentity.configure(
      accounts: accounts,
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: CLOCK5,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 3),
      api_tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      bearer_authenticators: [collider.as(KemalIdentity::RequestAuthenticator)],
    )

    outcome = app.bearer.not_nil!.authenticate("ki_#{"a" * 43}")

    outcome.should be_a(KemalIdentity::Failed)
    collider.io_calls.should eq(0)
  end

  it "works once the shapes are moved apart with api_token_prefix" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    collider = ShapeCollider.new(KemalIdentity::Testing::FIXED_NOW)

    app = KemalIdentity.configure(
      accounts: accounts,
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: CLOCK5,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 3),
      api_tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      api_token_prefix: "app_",
      bearer_authenticators: [collider.as(KemalIdentity::RequestAuthenticator)],
    )

    app.bearer.not_nil!.authenticate("ki_#{"a" * 43}")
      .as(KemalIdentity::Authenticated).principal.subject.should eq("collider")

    issued = app.api.not_nil!.issue(account: KemalIdentity::Testing.account, name: "ci")
    issued.token.reveal.starts_with?("app_").should be_true
    app.bearer.not_nil!.authenticate(issued.token.reveal)
      .as(KemalIdentity::Authenticated).principal.credential.not_nil!.kind
      .should eq(KemalIdentity::CredentialKind::ApiToken)
  end
end

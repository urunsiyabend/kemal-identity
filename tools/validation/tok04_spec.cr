require "spec"
require "kemal_identity"
require "kemal_identity/testing"
require "../src/tok04_gateway"

# TOK-04 — a consumer-written bearer authenticator, registered between two built-in ones.
#
# Every method body here is actually *called*: a file that merely defines an authenticator
# compiles even when its bodies would not, which is the trap `tools/validation/README.md` records.

CLOCK  = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
SECRET = "gateway-shared-secret"

private def accounts
  KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
end

private def api_service(repo)
  KemalIdentity::ApiTokens::Service.new(
    tokens: repo,
    clock: CLOCK,
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: 11),
  )
end

private def jwt_validator
  KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new(
      KemalIdentity::JWT::HS256, KemalIdentity::Testing::JWTForge::SECRET
    ),
    issuer: KemalIdentity::Testing::JWTForge::ISSUER,
    audience: KemalIdentity::Testing::JWTForge::AUDIENCE,
    algorithms: ["HS256"],
    clock: CLOCK,
  )
end

describe "TOK-04 — the authenticator on its own" do
  it "answers Anonymous for nothing presented" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    gw.authenticate(nil).should be_a(KemalIdentity::Anonymous)
    gw.authenticate("").should be_a(KemalIdentity::Anonymous)
  end

  it "answers MalformedCredential for a credential of somebody else's shape" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    outcome = gw.authenticate("ki_#{"a" * 43}")
    outcome.as(KemalIdentity::Failed).reason.malformed_credential?.should be_true
  end

  it "answers InvalidCredential for its own shape with a bad signature" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    outcome = gw.authenticate("gw.ada.0000000000000000")
    outcome.as(KemalIdentity::Failed).reason.invalid_credential?.should be_true
  end

  it "authenticates its own token and attaches credential metadata" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    principal = gw.authenticate(GatewayAuthenticator.mint(SECRET, "ada")).as(KemalIdentity::Authenticated).principal

    principal.subject.should eq("ada")
    credential = principal.credential.not_nil!
    credential.kind.should eq(KemalIdentity::CredentialKind::Custom)
    credential.id.should eq("gw-ada")
    credential.name.should eq("api gateway")
    credential.permits?("invoices.read").should be_true
    credential.permits?("invoices.refund").should be_false
  end
end

describe "TOK-04 — registered between two built-in authenticators" do
  it "is reachable in a chain the consumer builds, in the position it chose" do
    repo = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)
    api = api_service(repo)
    gw = GatewayAuthenticator.new(SECRET, CLOCK)

    chain = KemalIdentity::AuthenticatorChain.new([
      api.as(KemalIdentity::RequestAuthenticator),
      gw.as(KemalIdentity::RequestAuthenticator),
      jwt_validator.as(KemalIdentity::RequestAuthenticator),
    ])

    chain.authenticators.size.should eq(3)
    chain.authenticators[1].should be(gw)
  end

  it "routes each credential family to its own authenticator" do
    repo = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)
    api = api_service(repo)
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    chain = KemalIdentity::AuthenticatorChain.new([
      api.as(KemalIdentity::RequestAuthenticator),
      gw.as(KemalIdentity::RequestAuthenticator),
      jwt_validator.as(KemalIdentity::RequestAuthenticator),
    ])

    issued = api.issue(account: KemalIdentity::Testing.account, name: "ci")

    # The shard's own token: answered by the first authenticator.
    chain.authenticate(issued.token.reveal).as(KemalIdentity::Authenticated).principal.subject.should eq("a1")

    # The gateway's token: the shard's authenticator says "not mine", the chain falls through.
    chain.authenticate(GatewayAuthenticator.mint(SECRET, "ada"))
      .as(KemalIdentity::Authenticated).principal.subject.should eq("ada")

    # A JWT: past both, to the third.
    jwt = KemalIdentity::Testing::JWTForge.encode(
      KemalIdentity::Testing::JWTForge.claims(subject: "jwt-subject")
    )
    chain.authenticate(jwt).as(KemalIdentity::Authenticated).principal.subject.should eq("jwt-subject")
  end

  it "stops the chain on a recognised rejection rather than seeking a second opinion" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    gw.revoke("ada")
    jwt = jwt_validator

    chain = KemalIdentity::AuthenticatorChain.new([
      gw.as(KemalIdentity::RequestAuthenticator),
      jwt.as(KemalIdentity::RequestAuthenticator),
    ])

    outcome = chain.authenticate(GatewayAuthenticator.mint(SECRET, "ada"))
    outcome.as(KemalIdentity::Failed).reason.revoked?.should be_true
  end

  it "is ordered deterministically: the first authenticator that recognises the shape answers" do
    gw = GatewayAuthenticator.new(SECRET, CLOCK)
    shadow = GatewayAuthenticator.new(SECRET, CLOCK)
    shadow.revoke("ada")

    KemalIdentity::AuthenticatorChain.new([
      gw.as(KemalIdentity::RequestAuthenticator), shadow.as(KemalIdentity::RequestAuthenticator),
    ]).authenticate(GatewayAuthenticator.mint(SECRET, "ada")).should be_a(KemalIdentity::Authenticated)

    KemalIdentity::AuthenticatorChain.new([
      shadow.as(KemalIdentity::RequestAuthenticator), gw.as(KemalIdentity::RequestAuthenticator),
    ]).authenticate(GatewayAuthenticator.mint(SECRET, "ada")).should be_a(KemalIdentity::Failed)
  end
end

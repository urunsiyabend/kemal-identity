require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# TOK-03: an extension wants "used by token X", a per-credential policy, a token id on an audit
# event, or safe metadata — after standard authentication, without touching the request header
# or the persistence layer again.

# The fourth pass condition: "custom authenticators can attach their own safe reference."
private class GatewayAuthenticator < KemalIdentity::RequestAuthenticator
  PREFIX = "gw_"

  def initialize(@clock : KemalIdentity::Clock)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    # Shape before anything else, and a shape that is not ours falls through the chain.
    unless credential.starts_with?(PREFIX) && credential.size == PREFIX.size + 12
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: "gateway-subject",
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: @clock.now,
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::Custom,
          id: credential.lchop(PREFIX),
          name: "corporate gateway",
        ),
      )
    )
  end
end

describe "TOK-03: the credential behind the request" do
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

  # Pass condition: "Credential kind and stable ID are available separately from the identity."
  it "reports a session credential separately from who it belongs to" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
    sessions = KemalIdentity::Sessions::Service.new(
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new,
    )

    issued = sessions.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    principal = sessions.resolve(issued.token.reveal).as(KemalIdentity::Authenticated).principal

    credential = principal.credential.or_fail
    credential.kind.should eq(KemalIdentity::CredentialKind::Session)
    credential.id.should eq(issued.record.id)
    principal.subject.should eq("a1")           # identity
    credential.id.should_not eq(principal.subject)  # ...and the credential, separately
  end

  # Pass condition: "session, opaque token and JWT credentials have an explicit representation."
  it "gives each credential family its own kind" do
    KemalIdentity::CredentialKind.names
      .should eq(%w[Session ApiToken Jwt Custom])
  end

  it "reports a JWT credential as Jwt, named by its jti" do
    key = KemalIdentity::JWT::Key.new(
      KemalIdentity::JWT::HS256, KemalIdentity::Secret.new("a" * 32)
    )
    validator = KemalIdentity::JWT::Validator.new(
      keyring: KemalIdentity::JWT::Keyring.new([key]),
      issuer: "https://issuer.example.com",
      audience: "consumer-app",
      algorithms: ["HS256"],
      clock: clock,
    )

    token = KemalIdentity::Testing::JWTForge.encode(
      KemalIdentity::Testing::JWTForge.claims(
        now: clock.now, subject: "a1", issuer: "https://issuer.example.com",
        audience: ::JSON::Any.new("consumer-app"), jti: "jti-77"
      ),
      KemalIdentity::Secret.new("a" * 32)
    )

    credential = validator.authenticate(token)
      .as(KemalIdentity::Authenticated).principal.credential.or_fail

    credential.kind.should eq(KemalIdentity::CredentialKind::Jwt)
    credential.id.should eq("jti-77")
  end

  # Pass condition: "raw secret and digest remain inaccessible."
  it "exposes no way to reach the secret or the digest" do
    credential = KemalIdentity::CredentialRef.new(
      kind: KemalIdentity::CredentialKind::ApiToken, id: "tok-1", name: "deploy"
    )

    credential.responds_to?(:secret).should be_false
    credential.responds_to?(:digest).should be_false
    credential.responds_to?(:token).should be_false
    credential.responds_to?(:reveal).should be_false

    # And nothing secret can reach an audit line through it.
    credential.to_s.should_not contain("secret")
  end

  it "lets a consumer's own authenticator attach its own reference" do
    chain = KemalIdentity::AuthenticatorChain.new(
      [GatewayAuthenticator.new(clock).as(KemalIdentity::RequestAuthenticator)]
    )

    credential = chain.authenticate("gw_abcdef123456")
      .as(KemalIdentity::Authenticated).principal.credential.or_fail

    credential.kind.should eq(KemalIdentity::CredentialKind::Custom)
    credential.id.should eq("abcdef123456")
    credential.name.should eq("corporate gateway")
  end
end

require "../spec_helper"
require "../../src/kemal_identity/kemal"

# A `RequestAuthenticator` an application wrote itself, configured through
# `bearer_authenticators:` — `blueprints/0025-maturity-validation-results.md`, TOK-04.
#
# The contract has always been implementable; what it had nowhere to go. `app.bearer` is not only
# what resolves the header, it is also what `ErrorHandler` asks before sending an RFC 6750
# challenge and what `CSRFHandler` asks before exempting a token-only request, so an application
# whose only bearer credential was its own silently lost both.

# The smallest thing that satisfies the contract: `gw.<subject>` is mine, anything else is not.
private class GatewayAuthenticator < KemalIdentity::RequestAuthenticator
  def initialize(@now : Time)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    unless credential.starts_with?("gw.")
      # The one reason `AuthenticatorChain` reads as "not mine, try the next".
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    subject = credential.lchop("gw.")
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential) if subject.empty?
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::Revoked) if subject == "revoked"

    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: subject,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: @now,
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::Custom, id: "gw-#{subject}", name: "api gateway"
        ),
      )
    )
  end
end

private def gateway_app(
  api_tokens : Bool = false,
  csrf : KemalIdentity::CSRFConfig? = nil,
) : KemalIdentity::Application
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])

  KemalIdentity::Application.new(
    accounts: accounts,
    sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
    hasher: KemalIdentity::Testing::FastTestHasher.new,
    clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: 4),
    cookie: KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", secure: false, allow_insecure: true
    ),
    api_tokens: api_tokens ? KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts) : nil,
    bearer_authenticators: [
      GatewayAuthenticator.new(KemalIdentity::Testing::FIXED_NOW).as(KemalIdentity::RequestAuthenticator),
    ],
    csrf: csrf,
  )
end

describe "a consumer-written bearer authenticator" do
  it "becomes the application's bearer authenticator when it is the only one" do
    app = gateway_app
    app.bearer.should be_a(GatewayAuthenticator)
  end

  it "resolves its own credential through the application" do
    outcome = gateway_app.bearer.or_fail("no bearer authenticator").authenticate("gw.ada")

    principal = outcome.as(KemalIdentity::Authenticated).principal
    principal.subject.should eq("ada")
    principal.credential.or_fail.kind.should eq(KemalIdentity::CredentialKind::Custom)
  end

  it "goes after the shipped authenticators, in a chain, when both are configured" do
    app = gateway_app(api_tokens: true)
    chain = app.bearer.as(KemalIdentity::AuthenticatorChain)

    chain.authenticators.size.should eq(2)
    chain.authenticators.first.should be_a(KemalIdentity::ApiTokens::Service)
    chain.authenticators.last.should be_a(GatewayAuthenticator)
  end

  # Position among the shipped authenticators changes no answer, because every family checks
  # shape exactly — measured across all three positions in `blueprints/0025`, TOK-04. What the
  # order does buy is that a loose shape check in a consumer's authenticator cannot shadow a
  # credential this shard issued.
  it "does not intercept a credential the shipped authenticators recognise" do
    app = gateway_app(api_tokens: true)
    issued = app.api.or_fail("no api token service")
      .issue(account: KemalIdentity::Testing.account, name: "ci")

    outcome = app.bearer.or_fail.authenticate(issued.token.reveal)
    principal = outcome.as(KemalIdentity::Authenticated).principal

    principal.credential.or_fail.kind.should eq(KemalIdentity::CredentialKind::ApiToken)
  end

  it "stops the chain when it recognises a credential and rejects it" do
    app = gateway_app(api_tokens: true)
    outcome = app.bearer.or_fail.authenticate("gw.revoked")

    outcome.as(KemalIdentity::Failed).reason.revoked?.should be_true
  end
end

# `ErrorHandler` and `CSRFHandler` both branch on `app.bearer`, so both are driven here rather
# than asserted about. A no-op successor: without one, `call_next` answers 404 through
# `respond_with_status`, which resets the response and takes the headers under assertion with it.
private def run_handler(handler : ::Kemal::Handler, request : HTTP::Request) : HTTP::Server::Context
  env = HTTP::Server::Context.new(request, HTTP::Server::Response.new(IO::Memory.new))
  handler.next = ->(_ctx : HTTP::Server::Context) { }
  handler.call(env)
  env
end

private def raising_handler(handler : ::Kemal::Handler, request : HTTP::Request, error : Exception) : HTTP::Server::Context
  env = HTTP::Server::Context.new(request, HTTP::Server::Response.new(IO::Memory.new))
  handler.next = ->(_ctx : HTTP::Server::Context) { raise error }
  handler.call(env)
  env
end

describe "the RFC 6750 challenge with only a consumer's authenticator configured" do
  it "is sent when a request presented nothing" do
    env = raising_handler(
      KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, app: gateway_app),
      HTTP::Request.new("GET", "/api/me"),
      KemalIdentity::NotAuthenticatedError.new("nope"),
    )

    env.response.status_code.should eq(401)
    env.response.headers["WWW-Authenticate"].should eq(%(Bearer realm="api"))
  end

  it "names invalid_token when a credential was presented and did not hold" do
    env = raising_handler(
      KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, app: gateway_app),
      HTTP::Request.new("GET", "/api/me", HTTP::Headers{"Authorization" => "Bearer gw.revoked"}),
      KemalIdentity::NotAuthenticatedError.new("nope"),
    )

    env.response.headers["WWW-Authenticate"].should eq(%(Bearer realm="api", error="invalid_token"))
  end
end

describe "the CSRF exemption with only a consumer's authenticator configured" do
  it "exempts a mutation carrying only that authenticator's credential" do
    config = KemalIdentity::CSRFConfig.new(
      secret: "test-signing-key-of-at-least-32-bytes", cookie_name: "csrf", secure: false
    )
    request = HTTP::Request.new(
      "POST", "/api/things", HTTP::Headers{"Authorization" => "Bearer gw.ada"}
    )

    # No raise, and the successor ran: the exemption applied.
    reached = false
    handler = KemalIdentity::Kemal::CSRFHandler.new(config, gateway_app(csrf: config))
    env = HTTP::Server::Context.new(request, HTTP::Server::Response.new(IO::Memory.new))
    handler.next = ->(_ctx : HTTP::Server::Context) { reached = true; nil }
    handler.call(env)

    reached.should be_true
  end

  it "still protects a mutation that also presents a session cookie" do
    config = KemalIdentity::CSRFConfig.new(
      secret: "test-signing-key-of-at-least-32-bytes", cookie_name: "csrf", secure: false
    )
    request = HTTP::Request.new(
      "POST", "/api/things", HTTP::Headers{
      "Authorization" => "Bearer gw.ada",
      "Cookie"        => "kemal_identity=whatever",
    }
    )

    # Authentication first, as in a real chain: `CSRFHandler` reads `env.auth` to find the
    # anchor a token is bound to, so driving it alone would measure the missing handler instead.
    app = gateway_app(csrf: config)
    authn = KemalIdentity::Kemal::AuthenticationHandler.new(app)
    csrf = KemalIdentity::Kemal::CSRFHandler.new(config, app)
    authn.next = csrf
    csrf.next = ->(_ctx : HTTP::Server::Context) { }

    expect_raises(KemalIdentity::CSRFError) do
      authn.call(HTTP::Server::Context.new(request, HTTP::Server::Response.new(IO::Memory.new)))
    end
  end
end

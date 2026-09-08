require "../spec_helper"
require "../../src/kemal_identity/kemal"

# `CSRFHandler` takes an `Application` so that a process can wire one without installing a
# process-global — the arrangement `AuthenticationHandler` and `ErrorHandler` already support.
# Every read inside the handler has to honour that injection, and one of them did not: the
# bearer check fell back to `KemalIdentity.app` whenever the injected application's `bearer` was
# nil, which is a legitimate configuration rather than a missing one. With no global installed
# that raised `ConfigurationError` on every unsafe request; with one installed it decided the
# exemption from a different application's bearer.
#
# Nothing here installs a global, which is the point: the suite never calls
# `KemalIdentity.app=`, so a handler that reaches for it fails these examples.

private def csrf_config : KemalIdentity::CSRFConfig
  KemalIdentity::CSRFConfig.new(
    secret: "test-signing-key-of-at-least-32-bytes", cookie_name: "csrf", secure: false
  )
end

# No `bearer_authenticators:`, no `api_tokens:`, no `jwt:` — so `app.bearer` is nil.
private def cookie_only_app(csrf : KemalIdentity::CSRFConfig? = nil) : KemalIdentity::Application
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])

  KemalIdentity::Application.new(
    accounts: accounts,
    sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
    hasher: KemalIdentity::Testing::FastTestHasher.new,
    clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: 7),
    cookie: KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", secure: false, allow_insecure: true
    ),
    csrf: csrf,
  )
end

# Authentication first, as in a real chain: `CSRFHandler` reads `env.auth` for the anchor a
# token is bound to, so driving it alone would measure the missing handler instead.
private def call_csrf(
  app : KemalIdentity::Application,
  request : HTTP::Request,
  csrf : KemalIdentity::Kemal::CSRFHandler,
) : Bool
  reached = false
  authn = KemalIdentity::Kemal::AuthenticationHandler.new(app)
  authn.next = csrf
  csrf.next = ->(_ctx : HTTP::Server::Context) { reached = true; nil }
  authn.call(HTTP::Server::Context.new(request, HTTP::Server::Response.new(IO::Memory.new)))
  reached
end

private def call_csrf(
  app : KemalIdentity::Application,
  config : KemalIdentity::CSRFConfig,
  request : HTTP::Request,
) : Bool
  call_csrf(app, request, KemalIdentity::Kemal::CSRFHandler.new(config, app))
end

describe "CSRFHandler with an injected application and no process-global" do
  it "rejects an unsafe request rather than raising that nothing is configured" do
    config = csrf_config
    app = cookie_only_app(csrf: config)

    expect_raises(KemalIdentity::CSRFError) do
      call_csrf(app, config, HTTP::Request.new("POST", "/things"))
    end
  end

  # The same request against an application that accepts no bearer credential: an
  # `Authorization` header cannot buy an exemption an application never configured.
  it "does not exempt a request carrying an Authorization header" do
    config = csrf_config
    app = cookie_only_app(csrf: config)
    request = HTTP::Request.new(
      "POST", "/api/things", HTTP::Headers{"Authorization" => "Bearer whatever"}
    )

    expect_raises(KemalIdentity::CSRFError) { call_csrf(app, config, request) }
  end

  it "lets a safe method through" do
    config = csrf_config
    app = cookie_only_app(csrf: config)

    call_csrf(app, config, HTTP::Request.new("GET", "/things")).should be_true
  end

  # The handler's own configuration is read from the injected application too.
  it "resolves its configuration from the injected application" do
    app = cookie_only_app(csrf: csrf_config)

    expect_raises(KemalIdentity::CSRFError) do
      call_csrf(
        app,
        HTTP::Request.new("POST", "/things"),
        KemalIdentity::Kemal::CSRFHandler.new(app: app),
      )
    end
  end
end

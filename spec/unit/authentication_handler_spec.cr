require "../spec_helper"
require "../../src/kemal_identity/kemal"

# `AuthenticationHandler` resolves credentials in an order, and the order is a policy: under the
# default, a session cookie that was presented and failed stops the resolution, so a stale
# cookie riding along with a good bearer token gets a 401 -- measured over HTTP in
# `blueprints/0025-maturity-validation-results.md` (HTTP-03). `Precedence::Bearer` is the option
# that reverses it.
#
# Driven by calling the handler, not through Kemal: Kemal's handler chain is process-global and
# already spoken for by `spec/integration/kemal_spec.cr`, and this is about two chains that
# differ in one constructor argument.
private HANDLER_PASSWORD = "correct horse battery"

private record HandlerHarness,
  app : KemalIdentity::Application,
  account : KemalIdentity::Accounts::Account,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  clock : KemalIdentity::Testing::TestClock

private def handler_harness : HandlerHarness
  hasher = KemalIdentity::Testing::FastTestHasher.new
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

  account = KemalIdentity::Testing.account(
    password_digest: hasher.hash_secret(KemalIdentity::Secret.new(HANDLER_PASSWORD))
  )
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([account])

  app = KemalIdentity::Application.new(
    accounts: accounts,
    sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
    hasher: hasher,
    clock: clock,
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: 7),
    # Plain names, and insecure allowed: these contexts are built by hand and never ride TLS.
    cookie: KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", secure: false, allow_insecure: true
    ),
    api_tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
    remember_tokens: KemalIdentity::Testing::MemoryRememberRepository.new,
    remember_cookie: KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity_remember", secure: false, allow_insecure: true
    ),
    notifier: KemalIdentity::Testing::RecordingNotifier.new,
  )

  HandlerHarness.new(app: app, account: account, accounts: accounts, clock: clock)
end

# Runs one request through the handler and hands back the context it authenticated.
private def run_handler(
  app : KemalIdentity::Application,
  precedence : KemalIdentity::Kemal::AuthenticationHandler::Precedence,
  cookies : Hash(String, String) = {} of String => String,
  bearer : String? = nil,
) : HTTP::Server::Context
  headers = HTTP::Headers.new
  headers["Authorization"] = "Bearer #{bearer}" if bearer
  headers["Cookie"] = cookies.map { |name, value| "#{name}=#{value}" }.join("; ") unless cookies.empty?

  env = HTTP::Server::Context.new(
    HTTP::Request.new("GET", "/api/me", headers),
    HTTP::Server::Response.new(IO::Memory.new)
  )

  handler = KemalIdentity::Kemal::AuthenticationHandler.new(app, precedence: precedence)
  # A no-op successor. Without one, `call_next` answers 404 through `respond_with_status`, which
  # resets the response -- and takes the `Set-Cookie` this handler just wrote with it.
  handler.next = ->(_ctx : HTTP::Server::Context) { }
  handler.call(env)
  env
end

private def api_token(harness : HandlerHarness) : String
  harness.app.api.or_fail("no api token service").issue(account: harness.account, name: "ci").token.reveal
end

private def session_cookie(harness : HandlerHarness) : String
  harness.app.sessions.start(
    harness.account, KemalIdentity::AssuranceLevel::Password
  ).token.reveal
end

private def remember_cookie(harness : HandlerHarness) : String
  harness.app.remember.or_fail("no remember service").remember(harness.account).token.reveal
end

describe KemalIdentity::Kemal::AuthenticationHandler do
  describe "the default, Precedence::Cookie" do
    it "resolves the session cookie" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Cookie,
        cookies: {"kemal_identity" => session_cookie(harness)},
      )

      env.auth.authenticated?.should be_true
      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::Session)
    end

    it "prefers the session cookie over a bearer token presented beside it" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Cookie,
        cookies: {"kemal_identity" => session_cookie(harness)},
        bearer: api_token(harness),
      )

      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::Session)
    end

    it "resolves a bearer token when no session cookie was presented" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Cookie,
        bearer: api_token(harness),
      )

      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::ApiToken)
    end

    # The behaviour `Precedence::Bearer` exists to change. Asserted rather than merely
    # documented, so that reversing the default would fail here and be a deliberate act.
    it "lets a failed session cookie mask a valid bearer token" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Cookie,
        cookies: {"kemal_identity" => "ki_" + "a" * 43},
        bearer: api_token(harness),
      )

      env.auth.authenticated?.should be_false
      env.auth.failed?.should be_true
    end
  end

  describe "Precedence::Bearer" do
    it "resolves a valid bearer token past a session cookie that failed" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity" => "ki_" + "a" * 43},
        bearer: api_token(harness),
      )

      env.auth.authenticated?.should be_true
      env.auth.require!.subject.should eq(harness.account.id)
      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::ApiToken)
    end

    it "prefers the bearer token over a session cookie that would also have resolved" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity" => session_cookie(harness)},
        bearer: api_token(harness),
      )

      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::ApiToken)
    end

    # A presented token decides the request. Falling through to the cookie would let a stale
    # session paper over a revoked token, which is the mirror image of the bug being fixed.
    it "does not fall back to the session cookie when the bearer token is unusable" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity" => session_cookie(harness)},
        bearer: "ki_" + "a" * 43,
      )

      env.auth.authenticated?.should be_false
    end

    it "resolves the session cookie when no Authorization header arrived" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity" => session_cookie(harness)},
      )

      env.auth.authenticated?.should be_true
      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::Session)
    end

    it "clears a session cookie that was presented and failed" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity" => "ki_" + "a" * 43},
      )

      env.auth.failed?.should be_true
      env.response.cookies["kemal_identity"].value.should be_empty
    end

    # The reason this is an option on the handler rather than a public `restore_remembered!`:
    # remember-me only restores on a request carrying no session cookie at all, and that
    # ordering survives the reversal.
    it "still restores a remembered login" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity_remember" => remember_cookie(harness)},
      )

      env.auth.authenticated?.should be_true
      env.auth.require!.subject.should eq(harness.account.id)
      env.auth.require!.assurance.should eq(KemalIdentity::AssuranceLevel::Remembered)
      # A restored login gets a session, and the browser is told about both cookies.
      env.response.cookies["kemal_identity"].value.should_not be_empty
      env.response.cookies["kemal_identity_remember"].value.should_not be_empty
    end

    it "does not restore a remembered login for a request presenting a bearer token" do
      harness = handler_harness
      env = run_handler(
        harness.app,
        KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer,
        cookies: {"kemal_identity_remember" => remember_cookie(harness)},
        bearer: api_token(harness),
      )

      env.auth.credential.or_fail("nothing proved the request").kind.should eq(KemalIdentity::CredentialKind::ApiToken)
      env.response.cookies["kemal_identity_remember"]?.should be_nil
    end
  end
end

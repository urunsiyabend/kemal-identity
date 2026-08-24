require "spec-kemal"
require "../spec_helper"
require "../../src/kemal_identity/kemal"

# The Kemal integration and CSRF blockers from docs/05-testing.md, driven through Kemal's real
# handler chain rather than by calling handlers directly -- spec-kemal links the actual chain
# in memory, so `HEAD` dispatch is Kemal's own and not a simulation of it.
#
# Kemal's route table and handler chain are process-global, so there is exactly one application
# under test and every HTTP spec lives in this file.
#
# No DATABASE_URL: the repositories are the in-memory doubles, which pass the same contract
# specs as PostgreSQL.

PASSWORD    = "correct horse battery"
CSRF_COOKIE = "kemal_identity_csrf"
TEST_HASHER = KemalIdentity::Testing::FastTestHasher.new
TEST_CLOCK  = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

ACCOUNTS = KemalIdentity::Testing::MemoryAccountRepository.new([
  KemalIdentity::SpecHelper.account(
    password_digest: TEST_HASHER.hash_secret(KemalIdentity::Secret.new(PASSWORD))
  ),
])
SESSIONS = KemalIdentity::Testing::MemorySessionRepository.new(ACCOUNTS)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: SESSIONS,
  hasher: TEST_HASHER,
  clock: TEST_CLOCK,
  random: KemalIdentity::Testing::DeterministicRandom.new,
  # Plain cookie names: spec-kemal issues http:// requests, and __Host- cookies would be
  # correct but untestable here. The __Host- defaults and their validation have their own
  # specs in spec/security/cookie_policy_spec.cr and spec/unit/csrf_spec.cr.
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: "test-signing-key-of-at-least-32-bytes",
    cookie_name: CSRF_COOKIE,
    secure: false,
    exempt_prefixes: ["/api/webhook"],
  ),
)

# ErrorHandler outermost, so it catches what a route or a guard raises. CSRFHandler after
# authentication, because the token binds to the session. Never at position 0.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
use KemalIdentity::Kemal::PathGuard.new(prefix: "/step-up", within: 5.minutes)

# spec-kemal links Kemal's real handler chain, but only once `Kemal.config.setup` has built it.
# Called here, after the `use` calls, rather than in a `before_each`: `Kemal.config.clear` wipes
# the custom handlers along with the built-ins, so resetting per example would unregister
# everything under test. `setup` is idempotent.
Kemal.config.env = "test"
Kemal.config.setup

# Every verb Kemal has a DSL for. There is deliberately **no** `head` route: Kemal has no
# `head` DSL because a HEAD request is served by the GET route, and that is exactly the
# arrangement the regression below is about.
{% for verb in %w[get post put patch delete options query] %}
  {{ verb.id }} "/public" do |env|
    env.auth.authenticated? ? "signed in as #{env.auth.require!.subject}" : "anonymous"
  end

  {{ verb.id }} "/admin/users" do |env|
    "admin ok"
  end
{% end %}

get "/administrators" do |env|
  "public lookalike"
end

get "/guarded-route" do |env|
  "hello #{env.auth.require!.subject}"
end

get "/step-up/email" do |env|
  "step-up ok"
end

# Whatever renders a form asks for the token here. Asking is also what mints the anonymous
# anchor cookie, so a request for a static asset never pays for one.
get "/csrf" do |env|
  env.auth.csrf_token
end

post "/login" do |env|
  result = KemalIdentity.app.passwords.authenticate(
    login: env.params.body["email"], password: env.params.body["password"]
  )

  case result
  in KemalIdentity::Authenticated
    env.auth.start!(result.principal)
    "logged in"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # One message for every reason. Branching here is the account oracle.
    env.status(401).text("Invalid email or password")
  end
end

post "/logout" do |env|
  env.auth.logout!
  "logged out"
end

get "/whoami" do |env|
  principal = env.auth.principal?
  principal.nil? ? "nobody" : principal.subject
end

# An endpoint declared to accept no session cookie. Exempting a path is a promise, not a
# convenience.
post "/api/webhook/stripe" do |env|
  "webhook ok"
end

private def cookie_of(response : HTTP::Client::Response, name : String) : String?
  HTTP::Cookies.from_server_headers(response.headers)[name]?.try(&.value)
end

private def session_cookie(response : HTTP::Client::Response) : String?
  cookie_of(response, "kemal_identity")
end

# A CSRF token plus whatever cookie it is anchored to.
#
# For an authenticated request the anchor is the session id, so there is no anchor cookie and
# `anchor` comes back empty -- the session cookie alone is what the token binds to.
private record Csrf, token : String, anchor : String

private def fetch_csrf(session : String? = nil) : Csrf
  headers = session.nil? ? HTTP::Headers.new : cookies("kemal_identity=#{session}")
  get "/csrf", headers: headers

  Csrf.new(token: response.body, anchor: cookie_of(response, CSRF_COOKIE) || "")
end

# Builds a Cookie header from an arbitrary list.
private def cookies(*pairs : String) : HTTP::Headers
  HTTP::Headers{"Cookie" => pairs.to_a.reject(&.empty?).join("; ")}
end

private def form(csrf : Csrf, session : String? = nil) : HTTP::Headers
  pairs = [] of String
  pairs << "kemal_identity=#{session}" if session
  pairs << "#{CSRF_COOKIE}=#{csrf.anchor}" unless csrf.anchor.empty?

  headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
  headers["Cookie"] = pairs.join("; ") unless pairs.empty?
  headers
end

# `presenting` supplies a cookie the client already holds, which is what distinguishes session
# fixation from ordinary multi-device use.
private def log_in(presenting : String? = nil) : String
  csrf = fetch_csrf(presenting)

  post "/login",
    body: "email=ada@example.com&password=#{PASSWORD}&_csrf=#{csrf.token}",
    headers: form(csrf, presenting)

  session_cookie(response).or_fail("login did not set a session cookie")
end

# Issues a request with an arbitrary method, including ones spec-kemal has no helper for.
private def request(method : String, path : String, headers : HTTP::Headers? = nil) : HTTP::Client::Response
  SpecKemal.process_request(HTTP::Request.new(method, path, headers))
end

describe "env.auth on an unauthenticated request" do
  it "is populated without raising" do
    get "/public"
    response.status_code.should eq(200)
    response.body.should eq("anonymous")
  end

  it "reports anonymous rather than failed when no cookie is present" do
    get "/whoami"
    response.status_code.should eq(200)
    response.body.should eq("nobody")
  end

  it "sets no cookie for a request that presented none and asked for no token" do
    get "/public"
    response.headers["Set-Cookie"]?.should be_nil
  end
end

describe "a garbage cookie" do
  # docs/05: "a malformed or garbage cookie yields anonymous plus a cleared cookie, not a 500"
  it "does not produce a 500" do
    get "/public", headers: cookies("kemal_identity=garbage")
    response.status_code.should eq(200)
    response.body.should eq("anonymous")
  end

  it "is cleared, so the browser stops sending it" do
    get "/public", headers: cookies("kemal_identity=garbage")
    response.headers["Set-Cookie"]?.should_not be_nil
    response.headers["Set-Cookie"].should contain("max-age=0")
  end

  it "does not authenticate anybody" do
    get "/whoami", headers: cookies("kemal_identity=garbage")
    response.body.should eq("nobody")
  end

  it "survives a value that is absurdly long or full of punctuation" do
    get "/public", headers: cookies("kemal_identity=" + "a" * 100_000)
    response.status_code.should eq(200)

    get "/public", headers: cookies("kemal_identity=!@$%^&*()")
    response.status_code.should eq(200)
  end
end

describe "logging in over HTTP" do
  it "sets a session cookie" do
    token = log_in
    token.should_not be_empty
    response.body.should eq("logged in")
  end

  it "authenticates the following request" do
    token = log_in
    get "/whoami", headers: cookies("kemal_identity=#{token}")
    response.body.should eq("a1")
  end

  it "renders a public page differently once signed in" do
    token = log_in
    get "/public", headers: cookies("kemal_identity=#{token}")
    response.body.should eq("signed in as a1")
  end

  it "rejects a wrong password with one generic message" do
    csrf = fetch_csrf
    post "/login", body: "email=ada@example.com&password=wrong&_csrf=#{csrf.token}",
      headers: form(csrf)
    response.status_code.should eq(401)
    response.body.should eq("Invalid email or password")
  end

  it "gives an unknown login the identical response" do
    csrf = fetch_csrf
    post "/login", body: "email=nobody@example.com&password=wrong&_csrf=#{csrf.token}",
      headers: form(csrf)
    response.status_code.should eq(401)
    response.body.should eq("Invalid email or password")
  end

  # The session fixation defence, at the HTTP level: an identifier the client held *before*
  # authenticating is worthless afterwards, so an attacker who plants one does not inherit the
  # victim's authenticated session.
  it "revokes the session the client presented while logging in" do
    planted = log_in
    replacement = log_in(presenting: planted)

    replacement.should_not eq(planted)

    get "/whoami", headers: cookies("kemal_identity=#{planted}")
    response.body.should eq("nobody")

    get "/whoami", headers: cookies("kemal_identity=#{replacement}")
    response.body.should eq("a1")
  end

  # Not the same thing, and deliberately not the same behaviour. Logging in from a second
  # device must not end the first device's session: docs/02-security-model.md supports several
  # live sessions per account, which is what "list my devices" and revoke_all_for_account are
  # for. Only the session actually presented is rotated.
  it "leaves another device's session alone" do
    first_device = log_in
    second_device = log_in

    first_device.should_not eq(second_device)

    get "/whoami", headers: cookies("kemal_identity=#{first_device}")
    response.body.should eq("a1")

    get "/whoami", headers: cookies("kemal_identity=#{second_device}")
    response.body.should eq("a1")
  end
end

describe "logging out" do
  it "clears the cookie" do
    token = log_in
    csrf = fetch_csrf(token)
    post "/logout", body: "_csrf=#{csrf.token}", headers: form(csrf, token)
    response.headers["Set-Cookie"].should contain("max-age=0")
  end

  it "makes the old cookie useless" do
    token = log_in
    csrf = fetch_csrf(token)
    post "/logout", body: "_csrf=#{csrf.token}", headers: form(csrf, token)

    get "/whoami", headers: cookies("kemal_identity=#{token}")
    response.body.should eq("nobody")
  end
end

# THE regression. On Kemal 1.10.0 - 1.12.0, `HEAD /admin/users` skipped a `before_get`
# authentication filter while still running the protected handler and returning its headers,
# leaving no audit record (GHSA-jf9q-62h3-924j). 1.13.0 fixes it; 1.10.0 is the floor, so the
# guard matches on the path alone for every method and this spec proves it.
#
# QUERY is in the set because Kemal 1.13.0 added it: a guard with a method allowlist would have
# silently not covered a method that did not exist when it was written.
describe "PathGuard runs for every method" do
  %w[GET HEAD OPTIONS QUERY].each do |method|
    it "rejects an unauthenticated #{method}" do
      request(method, "/admin/users").status_code.should eq(302)
    end

    it "allows an authenticated #{method}" do
      token = log_in
      request(method, "/admin/users", cookies("kemal_identity=#{token}")).status_code.should eq(200)
    end
  end

  # The unsafe methods reach CSRFHandler first, which sits ahead of the guard, so an
  # unauthenticated request without a token is refused as a forgery rather than as
  # unauthenticated. With a valid token it reaches the guard and is refused there.
  %w[POST PUT PATCH DELETE].each do |method|
    it "refuses an unauthenticated #{method} carrying no token" do
      request(method, "/admin/users").status_code.should eq(403)
    end

    it "refuses an unauthenticated #{method} at the guard once it carries a token" do
      csrf = fetch_csrf
      headers = cookies("#{CSRF_COOKIE}=#{csrf.anchor}")
      headers["X-CSRF-Token"] = csrf.token

      request(method, "/admin/users", headers).status_code.should eq(302)
    end

    it "allows an authenticated #{method} carrying a token" do
      token = log_in
      csrf = fetch_csrf(token)
      headers = cookies("kemal_identity=#{token}")
      headers["X-CSRF-Token"] = csrf.token

      request(method, "/admin/users", headers).status_code.should eq(200)
    end
  end

  it "refuses a method nobody thought about as a forgery, since it is not named safe" do
    request("PROPFIND", "/admin/users").status_code.should eq(403)
  end

  # A naive starts_with? would hand an attacker an unguarded path that looks guarded.
  it "does not guard a path that merely shares the prefix" do
    get "/administrators"
    response.status_code.should eq(200)
    response.body.should eq("public lookalike")
  end

  it "guards the subtree root itself" do
    request("GET", "/admin").status_code.should eq(302)
  end
end

describe "route-level require!" do
  it "rejects an anonymous request" do
    get "/guarded-route"
    response.status_code.should eq(302)
  end

  it "allows an authenticated one and yields the principal" do
    token = log_in
    get "/guarded-route", headers: cookies("kemal_identity=#{token}")
    response.body.should eq("hello a1")
  end
end

describe "CSRF protection" do
  it "rejects a cookie-authenticated POST with no token" do
    token = log_in
    request("POST", "/admin/users", cookies("kemal_identity=#{token}")).status_code.should eq(403)
  end

  it "accepts the same POST with a valid token" do
    token = log_in
    csrf = fetch_csrf(token)
    headers = cookies("kemal_identity=#{token}")
    headers["X-CSRF-Token"] = csrf.token

    request("POST", "/admin/users", headers).status_code.should eq(200)
  end

  it "accepts a token in the form body as well as the header" do
    token = log_in
    csrf = fetch_csrf(token)

    post "/logout", body: "_csrf=#{csrf.token}", headers: form(csrf, token)
    response.status_code.should eq(200)
  end

  # docs/05 blocker: a token from another session is rejected. The token is an HMAC over the
  # session id, so one minted for another session cannot verify here.
  it "rejects a token minted for another session" do
    other = log_in
    other_csrf = fetch_csrf(other)

    mine = log_in
    headers = cookies("kemal_identity=#{mine}")
    headers["X-CSRF-Token"] = other_csrf.token

    request("POST", "/admin/users", headers).status_code.should eq(403)
  end

  it "rejects a token whose anchor cookie is missing" do
    csrf = fetch_csrf
    headers = HTTP::Headers{"X-CSRF-Token" => csrf.token}

    request("POST", "/logout", headers).status_code.should eq(403)
  end

  it "rejects a forged token" do
    token = log_in
    headers = cookies("kemal_identity=#{token}")
    headers["X-CSRF-Token"] = "a" * KemalIdentity::CSRF::TOKEN_LENGTH

    request("POST", "/admin/users", headers).status_code.should eq(403)
  end

  it "leaves safe methods alone" do
    token = log_in
    session = cookies("kemal_identity=#{token}")

    %w[GET HEAD OPTIONS].each do |method|
      request(method, "/public", session).status_code.should eq(200)
    end
  end

  # RFC 10008 defines QUERY as safe and idempotent. Its request body makes it look like a
  # mutation; it is not one, and treating it as one would break a legitimate read.
  it "does not treat a QUERY body as a mutation" do
    token = log_in
    request("QUERY", "/public", cookies("kemal_identity=#{token}")).status_code.should eq(200)
  end

  it "honours an exempt prefix" do
    request("POST", "/api/webhook/stripe").status_code.should eq(200)
  end

  it "returns 403 rather than redirecting, since the session is fine" do
    token = log_in
    result = request("POST", "/admin/users", cookies("kemal_identity=#{token}"))

    result.status_code.should eq(403)
    result.headers["Location"]?.should be_nil
    result.body.should contain("CSRF")
  end

  # docs/02-security-model.md calls this "the case most implementations miss": without a token
  # on the login form, an attacker logs the victim into the *attacker's* account and then
  # watches whatever the victim does under it.
  describe "the login form itself" do
    it "is protected" do
      headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
      post "/login", body: "email=ada@example.com&password=#{PASSWORD}", headers: headers

      response.status_code.should eq(403)
      response.headers["Set-Cookie"]?.to_s.should_not contain("kemal_identity=")
    end

    it "rejects a login whose token was minted against a different anchor" do
      attacker = fetch_csrf
      victim = fetch_csrf

      # The victim's browser sends the victim's anchor with the attacker's token.
      headers = HTTP::Headers{"Content-Type" => "application/x-www-form-urlencoded"}
      headers["Cookie"] = "#{CSRF_COOKIE}=#{victim.anchor}"

      post "/login",
        body: "email=ada@example.com&password=#{PASSWORD}&_csrf=#{attacker.token}",
        headers: headers

      response.status_code.should eq(403)
    end

    it "accepts a login whose token matches its anchor" do
      log_in.should_not be_empty
      response.body.should eq("logged in")
    end
  end
end

describe "the CSRF token endpoint" do
  it "mints an anchor cookie for an anonymous visitor" do
    get "/csrf"
    cookie_of(response, CSRF_COOKIE).should_not be_nil
    response.body.size.should eq(KemalIdentity::CSRF::TOKEN_LENGTH)
  end

  it "needs no anchor cookie once there is a session to bind to" do
    token = log_in
    get "/csrf", headers: cookies("kemal_identity=#{token}")

    cookie_of(response, CSRF_COOKIE).should be_nil
    response.body.size.should eq(KemalIdentity::CSRF::TOKEN_LENGTH)
  end

  # The mask: a token repeated in every response is what a compression oracle extracts.
  it "returns a different token each time for the same session" do
    token = log_in
    session = cookies("kemal_identity=#{token}")

    first = (get "/csrf", headers: session; response.body)
    second = (get "/csrf", headers: session; response.body)

    first.should_not eq(second)
  end
end

describe "ErrorHandler" do
  it "maps NotAuthenticatedError to 401 for a JSON client" do
    get "/guarded-route", headers: HTTP::Headers{"Accept" => "application/json"}
    response.status_code.should eq(401)
    response.body.should contain("authentication required")
  end

  it "honours X-Requested-With as well as Accept" do
    get "/guarded-route", headers: HTTP::Headers{"X-Requested-With" => "XMLHttpRequest"}
    response.status_code.should eq(401)
  end

  it "redirects a browser to the login page instead" do
    get "/guarded-route"
    response.status_code.should eq(302)
    response.headers["Location"].should eq("/login")
  end

  it "carries no return_to parameter, which would be an open redirect to get wrong" do
    get "/guarded-route"
    response.headers["Location"].should_not contain("return_to")
  end

  it "maps FreshAuthenticationRequiredError to 403, never a redirect" do
    token = log_in
    TEST_CLOCK.advance(10.minutes)

    get "/step-up/email", headers: cookies("kemal_identity=#{token}")
    response.status_code.should eq(403)
    response.body.should contain("fresh authentication")

    TEST_CLOCK.travel_to(KemalIdentity::SpecHelper::FIXED_NOW)
  end

  it "allows a step-up route while the authentication is still fresh" do
    token = log_in
    get "/step-up/email", headers: cookies("kemal_identity=#{token}")
    response.status_code.should eq(200)
    response.body.should eq("step-up ok")
  end

  it "leaks nothing about why authentication failed" do
    get "/guarded-route", headers: HTTP::Headers{"Accept" => "application/json"}
    body = response.body
    body.should_not contain("a1")
    body.should_not contain("ada@example.com")
    body.should_not contain("Revoked")
    body.should_not contain("InvalidCredential")
  end
end

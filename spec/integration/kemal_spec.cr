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
TEST_CLOCK  = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

ACCOUNTS = KemalIdentity::Testing::MemoryAccountRepository.new([
  KemalIdentity::Testing.account(
    password_digest: TEST_HASHER.hash_secret(KemalIdentity::Secret.new(PASSWORD))
  ),
])
SESSIONS        = KemalIdentity::Testing::MemorySessionRepository.new(ACCOUNTS)
ACTION_TOKENS   = KemalIdentity::Testing::MemoryActionTokenRepository.new
API_TOKENS      = KemalIdentity::Testing::MemoryApiTokenRepository.new(ACCOUNTS)
REMEMBER        = KemalIdentity::Testing::MemoryRememberRepository.new
NOTIFIER        = KemalIdentity::Testing::RecordingNotifier.new
REMEMBER_COOKIE = "kemal_identity_remember"
# Stands in for whatever the old system's cookie was. Its value is the subject, because the
# extractor block is the application's and this one is as simple as it gets.
LEGACY_COOKIE = "old_app_session"
MFA_FACTORS   = KemalIdentity::Testing::MemoryMfaRepository.new

# JWT validation is off by default; this application turns it on so that the chain behind one
# `Authorization: Bearer` header — opaque token first, JWT second — is exercised over HTTP.
JWT_VALIDATOR = KemalIdentity::JWT::Validator.new(
  keyring: KemalIdentity::JWT::Keyring.new(
    KemalIdentity::JWT::HS256, KemalIdentity::Testing::JWTForge::SECRET
  ),
  issuer: KemalIdentity::Testing::JWTForge::ISSUER,
  audience: KemalIdentity::Testing::JWTForge::AUDIENCE,
  algorithms: ["HS256"],
  clock: TEST_CLOCK,
)

AUTHZ_STORE = KemalIdentity::Testing::MemoryAuthzRepository.new

# Roles are code, assignments are data: the catalog is built here, and every example that needs
# a grant writes one row.
AUTHORIZER = KemalIdentity::Authz::RBAC.new(
  catalog: KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new([
      KemalIdentity::Authz::Permission.new("invoices.read"),
      KemalIdentity::Authz::Permission.new(
        "invoices.refund", minimum_assurance: KemalIdentity::AssuranceLevel::MFA
      ),
      # Declared at `ApiToken` assurance: a permission automation is allowed to reach at all.
      # The default is `Password`, which no token reaches however wide its scopes.
      KemalIdentity::Authz::Permission.new(
        "reports.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
      KemalIdentity::Authz::Permission.new(
        "reports.export", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
    ]),
    [
      KemalIdentity::Authz::Role.new("reader", ["invoices.read"]),
      KemalIdentity::Authz::Role.new(
        "finance", ["invoices.read", "invoices.refund", "reports.read", "reports.export"]
      ),
    ]
  ),
  store: AUTHZ_STORE,
  clock: TEST_CLOCK,
  random: KemalIdentity::Testing::DeterministicRandom.new(seed: 3),
)

# What an application with ownership rules actually writes: the shipped RBAC decides whether the
# account holds the permission at all, and this adds the per-object question on top. It is
# installed as *the* authorizer, so `env.auth.authorize!` reaches it — which is the whole point
# of `blueprints/0022`: before it, a route needing this had to bypass `env.auth` and lose the
# audit line, the step-up mapping and the uniform 403 with it.
class OwnershipAuthorizer < KemalIdentity::Authz::Authorizer
  def initialize(@inner : KemalIdentity::Authz::Authorizer)
  end

  def decide(
    principal : KemalIdentity::Principal,
    permission : String,
    context : KemalIdentity::Authz::Context,
  ) : KemalIdentity::Authz::Decision
    # The account's grant first. A resource rule can only ever narrow.
    decision = @inner.decide(principal, permission, context)
    return decision unless decision.permitted?

    resource = context.resource
    return decision if resource.nil?

    owner = resource.as?(KemalIdentity::Authz::Resource).try(&.["owner_id"])

    if owner && owner != principal.subject
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: "not_the_owner", tenant_id: context.tenant_id
      )
    end

    # An environment rule, to prove attributes arrive too — and one that asks for step-up under
    # its own name rather than borrowing InsufficientAssurance.
    if context["device"] == "unrecognised"
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: "unrecognised_device", step_up: true, tenant_id: context.tenant_id
      )
    end

    decision
  end
end

OWNERSHIP_AUTHORIZER = OwnershipAuthorizer.new(AUTHORIZER)

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
  action_tokens: ACTION_TOKENS,
  api_tokens: API_TOKENS,
  jwt: JWT_VALIDATOR,
  authorizer: OWNERSHIP_AUTHORIZER,
  mfa_factors: MFA_FACTORS,
  mfa_secret_key: KemalIdentity::Secret.new("mfa-secret-box-key-of-32-bytes!!"),
  mfa_issuer: "Acme",
  remember_tokens: REMEMBER,
  notifier: NOTIFIER,
  remember_cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: REMEMBER_COOKIE, secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: "test-signing-key-of-at-least-32-bytes",
    cookie_name: CSRF_COOKIE,
    secure: false,
    exempt_prefixes: ["/api/webhook"],
  ),
)

# Somebody the old system still has a session for and this one has disabled.
ACCOUNTS.insert(KemalIdentity::Testing.account(
  id: "a-disabled", login: "banned@example.com", disabled_at: KemalIdentity::Testing::FIXED_NOW
))

# A second live account, so "the old cookie does not override a live session" can name somebody
# the legacy path would otherwise happily adopt.
ACCOUNTS.insert(KemalIdentity::Testing.account(id: "a2", login: "grace@example.com"))

# ErrorHandler outermost, so it catches what a route or a guard raises. CSRFHandler after
# authentication, because the token binds to the session. Never at position 0.
# `api_prefixes:` so that /api answers rather than redirecting, whatever the client sent in
# `Accept` — the mixed monolith HTTP-02 describes, where the same process serves pages and an
# API and the redirect decision cannot be one setting for both.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login", api_prefixes: ["/api"])
use KemalIdentity::Kemal::AuthenticationHandler.new
# The migration seam: temporary, registered after authentication so it sees only requests that
# no live credential resolved, and ahead of CSRF so a token binds to the session it adopted.
# Built first and then passed to `use`: Kemal's `use` is a macro, so a block written after
# `use Handler.new(...)` attaches to `use` rather than to the constructor.
LEGACY_HANDLER = KemalIdentity::Kemal::LegacySessionHandler.new(clear_cookie: LEGACY_COOKIE) do |env|
  env.request.cookies[LEGACY_COOKIE]?.try(&.value)
end

use LEGACY_HANDLER
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
use KemalIdentity::Kemal::PathGuard.new(prefix: "/step-up", within: 5.minutes)

# Credential classes per subtree: /pages is for browsers, /api/strict is for API clients, and
# neither accepts the other's credential. HTTP-02.
use KemalIdentity::Kemal::PathGuard.new(
  prefix: "/pages", credentials: [KemalIdentity::CredentialKind::Session]
)
use KemalIdentity::Kemal::PathGuard.new(
  prefix: "/api/strict", credentials: [KemalIdentity::CredentialKind::ApiToken]
)

# spec-kemal links Kemal's real handler chain, but only once `Kemal.config.setup` has built it.
# Called here, after the `use` calls, rather than in a `before_each`: `Kemal.config.clear` wipes
# the custom handlers along with the built-ins, so resetting per example would unregister
# everything under test. `setup` is idempotent.
Kemal.config.env = "test"
Kemal.config.setup

# Every verb Kemal has a DSL for. There is deliberately **no** `head` route: Kemal has no
# `head` DSL because a HEAD request is served by the GET route, and that is exactly the
# arrangement the regression below is about.
#
# `query` arrived in Kemal 1.13.0 and the supported floor is lower, so the QUERY routes and the
# QUERY assertions are compiled only where the method exists. Pinning the floor to 1.13 for the
# sake of a test would be a floor invented by the test suite rather than measured from the
# library.
#
# The check asks Kemal's own `HTTP_METHODS` whether it has the verb, rather than comparing
# version strings: it is the feature that matters, and `Kemal::VERSION` is a macro expression
# that `compare_versions` cannot read at this point anyway.
KEMAL_HAS_QUERY = {{ HTTP_METHODS.includes?("query") }}

{% for verb in %w[get post put patch delete options] %}
  {{ verb.id }} "/public" do |env|
    env.auth.authenticated? ? "signed in as #{env.auth.require!.subject}" : "anonymous"
  end

  {{ verb.id }} "/admin/users" do |env|
    "admin ok"
  end
{% end %}

{% if HTTP_METHODS.includes?("query") %}
  query "/public" do |env|
    env.auth.authenticated? ? "signed in as #{env.auth.require!.subject}" : "anonymous"
  end

  query "/admin/users" do |env|
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

get "/pages/dashboard" do |env|
  "dashboard for #{env.auth.require!.subject}"
end

get "/api/strict/items" do |env|
  "items for #{env.auth.require!.subject}"
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

post "/login-remembered" do |env|
  result = KemalIdentity.app.passwords.authenticate(
    login: env.params.body["email"], password: env.params.body["password"]
  )

  case result
  in KemalIdentity::Authenticated
    env.auth.start!(result.principal)
    # Only ever after a real authentication.
    env.auth.remember!
    "remembered"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    env.status(401).text("Invalid email or password")
  end
end

# The second-factor step of a login. The person already has a Password session; proving a
# factor rotates it up to MFA.
post "/mfa/verify" do |env|
  principal = env.auth.require!

  case KemalIdentity.app.mfa!.verify(principal.subject, env.params.body["code"])
  in KemalIdentity::MFA::Verified
    env.auth.mfa_verified!
    "mfa ok"
  in KemalIdentity::Failed
    # One message for every reason, as everywhere else.
    env.status(401).text("Invalid code")
  end
end

# Reachable only once a second factor has been proved.
get "/vault" do |env|
  env.auth.require_assurance!(KemalIdentity::AssuranceLevel::MFA)
  "vault ok"
end

post "/logout" do |env|
  env.auth.logout!
  "logged out"
end

# An endpoint an API client reaches with a bearer token. Guarded like any other route.
get "/api/me" do |env|
  principal = env.auth.require!
  "#{principal.subject} via #{principal.assurance}"
end

post "/api/things" do |env|
  "created"
end

# Authorization guards the action, at the point of action, with the permission it is about to
# perform.
get "/invoices" do |env|
  env.auth.authorize!("invoices.read")
  "invoices ok"
end

get "/tenants/:tenant/invoices" do |env|
  env.auth.authorize!("invoices.read", tenant: env.params.url["tenant"])
  "tenant invoices ok"
end

# GET rather than POST only so the example need not carry a CSRF token; the permission is what
# is under test.
get "/invoices/refund" do |env|
  env.auth.authorize!("invoices.refund")
  "refunded"
end

# The resource-aware route. `invoice-1` belongs to the signed-in account; `invoice-2` does not.
get "/invoices/:id" do |env|
  env.auth.authorize!(
    "invoices.read",
    resource: KemalIdentity::Authz::Resource.new(
      "invoice", env.params.url["id"],
      {"owner_id" => env.params.url["id"] == "invoice-1" ? "a1" : "someone-else"}
    ),
  )
  "invoice ok"
end

# Environment attributes, and a custom denial that asks for step-up under its own name.
get "/invoices/export/:device" do |env|
  env.auth.authorize!(
    "invoices.read",
    resource: KemalIdentity::Authz::Resource.new("invoice", "invoice-1", {"owner_id" => "a1"}),
    attributes: {"device" => env.params.url["device"]},
  )
  "exported"
end

# Two permissions a token may hold. The scope decides which of them *this* token reaches.
get "/reports" do |env|
  env.auth.authorize!("reports.read")
  "report"
end

get "/reports/export" do |env|
  env.auth.authorize!("reports.export")
  "exported"
end

# What a template does: `can?` decides whether to render the button, `authorize!` guards the
# action behind it.
get "/invoices/menu" do |env|
  env.auth.can?("invoices.read") ? "show" : "hide"
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
  safe_methods = KEMAL_HAS_QUERY ? %w[GET HEAD OPTIONS QUERY] : %w[GET HEAD OPTIONS]

  safe_methods.each do |method|
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
    next unless KEMAL_HAS_QUERY

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

    TEST_CLOCK.travel_to(KemalIdentity::Testing::FIXED_NOW)
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

# Remember-me, end to end through the handler chain. The interesting part is that
# AuthenticationHandler restores the login on a request carrying no session cookie at all, so
# none of this needs an explicit call from a route.
private def remembered_cookie(response : HTTP::Client::Response) : String?
  cookie_of(response, REMEMBER_COOKIE)
end

private def log_in_remembered : String
  csrf = fetch_csrf

  post "/login-remembered",
    body: "email=ada@example.com&password=#{PASSWORD}&_csrf=#{csrf.token}",
    headers: form(csrf)

  remembered_cookie(response).or_fail("login did not set a remember cookie")
end

# Logs out a browser holding both cookies.
#
# The CSRF token goes in the header rather than the body. An earlier version of the two logout
# examples posted it as a form field *without* a Content-Type, so the body never parsed, the
# request was refused as a forgery, and the route under test never ran -- the examples passed
# while asserting nothing. Hence the explicit status assertion.
private def log_out_remembered(remember : String) : Nil
  session = cookie_of(response, "kemal_identity").or_fail
  csrf = fetch_csrf(session)

  headers = cookies("kemal_identity=#{session}", "#{REMEMBER_COOKIE}=#{remember}")
  headers["X-CSRF-Token"] = csrf.token

  request("POST", "/logout", headers).status_code.should eq(200)
end

describe "remember-me over HTTP" do
  it "sets a remember cookie alongside the session" do
    token = log_in_remembered
    token.should_not be_empty
    response.body.should eq("remembered")
  end

  it "gives the remember cookie a max-age, so it survives the browser closing" do
    log_in_remembered
    header = response.headers.get("Set-Cookie").find(&.starts_with?(REMEMBER_COOKIE)).or_fail
    header.should contain("max-age=")
  end

  # The session cookie is deliberately *not* persistent: the server-side row decides when a
  # session ends, and only the remember cookie is meant to outlive the browser.
  it "leaves the session cookie non-persistent" do
    log_in_remembered
    session = response.headers.get("Set-Cookie").find(&.starts_with?("kemal_identity=")).or_fail
    session.should_not contain("max-age=")
  end

  it "restores the login on a request carrying only the remember cookie" do
    remember = log_in_remembered

    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
    response.body.should eq("a1")
  end

  it "issues a fresh session cookie while restoring" do
    remember = log_in_remembered

    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
    cookie_of(response, "kemal_identity").should_not be_nil
  end

  # Rotation: the browser must be handed the successor in the same response, or its next visit
  # presents a token the server has already spent and is reported as a replay.
  it "rotates the remember cookie on every restore" do
    first = log_in_remembered

    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")
    second = remembered_cookie(response).or_fail

    second.should_not eq(first)

    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{second}")
    response.body.should eq("a1")
  end

  # A restored session is weaker than a password login, and the step-up guard enforces it.
  it "restores at Remembered assurance, which no step-up route accepts" do
    remember = log_in_remembered

    get "/step-up/email", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
    response.status_code.should eq(403)
  end

  it "still satisfies an ordinary guard" do
    remember = log_in_remembered

    get "/guarded-route", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
    response.status_code.should eq(200)
    response.body.should eq("hello a1")
  end

  describe "when a spent cookie comes back" do
    it "signs the browser out rather than restoring it" do
      first = log_in_remembered

      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")
      response.body.should eq("a1")

      # The stolen copy: the same token, presented after it was already spent.
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")
      response.body.should eq("nobody")
    end

    it "clears both cookies" do
      first = log_in_remembered
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")

      NOTIFIER.clear
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")

      response.headers.get("Set-Cookie").count(&.includes?("max-age=0")).should be >= 1
    end

    it "tells the account holder" do
      first = log_in_remembered
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")

      NOTIFIER.clear
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{first}")

      NOTIFIER.replays.size.should eq(1)
    end
  end

  # Pressing "log out" must not look like theft.
  describe "logging out" do
    it "clears the remember cookie" do
      remember = log_in_remembered
      log_out_remembered(remember)

      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
      response.body.should eq("nobody")
    end

    it "does not report the logged-out cookie as a replay" do
      remember = log_in_remembered
      log_out_remembered(remember)

      NOTIFIER.clear
      get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")

      # Revoked, not spent. Telling somebody their cookie may have been stolen because they
      # pressed "log out" would train them to ignore the warning that matters.
      NOTIFIER.replays.should be_empty
    end
  end

  it "ignores a garbage remember cookie without raising" do
    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=garbage")
    response.status_code.should eq(200)
    response.body.should eq("nobody")
  end

  # A live session takes precedence: restoring only from a request with no session cookie is
  # what keeps logout unambiguous and narrows the parallel-request window.
  it "does not restore when a valid session cookie is already present" do
    remember = log_in_remembered
    session = cookie_of(response, "kemal_identity").or_fail

    get "/whoami", headers: cookies("kemal_identity=#{session}", "#{REMEMBER_COOKIE}=#{remember}")
    response.body.should eq("a1")

    # The remember token was not spent, so it still works on its own.
    get "/whoami", headers: cookies("#{REMEMBER_COOKIE}=#{remember}")
    response.body.should eq("a1")
  end
end

# Bearer tokens over HTTP. `docs/06-roadmap.md`'s v0.4: opaque personal access tokens as a
# `RequestAuthenticator`, reaching the same guards a session does.
# Returns the whole `Issued`, not just the secret. Looking the token up again by listing would
# be unreliable: the spec clock is frozen, so every token shares a `created_at` and the ordering
# falls back to ids that do not sort by creation order.
private def issue_api_token(name : String = "ci") : KemalIdentity::ApiTokens::Issued
  KemalIdentity.app.api!.issue(ACCOUNTS.find_by_id("a1").or_fail, name)
end

private def issue_scoped_token(scopes : Array(String)?) : KemalIdentity::ApiTokens::Issued
  KemalIdentity.app.api!.issue(ACCOUNTS.find_by_id("a1").or_fail, "scoped", scopes: scopes)
end

private def challenge_header : String?
  response.headers["WWW-Authenticate"]?
end

private def bearer(token : String) : HTTP::Headers
  HTTP::Headers{"Authorization" => "Bearer #{token}"}
end

describe "bearer tokens over HTTP" do
  it "authenticates a request carrying only an Authorization header" do
    token = issue_api_token.token.reveal

    get "/api/me", headers: bearer(token)
    response.status_code.should eq(200)
    response.body.should eq("a1 via ApiToken")
  end

  it "satisfies an ordinary guard" do
    token = issue_api_token.token.reveal

    request("GET", "/admin/users", bearer(token)).status_code.should eq(200)
  end

  # An automated client cannot re-authenticate interactively, so a destructive action should not
  # be reachable with a token in the first place.
  it "never satisfies a step-up guard, however fresh" do
    token = issue_api_token.token.reveal

    get "/step-up/email", headers: bearer(token)
    response.status_code.should eq(403)
  end

  it "sets no session cookie: a token establishes nothing" do
    token = issue_api_token.token.reveal

    get "/api/me", headers: bearer(token)
    cookie_of(response, "kemal_identity").should be_nil
  end

  it "matches the scheme case-insensitively, as RFC 7235 requires" do
    token = issue_api_token.token.reveal

    ["Bearer", "bearer", "BEARER"].each do |scheme|
      request("GET", "/api/me", HTTP::Headers{"Authorization" => "#{scheme} #{token}"})
        .status_code.should eq(200)
    end
  end

  # The whole reason opaque tokens come before JWT: validity is read from storage, so revocation
  # lands on the next request rather than at some future `exp`.
  it "rejects a revoked token on the very next request" do
    issued = issue_api_token

    get "/api/me", headers: bearer(issued.token.reveal)
    response.status_code.should eq(200)

    KemalIdentity.app.api!.revoke(issued.record.id)

    # 401, not a redirect: a request that presented a bearer credential is an API client
    # saying so, whatever it sent in `Accept`.
    request("GET", "/api/me", bearer(issued.token.reveal)).status_code.should eq(401)
  end

  it "rejects garbage without raising" do
    ["", "ki_garbage", "not-a-token", "ki_" + "a" * 43].each do |candidate|
      request("GET", "/api/me", HTTP::Headers{"Authorization" => "Bearer #{candidate}"})
        .status_code.should_not eq(200)
    end
  end

  # A client that sent a token is asking to be authenticated by it. Falling through to a cookie
  # after a rejected token would let a stale credential mask a revoked one.
  it "does not fall back to a session cookie when the token was rejected" do
    session = log_in
    headers = cookies("kemal_identity=#{session}")

    get "/whoami", headers: headers
    response.body.should eq("a1")

    with_bad_token = cookies("kemal_identity=#{session}")
    with_bad_token["Authorization"] = "Bearer ki_" + "a" * 43

    # The session cookie resolves first, so this request is still the browser's. The point of
    # the assertion is the reverse case below.
    request("GET", "/whoami", with_bad_token).status_code.should eq(200)

    only_bad_token = HTTP::Headers{"Authorization" => "Bearer ki_" + "a" * 43}
    request("GET", "/whoami", only_bad_token).body.should eq("nobody")
  end
end

# docs/02-security-model.md: "the exemption applies only to endpoints that accept *nothing but*
# an Authorization header."
describe "CSRF and bearer tokens" do
  it "exempts a request carrying only a bearer token" do
    token = issue_api_token.token.reveal

    request("POST", "/api/things", bearer(token)).status_code.should eq(200)
  end

  it "still protects a request that also carries a session cookie" do
    session = log_in
    token = issue_api_token.token.reveal

    headers = cookies("kemal_identity=#{session}")
    headers["Authorization"] = "Bearer #{token}"

    # The cookie alone would authenticate this, so an attacker who can trigger it cross-site
    # does not need the token at all. Exempting it would hand back exactly what CSRF prevents.
    request("POST", "/api/things", headers).status_code.should eq(403)
  end

  # A request carrying an expired cookie still carries a cookie. Exempting it would let one
  # expire its way out of CSRF protection.
  it "still protects a request whose session cookie is merely invalid" do
    token = issue_api_token.token.reveal

    headers = cookies("kemal_identity=garbage")
    headers["Authorization"] = "Bearer #{token}"

    request("POST", "/api/things", headers).status_code.should eq(403)
  end

  it "still protects a cookie-authenticated request with no token" do
    session = log_in

    request("POST", "/api/things", cookies("kemal_identity=#{session}")).status_code.should eq(403)
  end
end

# One header, two kinds of credential. `AuthenticatorChain` routes on shape: an opaque token is
# `ki_` plus a fixed-length random part, a JWT is three base64url segments, and neither can be
# mistaken for the other before any I/O happens.
private def jwt_for(subject : String = "a1", purpose : String = "access") : String
  KemalIdentity::Testing::JWTForge.encode(
    KemalIdentity::Testing::JWTForge.claims(
      now: TEST_CLOCK.now, subject: subject, purpose: purpose
    )
  )
end

# This application's ErrorHandler sends a browser to the login page, so "turned away" reads as
# a 302 here rather than a 401. What matters is that it is not a 200.
describe "JWTs over HTTP" do
  it "authenticates a request carrying a valid token" do
    response = request("GET", "/api/me", bearer(jwt_for))

    response.status_code.should eq(200)
    response.body.should eq("a1 via ApiToken")
  end

  it "leaves opaque tokens working alongside it" do
    response = request("GET", "/api/me", bearer(issue_api_token.token.reveal))

    response.status_code.should eq(200)
    response.body.should eq("a1 via ApiToken")
  end

  it "turns away a forged signature" do
    forged = KemalIdentity::Testing::JWTForge.encode(
      KemalIdentity::Testing::JWTForge.claims(now: TEST_CLOCK.now),
      secret: KemalIdentity::Secret.new("z" * 64)
    )

    request("GET", "/api/me", bearer(forged)).status_code.should eq(401)
  end

  # The purpose claim, reaching all the way out to the response: a token minted to authorise a
  # password reset must not authenticate an API request.
  it "turns away a token minted for another flow" do
    request("GET", "/api/me", bearer(jwt_for(purpose: "password-reset")))
      .status_code.should eq(401)
  end

  it "turns away an unsigned token" do
    unsigned = KemalIdentity::Testing::JWTForge.unsigned(
      KemalIdentity::Testing::JWTForge.claims(now: TEST_CLOCK.now)
    )

    request("GET", "/api/me", bearer(unsigned)).status_code.should eq(401)
  end

  # An automated client cannot re-authenticate interactively, so a JWT is no freer than an
  # opaque token: both stop at `ApiToken` assurance.
  it "never satisfies a step-up guard" do
    request("GET", "/step-up/email", bearer(jwt_for)).status_code.should eq(403)
  end

  it "sets no session cookie: a token establishes nothing" do
    response = request("GET", "/api/me", bearer(jwt_for))

    cookie_of(response, "kemal_identity").should be_nil
  end

  # The chain falls through on shape and on shape only. A rejected opaque token is *recognised*
  # and rejected, so it must not get a second opinion from the JWT validator.
  it "does not let a rejected opaque token fall through to the JWT validator" do
    request("GET", "/api/me", bearer("ki_" + "a" * 43)).status_code.should eq(401)
  end

  it "exempts a JWT-only request from CSRF, as it does an opaque token" do
    request("POST", "/api/things", bearer(jwt_for)).status_code.should eq(200)
  end

  # Same rule as for opaque tokens: a request that carries a session cookie is a request an
  # attacker can trigger cross-site, whatever else it also carries.
  it "still protects a JWT-bearing request that also carries a session cookie" do
    session = log_in

    headers = cookies("kemal_identity=#{session}")
    headers["Authorization"] = "Bearer #{jwt_for}"

    request("POST", "/api/things", headers).status_code.should eq(403)
  end
end

# `docs/02-security-model.md` lists an assurance increase alongside login among the events that
# must produce a new session identifier.
private def enrol_mfa : Bytes
  clock = TEST_CLOCK
  pending = KemalIdentity.app.mfa!.enrol(ACCOUNTS.find_by_id("a1").or_fail, "phone")

  secret = KemalIdentity::MFA::Base32.decode?(
    URI.parse(pending.provisioning_uri).query_params["secret"]
  ).or_fail

  KemalIdentity.app.mfa!.confirm(
    pending.factor.id,
    KemalIdentity::MFA::TOTP.code(secret, KemalIdentity::MFA::TOTP.counter(clock.now))
  ).or_fail

  secret
end

private def totp_code(secret : Bytes, offset : Int32 = 0) : String
  KemalIdentity::MFA::TOTP.code(
    secret, KemalIdentity::MFA::TOTP.counter(TEST_CLOCK.now) + offset
  )
end

# Submits a code to /mfa/verify from an authenticated session, CSRF token and all.
private def submit_code(session : String, code : String) : HTTP::Client::Response
  csrf = fetch_csrf(session)

  post "/mfa/verify", body: "code=#{code}&_csrf=#{csrf.token}", headers: form(csrf, session)

  response
end

describe "the second factor over HTTP" do
  it "raises the session's assurance once a code is proved" do
    secret = enrol_mfa
    session = log_in

    request("GET", "/vault", cookies("kemal_identity=#{session}")).status_code.should eq(403)

    TEST_CLOCK.advance(30.seconds)
    proved = submit_code(session, totp_code(secret))

    proved.status_code.should eq(200)

    raised = session_cookie(proved).or_fail
    request("GET", "/vault", cookies("kemal_identity=#{raised}")).status_code.should eq(200)
  end

  # A session id an attacker learned while it was worth `Password` must not silently become one
  # worth `MFA`.
  it "rotates the session identifier, and the old one stops working" do
    secret = enrol_mfa
    session = log_in

    TEST_CLOCK.advance(30.seconds)
    raised = session_cookie(submit_code(session, totp_code(secret))).or_fail

    raised.should_not eq(session)
    request("GET", "/vault", cookies("kemal_identity=#{session}")).status_code.should eq(302)
  end

  it "answers the same way for a wrong code as for a replayed one" do
    secret = enrol_mfa
    session = log_in

    TEST_CLOCK.advance(30.seconds)
    code = totp_code(secret)

    submit_code(session, code).status_code.should eq(200)

    # The same code again, from a fresh Password session: correct arithmetic, already spent.
    replay_session = log_in
    replayed = submit_code(replay_session, code)
    body = replayed.body

    wrong = submit_code(log_in, "000000")

    replayed.status_code.should eq(401)
    wrong.status_code.should eq(401)
    body.should eq(wrong.body)
  end

  it "leaves an unproved session below the bar" do
    enrol_mfa
    session = log_in

    request("GET", "/vault", cookies("kemal_identity=#{session}")).status_code.should eq(403)
  end
end

# RFC 6750 §3 makes the challenge a MUST for a request that carried no credentials or a token
# that did not grant access. Before v0.8 the header was absent from every response, which
# blueprints/0025 measured against a running server (HTTP-01).
describe "the RFC 6750 challenge" do
  before_each { AUTHZ_STORE.remove_account("a1") }

  it "answers an anonymous API request with a challenge and no error code" do
    # "If the request lacks any authentication information ... SHOULD NOT include an error code."
    get "/api/me", headers: HTTP::Headers{"Accept" => "application/json"}

    response.status_code.should eq(401)
    challenge_header.should eq(%(Bearer realm="api"))
  end

  it "names a presented credential that did not hold as invalid_token" do
    get "/api/me", headers: bearer("ki_not-a-real-token")

    response.status_code.should eq(401)
    challenge_header.should eq(%(Bearer realm="api", error="invalid_token"))
  end

  # The one denial reason RFC 6750 has a code for, and the only one this shard reports.
  it "names an out-of-scope credential as insufficient_scope" do
    AUTHORIZER.grant("a1", "finance")
    token = issue_scoped_token([] of String).token.reveal

    get "/reports", headers: bearer(token)

    response.status_code.should eq(403)
    challenge_header.should eq(%(Bearer realm="api", error="insufficient_scope"))
  end

  # Every other denial gets the challenge and no error code: whether the caller is not a member
  # of a tenant or a member with no role stays an audit-log answer.
  it "reports no error code for a denial that is not about scope" do
    session = log_in

    get "/invoices", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(403)
    challenge_header.should eq(%(Bearer realm="api"))
  end

  it "answers 'not a member' and 'a member with no role' with the same challenge" do
    session = log_in
    AUTHORIZER.grant("a1", "reader")

    get "/tenants/globex/invoices", headers: cookies("kemal_identity=#{session}")
    outsider = {response.status_code, challenge_header, response.body}

    AUTHORIZER.add_member("a1", "globex")
    get "/tenants/globex/invoices", headers: cookies("kemal_identity=#{session}")

    {response.status_code, challenge_header, response.body}.should eq(outsider)
  end

  describe "step-up" do
    # RFC 9470 defines insufficient_user_authentication as the authentication event behind *the
    # access token* being too weak or too old. A browser session has no access token, so saying
    # it about one would be a claim about something that is not there.
    it "reports no bearer error for a session that needs re-authentication" do
      token = log_in
      TEST_CLOCK.advance(10.minutes)

      get "/step-up/email", headers: cookies("kemal_identity=#{token}")

      response.status_code.should eq(403)
      challenge_header.should eq(%(Bearer realm="api"))

      TEST_CLOCK.travel_to(KemalIdentity::Testing::FIXED_NOW)
    end

    # RFC 9470 §3's `max_age`: "the allowable elapsed time in seconds since the last active
    # authentication event". `require_fresh!(within: 5.minutes)` is exactly that, so the window
    # the caller asked for is what the client is told. Without it a 403 says only
    # "insufficient", and an API client cannot tell "type your password again" from "produce a
    # second factor" — two different prompts. AUT-07 in `blueprints/0025`.
    it "names the freshness window a recency denial wants" do
      token = issue_api_token.token.reveal

      get "/step-up/email", headers: bearer(token)

      response.status_code.should eq(403)
      challenge_header.should eq(
        %(Bearer realm="api", error="insufficient_user_authentication", max_age="300")
      )
    end

    # The other half, and the reason `max_age` has to be absent rather than zero: this denial is
    # about the *strength* of the credential, and no amount of re-authenticating an API token
    # makes it a second factor. A `max_age` here would tell a client to retry something that
    # cannot succeed.
    it "sends no max_age when a stronger credential is what is missing" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_api_token.token.reveal

      get "/invoices/refund", headers: bearer(token)

      response.status_code.should eq(403)
      challenge_header.should eq(
        %(Bearer realm="api", error="insufficient_user_authentication")
      )
    end

    # A browser session gets neither the error code nor the parameter: both are defined as
    # statements about an access token, and there is none. `blueprints/0026` decided the first
    # half of that; the parameter follows it rather than being gated separately.
    it "sends no max_age to a session, which has no access token to say it about" do
      token = log_in
      TEST_CLOCK.advance(10.minutes)

      get "/step-up/email", headers: cookies("kemal_identity=#{token}")

      response.status_code.should eq(403)
      challenge_header.should eq(%(Bearer realm="api"))

      TEST_CLOCK.travel_to(KemalIdentity::Testing::FIXED_NOW)
    end

    # Rounded down, not up: a client that re-authenticates within the number it was handed must
    # land inside the window, and 299 seconds is inside a 299.5-second one while 300 is not.
    it "rounds a fractional window down to whole seconds" do
      error = KemalIdentity::FreshAuthenticationRequiredError.new(max_age: 299.5.seconds)
      window = error.max_age.or_fail("the window must travel with the refusal")

      window.should eq(299.5.seconds)
      window.total_seconds.to_i.should eq(299)
    end
  end

  # The scope attribute is OPTIONAL in RFC 6750, and naming the permission a caller lacks is the
  # part of a denial this shard keeps to the audit log.
  it "never names the permission in the challenge" do
    session = log_in

    get "/invoices", headers: cookies("kemal_identity=#{session}")

    sent = challenge_header.or_fail("a denial must still carry the challenge")
    sent.should_not contain("scope=")
    sent.should_not contain("invoices")
  end
end

# HTTP-02: one process, HTML pages, a same-origin SPA and third-party API clients. The three
# things that have to be independently expressible are the credential classes a subtree takes,
# whether a refusal renders as a status or a redirect, and where CSRF applies.
describe "a mixed browser and API monolith" do
  it "lets a browser subtree take a session and refuse a token" do
    session = log_in
    token = issue_api_token.token.reveal

    request("GET", "/pages/dashboard", cookies("kemal_identity=#{session}"))
      .body.should eq("dashboard for a1")

    # 403 and not 401: the token is perfectly valid, it is the wrong door. A 401 would tell a
    # working client to authenticate again, which is a loop.
    refused = request("GET", "/pages/dashboard", bearer(token))
    refused.status_code.should eq(403)
    refused.body.should eq(%({"error":"not permitted"}))
  end

  it "lets an API subtree take a token and refuse a session" do
    session = log_in
    token = issue_api_token.token.reveal

    request("GET", "/api/strict/items", bearer(token)).body.should eq("items for a1")
    request("GET", "/api/strict/items", cookies("kemal_identity=#{session}"))
      .status_code.should eq(403)
  end

  # The wrong credential class must not be a way to find out what a subtree accepts before
  # holding any credential at all: the guard requires authentication first.
  it "answers an anonymous request to either subtree as unauthenticated" do
    request("GET", "/api/strict/items").status_code.should eq(401)

    # /pages is not an API prefix, so a browser there still gets the login page.
    request("GET", "/pages/dashboard").status_code.should eq(302)
  end

  # Without `api_prefixes:`, this is the case the redirect guess gets wrong: a client that
  # sends no `Accept` and no credential — curl with no flags, a probe for a 401 — used to
  # receive `302 Location: /login` for a path that serves no HTML.
  it "answers an API path with a status rather than a login page" do
    response = request("GET", "/api/me")

    response.status_code.should eq(401)
    response.body.should eq(%({"error":"authentication required"}))
    response.headers["Location"]?.should be_nil
  end

  it "still redirects a page path for the same client" do
    response = request("GET", "/guarded-route")

    response.status_code.should eq(302)
    response.headers["Location"].should eq("/login")
  end

  # The subtree, and only the subtree, for both parameters.
  it "does not treat a lookalike path as an API prefix" do
    KemalIdentity::Kemal::PathPrefix.covers?("/api", "/api").should be_true
    KemalIdentity::Kemal::PathPrefix.covers?("/api", "/api/items").should be_true
    KemalIdentity::Kemal::PathPrefix.covers?("/api", "/apiary").should be_false
    KemalIdentity::Kemal::PathPrefix.covers?("/", "/anything").should be_true
  end

  it "refuses a credential list that accepts nothing, at boot" do
    expect_raises(KemalIdentity::ConfigurationError, /at least one kind/) do
      KemalIdentity::Kemal::PathGuard.new(
        prefix: "/api", credentials: [] of KemalIdentity::CredentialKind
      )
    end
  end
end

describe "authorization over HTTP" do
  before_each { AUTHZ_STORE.remove_account("a1") }

  # 401, not 403: nobody is signed in, so logging in is the thing that could help.
  it "answers an anonymous request with a 401 rather than a 403" do
    get "/invoices", headers: HTTP::Headers{"Accept" => "application/json"}

    response.status_code.should eq(401)
  end

  it "answers a signed-in request with no grant with a 403" do
    session = log_in

    get "/invoices", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(403)
  end

  it "serves the route once the role is granted" do
    session = log_in
    AUTHORIZER.grant("a1", "reader")

    get "/invoices", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(200)
    response.body.should eq("invoices ok")
  end

  # TOK-01 and AUT-03, over real HTTP. Two tokens for one account, same role behind both.
  describe "a token narrower than the account that owns it" do
    it "serves the permission its scope names" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_scoped_token(["reports.read"]).token.reveal

      get "/reports", headers: bearer(token)

      response.status_code.should eq(200)
      response.body.should eq("report")
    end

    # The one that used to succeed. Same account, same grant, same role — only the scope
    # differs, and it is what refuses.
    it "refuses a permission its scope does not name, though the account holds it" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_scoped_token(["reports.read"]).token.reveal

      get "/reports/export", headers: bearer(token)

      response.status_code.should eq(403)
    end

    it "serves both when the scope names both" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_scoped_token(["reports.read", "reports.export"]).token.reveal

      get "/reports/export", headers: bearer(token)

      response.status_code.should eq(200)
    end

    # A scope is not a grant. Without the role, naming the permission changes nothing.
    it "does not let a scope stand in for the grant" do
      token = issue_scoped_token(["reports.read"]).token.reveal

      get "/reports", headers: bearer(token)

      response.status_code.should eq(403)
    end

    # Every token issued before v0.8 reads back with nil scopes, and nil is "unattenuated".
    it "leaves a token issued without scopes carrying whatever its owner holds" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_scoped_token(nil).token.reveal

      get "/reports/export", headers: bearer(token)

      response.status_code.should eq(200)
    end

    # An out-of-scope denial is not a step-up: no amount of re-authenticating widens a token
    # that was issued narrow. The body is the plain 403, not the freshness one.
    it "does not ask for stronger authentication when the scope is what refused" do
      AUTHORIZER.grant("a1", "finance")
      token = issue_scoped_token([] of String).token.reveal

      get "/reports", headers: bearer(token)

      response.status_code.should eq(403)
      response.body.should contain("not permitted")
      response.body.should_not contain("fresh authentication required")
    end
  end

  # `blueprints/0022`. Before it, a route needing a per-object rule had to reach past
  # `env.auth` to the authorizer, and re-implement the audit line, the step-up mapping and the
  # uniform 403 at every such route.
  describe "a resource-aware authorizer, reached through env.auth" do
    it "serves the object the caller owns" do
      session = log_in
      AUTHORIZER.grant("a1", "reader")

      get "/invoices/invoice-1", headers: cookies("kemal_identity=#{session}")

      response.status_code.should eq(200)
      response.body.should eq("invoice ok")
    end

    # Same account, same role, same permission. Only the object differs.
    it "refuses the object the caller does not own" do
      session = log_in
      AUTHORIZER.grant("a1", "reader")

      get "/invoices/invoice-2", headers: cookies("kemal_identity=#{session}")

      response.status_code.should eq(403)
    end

    # The resource rule narrows and never widens: no grant is still no, whoever owns the object.
    it "does not let ownership substitute for the grant" do
      session = log_in

      get "/invoices/invoice-1", headers: cookies("kemal_identity=#{session}")

      response.status_code.should eq(403)
    end

    it "passes environment attributes to the policy" do
      session = log_in
      AUTHORIZER.grant("a1", "reader")

      get "/invoices/export/managed", headers: cookies("kemal_identity=#{session}")

      response.status_code.should eq(200)
      response.body.should eq("exported")
    end

    # The custom denial asked for step-up under its own code, without borrowing
    # InsufficientAssurance — and `authorize!` honoured it, because it reads `step_up?` rather
    # than the enum member.
    it "raises a step-up for a custom denial that asked for one" do
      session = log_in
      AUTHORIZER.grant("a1", "reader")

      get "/invoices/export/unrecognised", headers: cookies("kemal_identity=#{session}")

      response.status_code.should eq(403)
      response.body.should contain("fresh authentication required")
    end

    # Every denial still renders one identical body. A custom `code` is for the audit trail; a
    # response that carried it would tell a caller which rule it tripped.
    it "renders an ownership denial identically to a missing grant" do
      session = log_in
      AUTHORIZER.grant("a1", "reader")

      get "/invoices/invoice-2", headers: cookies("kemal_identity=#{session}")
      owned = {response.status_code, response.body}

      AUTHZ_STORE.remove_account("a1")
      get "/invoices/invoice-1", headers: cookies("kemal_identity=#{session}")

      {response.status_code, response.body}.should eq(owned)
    end
  end

  # The denial reason is an audit-log value. A response that varied with it would confirm that
  # a guessed tenant exists and that the caller is outside it.
  it "answers 'not a member' and 'a member with no role' identically" do
    session = log_in
    AUTHZ_STORE.add_member(KemalIdentity::Authz::Membership.new(
      id: "m1", account_id: "a1", tenant_id: "acme", created_at: TEST_CLOCK.now
    ))

    get "/tenants/acme/invoices", headers: cookies("kemal_identity=#{session}")
    member = {response.status_code, response.body, response.headers["Content-Type"]?}

    get "/tenants/globex/invoices", headers: cookies("kemal_identity=#{session}")
    stranger = {response.status_code, response.body, response.headers["Content-Type"]?}

    member.should eq(stranger)
    member[0].should eq(403)
  end

  it "serves a tenant route to a member holding the role there" do
    session = log_in
    AUTHORIZER.add_member("a1", "acme")
    AUTHORIZER.grant("a1", "reader", tenant_id: "acme")

    get "/tenants/acme/invoices", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(200)
  end

  # A tenant grant is inert without a membership, over HTTP as everywhere else.
  it "refuses a tenant route to somebody holding the role but not a member" do
    session = log_in
    AUTHORIZER.grant("a1", "reader", tenant_id: "acme")

    get "/tenants/acme/invoices", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(403)
  end

  # Distinguishable from an outright denial on purpose, exactly as `require_fresh!` is: the
  # application has to be able to prompt for a second factor rather than show a dead end.
  it "asks for stronger authentication when the grant is there and the assurance is not" do
    session = log_in
    AUTHORIZER.grant("a1", "finance")

    get "/invoices/refund", headers: cookies("kemal_identity=#{session}")

    response.status_code.should eq(403)
    response.body.should contain("fresh authentication required")
  end

  it "lets a template ask without raising" do
    session = log_in

    get "/invoices/menu", headers: cookies("kemal_identity=#{session}")
    response.body.should eq("hide")

    AUTHORIZER.grant("a1", "reader")

    get "/invoices/menu", headers: cookies("kemal_identity=#{session}")
    response.body.should eq("show")
  end

  # Nothing is carried in the session, so nothing has to be reissued for a revocation to bite.
  it "stops serving the route the moment the role is revoked, with the same session" do
    session = log_in
    AUTHORIZER.grant("a1", "reader")

    get "/invoices", headers: cookies("kemal_identity=#{session}")
    response.status_code.should eq(200)

    AUTHORIZER.revoke("a1", "reader")

    get "/invoices", headers: cookies("kemal_identity=#{session}")
    response.status_code.should eq(403)
  end
end

describe "adopting a session from the system being migrated off" do
  # Nobody is signed out by the deployment that introduces this shard.
  it "signs in somebody the old cookie names" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=a1")

    response.status_code.should eq(200)
    response.body.should eq("a1")
  end

  it "issues a real session cookie, so the old one is needed exactly once" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=a1")

    session_cookie(response).should_not be_nil
  end

  # The browser must stop presenting a credential to a system that no longer reads it.
  it "clears the old cookie" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=a1")

    cleared = HTTP::Cookies.from_server_headers(response.headers)[LEGACY_COOKIE]?.or_fail
    cleared.value.should eq("")
    cleared.expires.or_fail.should be < KemalIdentity::Testing::FIXED_NOW
  end

  # The old cookie proves somebody authenticated at some point, to a system this one cannot
  # inspect. It does not prove the account holder is present.
  it "adopts at Remembered rather than claiming a password was typed" do
    get "/api/me", headers: cookies("#{LEGACY_COOKIE}=a1")

    response.body.should eq("a1 via Remembered")
  end

  it "cannot pass a freshness guard, so anything sensitive forces a real login" do
    get "/step-up/email", headers: cookies("#{LEGACY_COOKIE}=a1")

    response.status_code.should eq(403)
  end

  # The legacy cookie names an account this shard would adopt without hesitation on its own, so
  # the example fails if the handler stops checking that nothing else resolved first.
  it "leaves a live session alone rather than replacing it" do
    session = log_in

    get "/whoami", headers: cookies("kemal_identity=#{session}", "#{LEGACY_COOKIE}=a2")

    response.body.should eq("a1")
  end

  it "adopts that same account when there is no live session" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=a2")

    response.body.should eq("a2")
  end

  it "refuses a subject the account store does not have" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=nobody-at-all")

    response.body.should eq("nobody")
    session_cookie(response).should be_nil
  end

  # Somebody disabled here whose old session has not noticed yet.
  it "refuses a disabled account" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=a-disabled")

    response.body.should eq("nobody")
    session_cookie(response).should be_nil
  end

  it "clears the old cookie even when it refuses, since it will never start working" do
    get "/whoami", headers: cookies("#{LEGACY_COOKIE}=nobody-at-all")

    HTTP::Cookies.from_server_headers(response.headers)[LEGACY_COOKIE]?.should_not be_nil
  end

  it "does nothing at all when there is no old cookie" do
    get "/whoami"

    response.body.should eq("nobody")
    response.headers["Set-Cookie"]?.should be_nil
  end
end

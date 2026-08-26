# A complete first-party browser application: log in, stay logged in, step up, log out.
#
# This is the shape `docs/06-roadmap.md` calls the v0.1 deliverable, and CI compiles it on
# every push — an example that has drifted from the API is worse than no example.
#
#     createdb kemal_identity_example
#     export DATABASE_URL=postgres://localhost/kemal_identity_example
#     export CSRF_SECRET=$(head -c 32 /dev/urandom | base64)
#     bin/migrate up
#     crystal run examples/browser_session/app.cr
#
# It renders HTML inline rather than pulling in a template engine, because the point is the
# authentication wiring and nothing else.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/postgres"

DB_URL      = ENV["DATABASE_URL"]? || "postgres://localhost/kemal_identity_example"
CSRF_SECRET = ENV["CSRF_SECRET"]? || "development-only-secret-at-least-32-bytes"

database = DB.open(DB_URL)

KemalIdentity.configure(
  accounts: KemalIdentity::Postgres::AccountRepository.new(database),
  sessions: KemalIdentity::Postgres::SessionRepository.new(database),

  # Dispatched to a small dedicated context: bcrypt is tens of milliseconds of pure CPU, and
  # run on the request fiber a burst of logins queues every unrelated request behind it. Two
  # threads is a ceiling on how much of the machine logins may take, not a throughput target.
  #
  # Execution contexts arrived in Crystal 1.21, and this shard supports older ones. There, the
  # executor refuses to be built unless `allow_inline: true` is passed, because a security
  # property that vanishes silently on an older compiler is worse than one that is absent
  # loudly. An application pinned below 1.21 makes that trade explicitly, exactly like this.
  hasher: {% if Fiber.has_constant?("ExecutionContext") %}
    KemalIdentity::Passwords::HashingExecutor.new(
      KemalIdentity::Passwords::BcryptHasher.new(cost: 12), size: 2
    )
  {% else %}
    KemalIdentity::Passwords::HashingExecutor.new(
      KemalIdentity::Passwords::BcryptHasher.new(cost: 12), allow_inline: true
    )
  {% end %},

  # Off by default. Nothing throttles the login endpoint until an application says so.
  rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(limit: 10, window: 5.minutes),

  # Plain HTTP for a local example. In production drop both of these: the defaults are
  # `__Host-` prefixed and Secure, and `allow_insecure` is refused at boot without this.
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: CSRF_SECRET, cookie_name: "kemal_identity_csrf", secure: false
  ),
)

# Order matters and is not obvious.
#
# ErrorHandler is outermost so it catches what a route or a guard raises. AuthenticationHandler
# populates env.auth and never rejects. CSRFHandler comes after it, because the token binds to
# the session. PathGuard rejects, so it comes last.
#
# None of these is registered at position 0: that position sits ahead of Kemal::InitHandler and
# would make the handler responsible for cleaning up temporary upload files.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(prefix: "/dashboard")
use KemalIdentity::Kemal::PathGuard.new(prefix: "/account", within: 5.minutes)

def layout(title : String, body : String) : String
  <<-HTML
    <!doctype html>
    <html><head><meta charset="utf-8"><title>#{title}</title></head>
    <body style="font-family: system-ui; max-width: 34rem; margin: 4rem auto">
    #{body}
    </body></html>
    HTML
end

get "/" do |env|
  principal = env.auth.principal?

  body = if principal
           <<-HTML
             <p>Signed in as <strong>#{principal.subject}</strong>.</p>
             <p><a href="/dashboard">Dashboard</a> &middot; <a href="/account">Account</a></p>
             <form method="post" action="/logout">
               <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
               <button type="submit">Log out</button>
             </form>
             HTML
         else
           %(<p>Not signed in.</p><p><a href="/login">Log in</a></p>)
         end

  env.html layout("kemal_identity example", body)
end

get "/login" do |env|
  error = env.params.query["error"]?

  # Rendering the form is what mints the anonymous CSRF anchor cookie, so a request for a
  # static asset never pays for one. The login form is protected like any other mutation:
  # without a token here, an attacker can log a victim into the *attacker's* account and then
  # watch whatever the victim does under it.
  env.html layout("Log in", <<-HTML)
    <h1>Log in</h1>
    #{error ? %(<p style="color:#b00">Invalid email or password</p>) : ""}
    <form method="post" action="/login">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <p><label>Email <input name="email" type="email" autocomplete="username"></label></p>
      <p><label>Password <input name="password" type="password" autocomplete="current-password"></label></p>
      <button type="submit">Log in</button>
    </form>
    HTML
end

post "/login" do |env|
  result = KemalIdentity.app.passwords.authenticate(
    login: env.params.body["email"]? || "",
    password: env.params.body["password"]? || "",
    ip: env.request.remote_address.try(&.to_s),
  )

  case result
  in KemalIdentity::Authenticated
    # Mints the session, sets the cookie, and revokes whatever session the client presented
    # while logging in — the session fixation defence.
    env.auth.start!(result.principal)
    env.redirect "/dashboard"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # One response for every reason. `DisabledAccount` and `InvalidCredential` rendering
    # differently is an account oracle; the reason is already in the audit log.
    env.redirect "/login?error=1"
  end
end

post "/logout" do |env|
  env.auth.logout!
  env.redirect "/"
end

# Guarded by the PathGuard above. `require!` here would be equivalent for one route; the guard
# covers the whole subtree, for every HTTP method, including ones that did not exist when it
# was written.
get "/dashboard" do |env|
  principal = env.auth.require!

  env.html layout("Dashboard", <<-HTML)
    <h1>Dashboard</h1>
    <p>Account <strong>#{principal.subject}</strong>, authenticated at #{principal.authenticated_at}.</p>
    <p>Assurance: #{principal.assurance}.</p>
    <p><a href="/">Home</a></p>
    HTML
end

# Under a step-up guard: authenticated *and* recently. A session restored from a remember-me
# cookie is never fresh, however recently it was restored.
get "/account" do |env|
  principal = env.auth.require_fresh!(within: 5.minutes)

  env.html layout("Account", <<-HTML)
    <h1>Account</h1>
    <p>Sensitive settings for <strong>#{principal.subject}</strong>.</p>
    <p>Reachable only within five minutes of typing a password.</p>
    <p><a href="/">Home</a></p>
    HTML
end

Kemal.run

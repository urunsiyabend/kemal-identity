# A complete first-party browser application: log in, be remembered, step up, reset a
# forgotten password, confirm an address, log out.
#
# CI compiles this on every matrix entry — an example that has drifted from the API is worse
# than no example.
#
#     crystal run examples/browser_session/app.cr
#
# It uses SQLite so it runs with no setup at all, creates its schema on first boot, and prints
# the links a `Notifier` would email. Swapping to PostgreSQL is the block marked below.
#
# HTML is rendered inline rather than through a template engine: the point is the
# authentication wiring and nothing else.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

DB_PATH     = ENV["DB_PATH"]? || "./kemal_identity_example.db"
CSRF_SECRET = ENV["CSRF_SECRET"]? || "development-only-secret-at-least-32-bytes"

database = DB.open("sqlite3://#{DB_PATH}?journal_mode=wal&busy_timeout=5000")

# The **application** creates its schema here, not the shard.
#
# `docs/03-data-model.md` publishes migrations as files to copy into your own tooling, and is
# emphatic that the shard must never run them: a library that mutates the schema on boot is one
# that will mutate it at the wrong moment. An example gets to be its own migration tool; a real
# application should not copy this part.
Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last

  # Comments are stripped before splitting on `;`. A semicolon inside a comment otherwise cuts a
  # statement in half, which SQLite reports as `incomplete input` — a confusing way to discover
  # that a column comment contained one.
  body
    .lines
    .map(&.sub(/--.*$/, ""))
    .join('\n')
    .split(';')
    .each do |statement|
      next if statement.strip.empty?
      database.exec(statement) rescue nil # already applied
    end
end

# ---------------------------------------------------------------------------------------
# To use PostgreSQL instead, require `kemal_identity/postgres`, apply `migrations/postgres`
# with your own tooling, and swap the four repositories:
#
#   accounts:        KemalIdentity::Postgres::AccountRepository.new(database)
#   sessions:        KemalIdentity::Postgres::SessionRepository.new(database)
#   action_tokens:   KemalIdentity::Postgres::ActionTokenRepository.new(database)
#   remember_tokens: KemalIdentity::Postgres::RememberRepository.new(database)
#
# Nothing else changes. That is what the shared contract specs are for.
# ---------------------------------------------------------------------------------------

# Delivery is the application's job. `docs/00-scope.md` puts SMTP and templates out of scope,
# and there is deliberately no null default: a reset flow with nobody to send the link is a
# flow that silently never works.
#
# `deliver` must return promptly. `Accounts::Service#request_password_reset` takes the same time
# whether or not the address exists, and an implementation that waits on an SMTP server puts a
# network round trip on one path and not the other — handing back the account oracle the timing
# equalisation exists to remove. Enqueue and return.
class ConsoleNotifier < KemalIdentity::Accounts::Notifier
  def deliver(notification : KemalIdentity::Accounts::Notification) : Nil
    case notification
    in KemalIdentity::Accounts::PasswordResetRequested
      puts "  [mail] reset for #{notification.login}: http://localhost:3000/reset?token=#{notification.token.reveal}"
    in KemalIdentity::Accounts::EmailConfirmationRequested
      puts "  [mail] confirm #{notification.login}: http://localhost:3000/confirm?token=#{notification.token.reveal}"
    in KemalIdentity::Accounts::PasswordChanged
      puts "  [mail] password changed for #{notification.login} at #{notification.at}"
    in KemalIdentity::Accounts::RememberTokenReplayed
      puts "  [mail] SECURITY: a remember-me cookie for #{notification.login} was replayed; " \
           "every session was ended"
    end
  end
end

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(database),
  sessions: KemalIdentity::SQLite::SessionRepository.new(database),
  action_tokens: KemalIdentity::SQLite::ActionTokenRepository.new(database),
  remember_tokens: KemalIdentity::SQLite::RememberRepository.new(database),
  notifier: ConsoleNotifier.new,

  # Dispatched to a small dedicated context: bcrypt is tens of milliseconds of pure CPU, and on
  # the request fiber a burst of logins queues every unrelated request behind it. Two threads is
  # a ceiling on how much of the machine logins may take, not a throughput target.
  #
  # Execution contexts arrived in Crystal 1.21 and this shard supports 1.12 upwards. Below 1.21
  # the executor refuses to be built without `allow_inline: true`, because a security property
  # that vanishes silently on an older compiler is worse than one that is absent loudly. An
  # application pinned below 1.21 makes that trade explicitly, exactly like this.
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

  # Plain HTTP for a local example. In production drop `secure:` and `allow_insecure:` from both
  # — the defaults are `__Host-` prefixed and Secure, and `allow_insecure` is refused at boot
  # without an explicit opt-in.
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity", secure: false, allow_insecure: true
  ),
  remember_cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity_remember", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: CSRF_SECRET, cookie_name: "kemal_identity_csrf", secure: false
  ),
)

# Disk reclamation only: every expiry and revocation check happens on read, so a sweeper that
# never runs costs storage and nothing else. It does not start itself — behind several
# processes you want one scheduled sweep, not one per process.
KemalIdentity::Sweeper.new(KemalIdentity.app).run_every(1.hour)

# One account to log in as, created directly because registration is the application's job and
# deliberately not part of this shard.
if KemalIdentity.app.accounts.find_by_login("ada@example.com").nil?
  now = Time.utc
  digest = KemalIdentity.app.hasher.hash_secret(KemalIdentity::Secret.new("correct horse battery"))

  database.exec(<<-SQL, "a1", "ada@example.com", digest, KemalIdentity.app.hasher.scheme, now, now)
    INSERT INTO auth_accounts (id, normalized_login, password_digest, password_scheme, auth_version, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    SQL

  puts "seeded ada@example.com / correct horse battery"
end

# Order matters and is not obvious.
#
# ErrorHandler is outermost so it catches what a route or a guard raises. AuthenticationHandler
# populates env.auth, never rejects, and restores a remembered login when the request carries no
# session cookie. CSRFHandler comes after it, because the token binds to the session. PathGuard
# rejects, so it comes last.
#
# None of these is registered at position `0`: that position sits ahead of Kemal::InitHandler and
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
    <body style="font-family: system-ui; max-width: 34rem; margin: 4rem auto; line-height: 1.5">
    #{body}
    </body></html>
    HTML
end

def field(label : String, name : String, type : String, autocomplete : String) : String
  %(<p><label>#{label} <input name="#{name}" type="#{type}" autocomplete="#{autocomplete}"></label></p>)
end

get "/" do |env|
  principal = env.auth.principal?

  body = if principal
           <<-HTML
             <p>Signed in as <strong>#{principal.subject}</strong> (#{principal.assurance}).</p>
             <p><a href="/dashboard">Dashboard</a> &middot; <a href="/account">Account</a></p>
             <form method="post" action="/resend-confirmation">
               <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
               <button type="submit">Send me a confirmation link</button>
             </form>
             <form method="post" action="/logout">
               <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
               <button type="submit">Log out</button>
             </form>
             HTML
         else
           %(<p>Not signed in.</p><p><a href="/login">Log in</a> &middot; <a href="/forgot">Forgot password</a></p>)
         end

  env.html layout("kemal_identity example", body)
end

get "/login" do |env|
  error = env.params.query["error"]?

  # Rendering the form mints the anonymous CSRF anchor cookie, so a request for a static asset
  # never pays for one. The login form is protected like any other mutation: without a token an
  # attacker can log a victim into the *attacker's* account and watch what they do under it.
  env.html layout("Log in", <<-HTML)
    <h1>Log in</h1>
    #{error ? %(<p style="color:#b00">Invalid email or password</p>) : ""}
    <form method="post" action="/login">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      #{field("Email", "email", "email", "username")}
      #{field("Password", "password", "password", "current-password")}
      <p><label><input type="checkbox" name="remember" value="1"> Keep me signed in</label></p>
      <button type="submit">Log in</button>
    </form>
    <p><a href="/forgot">Forgot password</a></p>
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
    # Mints the session, sets the cookie, and revokes whatever session the client presented —
    # the session fixation defence.
    env.auth.start!(result.principal)

    # Only ever after a real authentication: chaining remembrance off a restored session would
    # make the thirty days a rolling window that never closes.
    env.auth.remember! if env.params.body["remember"]?

    env.redirect "/dashboard"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # One response for every reason. `DisabledAccount` and `InvalidCredential` rendering
    # differently is an account oracle; the reason is already in the audit log.
    env.redirect "/login?error=1"
  end
end

post "/logout" do |env|
  # Also forgets this browser's remember-me family — without that, the next request would sign
  # the user straight back in.
  env.auth.logout!
  env.redirect "/"
end

get "/forgot" do |env|
  env.html layout("Forgot password", <<-HTML)
    <h1>Forgot password</h1>
    #{env.params.query["sent"]? ? %(<p>If that address has an account, a link is on its way.</p>) : ""}
    <form method="post" action="/forgot">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      #{field("Email", "email", "email", "username")}
      <button type="submit">Send a reset link</button>
    </form>
    HTML
end

post "/forgot" do |env|
  KemalIdentity.app.accounts_service!.request_password_reset(
    login: env.params.body["email"]? || "",
    ip: env.request.remote_address.try(&.to_s),
  )

  # **The response never varies.** It returns nothing at all, so there is nothing to branch on
  # and no way to tell whether the address exists. The link, if there was one to send, is on
  # stdout.
  env.redirect "/forgot?sent=1"
end

get "/reset" do |env|
  token = env.params.query["token"]? || ""

  # The token arrives in the query string here because that is what an emailed link looks like.
  # It is carried into a form field rather than being re-submitted as a query parameter, so the
  # POST does not put it in a URL that could reach a `Referer` header
  # (`docs/02-security-model.md`, token discipline rule 2).
  env.html layout("Choose a new password", <<-HTML)
    <h1>Choose a new password</h1>
    #{env.params.query["error"]? ? %(<p style="color:#b00">That link is no longer valid, or the password was unacceptable.</p>) : ""}
    <form method="post" action="/reset">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <input type="hidden" name="token" value="#{token}">
      #{field("New password", "password", "password", "new-password")}
      <button type="submit">Set password</button>
    </form>
    HTML
end

post "/reset" do |env|
  outcome = KemalIdentity.app.accounts_service!.reset_password(
    env.params.body["token"]? || "",
    env.params.body["password"]? || "",
  )

  case outcome
  in KemalIdentity::Accounts::PasswordWasReset
    # Every session for the account is gone, including any the attacker held, and so is every
    # remembered browser. The user signs in again with the password they just chose.
    env.html layout("Password set", <<-HTML)
      <h1>Password set</h1>
      <p>#{outcome.revoked_sessions} session(s) were signed out.</p>
      <p><a href="/login">Log in</a></p>
      HTML
  in KemalIdentity::Accounts::ActionRejected
    # Safe to be specific about a policy violation: whoever holds the link already has it, and
    # refusing without saying why makes the form unusable. An invalid token stays vague.
    env.redirect "/reset?error=1"
  in KemalIdentity::Accounts::EmailWasConfirmed
    env.redirect "/"
  end
end

post "/resend-confirmation" do |env|
  # Takes an account id the application already holds, so unlike a reset request there is no
  # untrusted identifier to enumerate with and no reason to be silent.
  KemalIdentity.app.accounts_service!.request_email_confirmation(env.auth.require!.subject)
  env.redirect "/"
end

get "/confirm" do |env|
  outcome = KemalIdentity.app.accounts_service!.confirm_email(env.params.query["token"]? || "")

  case outcome
  in KemalIdentity::Accounts::EmailWasConfirmed
    # Deliberately does not touch sessions: proving an address is not a credential change.
    env.html layout("Address confirmed", "<h1>Address confirmed</h1><p><a href=\"/\">Home</a></p>")
  in KemalIdentity::Accounts::ActionRejected
    env.html layout("Link expired", "<h1>That link is no longer valid</h1><p><a href=\"/\">Home</a></p>")
  in KemalIdentity::Accounts::PasswordWasReset
    env.redirect "/"
  end
end

# Guarded by the PathGuard above. `require!` here would be equivalent for one route; the guard
# covers the whole subtree, for every HTTP method, including ones that did not exist when it was
# written.
get "/dashboard" do |env|
  principal = env.auth.require!

  env.html layout("Dashboard", <<-HTML)
    <h1>Dashboard</h1>
    <p>Account <strong>#{principal.subject}</strong>, authenticated at #{principal.authenticated_at}.</p>
    <p>Assurance: #{principal.assurance}.</p>
    <p><a href="/account">Account settings</a> &middot; <a href="/">Home</a></p>
    HTML
end

# Under a step-up guard: authenticated *and* recently. A session restored from a remember-me
# cookie is never fresh, however recently it was restored, so this always forces a real
# re-authentication for a remembered visitor.
get "/account" do |env|
  principal = env.auth.require_fresh!(within: 5.minutes)

  env.html layout("Account", <<-HTML)
    <h1>Account</h1>
    <p>Sensitive settings for <strong>#{principal.subject}</strong>.</p>
    <p>Reachable only within five minutes of typing a password.</p>
    <p><a href="/">Home</a></p>
    HTML
end

puts "listening on http://localhost:3000 — emails are printed here"
Kemal.run

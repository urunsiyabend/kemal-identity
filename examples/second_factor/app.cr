# A second factor end to end: enrol a TOTP device, prove it, spend a recovery code, and see
# what each of those is worth.
#
# CI compiles this on every matrix entry — an example that has drifted from the API is worse
# than no example.
#
#     crystal run examples/second_factor/app.cr
#
# The point of this one is the three questions an application asks that look alike and are not:
#
#   * **how strongly** was this proved — `require_assurance!`, and why a recovery code stops
#     short of `MFA`;
#   * **how recently** — `require_fresh!`;
#   * **by what** — `require_recent_password!`, which a second factor does not satisfy however
#     recent it is.
#
# `/vault` and `/account/link` below are the same session and two different answers.
#
# SQLite, schema on first boot, HTML inline. Codes come from any authenticator app: the
# enrolment page prints the `otpauth://` URI to paste into one.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

DB_PATH     = ENV["DB_PATH"]? || "./kemal_identity_second_factor_example.db"
CSRF_SECRET = ENV["CSRF_SECRET"]? || "development-only-secret-at-least-32-bytes"

# Encrypts the TOTP secrets at rest. A leaked database backup without this key yields no
# working authenticator; with it, every second factor on every account.
MFA_KEY = ENV["MFA_KEY"]? || "development-only-mfa-key-at-least-32-bytes"

database = DB.open("sqlite3://#{DB_PATH}?journal_mode=wal&busy_timeout=5000")

# The application creates its schema, never the shard — `docs/03-data-model.md` is emphatic
# about it. An example gets to be its own migration tool; a real application should not copy
# this part.
Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last

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

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(database),
  sessions: KemalIdentity::SQLite::SessionRepository.new(database),
  mfa_factors: KemalIdentity::SQLite::MfaRepository.new(database),
  mfa_secret_key: KemalIdentity::Secret.new(MFA_KEY),

  # The label an authenticator app shows beside the code.
  mfa_issuer: "Kemal Identity Example",

  # Guessing a six-digit code is bounded twice: a window, and a lifetime cap that a window
  # cannot express. `blueprints/0029` measured a five-minute window of twelve at 103,680
  # attempts a month — about a 27% chance against six digits — which is why the second one
  # exists. Recovery codes get their own bucket: sharing one meant a failed second factor took
  # the credential for that exact situation down with it.
  rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(limit: 12, window: 5.minutes),
  mfa_recovery_rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(limit: 5, window: 5.minutes),
  mfa_max_consecutive_failures: 100,

  hasher: KemalIdentity::Passwords::HashingExecutor.new(
    KemalIdentity::Passwords::BcryptHasher.new(cost: 12), allow_inline: true
  ),

  # Plain HTTP for a local example. Drop both in production: the defaults are `__Host-` prefixed
  # and Secure, and `allow_insecure` is refused at boot without an explicit opt-in.
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: CSRF_SECRET, cookie_name: "kemal_identity_csrf", secure: false
  ),
)

if KemalIdentity.app.accounts.find_by_login("ada@example.com").nil?
  now = Time.utc
  digest = KemalIdentity.app.hasher.hash_secret(KemalIdentity::Secret.new("correct horse battery"))

  database.exec(<<-SQL, "a1", "ada@example.com", digest, KemalIdentity.app.hasher.scheme, now, now)
    INSERT INTO auth_accounts (id, normalized_login, password_digest, password_scheme, auth_version, created_at, updated_at)
    VALUES (?, ?, ?, ?, 1, ?, ?)
    SQL

  puts "seeded ada@example.com / correct horse battery"
end

use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new

# Checked before the first request rather than discovered on it. Every wrong arrangement of the
# three lines above compiles, and what arrives later is a 500 where a 401 belonged or a CSRF
# token anchored on nothing.
KemalIdentity::Kemal.validate_middleware_order!

def layout(title : String, body : String) : String
  <<-HTML
    <!doctype html>
    <html><head><meta charset="utf-8"><title>#{title}</title></head>
    <body style="font-family: system-ui; max-width: 40rem; margin: 3rem auto; line-height: 1.5">
    #{body}
    </body></html>
    HTML
end

def code_form(action : String, label : String, token : String, name : String = "code") : String
  <<-HTML
    <form method="post" action="#{action}">
      <input type="hidden" name="_csrf" value="#{token}">
      <p><label>#{label} <input name="#{name}" autocomplete="one-time-code"></label></p>
      <button type="submit">Submit</button>
    </form>
    HTML
end

get "/" do |env|
  principal = env.auth.principal?

  if principal.nil?
    next env.html layout("Second factor", <<-HTML)
      <h1>Second factor</h1>
      <p><a href="/login">Log in</a> as ada@example.com / correct horse battery.</p>
      HTML
  end

  # Four different facts, and the example exists because three of them are routinely confused.
  # `authenticated_at` moves every time the session's assurance rises; `password_verified_at`
  # does not, because a second factor is not a password.
  env.html layout("Second factor", <<-HTML)
    <h1>Signed in as #{principal.subject}</h1>
    <ul>
      <li>assurance: <strong>#{principal.assurance}</strong></li>
      <li>authenticated_at: #{principal.authenticated_at}</li>
      <li>password_verified_at: #{principal.password_verified_at || "never"}</li>
      <li>mfa_verified_at: #{principal.mfa_verified_at || "never"}</li>
      <li>enrolled: #{KemalIdentity.app.mfa!.enrolled?(principal.subject)}</li>
    </ul>
    <p><a href="/mfa">Enrol a device</a> &middot; <a href="/mfa/challenge">Prove a factor</a></p>
    <p><a href="/vault">Vault</a> (needs MFA) &middot;
       <a href="/account/link">Link an identity</a> (needs a recent password)</p>
    <form method="post" action="/logout">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <button type="submit">Log out</button>
    </form>
    HTML
end

get "/login" do |env|
  env.html layout("Log in", <<-HTML)
    <h1>Log in</h1>
    <form method="post" action="/login">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <p><label>Email <input name="email" autocomplete="username"></label></p>
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
    # `Passwords::Authenticator` stamped `password_verified_at` on this principal, and `start!`
    # carries it into the session row. Nothing in this route says so, which is the point: no
    # later code could work out that it was a *password* that answered.
    env.auth.start!(result.principal)
    env.redirect "/"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # One response for every reason. Branching here is the account oracle.
    env.redirect "/login"
  end
end

post "/logout" do |env|
  env.auth.logout!
  env.redirect "/"
end

# ---------------------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------------------

get "/mfa" do |env|
  principal = env.auth.require!

  env.html layout("Enrol", <<-HTML)
    <h1>Enrol a device</h1>
    <p>Signed in as #{principal.subject}.</p>
    <form method="post" action="/mfa">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <p><label>Label <input name="label" value="phone"></label></p>
      <button type="submit">Start enrolment</button>
    </form>
    HTML
end

post "/mfa" do |env|
  principal = env.auth.require!
  account = KemalIdentity.app.accounts.find_by_id(principal.subject)
  next env.redirect "/" if account.nil?

  pending = KemalIdentity.app.mfa!.enrol(account, env.params.body["label"]? || "phone")

  # Unconfirmed until a code from it is accepted: an enrolment nobody proved must not start
  # demanding codes at the login screen, and must not count as "this account has MFA".
  env.html layout("Confirm the device", <<-HTML)
    <h1>Confirm the device</h1>
    <p>Paste this into an authenticator app:</p>
    <p><code style="word-break:break-all">#{pending.provisioning_uri}</code></p>
    #{code_form("/mfa/confirm?factor=#{pending.factor.id}", "Code from the app", env.auth.csrf_token)}
    HTML
end

post "/mfa/confirm" do |env|
  principal = env.auth.require!

  # `account_id:` is passed because the factor id came from the client. Confirming somebody
  # else's enrolment also needs a code from their secret, so this is the cheaper guard rather
  # than the load-bearing one — but it is free.
  confirmed = KemalIdentity.app.mfa!.confirm(
    env.params.query["factor"]? || "",
    env.params.body["code"]? || "",
    account_id: principal.subject,
    ip: env.request.remote_address.try(&.to_s),
  )

  if confirmed.nil?
    next env.html layout("Not confirmed", "<h1>That code was not accepted</h1><p><a href=\"/mfa\">Try again</a></p>")
  end

  # Shown once, and only here. They are stored as digests, so this page is the only chance
  # anybody has to write them down — an account with a second factor and no way around it is one
  # lost phone from being unrecoverable.
  codes = confirmed.recovery_codes.map { |code| "<li><code>#{code.reveal}</code></li>" }.join

  env.html layout("Recovery codes", <<-HTML)
    <h1>Device confirmed</h1>
    <p>Write these down. They are shown once.</p>
    <ul>#{codes}</ul>
    <p><a href="/">Back</a></p>
    HTML
end

# ---------------------------------------------------------------------------------------
# Proving it
# ---------------------------------------------------------------------------------------

get "/mfa/challenge" do |env|
  env.auth.require!

  env.html layout("Prove a factor", <<-HTML)
    <h1>Prove a factor</h1>
    #{code_form("/mfa/challenge", "Code from the app", env.auth.csrf_token)}
    <h2>Lost the device?</h2>
    #{code_form("/mfa/recover", "Recovery code", env.auth.csrf_token)}
    HTML
end

# The whole reason `elevate!` exists.
#
# `#verify` and `#redeem_recovery_code` return the same `MFA::Verified`, so which of them
# happened — and therefore whether this session may reach `AssuranceLevel::MFA` or must stop at
# `Recovery` — used to be a choice this route made between two similar-looking methods. One
# forgotten branch there raises a printed code to full MFA. The result already knows; the route
# does not have to.
post "/mfa/challenge" do |env|
  principal = env.auth.require!

  case result = KemalIdentity.app.mfa!.verify(
    principal.subject,
    env.params.body["code"]? || "",
    ip: env.request.remote_address.try(&.to_s),
  )
  in KemalIdentity::MFA::Verified
    env.auth.elevate!(result)
    env.redirect "/"
  in KemalIdentity::Failed
    # The same page for a wrong code, a replayed one and a throttled attempt. Which it was is
    # for the audit log, not for whoever is guessing.
    env.redirect "/mfa/challenge"
  end
end

# The identical line, landing on `Recovery` instead — because the result says so.
post "/mfa/recover" do |env|
  principal = env.auth.require!

  case result = KemalIdentity.app.mfa!.redeem_recovery_code(
    principal.subject,
    env.params.body["code"]? || "",
    # Spares the session doing the recovering. Every *other* session dies: "lost" and "taken"
    # look identical from here.
    except_session_id: principal.session_id,
    ip: env.request.remote_address.try(&.to_s),
  )
  in KemalIdentity::MFA::Verified
    env.auth.elevate!(result)
    env.redirect "/"
  in KemalIdentity::Failed
    env.redirect "/mfa/challenge"
  end
end

# ---------------------------------------------------------------------------------------
# What each proof is worth
# ---------------------------------------------------------------------------------------

# Strength. A recovery code does not open this, and that is the entire point of
# `AssuranceLevel::Recovery` sitting below `MFA`: recovery restores access, it does not stand in
# for a device.
get "/vault" do |env|
  principal = env.auth.require_assurance!(KemalIdentity::AssuranceLevel::MFA)

  env.html layout("Vault", <<-HTML)
    <h1>Vault</h1>
    <p>Open at assurance #{principal.assurance}.</p>
    <p><a href="/">Back</a></p>
    HTML

rescue error : KemalIdentity::FreshAuthenticationRequiredError
  # The refusal carries what would satisfy it, so the prompt is chosen rather than guessed.
  # Before `StepUpRequirement` the only signal was whether `max_age` was present, which cannot
  # tell "produce a second factor" from "type your password again".
  env.html layout("Not strong enough", <<-HTML)
    <h1>Not strong enough</h1>
    <p>This needs assurance #{error.requirement.minimum_assurance || "higher than you have"}.</p>
    <p><a href="/mfa/challenge">Prove a factor</a></p>
    HTML
end

# By what. This is the one that surprises people.
#
# A TOTP proved a second ago makes the session *fresh* — `require_fresh!` passes, because
# `authenticated_at` is restamped by every assurance increase. It says nothing about the
# password, and linking a new credential to an account is exactly the operation that must not
# accept a second factor in a password's place. Prove a factor, then open this: the session is
# at `MFA`, and this still refuses until the password itself is typed again.
get "/account/link" do |env|
  principal = env.auth.require_recent_password!(within: 5.minutes)

  env.html layout("Link an identity", <<-HTML)
    <h1>Link an identity</h1>
    <p>Password typed at #{principal.password_verified_at}.</p>
    <p><a href="/">Back</a></p>
    HTML

rescue error : KemalIdentity::FreshAuthenticationRequiredError
  next env.redirect "/login" unless error.requirement.method == KemalIdentity::AuthenticationMethod::Password

  env.redirect "/account/confirm-password"
end

get "/account/confirm-password" do |env|
  env.auth.require!

  env.html layout("Confirm your password", <<-HTML)
    <h1>Confirm your password</h1>
    <p>Not the second factor — the password.</p>
    <form method="post" action="/account/confirm-password">
      <input type="hidden" name="_csrf" value="#{env.auth.csrf_token}">
      <p><label>Password <input name="password" type="password" autocomplete="current-password"></label></p>
      <button type="submit">Confirm</button>
    </form>
    HTML
end

post "/account/confirm-password" do |env|
  principal = env.auth.require!
  account = KemalIdentity.app.accounts.find_by_id(principal.subject)
  next env.redirect "/" if account.nil?

  result = KemalIdentity.app.passwords.authenticate(
    # Already normalised, and `Passwords::Authenticator` normalises what it is given — the same
    # value either way. A confirmation form asks for the password and not the login: whoever is
    # signed in has already said who they are.
    login: account.normalized_login,
    password: env.params.body["password"]? || "",
    ip: env.request.remote_address.try(&.to_s),
  )

  case result
  in KemalIdentity::Authenticated
    # **Not** `start!(result.principal)`. That would work and would also throw this session back
    # down to `AssuranceLevel::Password`, spending the second factor to confirm a password.
    # `password_verified!` takes the level from the session that already exists and only raises
    # it.
    env.auth.password_verified!
    env.redirect "/account/link"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    env.redirect "/account/confirm-password"
  end
end

puts "listening on http://localhost:3000 — log in, enrol, then compare /vault with /account/link"
Kemal.run

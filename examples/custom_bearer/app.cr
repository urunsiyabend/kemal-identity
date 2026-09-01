# A credential this shard does not ship: a token an API gateway issued, accepted alongside the
# shard's own.
#
# The persona is a company that already has a token format — a gateway-minted key, an HMAC
# header, a legacy credential kept alive during a migration — and needs the application to accept
# it without giving up anything the shard does for the credentials it does ship.
#
# CI compiles this on every matrix entry.
#
#     crystal run examples/custom_bearer/app.cr
#
#     curl -i localhost:3000/me -H "Authorization: Bearer gw.ada.<signature>"   # printed on boot
#     curl -i localhost:3000/me -H "Authorization: Bearer gw.ada.0000000000000000"
#     curl -i localhost:3000/me -H "Authorization: Bearer $SHARD_TOKEN"          # printed on boot
#     curl -i -X POST localhost:3000/things -H "Authorization: Bearer gw.ada.<signature>"
#
# The last two matter most: the shard's own token still resolves through the shard, and a
# mutation carrying only a gateway token is exempt from CSRF — because `bearer_authenticators:`
# put your authenticator where the rest of the shard can see it.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

GATEWAY_SECRET = ENV["GATEWAY_SECRET"]? || "development-only-gateway-secret"

# ---------------------------------------------------------------------------------------
# The contract: one method.
#
# `authenticate` receives the raw credential — the part of the `Authorization` header after the
# scheme — and answers one of three things. Which one it answers is the whole design:
#
#   Anonymous                      nothing was presented
#   Failed(MalformedCredential)    "this is not a credential of mine"  → the chain tries the next
#   anything else                  recognised, and rejected on its merits → the chain STOPS
#
# That last rule is why `MalformedCredential` must be the only reason you use for "not mine".
# Falling through on a revoked or expired credential would let it get a second opinion from an
# authenticator that never issued it.
#
# Two more rules, both load-bearing:
#
#   * Never raise for anything a client controls. A two-megabyte header is a `Failed`, not a 500.
#   * Check shape before any I/O. The fall-through to the next authenticator should cost a length
#     comparison, not a database round trip — otherwise every authenticator in the chain queries
#     for every request.
# ---------------------------------------------------------------------------------------
class GatewayAuthenticator < KemalIdentity::RequestAuthenticator
  PREFIX = "gw."

  def initialize(@secret : String, @accounts : KemalIdentity::Accounts::Repository)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    # Shape first, and nothing but shape. No allocation of consequence, no I/O.
    unless credential.starts_with?(PREFIX) && credential.count('.') == 2
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    _, subject, signature = credential.split('.')
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential) if subject.empty?

    # Constant-time, because a byte-by-byte comparison of a signature is a byte-by-byte oracle.
    expected = OpenSSL::HMAC.hexdigest(:sha256, @secret, subject)[0, 16]
    unless Crypto::Subtle.constant_time_compare(signature, expected)
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential)
    end

    # The gateway vouches for the subject; this application still decides whether that subject
    # may act. An account that has been disabled here is refused whatever the gateway says.
    account = @accounts.find_by_id(subject)
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential) if account.nil?
    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::DisabledAccount) if account.disabled?

    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: account.id,
        # Not `Password`: nobody typed anything. `require_fresh!` and any permission whose
        # `minimum_assurance` is higher will refuse this credential, which is correct — a
        # gateway token cannot be re-authenticated interactively.
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: Time.utc,
        # `Custom` is what `CredentialKind` has for credentials the shard does not ship. Naming
        # the credential here is what lets an audit line say *which* one was refused, and lets
        # `authorize!` attenuate the account by the gateway's own scopes.
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::Custom,
          id: "gw-#{account.id}",
          name: "api gateway",
          scopes: ["things.write"],
        ),
      )
    )
  end

  # What the gateway would run. Here so the example can print a working credential.
  def self.mint(secret : String, subject : String) : String
    "#{PREFIX}#{subject}.#{OpenSSL::HMAC.hexdigest(:sha256, secret, subject)[0, 16]}"
  end
end

DATABASE = DB.open("sqlite3://#{ENV["DB_PATH"]? || "./kemal_identity_gateway_example.db"}?journal_mode=wal&busy_timeout=5000")

Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';').each do |statement|
    next if statement.strip.empty?
    DATABASE.exec(statement) rescue nil # already applied
  end
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)

if ACCOUNTS.find_by_id("ada").nil?
  now = Time.utc
  DATABASE.exec(<<-SQL, "ada", "ada@example.com", now, now)
    INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at)
    VALUES (?, ?, 1, ?, ?)
    SQL
end

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),

  # The shard's own token family, kept on purpose: this application accepts both.
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),

  # ---------------------------------------------------------------------------------------
  # The registration. Your authenticators join the same chain, after the shipped ones, in the
  # order you list them.
  #
  # This is a configuration parameter rather than a handler you write, and the reason is that
  # `Application#bearer` is read by more than the resolution: `ErrorHandler` asks it whether to
  # send an RFC 6750 challenge, and `CSRFHandler` asks it whether a token-only mutation is exempt
  # from CSRF. An application that resolved its own credential in a handler of its own got
  # neither — no `WWW-Authenticate` on any 401, and a 403 CSRF on requests no browser can forge.
  #
  # **One owner per shape.** The chain stops at the first authenticator that recognises a
  # credential and rejects it, so an authenticator of yours that claims a shape the shard also
  # claims will never see it. `gw.` collides with nothing. If yours were JWT-shaped you would
  # hold every issuer's validator yourself and not configure `jwt:` at all; if it looked like an
  # opaque token you would move the shard's prefix with `api_token_prefix:`.
  # ---------------------------------------------------------------------------------------
  bearer_authenticators: [
    GatewayAuthenticator.new(GATEWAY_SECRET, ACCOUNTS).as(KemalIdentity::RequestAuthenticator),
  ],

  hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
  cookie: KemalIdentity::Sessions::CookieConfig.new(
    name: "kemal_identity", secure: false, allow_insecure: true
  ),
  csrf: KemalIdentity::CSRFConfig.new(
    secret: ENV["CSRF_SECRET"]? || "development-only-secret-at-least-32-bytes",
    cookie_name: "kemal_identity_csrf",
    secure: false,
  ),
)

ADA         = ACCOUNTS.find_by_id("ada") || raise "seeding the account failed"
SHARD_TOKEN = KemalIdentity.app.api!.issue(ADA, "ada-cli")

puts
puts "GATEWAY_TOKEN=#{GatewayAuthenticator.mint(GATEWAY_SECRET, "ada")}"
puts "SHARD_TOKEN=#{SHARD_TOKEN.token.reveal}"
puts

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, realm: "api")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new

get "/me" do |env|
  principal = env.auth.require!
  credential = env.auth.credential

  {
    subject: principal.subject,
    kind:    credential.try(&.kind.to_s),
    name:    credential.try(&.name),
  }.to_json
end

# A mutation. With only a bearer credential it is exempt from CSRF; add a session cookie and it
# is not, because a request carrying a cookie is one a browser might have been tricked into
# sending.
post "/things" do |env|
  env.auth.require!
  {created: true}.to_json
end

Kemal.config.port = 3000
Kemal.run

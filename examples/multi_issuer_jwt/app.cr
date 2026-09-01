# A resource server accepting JWTs from more than one issuer.
#
# The shape of the problem: `AuthenticatorChain` routes on *shape*, and every JWT has the same
# shape. Two `JWT::Validator`s therefore cannot be chained — the first one recognises the token,
# rejects it on the signature, and the chain correctly stops rather than offering a rejected
# credential to somebody else for a second opinion.
#
# So routing between issuers is the application's, and `JWT.unverified_issuer` is the bounded
# read that makes it safe to write. Measured in `blueprints/0025-maturity-validation-results.md`
# (JWT-01).
#
# CI compiles this on every matrix entry.
#
#     crystal run examples/multi_issuer_jwt/app.cr
#
#     curl -i localhost:3000/me -H "Authorization: Bearer $PARTNER_A"
#     curl -i localhost:3000/me -H "Authorization: Bearer $PARTNER_B"
#     curl -i localhost:3000/me -H "Authorization: Bearer $CROSS_SIGNED"   # A's issuer, B's key
#     curl -i localhost:3000/me -H "Authorization: Bearer $UNKNOWN_ISSUER"

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

# Two tenants of this API, each with its own issuer and its own signing key. In production these
# would be RS256 with a JWKS endpoint per issuer; HS256 keeps the example self-contained.
ISSUERS = {
  "https://partner-a.example" => KemalIdentity::Secret.new("partner-a-signing-key-32-bytes!!"),
  "https://partner-b.example" => KemalIdentity::Secret.new("partner-b-signing-key-32-bytes!!"),
}

AUDIENCE = "https://api.example.com"

# ---------------------------------------------------------------------------------------
# One validator per issuer, and the router in front of them.
#
# `JWT.unverified_issuer` reads `iss` out of a token nothing has verified yet. That is safe for
# exactly one purpose — deciding *which* validator to hand the token to — and the name says
# `unverified` so no call site can pretend otherwise. It is bounded before it decodes anything and
# it reuses the validator's own strict base64url, because a second decoder that *almost* agrees
# with the first is how one token comes to mean two different things.
#
# Everything after the routing is the chosen validator's ordinary work: signature, `iss`, `aud`,
# `exp`, `nbf`, algorithm allow-list, maximum lifetime, purpose claim.
# ---------------------------------------------------------------------------------------
class IssuerRouter < KemalIdentity::RequestAuthenticator
  def initialize(@validators : Hash(String, KemalIdentity::JWT::Validator))
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    issuer = KemalIdentity::JWT.unverified_issuer(credential)

    # Two different "not mine", answered identically on purpose: a token that is not a JWT at all,
    # and a JWT from an issuer this API does not know. Answering differently would let a caller
    # enumerate which issuers are configured. `MalformedCredential` is also the only reason the
    # chain reads as "try the next authenticator".
    return malformed if issuer.nil?

    validator = @validators[issuer]?
    return malformed if validator.nil?

    validator.authenticate(credential)
  end

  private def malformed : KemalIdentity::Outcome
    KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
  end
end

VALIDATORS = ISSUERS.to_h do |issuer, secret|
  {
    issuer,
    KemalIdentity::JWT::Validator.new(
      keyring: KemalIdentity::JWT::Keyring.new(KemalIdentity::JWT::HS256, secret),
      issuer: issuer,
      audience: AUDIENCE,
      algorithms: ["HS256"],
      clock: KemalIdentity::SystemClock.new,

      # A JWT cannot be revoked before its `exp`, so keep the window small. `max_lifetime`
      # refuses a token whose own `exp` is further out than this, however the issuer felt about
      # it — a partner minting twelve-hour tokens does not get to decide this API's exposure.
      max_lifetime: 15.minutes,

      # An access token is not a password-reset token. Requiring a purpose claim stops one being
      # presented as the other, which is the confusion `blueprints/0016` exists for.
      purpose: "access",
    ),
  }
end

DATABASE = DB.open("sqlite3://#{ENV["DB_PATH"]? || "./kemal_identity_jwt_example.db"}?journal_mode=wal&busy_timeout=5000")

Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';').each do |statement|
    next if statement.strip.empty?
    DATABASE.exec(statement) rescue nil # already applied
  end
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)

{"a-alice", "b-bob"}.each do |who|
  next unless ACCOUNTS.find_by_id(who).nil?
  now = Time.utc
  DATABASE.exec(<<-SQL, who, "#{who}@example.com", now, now)
    INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at)
    VALUES (?, ?, 1, ?, ?)
    SQL
end

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),

  # Note what is *not* here: `jwt:`. One owner per shape — configuring a shipped validator
  # alongside a JWT-shaped authenticator of your own means the shipped one claims every JWT and
  # yours never runs. The router owns the shape, and holds every issuer's validator inside it.
  bearer_authenticators: [IssuerRouter.new(VALIDATORS).as(KemalIdentity::RequestAuthenticator)],

  hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
)

# Minting tokens is out of scope for this shard — it validates and deliberately does not issue —
# so the example signs its own, exactly as a partner's identity provider would.
def mint(issuer : String, subject : String, secret : KemalIdentity::Secret, lifetime = 5.minutes) : String
  header = {"alg" => "HS256", "typ" => "JWT"}
  now = Time.utc
  claims = {
    "iss"     => issuer,
    "sub"     => subject,
    "aud"     => AUDIENCE,
    "purpose" => "access",
    "iat"     => now.to_unix,
    "exp"     => (now + lifetime).to_unix,
  }

  encode = ->(json : String) { Base64.urlsafe_encode(json, padding: false) }
  signing_input = "#{encode.call(header.to_json)}.#{encode.call(claims.to_json)}"
  signature = OpenSSL::HMAC.digest(:sha256, secret.reveal, signing_input)

  "#{signing_input}.#{Base64.urlsafe_encode(signature, padding: false)}"
end

a_secret = ISSUERS["https://partner-a.example"]
b_secret = ISSUERS["https://partner-b.example"]

puts
puts "PARTNER_A=#{mint("https://partner-a.example", "a-alice", a_secret)}"
puts "PARTNER_B=#{mint("https://partner-b.example", "b-bob", b_secret)}"
# Claims to be from A, signed with B's key. Routed to A's validator, which refuses it on the
# signature — the routing decides *who checks*, never *whether it is valid*.
puts "CROSS_SIGNED=#{mint("https://partner-a.example", "a-alice", b_secret)}"
puts "UNKNOWN_ISSUER=#{mint("https://stranger.example", "nobody", a_secret)}"
puts

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, realm: "api")
use KemalIdentity::Kemal::AuthenticationHandler.new

get "/me" do |env|
  principal = env.auth.require!

  {
    subject:   principal.subject,
    kind:      env.auth.credential.try(&.kind.to_s),
    assurance: principal.assurance.to_s,
  }.to_json
end

Kemal.config.port = 3000
Kemal.run

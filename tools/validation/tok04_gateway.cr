require "kemal_identity"

# TOK-04 — the smallest useful implementation of the published `RequestAuthenticator` contract.
#
# The persona: an API gateway in front of the application already issues its own tokens, and the
# application has to accept them alongside whatever kemal_identity issues. The format here is
# deliberately not either of the shard's own — `gw.<subject>.<signature>` — so that shape routing
# has something real to route on.
class GatewayAuthenticator < KemalIdentity::RequestAuthenticator
  PREFIX = "gw."

  getter calls = 0

  def initialize(@secret : String, @clock : KemalIdentity::Clock, @revoked = Set(String).new)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    @calls += 1

    # Nothing presented.
    return KemalIdentity::Anonymous.new if credential.nil? || credential.empty?

    # Not a credential of mine. `MalformedCredential` is the only reason the chain treats as an
    # invitation to try the next authenticator, so the distinction the scenario asks about is
    # expressed here and nowhere else.
    unless credential.starts_with?(PREFIX) && credential.count('.') == 2
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential)
    end

    _, subject, signature = credential.split('.')

    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential) if subject.empty?

    expected = OpenSSL::HMAC.hexdigest(:sha256, @secret, subject)[0, 16]
    unless Crypto::Subtle.constant_time_compare(signature, expected)
      return KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential)
    end

    return KemalIdentity::Failed.new(KemalIdentity::FailureReason::Revoked) if @revoked.includes?(subject)

    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: subject,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: @clock.now,
        # The metadata the scenario asks about: `Custom` exists for exactly this, and the
        # gateway's own scopes attenuate the account the same way an issued token's do.
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::Custom,
          id: "gw-#{subject}",
          name: "api gateway",
          scopes: ["invoices.read"],
        ),
      )
    )
  end

  def revoke(subject : String) : Nil
    @revoked << subject
  end

  def self.mint(secret : String, subject : String) : String
    "#{PREFIX}#{subject}.#{OpenSSL::HMAC.hexdigest(:sha256, secret, subject)[0, 16]}"
  end
end

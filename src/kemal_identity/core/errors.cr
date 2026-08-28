module KemalIdentity
  # Base class for everything this shard raises.
  #
  # An error message must never contain a login, a token, or a digest. `"session not
  # found"`, not `"session #{digest} not found"`. Expected authentication failures are
  # values (`Failed`), not exceptions — the only deliberate exceptions on the
  # authentication path are `require!` and `require_fresh!`, which raise so that a route
  # guard can be one line.
  class Error < Exception; end

  # Raised at boot only, for an unusable configuration. Never raised while serving a
  # request: a configuration that would produce a cookie the browser discards must fail
  # at startup, loudly.
  class ConfigurationError < Error; end

  # A dependency the shard does not control failed: the database, the crypto backend.
  # Distinct from an authentication failure, which is a value.
  class InfrastructureError < Error; end

  # Raised by `require!` when the request carries no usable credential. Mapped to 401.
  class NotAuthenticatedError < Error; end

  # Raised when a state-changing request carries no valid CSRF token. Mapped to 403.
  #
  # This extends the taxonomy in `src/CLAUDE.md` by one class, deliberately: a CSRF rejection
  # is neither "not authenticated" (the caller may well be) nor "not fresh enough" (their
  # authentication is fine), and collapsing it into either would make the two existing classes
  # mean less. See `blueprints/0009-csrf-token-scheme.md`.
  class CSRFError < Error; end

  # Raised by `require_fresh!` when the principal is authenticated but not recently
  # enough, or at too low an assurance level. Mapped to 403 — the caller is known, they
  # simply have to prove it again.
  class FreshAuthenticationRequiredError < Error; end

  # Raised by `authorize!` when the caller is authenticated and simply not allowed. Mapped to
  # 403.
  #
  # Deliberately not `NotAuthenticatedError`: answering a denied action with a 401 tells the
  # caller to log in again, which for somebody who is already logged in is both wrong and a
  # loop. It is also not `FreshAuthenticationRequiredError` — proving themselves again would
  # change nothing, because the problem is the grant and not the credential.
  #
  # The message must not name the permission, the tenant, or the reason. `Authz::DenialReason`
  # exists for the audit log; a response that varies with it tells an attacker whether the
  # tenant they guessed exists and whether they are inside it.
  class ForbiddenError < Error; end
end

module KemalIdentity::Kemal
  # Whether a path is inside a prefix's subtree.
  #
  # Public because an application writing its own handler needs exactly this rule, and the
  # tempting one-liner is wrong: `path.starts_with?("/admin")` also matches
  # `/administrators`, which hands an attacker an unguarded path that looks guarded. One
  # implementation rather than two that almost agree — `PathGuard` and `ErrorHandler` both
  # ask here.
  module PathPrefix
    # `/admin` covers `/admin`, `/admin/` and `/admin/users`, and not `/administrators`.
    # A prefix of `/` covers everything.
    def self.covers?(prefix : String, path : String) : Bool
      return true if prefix == "/"
      return false unless path.starts_with?(prefix)

      rest = path[prefix.size..]
      rest.empty? || rest.starts_with?('/')
    end

    # Normalises a configured prefix: `"/admin/"` and `"/admin"` are the same subtree rather
    # than two subtly different ones. Raises for a prefix that is not a path.
    def self.normalise(prefix : String) : String
      raise ConfigurationError.new("prefix must start with \"/\"") unless prefix.starts_with?('/')

      prefix == "/" ? "/" : prefix.rstrip('/')
    end
  end

  # Requires authentication for a whole path subtree.
  #
  # ### It matches the path itself, for every method
  #
  # Deliberately not `only ["/admin/*"]`. On Kemal 1.10.0 – 1.12.0 that rule defaults to `GET`
  # and does not match `HEAD`, so middleware scoped that way never ran on a `HEAD` request
  # while the `GET` handler executed and returned the headers it set. 1.13.0 fixes it; the
  # floor does not have the fix, and matching on the path alone is immune either way.
  #
  # The same property makes new methods safe by default: HTTP QUERY arrived in Kemal 1.13.0
  # and this guard covered it without a change, because there was never a list of methods to
  # forget to update.
  #
  # ```
  # use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
  # use KemalIdentity::Kemal::PathGuard.new(prefix: "/account", within: 5.minutes)
  # ```
  #
  # ### Reject before touching params
  #
  # The guard answers from the request path alone and never reads `env.params`. On Kemal
  # 1.10.0 – 1.12.0, anything that parsed a multipart body and then rejected the request
  # leaked the temporary files it spooled, permanently — so an unauthenticated client could
  # fill the disk one *rejected* upload at a time (`docs/04-kemal-integration.md`).
  class PathGuard < ::Kemal::Handler
    getter prefix : String

    # `within` turns this into a step-up guard: the subtree then needs authentication that is
    # also *recent*, and a session restored from a remember-me cookie will never satisfy it.
    #
    # `credentials` says which *kinds* of credential the subtree accepts, for the monolith that
    # serves pages and an API from one process:
    #
    # ```
    # use KemalIdentity::Kemal::PathGuard.new(
    #   prefix: "/api", credentials: [KemalIdentity::CredentialKind::ApiToken, KemalIdentity::CredentialKind::Jwt]
    # )
    # ```
    #
    # A credential of another kind is refused with `ForbiddenError` — a 403, not a 401: the
    # caller is authenticated, they are using the wrong door, and telling them to log in again
    # would be a loop. The refusal is deliberately *after* `require!`, so an anonymous request
    # is still a 401 and nobody learns which credential classes a subtree takes without first
    # holding one.
    #
    # `CredentialKind::Custom` covers every credential an application's own
    # `RequestAuthenticator` establishes, so a deployment with two custom families cannot tell
    # them apart here — `CredentialRef#name` is what distinguishes those, and a subtree that
    # needs to select on it writes its own handler (`blueprints/0021`).
    def initialize(
      prefix : String,
      @within : Time::Span? = nil,
      @assurance : AssuranceLevel? = nil,
      @credentials : Array(CredentialKind)? = nil,
    )
      if credentials = @credentials
        if credentials.empty?
          # An empty list accepts nothing, which is a subtree nobody can ever reach. Almost
          # certainly a list built from configuration that came back empty, so it fails at boot
          # rather than 403-ing every request in production.
          raise ConfigurationError.new(
            "credentials must name at least one kind, or be nil to accept any"
          )
        end
      end

      @prefix = PathPrefix.normalise(prefix)
    end

    def call(env : HTTP::Server::Context)
      return call_next(env) unless guards?(env.request.path)

      principal =
        if within = @within
          env.auth.require_fresh!(within: within)
        elsif assurance = @assurance
          env.auth.require_assurance!(assurance)
        else
          env.auth.require!
        end

      if accepted = @credentials
        kind = principal.credential.try(&.kind)

        # A principal no credential produced is refused too. It cannot happen through the
        # handler chain, but an application that installs its own outcome could produce one,
        # and "no credential" is not a member of any accepted list.
        unless kind && accepted.includes?(kind)
          Log.info &.emit(
            "authn.wrong_credential_class",
            subject: principal.subject, path: env.request.path,
            presented: kind.to_s, credential: principal.credential.try(&.id),
          )

          raise ForbiddenError.new("credential class not accepted here")
        end
      end

      call_next(env)
    end

    # Whether this guard covers `path`.
    #
    # The subtree, and only the subtree. `/admin` guards `/admin`, `/admin/`, and
    # `/admin/users` — and pointedly **not** `/administrators`, which a naive
    # `starts_with?` would hand to an attacker as an unguarded path that looks guarded.
    def guards?(path : String) : Bool
      PathPrefix.covers?(@prefix, path)
    end
  end
end

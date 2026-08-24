module KemalIdentity::Kemal
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
    def initialize(prefix : String, @within : Time::Span? = nil, @assurance : AssuranceLevel? = nil)
      raise ConfigurationError.new("prefix must start with \"/\"") unless prefix.starts_with?('/')

      # Stored without a trailing slash so that "/admin/" and "/admin" configure the same
      # subtree rather than two subtly different ones.
      @prefix = prefix == "/" ? "/" : prefix.rstrip('/')
    end

    def call(env : HTTP::Server::Context)
      return call_next(env) unless guards?(env.request.path)

      if within = @within
        env.auth.require_fresh!(within: within)
      elsif assurance = @assurance
        env.auth.require_assurance!(assurance)
      else
        env.auth.require!
      end

      call_next(env)
    end

    # Whether this guard covers `path`.
    #
    # The subtree, and only the subtree. `/admin` guards `/admin`, `/admin/`, and
    # `/admin/users` — and pointedly **not** `/administrators`, which a naive
    # `starts_with?` would hand to an attacker as an unguarded path that looks guarded.
    def guards?(path : String) : Bool
      return true if @prefix == "/"
      return false unless path.starts_with?(@prefix)

      rest = path[@prefix.size..]
      rest.empty? || rest.starts_with?('/')
    end
  end
end

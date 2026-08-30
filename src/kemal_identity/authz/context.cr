module KemalIdentity::Authz
  # Everything an authorization question carries besides the principal and the permission.
  #
  # ### Why a context object rather than more parameters
  #
  # `Authorizer#decide` is frozen at v1.0, and the last time it needed something new — a
  # resource — there was nowhere to put it. A struct the shard owns can gain a defaulted field
  # without breaking a caller, a constructor or a read site, which was measured rather than
  # assumed (`blueprints/0022-authorization-context-and-denials.md`). This is the pressure valve
  # that keeps `Authorizable` at two methods and `decide` at one shape.
  #
  # ### The credential is not here
  #
  # It was, in the first draft, so that an authorizer would read one object instead of two. That
  # was wrong, and testing caught it: the tenant-only `decide` overload built a context without
  # one, so every call through that form silently skipped scope attenuation and an attenuated
  # token came back unrestricted. A fail-open, from a field that had two homes and no rule
  # keeping them equal.
  #
  # `Principal#credential` is the single source. An authorizer that needs it reads it there —
  # the principal is the first argument to `decide`, so it is never further away than this
  # would have been.
  #
  # ### There is no `at : Time` here
  #
  # An authorizer that reasons about time has a `Clock` injected, as `RBAC` does. A timestamp on
  # the context would be a second source of "now" that no injected clock controls, and
  # `src/CLAUDE.md` bans `Time.utc` outside `SystemClock` precisely so there is only one.
  struct Context
    # The tenant the question is about.
    #
    # `nil` asks outside any tenant, which is not "any tenant": a permission held only inside
    # tenant A is not granted by a check that names no tenant, and a route that forgets to pass
    # the tenant it is operating on gets a denial rather than a quiet upgrade to global scope.
    getter tenant_id : String?

    # The thing being acted on, when there is one.
    getter resource : Authorizable?

    # Environment the policy may consider: a device posture, a region, a change window. Free
    # keys, so a new one needs no type change anywhere.
    getter attributes : Hash(String, String)?

    def initialize(
      @tenant_id : String? = nil,
      @resource : Authorizable? = nil,
      @attributes : Hash(String, String)? = nil,
    )
    end

    # One environment attribute, or `nil`. Missing denies at the policy, rather than raising
    # here.
    def [](key : String) : String?
      @attributes.try(&.[key]?)
    end
  end
end

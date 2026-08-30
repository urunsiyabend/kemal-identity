module KemalIdentity::Authz
  # Decides whether a principal may perform an action.
  #
  # ### Why this is not part of authentication
  #
  # `docs/06-roadmap.md` puts authorization last on purpose. Authentication answers "who is
  # this", authorization answers "and may they", and the two have different lifetimes: a
  # session is minted once and lives for days, while a grant can be taken away in the middle of
  # it. Baking the second into the first is what produces an application where firing somebody
  # takes effect when their session happens to expire.
  #
  # Which is the reason `Principal` carries no roles and no permissions, and why nothing here
  # writes any into a session or a token. Every check reads the current answer — from the
  # store, or from a cache measured in seconds and documented as such.
  #
  # ### Implementing it directly
  #
  # `RBAC` is the implementation this shard ships, and it is deliberately opinionated: roles in
  # code, assignments in the database, no wildcards. An application whose authorization model
  # is genuinely different — attribute-based rules, per-record ownership, roles administered at
  # runtime — subclasses this instead and keeps everything else. That is the whole reason
  # authorization is a contract rather than a table.
  abstract class Authorizer
    # The decision, with the reason or the granting role attached.
    #
    # `context` carries the tenant, the resource being acted on, environment attributes and the
    # credential that proved the request. A `Context` rather than a longer parameter list
    # because this method is frozen at v1.0: the last time it needed something new — a resource
    # — there was nowhere to put it, and an application implementing ownership rules had to
    # bypass `env.auth` and lose the audit line, the step-up mapping and the uniform 403 along
    # with it (`blueprints/0022-authorization-context-and-denials.md`).
    #
    # `context.tenant_id` nil asks the question outside any tenant. That is not "any tenant": a
    # permission held only inside tenant A is not granted by a check that names no tenant, and
    # a route that forgets to pass the tenant it is operating on gets a denial rather than a
    # quiet upgrade to global scope.
    abstract def decide(principal : Principal, permission : String, context : Context) : Decision

    # The tenant-only form, kept because it is what most call sites want and what every
    # implementation before v0.8 was written against.
    def decide(principal : Principal, permission : String, tenant_id : String? = nil) : Decision
      decide(principal, permission, Context.new(tenant_id: tenant_id))
    end

    # The yes or no, for a call site that does not need the reason — a template deciding
    # whether to render a button.
    def can?(principal : Principal, permission : String, context : Context) : Bool
      decide(principal, permission, context).permitted?
    end

    # :ditto:
    def can?(principal : Principal, permission : String, tenant_id : String? = nil) : Bool
      decide(principal, permission, tenant_id).permitted?
    end
  end

  # Permits nothing, ever.
  #
  # The default when an application has configured authorization types but not yet a store, and
  # what a spec uses to prove that a route is actually guarded. Denying everything is the only
  # safe thing an unconfigured authorizer can do — an authorizer that permitted everything
  # would turn a wiring mistake into an open application.
  class DenyAll < Authorizer
    def decide(principal : Principal, permission : String, context : Context) : Decision
      Forbidden.not_permitted(permission, context.tenant_id)
    end
  end
end

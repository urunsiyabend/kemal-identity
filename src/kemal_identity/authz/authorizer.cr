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
    # `tenant_id` nil asks the question outside any tenant. That is not "any tenant": a
    # permission held only inside tenant A is not granted by a check that names no tenant, and
    # a route that forgets to pass the tenant it is operating on gets a denial rather than a
    # quiet upgrade to global scope.
    abstract def decide(principal : Principal, permission : String, tenant_id : String? = nil) : Decision

    # The yes or no, for a call site that does not need the reason — a template deciding
    # whether to render a button.
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
    def decide(principal : Principal, permission : String, tenant_id : String? = nil) : Decision
      Forbidden.new(permission, DenialReason::NotPermitted, tenant_id)
    end
  end
end

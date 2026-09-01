require "kemal_identity"

# TOK-02 — a fine-grained personal token, shaped the way GitHub's actually is: the token carries
# permissions, and the *resources* it may touch are a selection stored server-side against the
# token's identity. The application owns that table; the shard supplies the token id
# (`CredentialRef#id`) and the target (`Authz::Context`).
struct TokenRestriction
  getter organisations : Set(String)
  getter repositories : Set(String)

  def initialize(@organisations : Set(String), @repositories : Set(String))
  end

  def permits_organisation?(id : String?) : Bool
    return false if id.nil?
    @organisations.includes?(id)
  end

  def permits_repository?(id : String?) : Bool
    return true if id.nil?              # not a repository-scoped action
    return true if @repositories.empty? # "all repositories in the selected organisations"
    @repositories.includes?(id)
  end
end

# A repository object the application authorises against.
struct Repo
  include KemalIdentity::Authz::Authorizable

  getter id : String
  getter organisation : String

  def initialize(@id : String, @organisation : String)
  end

  def authz_type : String
    "repo"
  end

  def authz_id : String
    @id
  end
end

# The application's authorizer: the account's grant first, the token's selection second.
class FineGrainedAuthorizer < KemalIdentity::Authz::Authorizer
  # Every denial this adds uses one code, so that "no such repository" and "a repository this
  # token was not selected for" are indistinguishable from outside.
  OPAQUE = "resource_not_available"

  getter restriction_lookups = 0

  def initialize(
    @inner : KemalIdentity::Authz::Authorizer,
    @restrictions : Hash(String, TokenRestriction),
    @known_repositories : Hash(String, Repo),
  )
  end

  def decide(
    principal : KemalIdentity::Principal,
    permission : String,
    context : KemalIdentity::Authz::Context,
  ) : KemalIdentity::Authz::Decision
    decision = @inner.decide(principal, permission, context)
    return decision unless decision.permitted?

    credential = principal.credential
    # A browser session carries no restriction row and is not attenuated by one.
    return decision if credential.nil?

    id = credential.id
    return decision if id.nil?

    @restriction_lookups += 1
    restriction = @restrictions[id]?
    return decision if restriction.nil?

    unless restriction.permits_organisation?(context.tenant_id)
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: OPAQUE, tenant_id: context.tenant_id
      )
    end

    # The resource half. A repository the application does not know and a repository this token
    # was not selected for take the same branch on purpose.
    resource = context.resource
    if resource && resource.authz_type == "repo"
      repo = @known_repositories[resource.authz_id]?

      if repo.nil? || repo.organisation != context.tenant_id ||
         !restriction.permits_repository?(repo.id)
        return KemalIdentity::Authz::Forbidden.policy(
          permission, code: OPAQUE, tenant_id: context.tenant_id
        )
      end
    end

    decision
  end
end

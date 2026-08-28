module KemalIdentity::Authz
  # Role-based authorization over a `Repository`, with tenancy.
  #
  # ### The order the checks run in
  #
  # 1. **Is the permission declared?** An undeclared name is a typo or a half-finished rename,
  #    and it is refused before anything is read.
  # 2. **Is the principal bound to a different tenant?** A session issued inside tenant A
  #    asking about tenant B is refused without consulting membership at all. This is the
  #    horizontal escalation attempt — the identifier in the URL swapped for somebody else's —
  #    and it is the one check that must not depend on a database row being correct.
  # 3. **Does any role the principal actually holds grant it?** Global roles always count.
  #    Tenant roles count only for a member.
  # 4. **Have they proved who they are strongly enough?** Last, so that a denial for weak
  #    assurance is distinguishable in the trail from a denial for having no grant at all.
  #
  # ### Tenant roles are inert without a membership
  #
  # Holding `finance_admin` in tenant A grants nothing unless there is also a membership row
  # for A. Two rows to say one thing, and the redundancy is the point: removing somebody from a
  # tenant is then a single row that revokes everything at once, and it cannot be defeated by a
  # role assignment that was missed in the cleanup.
  #
  # A **global** assignment — `tenant_id` nil — is not gated this way. It applies everywhere,
  # including inside every tenant, which is what makes it the dangerous kind of grant and why
  # `Assignment#granted_by` exists.
  class RBAC < Authorizer
    getter catalog : RoleCatalog
    getter store : Repository
    getter cache : Cache?

    def initialize(
      @catalog : RoleCatalog,
      @store : Repository,
      @clock : Clock = SystemClock.new,
      @random : RandomSource = SecureRandomSource.new,
      @cache : Cache? = nil,
    )
    end

    def decide(principal : Principal, permission : String, tenant_id : String? = nil) : Decision
      declared = @catalog.registry[permission]?
      return Forbidden.new(permission, DenialReason::UnknownPermission, tenant_id) if declared.nil?

      if cross_tenant?(principal, tenant_id)
        return Forbidden.new(permission, DenialReason::TenantMismatch, tenant_id)
      end

      grants = grants_for(principal.subject, tenant_id)
      via = granting_role(grants, permission, tenant_id)

      if via.nil?
        return Forbidden.new(permission, denial_for(grants, tenant_id), tenant_id)
      end

      unless principal.at_least?(declared.minimum_assurance)
        return Forbidden.new(permission, DenialReason::InsufficientAssurance, tenant_id)
      end

      Permitted.new(permission, via, tenant_id)
    end

    # Every permission this principal currently holds, for a screen that renders a menu.
    #
    # Not for guarding an action — a route guards with `#decide`, against the permission it is
    # about to perform, at the moment it performs it. A list handed to a template is a snapshot,
    # and a snapshot used as an authorization decision is the stale-grant problem this whole
    # module exists to avoid.
    #
    # Assurance is **not** applied here: the list says what the account has been granted, not
    # what it can do at this instant, so a menu can show an action and let the step-up prompt
    # happen when it is clicked.
    def permissions_for(principal : Principal, tenant_id : String? = nil) : Array(String)
      return [] of String if cross_tenant?(principal, tenant_id)

      grants = grants_for(principal.subject, tenant_id)
      names = Set(String).new

      effective_roles(grants, tenant_id).each do |role_name|
        role = @catalog[role_name]?
        next if role.nil?

        names.concat(role.permissions)
      end

      names.to_a.sort!
    end

    # Grants a role, and drops this process's cached copy of the account's grants.
    #
    # Administration goes through here rather than straight to the repository so that the cache
    # cannot be left holding an answer the database no longer agrees with. Behind several
    # processes the others still wait out the TTL — `Cache` says why that is the honest bound.
    #
    # Raises `ArgumentError` for a role the catalog does not define. A row naming a role that
    # does not exist grants nothing, forever, and looks like it grants something.
    def grant(
      account_id : String,
      role : String,
      tenant_id : String? = nil,
      granted_by : String? = nil,
    ) : Bool
      unless @catalog.defined?(role)
        raise ArgumentError.new("role #{role.inspect} is not defined in this catalog")
      end

      granted = @store.grant(Assignment.new(
        id: @random.token,
        account_id: account_id,
        role: role,
        granted_at: @clock.now,
        tenant_id: tenant_id,
        granted_by: granted_by,
      ))

      invalidate(account_id)

      Log.info &.emit(
        "authz.granted", account: account_id, role: role, tenant: tenant_id, by: granted_by
      ) if granted

      granted
    end

    def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool
      revoked = @store.revoke(account_id, role, tenant_id)
      invalidate(account_id)

      Log.info &.emit("authz.revoked", account: account_id, role: role, tenant: tenant_id) if revoked

      revoked
    end

    def add_member(account_id : String, tenant_id : String) : Bool
      added = @store.add_member(Membership.new(
        id: @random.token, account_id: account_id, tenant_id: tenant_id, created_at: @clock.now
      ))

      invalidate(account_id)

      Log.info &.emit("authz.member_added", account: account_id, tenant: tenant_id) if added

      added
    end

    # Removes somebody from a tenant, taking that tenant's roles with them — see
    # `Repository#remove_member` for why those are one operation.
    def remove_member(account_id : String, tenant_id : String) : Bool
      removed = @store.remove_member(account_id, tenant_id)
      invalidate(account_id)

      Log.info &.emit("authz.member_removed", account: account_id, tenant: tenant_id) if removed

      removed
    end

    def member?(account_id : String, tenant_id : String) : Bool
      @store.member?(account_id, tenant_id)
    end

    # Deletes every membership and assignment for an account. What account deletion calls.
    def remove_account(account_id : String) : Int32
      removed = @store.remove_account(account_id)
      invalidate(account_id)
      removed
    end

    # Drops this process's cached grants for an account. Public because an application that
    # writes to the repository through some other path — a migration, an admin tool sharing the
    # process — has to be able to say so.
    def invalidate(account_id : String) : Nil
      @cache.try(&.invalidate(account_id))
    end

    # A session bound to one tenant asking about another.
    #
    # A principal with no tenant is unconstrained, which is the single-tenant deployment and the
    # overwhelming majority of them. A check that names *no* tenant is not a mismatch either: it
    # is a question about global scope, and global roles are the only thing that can answer it.
    private def cross_tenant?(principal : Principal, tenant_id : String?) : Bool
      bound = principal.tenant_id
      return false if bound.nil? || tenant_id.nil?

      bound != tenant_id
    end

    # Global first: it is the smaller list, and a global grant needs no membership to be
    # consulted.
    private def granting_role(grants : Grants, permission : String, tenant_id : String?) : String?
      @catalog.grants?(effective_roles(grants, tenant_id), permission)
    end

    private def effective_roles(grants : Grants, tenant_id : String?) : Array(String)
      return grants.global_roles if tenant_id.nil? || !grants.member?

      grants.global_roles + grants.tenant_roles
    end

    # A non-member is told apart from a member with no role, because the two mean different
    # things to whoever reads the audit trail: one is a provisioning gap, the other is somebody
    # reaching into a tenant they are not in.
    private def denial_for(grants : Grants, tenant_id : String?) : DenialReason
      return DenialReason::NotPermitted if tenant_id.nil? || grants.member?

      DenialReason::NotAMember
    end

    private def grants_for(account_id : String, tenant_id : String?) : Grants
      cache = @cache
      return @store.grants_for(account_id, tenant_id) if cache.nil?

      cache.fetch(account_id, tenant_id) { @store.grants_for(account_id, tenant_id) }
    end
  end
end

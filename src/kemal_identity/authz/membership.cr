module KemalIdentity::Authz
  # An account belongs to a tenant.
  #
  # Separate from role assignment, and the separation is deliberate. Membership answers "may
  # this person be inside this tenant at all", roles answer "and what may they do there". A
  # person can be a member with no roles — freshly invited, or with everything revoked while an
  # investigation runs — and that is a state the model has to be able to express, because the
  # alternative is deleting them and losing the audit trail of when they joined.
  struct Membership
    getter id : String
    getter account_id : String
    getter tenant_id : String
    getter created_at : Time

    def initialize(@id : String, @account_id : String, @tenant_id : String, @created_at : Time)
      raise ArgumentError.new("membership id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("tenant_id must not be empty") if @tenant_id.empty?
    end
  end

  # An account holds a role, either globally or inside one tenant.
  #
  # `tenant_id` nil means global — the role applies everywhere, including inside every tenant.
  # That is how an operator role works, and it is the sharpest thing in this file: a global
  # assignment is not gated by membership, so granting one is granting access to every tenant's
  # data at once. Applications should have very few of them, and `granted_by` exists so that
  # each one can be traced to whoever created it.
  struct Assignment
    getter id : String
    getter account_id : String

    # nil means global.
    getter tenant_id : String?

    getter role : String
    getter granted_at : Time

    # The account id of whoever granted it, when the application records that. Nil for a grant
    # made by a migration or a seed script.
    getter granted_by : String?

    def initialize(
      @id : String,
      @account_id : String,
      @role : String,
      @granted_at : Time,
      @tenant_id : String? = nil,
      @granted_by : String? = nil,
    )
      raise ArgumentError.new("assignment id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("role must not be empty") if @role.empty?
      raise ArgumentError.new("tenant_id must not be empty when present") if @tenant_id.try(&.empty?)
    end

    def global? : Bool
      @tenant_id.nil?
    end
  end

  # Everything one authorization check needs about one account, in one round trip.
  #
  # The three fields are kept apart rather than pre-merged into a single role list because the
  # merge *is* the policy: tenant roles count only for a member, global roles count always, and
  # `RBAC` is where that is written down. A repository that merged them would be a repository
  # that could get the policy wrong, in a place nobody looks for policy.
  struct Grants
    # Whether the account belongs to the tenant that was asked about. Always false when the
    # check named no tenant, where it has no meaning.
    getter? member : Bool

    # Roles held with no tenant, which apply everywhere.
    getter global_roles : Array(String)

    # Roles held inside the tenant that was asked about. Empty when no tenant was named.
    getter tenant_roles : Array(String)

    def initialize(
      @member : Bool = false,
      @global_roles : Array(String) = [] of String,
      @tenant_roles : Array(String) = [] of String,
    )
    end

    def empty? : Bool
      !@member && @global_roles.empty? && @tenant_roles.empty?
    end
  end
end

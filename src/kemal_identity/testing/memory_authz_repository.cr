module KemalIdentity::Testing
  # In-memory `Authz::Repository`, passing the same contract the database adapters must.
  class MemoryAuthzRepository < KemalIdentity::Authz::Repository
    def initialize
      @mutex = Mutex.new
      @memberships = {} of String => KemalIdentity::Authz::Membership
      @assignments = {} of String => KemalIdentity::Authz::Assignment
    end

    def grants_for(account_id : String, tenant_id : String? = nil) : KemalIdentity::Authz::Grants
      @mutex.synchronize do
        mine = ordered_assignments.select { |held| held.account_id == account_id }
        global = mine.select(&.global?).map(&.role)

        next KemalIdentity::Authz::Grants.new(global_roles: global) if tenant_id.nil?

        KemalIdentity::Authz::Grants.new(
          member: membership?(account_id, tenant_id),
          global_roles: global,
          tenant_roles: mine.select { |held| held.tenant_id == tenant_id }.map(&.role),
        )
      end
    end

    def add_member(membership : KemalIdentity::Authz::Membership) : Bool
      @mutex.synchronize do
        next false if membership?(membership.account_id, membership.tenant_id)

        @memberships[membership.id] = membership
        true
      end
    end

    def remove_member(account_id : String, tenant_id : String) : Bool
      @mutex.synchronize do
        before = @memberships.size

        @memberships.reject! do |_, existing|
          existing.account_id == account_id && existing.tenant_id == tenant_id
        end

        removed = @memberships.size < before

        # The roles go with the membership: re-inviting somebody must not silently restore
        # every role they used to hold.
        @assignments.reject! do |_, held|
          held.account_id == account_id && held.tenant_id == tenant_id
        end

        removed
      end
    end

    def member?(account_id : String, tenant_id : String) : Bool
      @mutex.synchronize { membership?(account_id, tenant_id) }
    end

    def memberships_for(account_id : String) : Array(KemalIdentity::Authz::Membership)
      @mutex.synchronize do
        ordered_memberships.select { |existing| existing.account_id == account_id }
      end
    end

    def members_of(
      tenant_id : String,
      limit : Int32 = 100,
      offset : Int32 = 0,
    ) : Array(KemalIdentity::Authz::Membership)
      @mutex.synchronize do
        ordered_memberships
          .select { |existing| existing.tenant_id == tenant_id }
          .skip(offset)
          .first(limit)
      end
    end

    def grant(assignment : KemalIdentity::Authz::Assignment) : Bool
      @mutex.synchronize do
        held = @assignments.each_value.any? do |existing|
          existing.account_id == assignment.account_id &&
            existing.role == assignment.role &&
            existing.tenant_id == assignment.tenant_id
        end

        next false if held

        @assignments[assignment.id] = assignment
        true
      end
    end

    def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool
      @mutex.synchronize do
        before = @assignments.size

        @assignments.reject! do |_, held|
          held.account_id == account_id && held.role == role && held.tenant_id == tenant_id
        end

        @assignments.size < before
      end
    end

    def assignments_for(account_id : String) : Array(KemalIdentity::Authz::Assignment)
      @mutex.synchronize do
        ordered_assignments.select { |held| held.account_id == account_id }
      end
    end

    def accounts_with_role(role : String, tenant_id : String? = nil) : Array(String)
      @mutex.synchronize do
        @assignments.each_value
          .select { |held| held.role == role && held.tenant_id == tenant_id }
          .map(&.account_id)
          .to_a
          .sort!
      end
    end

    def remove_account(account_id : String) : Int32
      @mutex.synchronize do
        removed = 0

        before_assignments = @assignments.size
        @assignments.reject! { |_, held| held.account_id == account_id }
        removed += before_assignments - @assignments.size

        before_memberships = @memberships.size
        @memberships.reject! { |_, existing| existing.account_id == account_id }
        removed += before_memberships - @memberships.size

        removed
      end
    end

    private def membership?(account_id : String, tenant_id : String) : Bool
      @memberships.each_value.any? do |existing|
        existing.account_id == account_id && existing.tenant_id == tenant_id
      end
    end

    private def ordered_memberships : Array(KemalIdentity::Authz::Membership)
      @memberships.values.sort_by! { |existing| {existing.created_at, existing.id} }
    end

    private def ordered_assignments : Array(KemalIdentity::Authz::Assignment)
      @assignments.values.sort_by! { |held| {held.granted_at, held.id} }
    end
  end
end

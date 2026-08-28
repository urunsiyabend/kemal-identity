module KemalIdentity::Postgres
  # `Authz::Repository` over `auth_tenant_memberships` and `auth_role_assignments`.
  #
  # `#grants_for` is the hot path — every authorized request runs it — so it is two statements
  # at most, and one when the check names no tenant.
  class AuthzRepository < Authz::Repository
    MEMBERSHIP_COLUMNS = "id, account_id, tenant_id, created_at"
    ASSIGNMENT_COLUMNS = "id, account_id, tenant_id, role, granted_at, granted_by"

    def initialize(@db : DB::Database)
    end

    def grants_for(account_id : String, tenant_id : String? = nil) : Authz::Grants
      if tenant_id.nil?
        return Authz::Grants.new(global_roles: global_roles(account_id))
      end

      # One statement for both scopes: a second round trip to fetch the global roles separately
      # would double the cost of the check every request makes.
      global = [] of String
      scoped = [] of String

      @db.query_each(<<-SQL, account_id, tenant_id) do |row|
        SELECT tenant_id, role FROM auth_role_assignments
         WHERE account_id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
         ORDER BY granted_at ASC, id ASC
        SQL
        scope = row.read(String?)
        role = row.read(String)

        scope.nil? ? global << role : scoped << role
      end

      Authz::Grants.new(
        member: member?(account_id, tenant_id), global_roles: global, tenant_roles: scoped
      )
    end

    def add_member(membership : Authz::Membership) : Bool
      result = @db.exec(<<-SQL,
        INSERT INTO auth_tenant_memberships (#{MEMBERSHIP_COLUMNS})
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        SQL
        membership.id, membership.account_id, membership.tenant_id, membership.created_at)

      result.rows_affected == 1
    end

    # Membership and that tenant's assignments go together, in one transaction — see
    # `Authz::Repository#remove_member`. Leaving the assignments would make re-inviting somebody
    # silently restore every role they used to hold.
    def remove_member(account_id : String, tenant_id : String) : Bool
      removed = false

      @db.transaction do |tx|
        connection = tx.connection

        result = connection.exec(
          "DELETE FROM auth_tenant_memberships WHERE account_id = $1 AND tenant_id = $2",
          account_id, tenant_id
        )

        removed = result.rows_affected == 1

        connection.exec(
          "DELETE FROM auth_role_assignments WHERE account_id = $1 AND tenant_id = $2",
          account_id, tenant_id
        )
      end

      removed
    end

    def member?(account_id : String, tenant_id : String) : Bool
      !@db.query_one?(
        "SELECT 1 FROM auth_tenant_memberships WHERE account_id = $1 AND tenant_id = $2",
        account_id, tenant_id, as: Int32
      ).nil?
    end

    def memberships_for(account_id : String) : Array(Authz::Membership)
      @db.query_all(<<-SQL, account_id) { |row| read_membership(row) }
        SELECT #{MEMBERSHIP_COLUMNS} FROM auth_tenant_memberships
         WHERE account_id = $1
         ORDER BY created_at ASC, id ASC
        SQL
    end

    def members_of(tenant_id : String, limit : Int32 = 100, offset : Int32 = 0) : Array(Authz::Membership)
      @db.query_all(<<-SQL, tenant_id, limit, offset) { |row| read_membership(row) }
        SELECT #{MEMBERSHIP_COLUMNS} FROM auth_tenant_memberships
         WHERE tenant_id = $1
         ORDER BY created_at ASC, id ASC
         LIMIT $2 OFFSET $3
        SQL
    end

    def grant(assignment : Authz::Assignment) : Bool
      result = @db.exec(<<-SQL,
        INSERT INTO auth_role_assignments (#{ASSIGNMENT_COLUMNS})
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
        SQL
        assignment.id, assignment.account_id, assignment.tenant_id, assignment.role,
        assignment.granted_at, assignment.granted_by)

      result.rows_affected == 1
    end

    # `IS NULL` rather than `= $3` for the global case: a global grant and a tenant grant of the
    # same role are different rows, and `= NULL` matches neither, so revoking the wrong one
    # would silently leave the access in place.
    def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool
      result =
        if tenant_id.nil?
          @db.exec(<<-SQL, account_id, role)
            DELETE FROM auth_role_assignments
             WHERE account_id = $1 AND role = $2 AND tenant_id IS NULL
            SQL
        else
          @db.exec(<<-SQL, account_id, role, tenant_id)
            DELETE FROM auth_role_assignments
             WHERE account_id = $1 AND role = $2 AND tenant_id = $3
            SQL
        end

      result.rows_affected == 1
    end

    def assignments_for(account_id : String) : Array(Authz::Assignment)
      @db.query_all(<<-SQL, account_id) { |row| read_assignment(row) }
        SELECT #{ASSIGNMENT_COLUMNS} FROM auth_role_assignments
         WHERE account_id = $1
         ORDER BY granted_at ASC, id ASC
        SQL
    end

    def accounts_with_role(role : String, tenant_id : String? = nil) : Array(String)
      if tenant_id.nil?
        @db.query_all(<<-SQL, role, as: String)
          SELECT account_id FROM auth_role_assignments
           WHERE role = $1 AND tenant_id IS NULL
           ORDER BY account_id ASC
          SQL
      else
        @db.query_all(<<-SQL, role, tenant_id, as: String)
          SELECT account_id FROM auth_role_assignments
           WHERE role = $1 AND tenant_id = $2
           ORDER BY account_id ASC
          SQL
      end
    end

    def remove_account(account_id : String) : Int32
      removed = 0

      @db.transaction do |tx|
        connection = tx.connection

        removed += connection.exec(
          "DELETE FROM auth_role_assignments WHERE account_id = $1", account_id
        ).rows_affected.to_i

        removed += connection.exec(
          "DELETE FROM auth_tenant_memberships WHERE account_id = $1", account_id
        ).rows_affected.to_i
      end

      removed
    end

    private def global_roles(account_id : String) : Array(String)
      @db.query_all(<<-SQL, account_id, as: String)
        SELECT role FROM auth_role_assignments
         WHERE account_id = $1 AND tenant_id IS NULL
         ORDER BY granted_at ASC, id ASC
        SQL
    end

    private def read_membership(row : DB::ResultSet) : Authz::Membership
      Authz::Membership.new(
        id: row.read(String),
        account_id: row.read(String),
        tenant_id: row.read(String),
        created_at: row.read(Time),
      )
    end

    private def read_assignment(row : DB::ResultSet) : Authz::Assignment
      Authz::Assignment.new(
        id: row.read(String),
        account_id: row.read(String),
        tenant_id: row.read(String?),
        role: row.read(String),
        granted_at: row.read(Time),
        granted_by: row.read(String?),
      )
    end
  end
end

module KemalIdentity::Authz
  # Storage for memberships and role assignments.
  #
  # ### This is on the hot path, and it is one call
  #
  # `#grants_for` is what every authorized request runs, so it is a single method returning
  # everything a decision needs rather than a membership lookup followed by a role lookup. An
  # adapter is free to answer it with one statement or two; what it must not do is make the
  # caller decide.
  #
  # ### Nothing here expires
  #
  # There is no `expires_at` on an assignment, and the sweeper has nothing to do in this
  # module. A time-limited grant sounds useful and is a trap: it puts the moment somebody
  # loses access into a column nobody watches, and an access review that reads the table sees a
  # row that looks live. Applications that want temporary access revoke it, and the revocation
  # is a row that disappears and an audit line that says who removed it.
  #
  # ### Removing a member removes their roles
  #
  # `#remove_member` must delete that tenant's assignments for the account as well, and the two
  # must not be observable apart. Leaving the rows would be safe *today* — `RBAC` ignores
  # tenant roles for a non-member — but it makes re-inviting somebody silently restore every
  # role they used to hold, which is not what anybody means by "add them back".
  abstract class Repository
    # Everything one decision needs about `account_id`, optionally within `tenant_id`.
    #
    # With a nil `tenant_id` the result must have `member` false and `tenant_roles` empty: no
    # tenant was named, so neither has any meaning.
    abstract def grants_for(account_id : String, tenant_id : String? = nil) : Grants

    # Adds a membership. Returns `false` if the account is already a member, which is not an
    # error — a double-submitted invitation is an ordinary thing.
    abstract def add_member(membership : Membership) : Bool

    # Removes a membership **and every role assignment for that account in that tenant**.
    # Returns `false` if there was no membership. See the note above on why the two are one
    # operation.
    abstract def remove_member(account_id : String, tenant_id : String) : Bool

    abstract def member?(account_id : String, tenant_id : String) : Bool

    # Which tenants this account belongs to, oldest first.
    abstract def memberships_for(account_id : String) : Array(Membership)

    # Who belongs to this tenant, oldest first. Paged, because a tenant with fifty thousand
    # members is a tenant whose administration screen must not load fifty thousand rows to show
    # the first twenty.
    abstract def members_of(tenant_id : String, limit : Int32 = 100, offset : Int32 = 0) : Array(Membership)

    # Grants a role. Returns `false` if the account already holds it in that scope.
    #
    # It is not this method's job to check that the role exists — `RoleCatalog` is what knows
    # that, it lives in the application, and a repository that validated role names would be a
    # second, weaker copy of the same rule.
    abstract def grant(assignment : Assignment) : Bool

    # Takes a role away. `tenant_id` nil revokes the global assignment, not every tenant one:
    # they are different grants and revoking the wrong one silently leaves access in place.
    # Returns `false` if it was not held.
    abstract def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool

    # Every assignment for an account, global and per-tenant, oldest first. For an access
    # review, and for the "what would deleting this account remove" screen.
    abstract def assignments_for(account_id : String) : Array(Assignment)

    # Everyone holding `role` in `tenant_id`, for the access review that asks the question the
    # other way round: not "what can this person do" but "who can do this".
    abstract def accounts_with_role(role : String, tenant_id : String? = nil) : Array(String)

    # Deletes every membership and assignment for an account, returning how many rows went.
    # What account deletion calls, and what a repository must offer so that authorization data
    # does not outlive the account it describes.
    abstract def remove_account(account_id : String) : Int32
  end
end

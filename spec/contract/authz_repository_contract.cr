# Shared spec for `KemalIdentity::Authz::Repository`. Every implementation runs it.
def it_behaves_like_an_authz_repository(&build : -> KemalIdentity::Authz::Repository)
  now = KemalIdentity::SpecHelper::FIXED_NOW

  membership = ->(id : String, account_id : String, tenant_id : String, at : Time) do
    KemalIdentity::Authz::Membership.new(
      id: id, account_id: account_id, tenant_id: tenant_id, created_at: at
    )
  end

  assignment = ->(id : String, account_id : String, role : String, tenant_id : String?) do
    KemalIdentity::Authz::Assignment.new(
      id: id, account_id: account_id, role: role, granted_at: now, tenant_id: tenant_id
    )
  end

  describe "#grants_for" do
    it "returns nothing at all for an account with no rows" do
      grants = build.call.grants_for("nobody")

      grants.member?.should be_false
      grants.global_roles.should be_empty
      grants.tenant_roles.should be_empty
      grants.empty?.should be_true
    end

    # A check that names no tenant is a question about global scope. Answering it with a role
    # held only inside a tenant would let a route that forgot its tenant argument read as
    # allowed.
    it "reports no tenant roles and no membership when no tenant is asked about" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.grant(assignment.call("g1", "a1", "operator", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))

      grants = repo.grants_for("a1")

      grants.member?.should be_false
      grants.global_roles.should eq(["operator"])
      grants.tenant_roles.should be_empty
    end

    it "separates global roles from the tenant's own" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.grant(assignment.call("g1", "a1", "operator", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))
      repo.grant(assignment.call("g3", "a1", "support", "globex"))

      grants = repo.grants_for("a1", "acme")

      grants.member?.should be_true
      grants.global_roles.should eq(["operator"])
      grants.tenant_roles.should eq(["finance"])
    end

    # The roles are still reported; whether they count is `RBAC`'s decision, and keeping the
    # policy in one place is why the repository does not pre-merge them.
    it "reports a non-member's tenant roles with member false" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", "acme"))

      grants = repo.grants_for("a1", "acme")

      grants.member?.should be_false
      grants.tenant_roles.should eq(["finance"])
    end

    it "does not leak another account's roles" do
      repo = build.call
      repo.add_member(membership.call("m1", "a2", "acme", now))
      repo.grant(assignment.call("g1", "a2", "finance", "acme"))

      grants = repo.grants_for("a1", "acme")

      grants.member?.should be_false
      grants.tenant_roles.should be_empty
    end
  end

  describe "#add_member and #member?" do
    it "adds a membership" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now)).should be_true
      repo.member?("a1", "acme").should be_true
    end

    # A double-submitted invitation is an ordinary thing, not an error.
    it "returns false rather than raising when the account is already a member" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now)).should be_true
      repo.add_member(membership.call("m2", "a1", "acme", now)).should be_false

      repo.memberships_for("a1").size.should eq(1)
    end

    it "keeps memberships of different tenants apart" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))

      repo.member?("a1", "globex").should be_false
    end
  end

  describe "#remove_member" do
    it "removes the membership" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))

      repo.remove_member("a1", "acme").should be_true
      repo.member?("a1", "acme").should be_false
    end

    it "returns false when there was no membership" do
      build.call.remove_member("a1", "acme").should be_false
    end

    # Otherwise re-inviting somebody silently restores every role they used to hold, which is
    # not what anybody means by "add them back".
    it "takes that tenant's role assignments with it" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.grant(assignment.call("g1", "a1", "finance", "acme"))

      repo.remove_member("a1", "acme")

      repo.grants_for("a1", "acme").tenant_roles.should be_empty
      repo.assignments_for("a1").should be_empty
    end

    it "leaves global roles and other tenants alone" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.add_member(membership.call("m2", "a1", "globex", now + 1.second))
      repo.grant(assignment.call("g1", "a1", "operator", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))
      repo.grant(assignment.call("g3", "a1", "support", "globex"))

      repo.remove_member("a1", "acme")

      repo.grants_for("a1").global_roles.should eq(["operator"])
      repo.member?("a1", "globex").should be_true
      repo.grants_for("a1", "globex").tenant_roles.should eq(["support"])
    end
  end

  describe "#memberships_for and #members_of" do
    it "lists an account's tenants oldest first" do
      repo = build.call
      repo.add_member(membership.call("m2", "a1", "globex", now + 1.hour))
      repo.add_member(membership.call("m1", "a1", "acme", now))

      repo.memberships_for("a1").map(&.tenant_id).should eq(["acme", "globex"])
    end

    it "pages a tenant's members oldest first" do
      repo = build.call
      5.times { |i| repo.add_member(membership.call("m#{i}", "a#{i}", "acme", now + i.seconds)) }

      repo.members_of("acme", limit: 2).map(&.account_id).should eq(["a0", "a1"])
      repo.members_of("acme", limit: 2, offset: 2).map(&.account_id).should eq(["a2", "a3"])
      repo.members_of("acme", limit: 2, offset: 4).map(&.account_id).should eq(["a4"])
    end

    it "does not list another tenant's members" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))

      repo.members_of("globex").should be_empty
    end
  end

  describe "#grant" do
    it "returns false for a role the account already holds in that scope" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", "acme")).should be_true
      repo.grant(assignment.call("g2", "a1", "finance", "acme")).should be_false

      repo.assignments_for("a1").size.should eq(1)
    end

    # A global grant and a tenant grant of the same role are different grants: one applies
    # everywhere and one does not.
    it "treats the same role globally and inside a tenant as two grants" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", nil)).should be_true
      repo.grant(assignment.call("g2", "a1", "finance", "acme")).should be_true

      repo.assignments_for("a1").size.should eq(2)
    end

    # The unique index has to cover the NULL case too, which in both dialects needs a partial
    # index — a plain unique index does not collide on NULL.
    it "refuses a duplicate global grant" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "operator", nil)).should be_true
      repo.grant(assignment.call("g2", "a1", "operator", nil)).should be_false
    end

    it "records who granted it" do
      repo = build.call
      repo.grant(KemalIdentity::Authz::Assignment.new(
        id: "g1", account_id: "a1", role: "operator", granted_at: now, granted_by: "a9"
      ))

      repo.assignments_for("a1").first.granted_by.should eq("a9")
    end
  end

  describe "#revoke" do
    it "takes a tenant role away" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", "acme"))

      repo.revoke("a1", "finance", "acme").should be_true
      repo.grants_for("a1", "acme").tenant_roles.should be_empty
    end

    it "returns false for a role that was not held" do
      build.call.revoke("a1", "finance", "acme").should be_false
    end

    # `= NULL` matches nothing, so an adapter that did not special-case the global scope would
    # report success and leave the access in place.
    it "revokes the global grant without touching the tenant one" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))

      repo.revoke("a1", "finance", nil).should be_true

      repo.grants_for("a1").global_roles.should be_empty
      repo.grants_for("a1", "acme").tenant_roles.should eq(["finance"])
    end

    it "revokes the tenant grant without touching the global one" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))

      repo.revoke("a1", "finance", "acme").should be_true

      repo.grants_for("a1").global_roles.should eq(["finance"])
    end

    it "leaves another account's identical grant alone" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "finance", "acme"))
      repo.grant(assignment.call("g2", "a2", "finance", "acme"))

      repo.revoke("a1", "finance", "acme")

      repo.grants_for("a2", "acme").tenant_roles.should eq(["finance"])
    end
  end

  describe "#assignments_for" do
    it "lists every scope oldest first" do
      repo = build.call
      repo.grant(KemalIdentity::Authz::Assignment.new(
        id: "g2", account_id: "a1", role: "finance", granted_at: now + 1.hour, tenant_id: "acme"
      ))
      repo.grant(assignment.call("g1", "a1", "operator", nil))

      repo.assignments_for("a1").map(&.role).should eq(["operator", "finance"])
      repo.assignments_for("a1").map(&.tenant_id).should eq([nil, "acme"])
    end
  end

  describe "#accounts_with_role" do
    it "answers the access review's question the other way round" do
      repo = build.call
      repo.grant(assignment.call("g1", "a2", "finance", "acme"))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))
      repo.grant(assignment.call("g3", "a3", "finance", "globex"))

      repo.accounts_with_role("finance", "acme").should eq(["a1", "a2"])
    end

    it "keeps global holders apart from a tenant's" do
      repo = build.call
      repo.grant(assignment.call("g1", "a1", "operator", nil))
      repo.grant(assignment.call("g2", "a2", "operator", "acme"))

      repo.accounts_with_role("operator").should eq(["a1"])
      repo.accounts_with_role("operator", "acme").should eq(["a2"])
    end
  end

  describe "#remove_account" do
    it "removes every membership and assignment, and says how many" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.grant(assignment.call("g1", "a1", "operator", nil))
      repo.grant(assignment.call("g2", "a1", "finance", "acme"))

      repo.remove_account("a1").should eq(3)

      repo.memberships_for("a1").should be_empty
      repo.assignments_for("a1").should be_empty
    end

    it "leaves other accounts alone" do
      repo = build.call
      repo.add_member(membership.call("m1", "a1", "acme", now))
      repo.add_member(membership.call("m2", "a2", "acme", now))

      repo.remove_account("a1")

      repo.member?("a2", "acme").should be_true
    end

    it "returns zero for an account with nothing" do
      build.call.remove_account("nobody").should eq(0)
    end
  end
end

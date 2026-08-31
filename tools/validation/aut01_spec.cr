require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# AUT-01: "Implement `can?(principal, action, resource, context)` without converting every
# resource into a role." Written from the consumer side, on the contract v0.8 introduced.

private record Invoice, id : String, owner_id : String, state : String do
  include KemalIdentity::Authz::Authorizable

  def authz_type : String
    "invoice"
  end

  def authz_id : String
    @id
  end
end

# The consumer's authorizer: the shipped RBAC decides whether the account may act on invoices at
# all, and this adds the per-object question. Counting reads so the N+1 condition is measurable.
private class OwnershipAuthorizer < KemalIdentity::Authz::Authorizer
  getter grant_checks = 0

  def initialize(@inner : KemalIdentity::Authz::Authorizer)
  end

  def decide(
    principal : KemalIdentity::Principal,
    permission : String,
    context : KemalIdentity::Authz::Context,
  ) : KemalIdentity::Authz::Decision
    @grant_checks += 1
    decision = @inner.decide(principal, permission, context)
    return decision unless decision.permitted?

    resource = context.resource
    return decision if resource.nil? # no object question was asked; the grant decided it

                       # Ownership stays in the domain layer: the rule reads the application's own object, and the
                       # authorizer never learned what an invoice is beyond this line.
                       #
                       # The rule was asked about an object, so anything it cannot read an owner from denies. The
                       # obvious `return decision if invoice.nil?` fails *open*, which is what this validation
                       # found in the README's own example.
    invoice = resource.as?(Invoice)
    return decision if invoice && invoice.owner_id == principal.subject

    KemalIdentity::Authz::Forbidden.policy(permission, code: "not_the_owner")
  end
end

# The in-memory double counts nothing, so the store is wrapped to count the one read that
# matters: how many times the grants were fetched while a list endpoint authorised its rows.
private class CountingAuthzRepository < KemalIdentity::Authz::Repository
  getter grants_reads = 0

  def initialize(@inner : KemalIdentity::Authz::Repository)
  end

  def grants_for(account_id : String, tenant_id : String? = nil) : KemalIdentity::Authz::Grants
    @grants_reads += 1
    @inner.grants_for(account_id, tenant_id)
  end

  def add_member(membership : KemalIdentity::Authz::Membership) : Bool
    @inner.add_member(membership)
  end

  def remove_member(account_id : String, tenant_id : String) : Bool
    @inner.remove_member(account_id, tenant_id)
  end

  def member?(account_id : String, tenant_id : String) : Bool
    @inner.member?(account_id, tenant_id)
  end

  def memberships_for(account_id : String) : Array(KemalIdentity::Authz::Membership)
    @inner.memberships_for(account_id)
  end

  def members_of(tenant_id : String, limit : Int32 = 100, offset : Int32 = 0) : Array(KemalIdentity::Authz::Membership)
    @inner.members_of(tenant_id, limit, offset)
  end

  def grant(assignment : KemalIdentity::Authz::Assignment) : Bool
    @inner.grant(assignment)
  end

  def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool
    @inner.revoke(account_id, role, tenant_id)
  end

  def assignments_for(account_id : String) : Array(KemalIdentity::Authz::Assignment)
    @inner.assignments_for(account_id)
  end

  def accounts_with_role(role : String, tenant_id : String? = nil) : Array(String)
    @inner.accounts_with_role(role, tenant_id)
  end

  def remove_account(account_id : String) : Int32
    @inner.remove_account(account_id)
  end
end

private PERMS = [KemalIdentity::Authz::Permission.new("invoices.edit")]
private ROLES = [KemalIdentity::Authz::Role.new("clerk", ["invoices.edit"])]

private def authz_harness(cached : Bool = true)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  store = CountingAuthzRepository.new(KemalIdentity::Testing::MemoryAuthzRepository.new)
  rbac = KemalIdentity::Authz::RBAC.new(
    catalog: KemalIdentity::Authz::RoleCatalog.new(
      KemalIdentity::Authz::PermissionRegistry.new(PERMS), ROLES
    ),
    store: store, clock: clock,
    random: KemalIdentity::Testing::DeterministicRandom.new,
    cache: cached ? KemalIdentity::Authz::Cache.new(clock: clock) : nil,
  )
  rbac.grant("a1", "clerk")
  {OwnershipAuthorizer.new(rbac), store}
end

describe "AUT-01: object ownership without turning every row into a role" do
  principal = KemalIdentity::Testing.principal(subject: "a1")

  it "permits the owner and refuses everybody else, for the same permission" do
    authorizer, _ = authz_harness

    authorizer.can?(
      principal, "invoices.edit",
      KemalIdentity::Authz::Context.new(resource: Invoice.new("inv-1", "a1", "open"))
    ).should be_true

    denial = authorizer.decide(
      principal, "invoices.edit",
      KemalIdentity::Authz::Context.new(resource: Invoice.new("inv-2", "someone-else", "open"))
    )
    denial.permitted?.should be_false
    denial.as(KemalIdentity::Authz::Forbidden).code.should eq("not_the_owner")
  end

  # Pass condition: "missing attributes deny". A resource the policy cannot read the owner of
  # must not be waved through.
  it "denies when the resource is the wrong type for the rule" do
    authorizer, _ = authz_harness

    # An Authz::Resource carries a type and an id but not this application's Invoice, so the
    # ownership rule cannot read an owner from it.
    decision = authorizer.decide(
      principal, "invoices.edit",
      KemalIdentity::Authz::Context.new(
        resource: KemalIdentity::Authz::Resource.new("invoice", "inv-2")
      )
    )

    # With the rule written to deny what it cannot read, the wrong-typed resource is refused.
    # Written the obvious way — `return decision if invoice.nil?` — this same example passed,
    # which is the finding: the shard cannot make a consumer's downcast fail closed, so the
    # example it ships must not be the version that fails open.
    decision.permitted?.should be_false
    decision.as(KemalIdentity::Authz::Forbidden).code.should eq("not_the_owner")
  end

  # Pass condition: "list endpoints can apply the same policy without an N+1 query per row."
  it "authorizes a hundred rows without a hundred grant reads" do
    authorizer, store = authz_harness
    invoices = Array.new(100) { |i| Invoice.new("inv-#{i}", i.even? ? "a1" : "other", "open") }

    permitted = invoices.count do |invoice|
      authorizer.can?(
        principal, "invoices.edit",
        KemalIdentity::Authz::Context.new(resource: invoice)
      )
    end

    permitted.should eq(50)

    # The authorizer was asked a hundred times -- that is the policy running per row, which is
    # correct. What must not happen is a hundred *store* reads.
    authorizer.grant_checks.should eq(100)

    # The measured number, recorded rather than bounded: the five-second authorization cache
    # turns a hundred policy evaluations into one store read.
    store.grants_reads.should eq(1)
  end

  # And the same list with the cache left at its default, which is **off**. This is the finding:
  # the N+1 condition is met by a cache the application has to switch on, and the default is one
  # store read per row.
  it "does read once per row when no cache was configured" do
    authorizer, store = authz_harness(cached: false)
    invoices = Array.new(100) { |i| Invoice.new("inv-#{i}", "a1", "open") }

    invoices.each do |invoice|
      authorizer.can?(
        principal, "invoices.edit",
        KemalIdentity::Authz::Context.new(resource: invoice)
      )
    end

    store.grants_reads.should eq(100)
  end
end

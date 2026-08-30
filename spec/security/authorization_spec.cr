require "../spec_helper"

# One spec per threat, named for the attack.
#
# Authorization has its own list, and it is short because most of it is one idea: a grant is
# read at the moment it is used, from a place that can be changed, and nothing about it is
# carried inside a credential.

private ROLES = [
  KemalIdentity::Authz::Role.new("reader", ["invoices.read"]),
  KemalIdentity::Authz::Role.new("finance", ["invoices.read", "invoices.refund", "reports.read", "reports.export"]),
  KemalIdentity::Authz::Role.new("operator", ["invoices.read", "tenants.administer"]),
]

private PERMISSIONS = [
  KemalIdentity::Authz::Permission.new("invoices.read"),
  # Declared at `ApiToken` assurance, which is what a permission automation is allowed to reach
  # at all looks like. `Permission#minimum_assurance` defaults to `Password`, and
  # `AssuranceLevel::ApiToken` sits below it, so a token cannot reach a default permission
  # however wide its scopes are — the assurance answers "may a machine do this", the scope
  # answers "may *this* token". Both have to say yes.
  KemalIdentity::Authz::Permission.new(
    "reports.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
  KemalIdentity::Authz::Permission.new(
    "reports.export", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
  KemalIdentity::Authz::Permission.new(
    "invoices.refund", minimum_assurance: KemalIdentity::AssuranceLevel::MFA
  ),
  KemalIdentity::Authz::Permission.new("tenants.administer"),
]

private record AuthzHarness,
  clock : KemalIdentity::Testing::TestClock,
  store : KemalIdentity::Testing::MemoryAuthzRepository,
  rbac : KemalIdentity::Authz::RBAC

private def harness(cache : KemalIdentity::Authz::Cache? = nil) : AuthzHarness
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  store = KemalIdentity::Testing::MemoryAuthzRepository.new

  catalog = KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new(PERMISSIONS), ROLES
  )

  AuthzHarness.new(
    clock: clock,
    store: store,
    rbac: KemalIdentity::Authz::RBAC.new(
      catalog: catalog,
      store: store,
      clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 7),
      cache: cache,
    ),
  )
end

private def denied_because(decision : KemalIdentity::Authz::Decision) : KemalIdentity::Authz::DenialReason
  decision.should be_a(KemalIdentity::Authz::Forbidden)
  decision.as(KemalIdentity::Authz::Forbidden).reason
end

describe "authorization" do
  # AUT-03 and TOK-01 in `blueprints/maturity-validation-scenarios.md`, both very high. The
  # property is that effective permission is the *intersection* of what the account holds and
  # what the credential carries — never the union, in either direction.
  describe "a token that is narrower than its owner" do
    scoped = ->(scopes : Array(String)?) do
      KemalIdentity::SpecHelper.principal(
        subject: "a1",
        session_id: nil,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::ApiToken, id: "tok-1", scopes: scopes
        ),
      )
    end

    # The whole point. Same account, same role, two tokens.
    it "refuses a permission the account holds but the token does not carry" do
      h = harness
      h.rbac.grant("a1", "finance")

      denied_because(h.rbac.decide(scoped.call(["reports.read"]), "reports.export"))
        .should eq(KemalIdentity::Authz::DenialReason::OutOfScope)
    end

    it "allows a permission both the account and the token carry" do
      h = harness
      h.rbac.grant("a1", "finance")

      h.rbac.decide(scoped.call(["reports.read"]), "reports.read").permitted?.should be_true
    end

    # The other direction, and the one that would be an escalation: a scope is not a grant. A
    # token naming a permission its owner was never given still gets nothing.
    it "does not let a scope grant what the account was never given" do
      h = harness

      denied_because(h.rbac.decide(scoped.call(["reports.read"]), "reports.read"))
        .should eq(KemalIdentity::Authz::DenialReason::NotPermitted)
    end

    # nil is "unattenuated", not "an empty set". Every token issued before scopes existed reads
    # back this way, and so does every browser session.
    it "leaves an unattenuated credential alone" do
      h = harness
      h.rbac.grant("a1", "finance")

      h.rbac.decide(scoped.call(nil), "reports.export").permitted?.should be_true
    end

    # And the fail-closed edge: an empty list permits nothing, even for an account that holds
    # everything.
    it "refuses everything for a credential attenuated to nothing" do
      h = harness
      h.rbac.grant("a1", "finance")

      denied_because(h.rbac.decide(scoped.call([] of String), "reports.read"))
        .should eq(KemalIdentity::Authz::DenialReason::OutOfScope)
    end

    # The interaction worth stating out loud, because it makes scopes look broken until you see
    # it: `Permission#minimum_assurance` defaults to `Password`, and `AssuranceLevel::ApiToken`
    # is below that. A permission left at the default is unreachable by *any* token, however
    # wide its scopes. Assurance answers "may a machine do this at all"; the scope answers "may
    # this particular token". A scope cannot overrule the first question.
    it "cannot reach a permission left at the default assurance, however wide the scope" do
      h = harness
      h.rbac.grant("a1", "finance")

      denied_because(h.rbac.decide(scoped.call(["invoices.refund"]), "invoices.refund"))
        .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    end

    # A session carries no scopes and must not be denied for it.
    it "leaves a browser session alone" do
      h = harness
      h.rbac.grant("a1", "finance")

      session = KemalIdentity::SpecHelper.principal(
        subject: "a1", assurance: KemalIdentity::AssuranceLevel::MFA
      )

      h.rbac.decide(session, "invoices.refund").permitted?.should be_true
    end

    # `blueprints/0018` refuses `*` in a permission because a wildcard grants permissions that
    # do not exist yet. A wildcard scope is that hazard aimed at tokens: `*` is a scope named
    # `*` and matches nothing. Unrestricted is nil.
    it "treats a star scope as a literal, never as a wildcard" do
      h = harness
      h.rbac.grant("a1", "finance")

      denied_because(h.rbac.decide(scoped.call(["*"]), "reports.read"))
        .should eq(KemalIdentity::Authz::DenialReason::OutOfScope)
    end

    # Attenuation runs last, so a denial for weak assurance is still reported as such rather
    # than being masked by the scope check — the trail keeps saying which wall was hit first.
    it "reports insufficient assurance ahead of a scope that would also have denied" do
      h = harness
      h.rbac.grant("a1", "finance")

      weak = KemalIdentity::SpecHelper.principal(
        subject: "a1",
        session_id: nil,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::ApiToken, id: "tok-1", scopes: ["reports.read"]
        ),
      )

      # invoices.refund needs MFA, and the token neither reaches it nor carries the scope.
      denied_because(h.rbac.decide(weak, "invoices.refund"))
        .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    end
  end

  describe "horizontal privilege escalation" do
    # The identifier in the URL swapped for somebody else's. Refused on the principal's own
    # binding, before membership is read, so it cannot be defeated by a wrong row.
    it "refuses a principal bound to one tenant asking about another, even when it holds the role there" do
      h = harness
      h.rbac.add_member("a1", "globex")
      h.rbac.grant("a1", "finance", tenant_id: "globex")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1", tenant_id: "acme")

      denied_because(h.rbac.decide(principal, "invoices.read", "globex"))
        .should eq(KemalIdentity::Authz::DenialReason::TenantMismatch)
    end

    it "lists no permissions at all across a tenant boundary" do
      h = harness
      h.rbac.add_member("a1", "globex")
      h.rbac.grant("a1", "finance", tenant_id: "globex")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1", tenant_id: "acme")

      h.rbac.permissions_for(principal, "globex").should be_empty
    end

    # The single-tenant deployment, which is most of them: a principal with no tenant is not
    # constrained by this check, and membership is what decides.
    it "does not constrain a principal that is not bound to a tenant" do
      h = harness
      h.rbac.add_member("a1", "acme")
      h.rbac.grant("a1", "reader", tenant_id: "acme")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      h.rbac.decide(principal, "invoices.read", "acme").permitted?.should be_true
    end
  end

  describe "a tenant role held by somebody who is not a member" do
    # Two rows to say one thing, so that removing somebody from a tenant is a single row that
    # revokes everything at once and cannot be defeated by an assignment missed in the cleanup.
    it "grants nothing" do
      h = harness
      h.rbac.grant("a1", "finance", tenant_id: "acme")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      denied_because(h.rbac.decide(principal, "invoices.read", "acme"))
        .should eq(KemalIdentity::Authz::DenialReason::NotAMember)
    end

    it "is told apart in the trail from a member who simply has no role" do
      h = harness
      h.rbac.add_member("a1", "acme")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      denied_because(h.rbac.decide(principal, "invoices.read", "acme"))
        .should eq(KemalIdentity::Authz::DenialReason::NotPermitted)
    end
  end

  describe "a route that forgets which tenant it is operating on" do
    # A check naming no tenant is a question about global scope, not about whichever tenant the
    # request happens to concern. Answering it from a tenant role would make the omission
    # invisible.
    it "is denied rather than quietly answered from a tenant grant" do
      h = harness
      h.rbac.add_member("a1", "acme")
      h.rbac.grant("a1", "finance", tenant_id: "acme")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      denied_because(h.rbac.decide(principal, "invoices.read"))
        .should eq(KemalIdentity::Authz::DenialReason::NotPermitted)
    end
  end

  describe "a global role" do
    # Documented behaviour, asserted so it cannot change quietly: a global assignment is not
    # gated by membership and reaches inside every tenant. It is the dangerous kind of grant.
    it "applies inside a tenant the account is not even a member of" do
      h = harness
      h.rbac.grant("a1", "operator")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      decision = h.rbac.decide(principal, "tenants.administer", "acme")

      decision.permitted?.should be_true
      decision.as(KemalIdentity::Authz::Permitted).via.should eq("operator")
    end

    it "is still refused across a tenant the principal is not bound to" do
      h = harness
      h.rbac.grant("a1", "operator")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1", tenant_id: "acme")

      denied_because(h.rbac.decide(principal, "tenants.administer", "globex"))
        .should eq(KemalIdentity::Authz::DenialReason::TenantMismatch)
    end
  end

  describe "a mistyped permission" do
    # Both deny. The reason is what tells a typo apart from an access-control event, and
    # `RoleCatalog` refuses the same mistake in a role definition at boot.
    it "denies and says the permission was never declared" do
      h = harness
      h.rbac.grant("a1", "finance")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      denied_because(h.rbac.decide(principal, "invoices.refnud"))
        .should eq(KemalIdentity::Authz::DenialReason::UnknownPermission)
    end
  end

  describe "an action that needs a second factor" do
    it "refuses a password-only session that holds the role" do
      h = harness
      h.rbac.grant("a1", "finance")

      principal = KemalIdentity::SpecHelper.principal(
        subject: "a1", assurance: KemalIdentity::AssuranceLevel::Password
      )

      denied_because(h.rbac.decide(principal, "invoices.refund"))
        .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    end

    it "allows the same session once the factor is proved" do
      h = harness
      h.rbac.grant("a1", "finance")

      principal = KemalIdentity::SpecHelper.principal(
        subject: "a1", assurance: KemalIdentity::AssuranceLevel::MFA
      )

      h.rbac.decide(principal, "invoices.refund").permitted?.should be_true
    end

    # A restored remember-me session proves possession of a stored token, not the presence of
    # the account holder, so it is below the floor for every permission by default.
    it "refuses a remembered session even for an ordinary permission" do
      h = harness
      h.rbac.grant("a1", "reader")

      principal = KemalIdentity::SpecHelper.principal(
        subject: "a1", assurance: KemalIdentity::AssuranceLevel::Remembered
      )

      denied_because(h.rbac.decide(principal, "invoices.read"))
        .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    end

    # The menu shows the action; the step-up prompt happens when it is clicked.
    it "still lists the permission, because a menu is not a guard" do
      h = harness
      h.rbac.grant("a1", "finance")

      principal = KemalIdentity::SpecHelper.principal(
        subject: "a1", assurance: KemalIdentity::AssuranceLevel::Password
      )

      h.rbac.permissions_for(principal).should contain("invoices.refund")
    end
  end

  describe "a grant taken away mid-session" do
    # The reason `Principal` carries no roles: nothing has to be reissued for a revocation to
    # take effect, and the session that was minted an hour ago reads the current answer.
    it "stops working on the very next check, with no cache" do
      h = harness
      h.rbac.grant("a1", "reader")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      h.rbac.decide(principal, "invoices.read").permitted?.should be_true

      h.rbac.revoke("a1", "reader")

      h.rbac.decide(principal, "invoices.read").permitted?.should be_false
    end

    it "stops working when the membership goes, taking the tenant role with it" do
      h = harness
      h.rbac.add_member("a1", "acme")
      h.rbac.grant("a1", "reader", tenant_id: "acme")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      h.rbac.decide(principal, "invoices.read", "acme").permitted?.should be_true

      h.rbac.remove_member("a1", "acme")

      denied_because(h.rbac.decide(principal, "invoices.read", "acme"))
        .should eq(KemalIdentity::Authz::DenialReason::NotAMember)

      # And re-inviting them does not silently restore the role they used to hold.
      h.rbac.add_member("a1", "acme")
      h.rbac.decide(principal, "invoices.read", "acme").permitted?.should be_false
    end

    it "takes everything with the account when the account is deleted" do
      h = harness
      h.rbac.add_member("a1", "acme")
      h.rbac.grant("a1", "reader", tenant_id: "acme")
      h.rbac.grant("a1", "operator")

      h.rbac.remove_account("a1").should eq(3)

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      h.rbac.decide(principal, "invoices.read", "acme").permitted?.should be_false
      h.rbac.decide(principal, "tenants.administer").permitted?.should be_false
    end
  end

  describe "a cached grant after revocation" do
    it "is dropped immediately when the revocation goes through the authorizer" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      cache = KemalIdentity::Authz::Cache.new(clock, ttl: 5.seconds)
      h = harness(cache)
      h.rbac.grant("a1", "reader")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      h.rbac.decide(principal, "invoices.read").permitted?.should be_true

      h.rbac.revoke("a1", "reader")

      h.rbac.decide(principal, "invoices.read").permitted?.should be_false
    end

    # The honest part. A revocation written by *another* process is not seen until the entry
    # expires, and the ttl is therefore the revocation delay — which is why `Cache::MAX_TTL`
    # exists and why the cache is off by default.
    it "keeps working until the ttl expires when the revocation happened elsewhere" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      cache = KemalIdentity::Authz::Cache.new(clock, ttl: 5.seconds)
      h = harness(cache)
      h.rbac.grant("a1", "reader")

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")
      h.rbac.decide(principal, "invoices.read").permitted?.should be_true

      # Straight to the store, as another process's write would appear.
      h.store.revoke("a1", "reader")

      h.rbac.decide(principal, "invoices.read").permitted?.should be_true

      clock.advance(5.seconds)

      h.rbac.decide(principal, "invoices.read").permitted?.should be_false
    end

    it "does not serve one account's grants to another" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      h = harness(KemalIdentity::Authz::Cache.new(clock))
      h.rbac.grant("a1", "finance")

      h.rbac.decide(KemalIdentity::SpecHelper.principal(subject: "a1"), "invoices.read")
        .permitted?.should be_true

      h.rbac.decide(KemalIdentity::SpecHelper.principal(subject: "a2"), "invoices.read")
        .permitted?.should be_false
    end
  end

  describe "a role that no longer exists in the catalog" do
    # Assignments outlive the code that defined them. A role nobody defines grants nothing,
    # rather than everything or a crash.
    it "grants nothing, and is findable so the rows can be cleaned up" do
      h = harness
      h.store.grant(KemalIdentity::Authz::Assignment.new(
        id: "g1", account_id: "a1", role: "beta_tester",
        granted_at: KemalIdentity::SpecHelper::FIXED_NOW
      ))

      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      h.rbac.decide(principal, "invoices.read").permitted?.should be_false
      h.rbac.catalog.undefined_roles(h.store.assignments_for("a1").map(&.role))
        .should eq(["beta_tester"])
    end

    it "cannot be granted through the authorizer in the first place" do
      h = harness

      expect_raises(ArgumentError, /beta_tester/) do
        h.rbac.grant("a1", "beta_tester")
      end
    end
  end

  describe "an unconfigured authorizer" do
    # A wiring mistake must not become an open application.
    it "permits nothing" do
      principal = KemalIdentity::SpecHelper.principal(subject: "a1")

      KemalIdentity::Authz::DenyAll.new.can?(principal, "invoices.read").should be_false
    end
  end
end

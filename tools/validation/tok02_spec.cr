require "spec"
require "kemal_identity"
require "kemal_identity/testing"
require "../src/tok02_fine_grained"

# TOK-02 — two tokens for one subject, different resource selections, and horizontal access
# attempted by changing the tenant or the resource id.
CLOCK2 = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

REPOS = {
  "17" => Repo.new("17", "org-a"),
  "24" => Repo.new("24", "org-a"),
  "31" => Repo.new("31", "org-b"),
}

private def catalog
  KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new([
      KemalIdentity::Authz::Permission.new(
        "repo.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
      KemalIdentity::Authz::Permission.new(
        "repo.write", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
      KemalIdentity::Authz::Permission.new(
        "org.admin", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
    ]),
    [
      KemalIdentity::Authz::Role.new("developer", ["repo.read", "repo.write"]),
      KemalIdentity::Authz::Role.new("operator", ["repo.read", "repo.write", "org.admin"]),
    ]
  )
end

record Fixture,
  authorizer : FineGrainedAuthorizer,
  store : KemalIdentity::Testing::MemoryAuthzRepository,
  narrow : KemalIdentity::Principal,
  wide : KemalIdentity::Principal,
  session : KemalIdentity::Principal

# One human, member of both organisations, with a `developer` role in each. Two tokens:
# `tok-narrow` selected for org-a repositories 17 and 24, `tok-wide` for all of org-b.
private def fixture(global_operator : Bool = false) : Fixture
  store = KemalIdentity::Testing::MemoryAuthzRepository.new
  {"org-a", "org-b"}.each_with_index do |org, i|
    store.add_member(KemalIdentity::Authz::Membership.new(
      id: "m#{i}", account_id: "ada", tenant_id: org, created_at: KemalIdentity::Testing::FIXED_NOW
    ))
    store.grant(KemalIdentity::Authz::Assignment.new(
      id: "g#{i}", account_id: "ada", role: "developer", tenant_id: org,
      granted_at: KemalIdentity::Testing::FIXED_NOW
    ))
  end

  if global_operator
    store.grant(KemalIdentity::Authz::Assignment.new(
      id: "g-global", account_id: "ada", role: "operator", tenant_id: nil,
      granted_at: KemalIdentity::Testing::FIXED_NOW
    ))
  end

  rbac = KemalIdentity::Authz::RBAC.new(
    catalog: catalog, store: store, clock: CLOCK2,
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: 2)
  )

  restrictions = {
    "tok-narrow" => TokenRestriction.new(Set{"org-a"}, Set{"17", "24"}),
    "tok-wide"   => TokenRestriction.new(Set{"org-b"}, Set(String).new),
  }

  principal = ->(credential : KemalIdentity::CredentialRef?) do
    KemalIdentity::Principal.new(
      subject: "ada",
      assurance: KemalIdentity::AssuranceLevel::ApiToken,
      authenticated_at: KemalIdentity::Testing::FIXED_NOW,
      credential: credential,
      # Deliberately nil: this human belongs to more than one organisation, so the *account* is
      # not bound to one. Any tenant restriction therefore cannot come from here.
      tenant_id: nil,
    )
  end

  token = ->(id : String, scopes : Array(String)?) do
    KemalIdentity::CredentialRef.new(
      kind: KemalIdentity::CredentialKind::ApiToken, id: id, name: id, scopes: scopes
    )
  end

  Fixture.new(
    authorizer: FineGrainedAuthorizer.new(rbac, restrictions, REPOS),
    store: store,
    narrow: principal.call(token.call("tok-narrow", ["repo.read"])),
    wide: principal.call(token.call("tok-wide", ["repo.read", "repo.write"])),
    session: KemalIdentity::Principal.new(
      subject: "ada", assurance: KemalIdentity::AssuranceLevel::Password,
      authenticated_at: KemalIdentity::Testing::FIXED_NOW,
      credential: KemalIdentity::CredentialRef.new(
        kind: KemalIdentity::CredentialKind::Session, id: "sess-1"
      ),
    ),
  )
end

private def decide(f : Fixture, principal : KemalIdentity::Principal, permission : String,
                   tenant : String?, repo : String? = nil)
  f.authorizer.decide(
    principal, permission,
    KemalIdentity::Authz::Context.new(
      tenant_id: tenant, resource: repo.try { |id| Repo.new(id, "unknown") }
    )
  )
end

describe "TOK-02 — a token restricted to organisations and repositories" do
  it "receives both the credential identity and the target" do
    f = fixture
    decide(f, f.narrow, "repo.read", "org-a", "17").permitted?.should be_true
    f.authorizer.restriction_lookups.should eq(1)
  end

  it "refuses the same permission in an organisation the token was not selected for" do
    f = fixture
    # The account is a member of org-b with the same role, so this is the token's restriction
    # doing the work and nothing else.
    decide(f, f.narrow, "repo.read", "org-b").permitted?.should be_false
    decide(f, f.wide, "repo.read", "org-b").permitted?.should be_true
  end

  it "refuses a repository inside the right organisation that the token was not selected for" do
    f = fixture
    decide(f, f.narrow, "repo.read", "org-a", "17").permitted?.should be_true
    decide(f, f.narrow, "repo.read", "org-a", "24").permitted?.should be_true
    # 31 exists, in org-b. Same organisation check, then the repository check.
    decide(f, f.narrow, "repo.read", "org-a", "31").permitted?.should be_false
  end

  it "does not infer the restriction from Principal#tenant_id" do
    f = fixture
    f.narrow.tenant_id.should be_nil
    f.wide.tenant_id.should be_nil

    # Two tokens, one account, no account-level tenant: the answers still differ.
    decide(f, f.narrow, "repo.read", "org-a").permitted?.should be_true
    decide(f, f.wide, "repo.read", "org-a").permitted?.should be_false
  end

  it "intersects the token's scopes with the account's grant, in both directions" do
    f = fixture
    # The account holds repo.write in org-a; the narrow token's scopes do not.
    decision = decide(f, f.narrow, "repo.write", "org-a", "17")
    decision.permitted?.should be_false
    decision.as(KemalIdentity::Authz::Forbidden).reason.out_of_scope?.should be_true

    # And the wide token's scopes include repo.write, but the account holds no role in org-c.
    decide(f, f.wide, "repo.write", "org-c").permitted?.should be_false
  end

  it "is not erased by a global role" do
    f = fixture(global_operator: true)
    # A global `operator` grants org.admin everywhere and needs no membership. The token
    # restriction must still apply.
    decide(f, f.narrow, "repo.read", "org-b").permitted?.should be_false

    # And the permission the global role adds is still outside the narrow token's scopes.
    decide(f, f.narrow, "org.admin", "org-a").permitted?.should be_false

    # The same global role, asked through the browser session, is unattenuated.
    decide(f, f.session, "org.admin", "org-b").permitted?.should be_true
  end

  it "denies an unknown resource and an unavailable one identically" do
    f = fixture
    unavailable = decide(f, f.narrow, "repo.read", "org-a", "31").as(KemalIdentity::Authz::Forbidden)
    unknown = decide(f, f.narrow, "repo.read", "org-a", "9999").as(KemalIdentity::Authz::Forbidden)

    unknown.reason.should eq(unavailable.reason)
    unknown.code.should eq(unavailable.code)
    unknown.step_up?.should eq(unavailable.step_up?)
  end

  it "leaves a browser session unrestricted" do
    f = fixture
    decide(f, f.session, "repo.read", "org-a", "31").permitted?.should be_true
    decide(f, f.session, "repo.read", "org-b").permitted?.should be_true
  end
end

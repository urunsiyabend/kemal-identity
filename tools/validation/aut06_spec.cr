require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# AUT-06 — immediate grant revocation and cache invalidation.
#
# Every attempt here revokes *behind* `RBAC`, straight against the repository, because that is
# what "in another process" means to a process holding a cache: the write happened somewhere
# that could not call `#invalidate` on this object. Going through `RBAC#revoke` would test the
# local invalidation hook, which is a different (and much weaker) claim.

# Counts reads so a spec can prove a cache was warm rather than assert it.
class CountingAuthzRepository < KemalIdentity::Authz::Repository
  getter reads = 0

  def initialize(@inner : KemalIdentity::Authz::Repository)
  end

  def grants_for(account_id : String, tenant_id : String? = nil) : KemalIdentity::Authz::Grants
    @reads += 1
    @inner.grants_for(account_id, tenant_id)
  end

  # Written out rather than `delegate`: the contract's methods carry explicit return types, and
  # the macro's `def add_member(*args, **options)` cannot override one of those.
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

  def members_of(
    tenant_id : String,
    limit : Int32 = 100,
    offset : Int32 = 0,
  ) : Array(KemalIdentity::Authz::Membership)
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

# `minimum_assurance: ApiToken` on both, because these are permissions a personal access token
# is meant to be able to use and `Permission`'s default is `Password`. TOK-01 recorded this
# interaction; it bites again here, and a spec written the obvious way fails with
# `InsufficientAssurance` rather than the scope answer it was measuring.
REGISTRY = KemalIdentity::Authz::PermissionRegistry.new(
  KemalIdentity::Authz::Permission.new(
    "reports.read", "Read reports", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
  KemalIdentity::Authz::Permission.new(
    "reports.write", "Write reports", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
  ),
)

CATALOG = KemalIdentity::Authz::RoleCatalog.new(
  REGISTRY,
  [
    KemalIdentity::Authz::Role.new("member", ["reports.read"]),
    KemalIdentity::Authz::Role.new("auditor", ["reports.read", "reports.write"]),
  ]
)

def build(ttl : Time::Span? = 5.seconds)
  clock = KemalIdentity::Testing::TestClock.new
  store = CountingAuthzRepository.new(KemalIdentity::Testing::MemoryAuthzRepository.new)
  cache = ttl.nil? ? nil : KemalIdentity::Authz::Cache.new(clock, ttl: ttl)
  rbac = KemalIdentity::Authz::RBAC.new(CATALOG, store, clock, cache: cache)
  {clock, store, cache, rbac}
end

def session_principal(subject : String, tenant : String? = nil)
  KemalIdentity::Principal.new(
    subject: subject,
    assurance: KemalIdentity::AssuranceLevel::Password,
    authenticated_at: Time.utc(2026, 8, 24, 12, 0, 0),
    credential: KemalIdentity::CredentialRef.new(
      KemalIdentity::CredentialKind::Session, id: "sess-#{subject}"
    ),
    tenant_id: tenant,
  )
end

def token_principal(subject : String, scopes : Array(String))
  KemalIdentity::Principal.new(
    subject: subject,
    assurance: KemalIdentity::AssuranceLevel::ApiToken,
    authenticated_at: Time.utc(2026, 8, 24, 12, 0, 0),
    credential: KemalIdentity::CredentialRef.new(
      KemalIdentity::CredentialKind::ApiToken, id: "tok-#{scopes.join('-')}", scopes: scopes
    ),
  )
end

def context(tenant : String?)
  KemalIdentity::Authz::Context.new(tenant_id: tenant)
end

describe "AUT-06 — the stale-access window" do
  it "is bounded by the cache ttl, and the ttl has an enforced ceiling" do
    KemalIdentity::Authz::Cache::DEFAULT_TTL.should eq(5.seconds)
    KemalIdentity::Authz::Cache::MAX_TTL.should eq(1.minute)

    clock = KemalIdentity::Testing::TestClock.new

    expect_raises(KemalIdentity::ConfigurationError, /exceeds/) do
      KemalIdentity::Authz::Cache.new(clock, ttl: 61.seconds)
    end

    expect_raises(KemalIdentity::ConfigurationError, /positive/) do
      KemalIdentity::Authz::Cache.new(clock, ttl: Time::Span.zero)
    end
  end

  it "keeps a removed member working for exactly the ttl and no longer" do
    clock, store, _cache, rbac = build(ttl: 5.seconds)

    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "member", "org-a")

    principal = session_principal("ada")

    # Warm.
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true
    warm_reads = store.reads

    # Another process removes the membership. This object is not told.
    store.remove_member("ada", "org-a")

    # One second before the ttl expires: still permitted, and still not reading the store.
    clock.advance(4.seconds)
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true
    store.reads.should eq(warm_reads)

    # At the ttl: the entry is expired, the store is read, and access is gone.
    clock.advance(1.second)
    decision = rbac.decide(principal, "reports.read", context("org-a"))
    decision.permitted?.should be_false
    decision.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::NotAMember)
    store.reads.should eq(warm_reads + 1)
  end

  it "has no window at all when no cache is passed" do
    _clock, store, cache, rbac = build(ttl: nil)
    cache.should be_nil

    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "member", "org-a")

    principal = session_principal("ada")
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true

    store.remove_member("ada", "org-a")
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_false
  end
end

describe "AUT-06 — multi-process invalidation" do
  it "is reachable from outside: RBAC#invalidate closes the window early" do
    clock, store, _cache, rbac = build(ttl: 60.seconds)

    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "member", "org-a")

    principal = session_principal("ada")
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true

    store.remove_member("ada", "org-a")

    # What a pub/sub subscriber, an admin tool sharing the process, or a message consumer calls.
    rbac.invalidate("ada")

    clock.advance(1.millisecond)
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_false
  end

  it "drops every tenant's entry for the account, not only the one asked about" do
    _clock, store, cache, rbac = build(ttl: 60.seconds)

    rbac.add_member("ada", "org-a")
    rbac.add_member("ada", "org-b")
    rbac.grant("ada", "member", "org-a")
    rbac.grant("ada", "member", "org-b")

    principal = session_principal("ada")
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true
    rbac.decide(principal, "reports.read", context("org-b")).permitted?.should be_true
    cache.not_nil!.size.should eq(2)

    store.remove_member("ada", "org-b")
    rbac.invalidate("ada")
    cache.not_nil!.size.should eq(0)

    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true
    rbac.decide(principal, "reports.read", context("org-b")).permitted?.should be_false
  end

  it "does not drop another account's entries" do
    _clock, _store, cache, rbac = build(ttl: 60.seconds)

    rbac.add_member("ada", "org-a")
    rbac.add_member("bob", "org-a")
    rbac.grant("ada", "member", "org-a")
    rbac.grant("bob", "member", "org-a")

    rbac.decide(session_principal("ada"), "reports.read", context("org-a"))
    rbac.decide(session_principal("bob"), "reports.read", context("org-a"))
    cache.not_nil!.size.should eq(2)

    rbac.invalidate("ada")
    cache.not_nil!.size.should eq(1)
  end
end

describe "AUT-06 — what the cache key has to separate" do
  it "separates tenants: a warm answer for one tenant is not served for another" do
    _clock, store, _cache, rbac = build(ttl: 60.seconds)

    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "member", "org-a")

    principal = session_principal("ada")
    rbac.decide(principal, "reports.read", context("org-a")).permitted?.should be_true
    reads = store.reads

    # org-b was never asked about, so it cannot be answered from the org-a entry.
    rbac.decide(principal, "reports.read", context("org-b")).permitted?.should be_false
    store.reads.should eq(reads + 1)

    # And the global question is a third key, not either of the two above.
    rbac.decide(principal, "reports.read", context(nil)).permitted?.should be_false
    store.reads.should eq(reads + 2)
  end

  it "cannot collide two accounts whose ids and tenants concatenate the same way" do
    _clock, _store, _cache, rbac = build(ttl: 60.seconds)

    # "ada:x" + tenant nil vs "ada" + tenant "x" — the same characters, different questions.
    rbac.grant("ada:x", "auditor")
    rbac.add_member("ada", "x")
    rbac.grant("ada", "member", "x")

    rbac.decide(session_principal("ada:x"), "reports.write", context(nil)).permitted?.should be_true
    rbac.decide(session_principal("ada"), "reports.write", context("x")).permitted?.should be_false
  end

  it "serves one cached grant set to two differently attenuated credentials, and still answers differently" do
    _clock, store, _cache, rbac = build(ttl: 60.seconds)

    rbac.grant("ada", "auditor")

    read_only = token_principal("ada", ["reports.read"])
    read_write = token_principal("ada", ["reports.read", "reports.write"])

    # Warm from the narrow token.
    rbac.decide(read_only, "reports.read", context(nil)).permitted?.should be_true
    warm_reads = store.reads

    # The wide token reuses the same cached grants — no second read — and is still permitted
    # more than the narrow one. Attenuation is applied after the cache, never cached with it.
    rbac.decide(read_write, "reports.write", context(nil)).permitted?.should be_true
    store.reads.should eq(warm_reads)

    denial = rbac.decide(read_only, "reports.write", context(nil))
    denial.permitted?.should be_false
    denial.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::OutOfScope)
    store.reads.should eq(warm_reads)
  end

  it "does not let a cached decision outlive the credential that asked for it" do
    _clock, _store, _cache, rbac = build(ttl: 60.seconds)

    rbac.grant("ada", "auditor")

    # A session, unattenuated, warms the cache and may write.
    rbac.decide(session_principal("ada"), "reports.write", context(nil)).permitted?.should be_true

    # A token for the same account, issued with no write scope, must not inherit that answer.
    rbac.decide(token_principal("ada", ["reports.read"]), "reports.write", context(nil))
      .permitted?.should be_false
  end
end

describe "AUT-06 — account-wide and tenant-only revocation" do
  it "removes a tenant's roles with its membership and leaves other tenants alone" do
    _clock, store, _cache, rbac = build(ttl: nil)

    rbac.add_member("ada", "org-a")
    rbac.add_member("ada", "org-b")
    rbac.grant("ada", "auditor", "org-a")
    rbac.grant("ada", "auditor", "org-b")

    rbac.remove_member("ada", "org-a").should be_true

    store.assignments_for("ada").map(&.tenant_id).should eq(["org-b"])
    rbac.member?("ada", "org-b").should be_true

    principal = session_principal("ada")
    rbac.decide(principal, "reports.write", context("org-a")).permitted?.should be_false
    rbac.decide(principal, "reports.write", context("org-b")).permitted?.should be_true
  end

  it "leaves a global role untouched when a tenant membership is removed" do
    _clock, _store, _cache, rbac = build(ttl: nil)

    rbac.grant("ada", "auditor")
    rbac.add_member("ada", "org-a")

    rbac.remove_member("ada", "org-a").should be_true

    principal = session_principal("ada")
    # The global role still applies everywhere, including inside the tenant they just left.
    rbac.decide(principal, "reports.write", context("org-a")).permitted?.should be_true
    rbac.decide(principal, "reports.write", context(nil)).permitted?.should be_true
  end

  it "revokes the global assignment and the tenant one separately, and says which it did" do
    _clock, _store, _cache, rbac = build(ttl: nil)

    rbac.grant("ada", "auditor")
    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "auditor", "org-a")

    # No tenant argument means the global grant, and only that one.
    rbac.revoke("ada", "auditor").should be_true

    principal = session_principal("ada")
    rbac.decide(principal, "reports.write", context("org-a")).permitted?.should be_true
    rbac.decide(principal, "reports.write", context(nil)).permitted?.should be_false

    rbac.revoke("ada", "auditor", "org-a").should be_true
    rbac.decide(principal, "reports.write", context("org-a")).permitted?.should be_false

    # And a second attempt is false rather than silently true, so a caller can tell that the
    # row it meant to remove was not there.
    rbac.revoke("ada", "auditor", "org-a").should be_false
  end

  it "removes everything for an account when the account itself goes" do
    _clock, _store, _cache, rbac = build(ttl: nil)

    rbac.grant("ada", "auditor")
    rbac.add_member("ada", "org-a")
    rbac.grant("ada", "auditor", "org-a")

    rbac.remove_account("ada").should eq(3)

    principal = session_principal("ada")
    rbac.decide(principal, "reports.write", context("org-a")).permitted?.should be_false
    rbac.decide(principal, "reports.write", context(nil)).permitted?.should be_false
  end
end

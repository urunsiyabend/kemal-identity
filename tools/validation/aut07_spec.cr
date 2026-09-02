require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# AUT-07 — per-permission assurance and step-up.
#
# The scenario's three products: reading a profile needs an ordinary session, exporting data
# needs a recent password, changing payout details needs phishing-resistant MFA. Declared here
# the way the shard offers — assurance on the permission, freshness at the call site — and then
# called through every credential the shard can produce.

PROFILE = KemalIdentity::Authz::Permission.new(
  "profile.read", "Read your own profile",
  minimum_assurance: KemalIdentity::AssuranceLevel::Remembered
)

# The one an API client is meant to be able to reach.
REPORTS = KemalIdentity::Authz::Permission.new(
  "reports.read", "Read reports",
  minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
)

EXPORT = KemalIdentity::Authz::Permission.new(
  "data.export", "Export everything",
  minimum_assurance: KemalIdentity::AssuranceLevel::Password
)

PAYOUT = KemalIdentity::Authz::Permission.new(
  "payout.update", "Change payout details",
  minimum_assurance: KemalIdentity::AssuranceLevel::MFA
)

CATALOG7 = KemalIdentity::Authz::RoleCatalog.new(
  KemalIdentity::Authz::PermissionRegistry.new(PROFILE, REPORTS, EXPORT, PAYOUT),
  [KemalIdentity::Authz::Role.new(
    "owner", ["profile.read", "reports.read", "data.export", "payout.update"]
  )]
)

NOW = Time.utc(2026, 9, 2, 12, 0, 0)

def rbac7
  store = KemalIdentity::Testing::MemoryAuthzRepository.new
  clock = KemalIdentity::Testing::TestClock.new(NOW)
  rbac = KemalIdentity::Authz::RBAC.new(CATALOG7, store, clock)
  rbac.grant("ada", "owner")
  rbac
end

def principal7(
  assurance : KemalIdentity::AssuranceLevel,
  at : Time = NOW,
  kind : KemalIdentity::CredentialKind = KemalIdentity::CredentialKind::Session,
  scopes : Array(String)? = nil,
)
  KemalIdentity::Principal.new(
    subject: "ada",
    assurance: assurance,
    authenticated_at: at,
    credential: KemalIdentity::CredentialRef.new(kind, id: "c1", scopes: scopes),
    mfa_verified_at: assurance.mfa? ? at : nil,
  )
end

def decide7(rbac, principal, permission)
  rbac.decide(principal, permission, KemalIdentity::Authz::Context.new)
end

describe "AUT-07 — assurance is declared once, on the permission" do
  it "answers each of the three products differently for the same account" do
    rbac = rbac7

    remembered = principal7(KemalIdentity::AssuranceLevel::Remembered)
    password = principal7(KemalIdentity::AssuranceLevel::Password)
    mfa = principal7(KemalIdentity::AssuranceLevel::MFA)
    token = principal7(KemalIdentity::AssuranceLevel::ApiToken, kind: KemalIdentity::CredentialKind::ApiToken)

    # profile.read — every credential clears it.
    {remembered, password, mfa, token}.each do |who|
      decide7(rbac, who, "profile.read").permitted?.should be_true
    end

    # data.export — a password or better, and a token is not better however deliberate it is.
    decide7(rbac, remembered, "data.export").permitted?.should be_false
    decide7(rbac, token, "data.export").permitted?.should be_false
    decide7(rbac, password, "data.export").permitted?.should be_true
    decide7(rbac, mfa, "data.export").permitted?.should be_true

    # payout.update — MFA only.
    decide7(rbac, remembered, "payout.update").permitted?.should be_false
    decide7(rbac, token, "payout.update").permitted?.should be_false
    decide7(rbac, password, "payout.update").permitted?.should be_false
    decide7(rbac, mfa, "payout.update").permitted?.should be_true
  end

  it "denies for weak assurance distinguishably from denying for no grant" do
    rbac = rbac7

    weak = decide7(rbac, principal7(KemalIdentity::AssuranceLevel::Password), "payout.update")
    weak.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    weak.as(KemalIdentity::Authz::Forbidden).step_up?.should be_true

    # Somebody with no role at all: the same 403 to a client, a different line in the trail.
    ungranted = KemalIdentity::Authz::RBAC.new(
      CATALOG7, KemalIdentity::Testing::MemoryAuthzRepository.new,
      KemalIdentity::Testing::TestClock.new(NOW)
    )
    nothing = decide7(ungranted, principal7(KemalIdentity::AssuranceLevel::MFA), "payout.update")
    nothing.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::NotPermitted)
    nothing.as(KemalIdentity::Authz::Forbidden).step_up?.should be_false
  end

  it "keeps the assurance gate behind the grant, so a stranger is never told to step up" do
    # The order matters for what an attacker learns: somebody with no grant is told "no",
    # not "authenticate more strongly and try again", which would confirm the permission
    # exists and that they would hold it.
    ungranted = KemalIdentity::Authz::RBAC.new(
      CATALOG7, KemalIdentity::Testing::MemoryAuthzRepository.new,
      KemalIdentity::Testing::TestClock.new(NOW)
    )

    decision = decide7(ungranted, principal7(KemalIdentity::AssuranceLevel::Remembered), "payout.update")
    decision.as(KemalIdentity::Authz::Forbidden).step_up?.should be_false
  end
end

describe "AUT-07 — strength and freshness are separate axes" do
  it "measures them independently, and each can fail while the other holds" do
    # Strong but old: a second factor proved three hours ago.
    old_mfa = principal7(KemalIdentity::AssuranceLevel::MFA, at: NOW - 3.hours)
    old_mfa.at_least?(KemalIdentity::AssuranceLevel::MFA).should be_true
    old_mfa.fresh?(within: 5.minutes, now: NOW).should be_false

    # Fresh but weak: a password typed one second ago.
    new_password = principal7(KemalIdentity::AssuranceLevel::Password, at: NOW - 1.second)
    new_password.fresh?(within: 5.minutes, now: NOW).should be_true
    new_password.at_least?(KemalIdentity::AssuranceLevel::MFA).should be_false

    # And the authorization decision reads only strength: `data.export` passes for the old MFA
    # principal, so a route that also wants recency has to ask for it separately.
    decide7(rbac7, old_mfa, "data.export").permitted?.should be_true
  end

  it "refuses to let a recent timestamp stand in for an interactive credential" do
    # The attack this condition is about: an automated client re-authenticates every minute, so
    # its `authenticated_at` is always seconds old. Freshness must not accept that as presence.
    just_now = principal7(
      KemalIdentity::AssuranceLevel::ApiToken, at: NOW,
      kind: KemalIdentity::CredentialKind::ApiToken
    )

    just_now.authenticated_at.should eq(NOW)
    just_now.fresh?(within: 1.second, now: NOW).should be_false
    just_now.fresh?(within: 365.days, now: NOW).should be_false

    # Same for a remembered browser, which is the other credential nobody typed into.
    principal7(KemalIdentity::AssuranceLevel::Remembered, at: NOW)
      .fresh?(within: 1.second, now: NOW).should be_false

    # A password session of the same age is fresh, so the difference is the assurance floor and
    # not the clock.
    principal7(KemalIdentity::AssuranceLevel::Password, at: NOW)
      .fresh?(within: 1.second, now: NOW).should be_true
  end

  it "puts ApiToken below Password so no scope grants an interactive action" do
    KemalIdentity::AssuranceLevel::Remembered.value.should eq(10)
    KemalIdentity::AssuranceLevel::ApiToken.value.should eq(15)
    KemalIdentity::AssuranceLevel::Password.value.should eq(20)
    KemalIdentity::AssuranceLevel::MFA.value.should eq(30)

    # A token scoped to exactly the permission still cannot reach it: the scope can only ever
    # remove, and the assurance floor is checked before the scope is even consulted.
    scoped = principal7(
      KemalIdentity::AssuranceLevel::ApiToken,
      kind: KemalIdentity::CredentialKind::ApiToken,
      scopes: ["payout.update"],
    )

    decision = decide7(rbac7, scoped, "payout.update")
    decision.permitted?.should be_false
    decision.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
  end
end

describe "AUT-07 — what a permission cannot declare" do
  it "has no maximum authentication age, so freshness is per call site only" do
    # `Permission` carries `minimum_assurance` and nothing about recency. The scenario asks for
    # both to be declarable per permission; only one is. Recorded rather than worked around.
    KemalIdentity::Authz::Permission.new("x.y", "").minimum_assurance
      .should eq(KemalIdentity::AssuranceLevel::Password)

    {% begin %}
      {{ KemalIdentity::Authz::Permission.methods.map(&.name.stringify).includes?("maximum_age") }}
        .should be_false
    {% end %}
  end
end

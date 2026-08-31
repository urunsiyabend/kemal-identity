require "spec"
# Deliberately NOT `kemal_identity/kemal`, and not `kemal`. If either is needed, this fails.
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# DEV-03's last pass condition, and HTTP-07 whole: the application object and the authorization
# path with no HTTP request in sight.
describe "DEV-03: the application object without Kemal" do
  it "configures without the Kemal adapter loaded" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])

    KemalIdentity.configure(
      accounts: accounts,
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
      random: KemalIdentity::Testing::DeterministicRandom.new,
      cookie: KemalIdentity::Sessions::CookieConfig.new(
        name: "raw_session", secure: false, allow_insecure: true
      ),
    )

    KemalIdentity.app.should be_a(KemalIdentity::Application)
    KemalIdentity.app.sessions.should be_a(KemalIdentity::Sessions::Service)
  end
end

# HTTP-07: a background job, a maintenance task or a message consumer acting under a principal,
# running the same authorization policy an HTTP request would.
describe "HTTP-07: authentication outside an HTTP request" do
  private_perms = [
    KemalIdentity::Authz::Permission.new(
      "invoices.sweep", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
    ),
  ]

  it "builds an execution context with no HTTP::Server::Context and authorises against it" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    rbac = KemalIdentity::Authz::RBAC.new(
      catalog: KemalIdentity::Authz::RoleCatalog.new(
        KemalIdentity::Authz::PermissionRegistry.new(private_perms),
        [KemalIdentity::Authz::Role.new("sweeper", ["invoices.sweep"])]
      ),
      store: KemalIdentity::Testing::MemoryAuthzRepository.new,
      clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
    )
    rbac.grant("worker-1", "sweeper")

    # The job's own principal. No request, no cookie, no fake HTTP anything.
    actor = KemalIdentity::Principal.new(
      subject: "worker-1",
      assurance: KemalIdentity::AssuranceLevel::ApiToken,
      authenticated_at: clock.now,
      credential: KemalIdentity::CredentialRef.new(
        kind: KemalIdentity::CredentialKind::Custom, id: "cron:nightly-sweep", name: "scheduler"
      ),
    )

    rbac.decide(actor, "invoices.sweep").permitted?.should be_true

    # Pass condition: "actor and source are auditable" -- the credential names the launcher.
    actor.credential.not_nil!.id.should eq("cron:nightly-sweep")
  end

  # Pass condition: "jobs cannot invent a stronger assurance than their trusted launcher grants."
  # The shard cannot stop a job constructing any Principal it likes -- so what protects the
  # boundary is that a permission can demand an assurance the job does not have.
  it "cannot reach a permission that demands more assurance than it claims" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    rbac = KemalIdentity::Authz::RBAC.new(
      catalog: KemalIdentity::Authz::RoleCatalog.new(
        KemalIdentity::Authz::PermissionRegistry.new([
          KemalIdentity::Authz::Permission.new(
            "invoices.refund", minimum_assurance: KemalIdentity::AssuranceLevel::MFA
          ),
        ]),
        [KemalIdentity::Authz::Role.new("finance", ["invoices.refund"])]
      ),
      store: KemalIdentity::Testing::MemoryAuthzRepository.new,
      clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
    )
    rbac.grant("worker-1", "finance")

    job = KemalIdentity::Principal.new(
      subject: "worker-1", assurance: KemalIdentity::AssuranceLevel::ApiToken,
      authenticated_at: clock.now,
    )

    denial = rbac.decide(job, "invoices.refund")
    denial.permitted?.should be_false
    denial.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)

    # And nothing stops the job claiming MFA. Recorded rather than asserted away: the honest
    # boundary is that whatever constructs the Principal is trusted, and that is the launcher.
    liar = KemalIdentity::Principal.new(
      subject: "worker-1", assurance: KemalIdentity::AssuranceLevel::MFA,
      authenticated_at: clock.now,
    )
    rbac.decide(liar, "invoices.refund").permitted?.should be_true
  end

  it "runs a freshness check with an injected clock and no request" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    actor = KemalIdentity::Principal.new(
      subject: "worker-1", assurance: KemalIdentity::AssuranceLevel::Password,
      authenticated_at: clock.now,
    )

    actor.fresh?(within: 5.minutes, now: clock.now).should be_true
    clock.advance(10.minutes)
    actor.fresh?(within: 5.minutes, now: clock.now).should be_false
  end
end

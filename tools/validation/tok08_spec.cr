require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# TOK-08 — rotating a deploy key without breaking a running fleet.
#
# The shape the scenario describes: a replacement linked to an existing token family, a bounded
# overlap during which both work, then the old one stops. Built here the way an application has
# to build it, because the shard has no family concept and no rotation call.

NOW08 = Time.utc(2026, 9, 2, 12, 0, 0)

# The family table is the application's — `ApiTokens::Token` has an id, an account, a name and
# scopes, and nothing that groups two tokens together. Fifteen lines, and it is the same shape
# TOK-02's resource selection turned out to be.
class KeyFamilies
  record Member, token_id : String, issued_at : Time

  def initialize
    @families = {} of String => Array(Member)
  end

  def add(family : String, token_id : String, at : Time) : Nil
    (@families[family] ||= [] of Member) << Member.new(token_id, at)
  end

  def members(family : String) : Array(Member)
    @families[family]? || [] of Member
  end

  def current(family : String) : String?
    members(family).max_by?(&.issued_at).try(&.token_id)
  end
end

record Rotation,
  clock : KemalIdentity::Testing::TestClock,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  tokens : KemalIdentity::Testing::MemoryApiTokenRepository,
  api : KemalIdentity::ApiTokens::Service,
  families : KeyFamilies

def rotation : Rotation
  clock = KemalIdentity::Testing::TestClock.new(NOW08)
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new
  accounts.insert(KemalIdentity::Accounts::Account.new(
    id: "svc-deploy",
    normalized_login: "svc-deploy",
    auth_version: 1,
    created_at: NOW08,
    updated_at: NOW08,
  ))

  tokens = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)

  Rotation.new(
    clock: clock, accounts: accounts, tokens: tokens, families: KeyFamilies.new,
    api: KemalIdentity::ApiTokens::Service.new(
      tokens: tokens, clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new
    )
  )
end

def account(r : Rotation) : KemalIdentity::Accounts::Account
  r.accounts.find_by_id("svc-deploy").not_nil!
end

describe "TOK-08 — two credentials, one family" do
  it "keeps them separately auditable: two ids, two last-used stamps, one listing" do
    r = rotation

    old = r.api.issue(account(r), "deploy-key", scopes: ["deploy.run"])
    r.families.add("deploy", old.record.id, r.clock.now)

    r.clock.advance(30.days)

    new = r.api.issue(account(r), "deploy-key (rotated)", scopes: ["deploy.run"])
    r.families.add("deploy", new.record.id, r.clock.now)

    old.record.id.should_not eq(new.record.id)
    r.families.current("deploy").should eq(new.record.id)

    # Both authenticate during the overlap, which is the whole point of having one.
    r.api.authenticate(old.token.reveal).should be_a(KemalIdentity::Authenticated)
    r.api.authenticate(new.token.reveal).should be_a(KemalIdentity::Authenticated)

    # And the fleet's progress is visible without asking the fleet: `last_used_at` per token is
    # what says whether anything is still presenting the old key.
    listed = r.api.list("svc-deploy")
    listed.size.should eq(2)
    listed.map(&.id).sort!.should eq([old.record.id, new.record.id].sort!)
    listed.each { |token| token.last_used_at.should_not be_nil }

    # One credential per principal, named. A denial or an action taken with either is
    # attributable to that half of the rotation rather than to the account.
    r.api.authenticate(old.token.reveal).as(KemalIdentity::Authenticated)
      .principal.credential.not_nil!.id.should eq(old.record.id)
    r.api.authenticate(new.token.reveal).as(KemalIdentity::Authenticated)
      .principal.credential.not_nil!.id.should eq(new.record.id)
  end

  it "never reveals the old raw token again" do
    r = rotation

    issued = r.api.issue(account(r), "deploy-key")
    raw = issued.token.reveal

    # The record the management API hands back carries a digest and no secret, and the digest is
    # bytes rather than a string that could be mistaken for one.
    listed = r.api.list("svc-deploy").first
    listed.token_digest.should be_a(Bytes)

    # Nothing in the record equals the raw value, and nothing in the shard can reconstruct it:
    # `issue` is the only place the secret exists.
    listed.to_s.should_not contain(raw)
    listed.inspect.should_not contain(raw)
  end
end

describe "TOK-08 — the overlap window" do
  it "can be bounded at issuance, which is the wrong moment for a rotation" do
    r = rotation

    # A token issued with a deadline expires on its own — fail-closed, checked on every
    # authentication, no job involved.
    short = r.api.issue(account(r), "deploy-key", expires_at: NOW08 + 1.hour)
    r.api.authenticate(short.token.reveal).should be_a(KemalIdentity::Authenticated)

    r.clock.advance(1.hour + 1.second)
    KemalIdentity::Testing.should_fail_with(
      r.api.authenticate(short.token.reveal), KemalIdentity::FailureReason::Expired
    )

    # But the deadline has to be chosen when the token is *created*, and a rotation happens
    # months later. An expiry that means "one hour from whenever somebody rotates" cannot be
    # written at issuance.
  end

  it "is bounded after issuance by expire, which is what a rotation needs" do
    r = rotation

    old = r.api.issue(account(r), "deploy-key")
    r.clock.advance(30.days)
    new = r.api.issue(account(r), "deploy-key (rotated)")

    # The rotation: the replacement exists, and the old credential is given a deadline rather
    # than being killed outright, so the fleet has a window to pick the new one up.
    overlap = 15.minutes
    r.api.expire(old.record.id, "svc-deploy", at: r.clock.now + overlap).should be_true

    # Inside the window both work.
    r.clock.advance(overlap - 1.second)
    r.api.authenticate(old.token.reveal).should be_a(KemalIdentity::Authenticated)
    r.api.authenticate(new.token.reveal).should be_a(KemalIdentity::Authenticated)

    # Past it the old one is refused by the credential check itself — no sweeper, no scheduled
    # revoke, nothing that has to have run.
    r.clock.advance(2.seconds)
    KemalIdentity::Testing.should_fail_with(
      r.api.authenticate(old.token.reveal), KemalIdentity::FailureReason::Expired
    )
    r.api.authenticate(new.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "refuses to lengthen a token's life, and refuses somebody else's token" do
    r = rotation

    issued = r.api.issue(account(r), "deploy-key", expires_at: NOW08 + 1.hour)

    # Later than the deadline it already has: refused, because "expire" is not "renew". A
    # rotation that could extend the credential it is replacing is not a rotation.
    r.api.expire(issued.record.id, "svc-deploy", at: NOW08 + 2.hours).should be_false

    # Earlier: accepted.
    r.api.expire(issued.record.id, "svc-deploy", at: NOW08 + 1.minute).should be_true

    # Somebody else's token, and a token that does not exist, answer the same way — a token id
    # is not secret material, and the difference would say whether one exists.
    r.api.expire(issued.record.id, "other-account", at: NOW08 + 30.seconds).should be_false
    r.api.expire("no-such-token", "svc-deploy", at: NOW08 + 30.seconds).should be_false
  end
end

describe "TOK-08 — revoking the family" do
  it "is one call when the family is the whole account, which a deploy key usually is" do
    r = rotation

    old = r.api.issue(account(r), "deploy-key")
    new = r.api.issue(account(r), "deploy-key (rotated)")

    # `revoke_all` is account-scoped and atomic in the adapters: one statement.
    r.api.revoke_all("svc-deploy").should eq(2)

    [old, new].each do |issued|
      KemalIdentity::Testing.should_fail_with(
        r.api.authenticate(issued.token.reveal), KemalIdentity::FailureReason::Revoked
      )
    end
  end

  it "is one call per member when the account holds more than one family" do
    r = rotation

    deploy_old = r.api.issue(account(r), "deploy-key")
    deploy_new = r.api.issue(account(r), "deploy-key (rotated)")
    unrelated = r.api.issue(account(r), "metrics-scraper")

    r.families.add("deploy", deploy_old.record.id, r.clock.now)
    r.families.add("deploy", deploy_new.record.id, r.clock.now)
    r.families.add("metrics", unrelated.record.id, r.clock.now)

    # Two revocations, not one, and nothing makes them one operation: `revoke_all` would take
    # the metrics token with them, and the contract has no "revoke these ids".
    revoked = r.families.members("deploy").count { |member| r.api.revoke(member.token_id, "svc-deploy") }
    revoked.should eq(2)

    r.api.authenticate(unrelated.token.reveal).should be_a(KemalIdentity::Authenticated)

    # The consequence, stated rather than worked around: a process that dies between the two
    # leaves half the family live. An application that needs the pair to fall together
    # implements `ApiTokens::Repository` over its own table, where it owns the transaction.
    [deploy_old, deploy_new].each do |issued|
      KemalIdentity::Testing.should_fail_with(
        r.api.authenticate(issued.token.reveal), KemalIdentity::FailureReason::Revoked
      )
    end
  end
end

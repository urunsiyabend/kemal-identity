require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# TOK-09 — an organisation-wide token lifetime policy: every personal token must expire within
# 30 days and an unbounded one is forbidden, while another deployment permits non-expiring
# deploy keys.

NOW09 = Time.utc(2026, 9, 2, 12, 0, 0)

record Fleet,
  clock : KemalIdentity::Testing::TestClock,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  tokens : KemalIdentity::Testing::MemoryApiTokenRepository,
  api : KemalIdentity::ApiTokens::Service

def fleet(policy : KemalIdentity::ApiTokens::LifetimePolicy? = nil) : Fleet
  clock = KemalIdentity::Testing::TestClock.new(NOW09)
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new
  accounts.insert(KemalIdentity::Accounts::Account.new(
    id: "ada", normalized_login: "ada@example.com", auth_version: 1,
    created_at: NOW09, updated_at: NOW09,
  ))

  tokens = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)

  Fleet.new(
    clock: clock, accounts: accounts, tokens: tokens,
    api: KemalIdentity::ApiTokens::Service.new(
      tokens: tokens, clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new,
      lifetime_policy: policy,
    )
  )
end

def ada(f : Fleet) : KemalIdentity::Accounts::Account
  f.accounts.find_by_id("ada").not_nil!
end

describe "TOK-09 — the policy is injectable" do
  it "is absent by default, which is the deployment that permits non-expiring deploy keys" do
    f = fleet

    issued = f.api.issue(ada(f), "deploy-key")
    issued.record.expires_at.should be_nil

    # Still working a year later. That is the documented default and the second deployment the
    # scenario describes.
    f.clock.advance(365.days)
    f.api.authenticate(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "refuses an unbounded token when the policy requires an expiry" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days))

    expect_raises(KemalIdentity::ApiTokens::PolicyError, /must expire/) do
      f.api.issue(ada(f), "personal")
    end

    # Nothing was written. The refusal is before storage, so a rejected issuance leaves no row
    # to clean up and no digest to collide with later.
    f.api.list("ada").should be_empty
  end

  it "refuses an expiry beyond the maximum, and names the limit" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days))

    expect_raises(KemalIdentity::ApiTokens::PolicyError, /30/) do
      f.api.issue(ada(f), "personal", expires_at: NOW09 + 31.days)
    end

    f.api.list("ada").should be_empty
  end

  it "accepts a compliant expiry, including exactly the maximum" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days))

    f.api.issue(ada(f), "personal", expires_at: NOW09 + 7.days)
      .record.expires_at.should eq(NOW09 + 7.days)

    f.api.issue(ada(f), "personal-max", expires_at: NOW09 + 30.days)
      .record.expires_at.should eq(NOW09 + 30.days)
  end

  it "still refuses a past expiry, which is not the policy's job but must not regress" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days))

    expect_raises(ArgumentError, /future/) do
      f.api.issue(ada(f), "personal", expires_at: NOW09 - 1.second)
    end
  end

  it "applies a default lifetime when the caller names none" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days, default: 7.days))

    f.api.issue(ada(f), "personal").record.expires_at.should eq(NOW09 + 7.days)
  end

  it "is testable on its own, with no service and no repository" do
    policy = KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days)

    policy.violation(nil, now: NOW09).should eq(KemalIdentity::ApiTokens::PolicyViolation::ExpiryRequired)
    policy.violation(NOW09 + 31.days, now: NOW09).should eq(KemalIdentity::ApiTokens::PolicyViolation::TooLong)
    policy.violation(NOW09 + 30.days, now: NOW09).should be_nil
    policy.violation(NOW09 + 1.hour, now: NOW09).should be_nil
  end

  it "refuses a contradictory policy at construction" do
    expect_raises(KemalIdentity::ConfigurationError, /default/) do
      KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 7.days, default: 30.days)
    end

    expect_raises(KemalIdentity::ConfigurationError, /positive/) do
      KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: Time::Span.zero)
    end
  end
end

describe "TOK-09 — tightening the policy while old tokens exist" do
  it "leaves the tokens that already exist exactly as they were" do
    lenient = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 90.days))
    long = lenient.api.issue(ada(lenient), "personal", expires_at: NOW09 + 90.days)

    # The organisation tightens to 30 days. The service is reconfigured; the rows are not.
    strict = KemalIdentity::ApiTokens::Service.new(
      tokens: lenient.tokens, clock: lenient.clock,
      random: KemalIdentity::Testing::DeterministicRandom.new,
      lifetime_policy: KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days),
    )

    # Issuance now obeys the new limit.
    expect_raises(KemalIdentity::ApiTokens::PolicyError) do
      strict.issue(ada(lenient), "personal", expires_at: NOW09 + 90.days)
    end

    # And the existing 90-day token still authenticates: a policy is checked when a credential
    # is created, not on every request, so tightening it does not retroactively kill anything.
    lenient.clock.advance(31.days)
    strict.authenticate(long.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "can be applied to the tokens that already exist, with expire" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 90.days))
    long = f.api.issue(ada(f), "personal", expires_at: NOW09 + 90.days)

    # The retro-fit an organisation actually wants after tightening: walk the tokens that
    # violate the new limit and bring them forward. TOK-08's `expire` is what makes this
    # possible at all, and it cannot lengthen anything by accident.
    deadline = NOW09 + 30.days
    f.api.list("ada").each do |token|
      expires = token.expires_at
      next if expires && expires <= deadline

      f.api.expire(token.id, "ada", at: deadline).should be_true
    end

    f.api.list("ada").first.expires_at.should eq(deadline)

    f.clock.advance(31.days)
    KemalIdentity::Testing.should_fail_with(
      f.api.authenticate(long.token.reveal), KemalIdentity::FailureReason::Expired
    )
  end
end

describe "TOK-09 — finding tokens that are about to expire" do
  it "reports expiry through the management listing, with no secret in it" do
    f = fleet(KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days))

    soon = f.api.issue(ada(f), "expiring-soon", expires_at: NOW09 + 2.days)
    later = f.api.issue(ada(f), "expiring-later", expires_at: NOW09 + 20.days)

    within_a_week = f.api.list("ada").select do |token|
      expires = token.expires_at
      expires && expires <= f.clock.now + 7.days
    end

    within_a_week.map(&.id).should eq([soon.record.id])
    within_a_week.first.name.should eq("expiring-soon")

    # Nothing a client could present: the record carries a digest, and the listing is the same
    # records a management screen renders.
    f.api.list("ada").each do |token|
      token.token_digest.should be_a(Bytes)
      token.to_s.should_not contain(soon.token.reveal)
      token.to_s.should_not contain(later.token.reveal)
    end
  end
end

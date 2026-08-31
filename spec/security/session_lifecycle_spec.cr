require "../spec_helper"

# The session lifecycle blockers from docs/05-testing.md. v0.1 does not ship until every one
# of these passes, and each is named for the situation rather than for the method under test.
#
# No sleeping and no real clock anywhere: expiry is asserted by advancing a `TestClock`.

describe "logout" do
  it "rejects the session cookie afterwards" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    h.service.revoke(issued.record.id).should be_true

    outcome = h.service.resolve(issued.token.reveal)
    outcome.should be_a(KemalIdentity::Failed)
    KemalIdentity::Testing.should_fail_with(outcome, KemalIdentity::FailureReason::Revoked)
  end

  it "does not affect the account's other sessions" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    first = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
    second = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.service.revoke(first.record.id)

    h.service.resolve(second.token.reveal).should be_a(KemalIdentity::Authenticated)
  end
end

describe "session expiry" do
  # kemal-session #116: a timeout that only marks a session for deletion at the next GC pass
  # leaves it valid until the sweeper runs, and a read can refresh its access time before any
  # expiry check, reviving it. Expiry is evaluated on read, here, always.
  it "rejects an expired session without waiting for the sweeper" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.clock.advance(13.hours)

    outcome = h.service.resolve(issued.token.reveal)
    KemalIdentity::Testing.should_fail_with(outcome, KemalIdentity::FailureReason::Expired)

    # The row is still there. Nothing swept it, and it was rejected anyway.
    h.sessions.size.should eq(1)
  end

  it "expires an idle session" do
    config = KemalIdentity::Sessions::Config.new(idle_timeout: 30.minutes, absolute_timeout: 12.hours)
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.clock.advance(31.minutes)

    KemalIdentity::Testing.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Expired)
  end

  it "extends an idle session when the user is active" do
    config = KemalIdentity::Sessions::Config.new(
      idle_timeout: 30.minutes, absolute_timeout: 12.hours, touch_interval: 60.seconds
    )
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    # Active every 20 minutes for two hours: well past the idle window, never idle for it.
    6.times do
      h.clock.advance(20.minutes)
      h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
    end
  end

  # The throttle's price, stated as a contract rather than left as an implementation
  # accident: idle expiry is accurate only to within one touch_interval.
  it "is accurate to within exactly one touch_interval" do
    config = KemalIdentity::Sessions::Config.new(
      idle_timeout: 30.minutes, absolute_timeout: 12.hours, touch_interval: 60.seconds
    )
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    # A read inside the throttle window does not move the deadline.
    h.clock.advance(30.seconds)
    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
    h.sessions.find_by_digest(issued.record.token_digest).or_fail
      .session.idle_expires_at.should eq(KemalIdentity::Testing::FIXED_NOW + 30.minutes)

    # A read past it does.
    h.clock.advance(31.seconds)
    h.service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
    h.sessions.find_by_digest(issued.record.token_digest).or_fail
      .session.idle_expires_at.should eq(KemalIdentity::Testing::FIXED_NOW + 61.seconds + 30.minutes)
  end

  it "fires absolute expiry regardless of activity" do
    config = KemalIdentity::Sessions::Config.new(
      idle_timeout: 30.minutes, absolute_timeout: 4.hours, touch_interval: 60.seconds
    )
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    # Continuously active, so idle expiry never fires. The absolute deadline still does.
    outcomes = Array.new(13) do
      h.clock.advance(20.minutes)
      h.service.resolve(issued.token.reveal)
    end

    outcomes[0..10].each(&.should(be_a(KemalIdentity::Authenticated)))
    KemalIdentity::Testing.should_fail_with(outcomes[12], KemalIdentity::FailureReason::Expired)
  end

  it "treats the deadline itself as expired, agreeing with the sweeper" do
    config = KemalIdentity::Sessions::Config.new(idle_timeout: 1.hour, absolute_timeout: 4.hours)
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    h.clock.advance(4.hours)

    KemalIdentity::Testing.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Expired)
    # The sweeper agrees at the same instant, so it can never delete a row resolve calls live.
    h.service.delete_expired.should eq(1)
  end
end

describe "session fixation" do
  # The defence: whatever identifier a client held before authenticating is worthless
  # afterwards, so an attacker cannot plant one and inherit the victim's session.
  it "issues a different session id after login than before" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail

    before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)
    after = h.service.rotate(before.record, account, assurance: KemalIdentity::AssuranceLevel::Password)

    after.record.id.should_not eq(before.record.id)
  end

  it "issues a different token, not merely a different id" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail

    before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)
    after = h.service.rotate(before.record, account, assurance: KemalIdentity::AssuranceLevel::Password)

    after.token.reveal.should_not eq(before.token.reveal)
    after.record.token_digest.should_not eq(before.record.token_digest)
  end

  it "makes the pre-login token unusable" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail

    before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)
    h.service.rotate(before.record, account, assurance: KemalIdentity::AssuranceLevel::Password)

    KemalIdentity::Testing.should_fail_with(h.service.resolve(before.token.reveal), KemalIdentity::FailureReason::Revoked)
  end

  it "raises the assurance level and refreshes authenticated_at" do
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)

    h.clock.advance(1.hour)
    after = h.service.rotate(before.record, account, assurance: KemalIdentity::AssuranceLevel::Password)

    after.principal.assurance.should eq(KemalIdentity::AssuranceLevel::Password)
    after.principal.authenticated_at.should eq(KemalIdentity::Testing::FIXED_NOW + 1.hour)
    after.principal.fresh?(within: 5.minutes, now: h.clock.now).should be_true
  end

  # Rotation is not a way to live forever: the new session gets a fresh absolute window
  # because a credential was just verified, which is a different thing from activity.
  it "restarts the absolute window on re-authentication but not on activity" do
    config = KemalIdentity::Sessions::Config.new(idle_timeout: 30.minutes, absolute_timeout: 4.hours)
    h = KemalIdentity::Testing.harness(config: config, accounts: [KemalIdentity::Testing.account])
    account = h.accounts.find_by_id("a1").or_fail
    before = h.service.start(account, KemalIdentity::AssuranceLevel::Password)

    h.clock.advance(1.hour)
    after = h.service.rotate(before.record, account)

    after.record.absolute_expires_at.should eq(KemalIdentity::Testing::FIXED_NOW + 1.hour + 4.hours)
  end
end

require "../spec_helper"

describe KemalIdentity::Sessions::Service do
  describe "#resolve" do
    # Anonymous and Failed are different on purpose: a request with no cookie needs no
    # response action, while a request whose cookie did not resolve needs that cookie
    # cleared. A handler cannot tell those apart from a nilable principal.
    it "is anonymous when there is no cookie at all" do
      h = KemalIdentity::SpecHelper.harness
      h.service.resolve(nil).should be_a(KemalIdentity::Anonymous)
      h.service.resolve("").should be_a(KemalIdentity::Anonymous)
    end

    it "fails rather than going anonymous when a cookie is present but unusable" do
      h = KemalIdentity::SpecHelper.harness
      h.service.resolve("garbage").should be_a(KemalIdentity::Failed)
    end

    describe "the shape check that runs before any I/O" do
      it "rejects a value of the wrong length" do
        h = KemalIdentity::SpecHelper.harness
        KemalIdentity::SpecHelper.should_fail_with(h.service.resolve("a" * 42), KemalIdentity::FailureReason::MalformedCredential)
      end

      it "rejects a value outside the base64url alphabet" do
        h = KemalIdentity::SpecHelper.harness
        KemalIdentity::SpecHelper.should_fail_with(
          h.service.resolve("a" * 42 + "!"), KemalIdentity::FailureReason::MalformedCredential
        )
        KemalIdentity::SpecHelper.should_fail_with(
          h.service.resolve("a" * 42 + "="), KemalIdentity::FailureReason::MalformedCredential
        )
      end

      # A client sending a two-megabyte cookie should be turned away by a length comparison,
      # not by the database.
      it "rejects an oversized value without touching the repository" do
        h = KemalIdentity::SpecHelper.harness
        counting = CountingSessionRepository.new(h.sessions)
        service = KemalIdentity::Sessions::Service.new(
          sessions: counting, clock: h.clock, random: h.random
        )

        KemalIdentity::SpecHelper.should_fail_with(service.resolve("a" * 2_000_000), KemalIdentity::FailureReason::MalformedCredential)

        counting.lookups.should eq(0)
      end

      it "accepts a well-shaped value and does query for it" do
        h = KemalIdentity::SpecHelper.harness
        counting = CountingSessionRepository.new(h.sessions)
        service = KemalIdentity::Sessions::Service.new(
          sessions: counting, clock: h.clock, random: h.random
        )

        service.resolve("a" * 43).should be_a(KemalIdentity::Failed)
        counting.lookups.should eq(1)
      end
    end

    it "fails with InvalidCredential for a well-shaped token nobody issued" do
      h = KemalIdentity::SpecHelper.harness
      KemalIdentity::SpecHelper.should_fail_with(h.service.resolve("a" * 43), KemalIdentity::FailureReason::InvalidCredential)
    end

    it "builds a principal carrying the session's security context" do
      h = KemalIdentity::SpecHelper.harness(
        accounts: [KemalIdentity::SpecHelper.account(tenant_id: "t1")]
      )
      issued = h.service.start(
        h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::MFA,
        mfa_verified_at: KemalIdentity::SpecHelper::FIXED_NOW
      )

      principal = h.service.resolve(issued.token.reveal).as(KemalIdentity::Authenticated).principal
      principal.subject.should eq("a1")
      principal.session_id.should eq(issued.record.id)
      principal.assurance.should eq(KemalIdentity::AssuranceLevel::MFA)
      principal.tenant_id.should eq("t1")
      principal.mfa_verified_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW)
    end

    # The order in docs/02-security-model.md. Revocation is reported ahead of expiry, so a
    # session that is both reports the deliberate action rather than the passive one.
    it "reports revocation ahead of expiry" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      h.service.revoke(issued.record.id)
      h.clock.advance(13.hours)

      KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Revoked)
    end

    it "reports expiry ahead of account status" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      h.clock.advance(13.hours)
      h.accounts.disable("a1", h.clock.now)

      KemalIdentity::SpecHelper.should_fail_with(h.service.resolve(issued.token.reveal), KemalIdentity::FailureReason::Expired)
    end

    it "does not write on a read inside the touch interval" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      counting = CountingSessionRepository.new(h.sessions)
      service = KemalIdentity::Sessions::Service.new(
        sessions: counting, clock: h.clock, random: h.random
      )
      issued = service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      5.times { service.resolve(issued.token.reveal) }

      counting.touches.should eq(0)
    end

    it "writes once the touch interval has passed" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      counting = CountingSessionRepository.new(h.sessions)
      service = KemalIdentity::Sessions::Service.new(
        sessions: counting, clock: h.clock, random: h.random
      )
      issued = service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      h.clock.advance(61.seconds)
      service.resolve(issued.token.reveal)

      counting.touches.should eq(1)
    end
  end

  describe "#start" do
    it "stamps the account's current auth_version onto the session" do
      h = KemalIdentity::SpecHelper.harness(
        accounts: [KemalIdentity::SpecHelper.account(auth_version: 5)]
      )
      issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      issued.record.auth_version.should eq(5)
    end

    it "carries the account's tenant onto the session" do
      h = KemalIdentity::SpecHelper.harness(
        accounts: [KemalIdentity::SpecHelper.account(tenant_id: "t1")]
      )
      h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
        .record.tenant_id.should eq("t1")
    end

    it "sets both deadlines from the configured windows" do
      config = KemalIdentity::Sessions::Config.new(idle_timeout: 15.minutes, absolute_timeout: 8.hours)
      h = KemalIdentity::SpecHelper.harness(config: config, accounts: [KemalIdentity::SpecHelper.account])
      record = h.service.start(
        h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password
      ).record

      record.idle_expires_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW + 15.minutes)
      record.absolute_expires_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW + 8.hours)
    end
  end

  describe "#delete_expired" do
    # Correctness never depends on this having run, which is exactly why it must not remove
    # anything resolve still considers live.
    it "leaves live sessions alone" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      h.service.delete_expired.should eq(0)
      h.sessions.size.should eq(1)
    end

    it "removes rows past their absolute deadline" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

      h.clock.advance(13.hours)
      h.service.delete_expired.should eq(1)
      h.sessions.size.should eq(0)
    end
  end
end

describe KemalIdentity::Sessions::Config do
  it "refuses an idle window longer than the absolute one, which could never fire" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::Config.new(idle_timeout: 2.hours, absolute_timeout: 1.hour)
    end
  end

  it "refuses a touch interval that could expire an active session" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::Config.new(idle_timeout: 30.minutes, touch_interval: 30.minutes)
    end
  end

  it "refuses non-positive windows" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::Config.new(idle_timeout: Time::Span::ZERO)
    end
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Sessions::Config.new(absolute_timeout: -1.hour)
    end
  end

  it "allows a zero touch interval, which writes on every read" do
    KemalIdentity::Sessions::Config.new(touch_interval: Time::Span::ZERO)
      .touch_interval.should eq(Time::Span::ZERO)
  end
end

# Counts the calls that matter for the hot path: a lookup per request is the design, a write
# per request is the trap.
class CountingSessionRepository < KemalIdentity::Sessions::Repository
  getter lookups : Int32 = 0
  getter touches : Int32 = 0

  def initialize(@inner : KemalIdentity::Sessions::Repository)
  end

  def create(record : KemalIdentity::Sessions::Record) : Nil
    @inner.create(record)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
    @lookups += 1
    @inner.find_by_digest(digest)
  end

  def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
    @touches += 1
    @inner.touch(id, last_seen_at, idle_expires_at)
  end

  def revoke(id : String, at : Time) : Bool
    @inner.revoke(id, at)
  end

  def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
    @inner.revoke_all_for_account(account_id, at, except_id: except_id)
  end

  def delete_expired(before : Time) : Int32
    @inner.delete_expired(before)
  end
end

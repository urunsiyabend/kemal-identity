require "log/spec"
require "../spec_helper"

# A limiter whose store is down, as a Redis-backed adapter would report it.
private class BrokenStoreRateLimiter < KemalIdentity::RateLimiter
  def consume(key : String) : KemalIdentity::Verdict
    KemalIdentity::Verdict.unavailable
  end

  def reset(key : String) : Nil
  end
end

# `docs/02-security-model.md`, "Logging":
#
#   Do log, as structured events: login success and failure with reason, logout, session
#   rotation, bulk revocation, rate-limit denials, and replay detection.
#
# `spec/security/audit_log_spec.cr` covers what must never appear in a log line. This file
# covers the other half: that the events on that list are actually emitted, with the fields an
# investigator needs. Two of them — rotation and bulk revocation — were missing entirely until
# this spec was written, which is the argument for having it.
private PASSWORD = "correct horse battery"

# Every entry the shard emitted during the block.
#
# `Log.capture` consumes entries as it matches them, which suits an assertion about one event
# and not an assertion about the shape of a whole trail.
private def captured(&) : Array(Log::Entry)
  backend = Log::MemoryBackend.new
  Log.builder.bind("kemal_identity.*", :trace, backend)
  yield
  backend.entries
end

private def messages(entries : Array(Log::Entry)) : Array(String)
  entries.map(&.message)
end

private def entry(entries : Array(Log::Entry), message : String) : Log::Entry
  found = entries.find { |candidate| candidate.message == message }

  if found.nil?
    raise Spec::AssertionFailed.new(
      "expected a #{message.inspect} event, got #{messages(entries).inspect}", __FILE__, __LINE__
    )
  end

  found
end

describe "the audit trail" do
  describe "login" do
    it "records a success with the account it authenticated" do
      h = KemalIdentity::SpecHelper.account_harness
      hasher = h.hasher
      repo = KemalIdentity::Testing::MemoryAccountRepository.new([
        KemalIdentity::SpecHelper.account(
          password_digest: hasher.hash_secret(KemalIdentity::Secret.new(PASSWORD))
        ),
      ])
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: repo, hasher: hasher, clock: h.clock
      )

      entries = captured { auth.authenticate(login: "ada@example.com", password: PASSWORD) }

      entry(entries, "authentication.succeeded").data[:subject].should eq("a1")
    end

    it "records a failure with its reason" do
      h = KemalIdentity::SpecHelper.account_harness
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: h.accounts, hasher: h.hasher, clock: h.clock
      )

      entries = captured { auth.authenticate(login: "ada@example.com", password: "wrong") }

      entry(entries, "authentication.failed").data[:reason].should eq("InvalidCredential")
    end

    # The response is forbidden to distinguish these; the trail is required to.
    it "records a rate-limit denial distinctly from a wrong password" do
      limiter = KemalIdentity::FixedWindowRateLimiter.new(
        limit: 1, window: 1.hour,
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      )
      h = KemalIdentity::SpecHelper.account_harness
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: h.accounts, hasher: h.hasher, clock: h.clock, rate_limiter: limiter
      )

      entries = captured do
        auth.authenticate(login: "ada@example.com", password: "wrong")
        auth.authenticate(login: "ada@example.com", password: "wrong")
      end

      reasons = entries.select { |candidate| candidate.message == "authentication.failed" }
        .map(&.data.[:reason].to_s)

      reasons.should contain("InvalidCredential")
      reasons.should contain("RateLimited")
    end

    # A broken limiter and a working one are different events. `RateLimited` is somebody having
    # had their share; this is nobody knowing what anybody's share is, which is an incident and
    # often the first half of an attack — the cheapest way to disable rate limiting is to break
    # what stores it. A trail that reported them the same way would bury the page-worthy one
    # inside the routine one.
    it "records a broken limiter distinctly from a throttle, at error level" do
      h = KemalIdentity::SpecHelper.account_harness
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: h.accounts, hasher: h.hasher, clock: h.clock,
        rate_limiter: BrokenStoreRateLimiter.new
      )

      entries = captured do
        auth.authenticate(login: "ada@example.com", password: "wrong")
      end

      outage = entry(entries, "rate_limiter.unavailable")
      outage.severity.should eq(::Log::Severity::Error)
      outage.data[:endpoint].to_s.should eq("login")

      entries.select { |candidate| candidate.message == "authentication.failed" }
        .map(&.data.[:reason].to_s)
        .should contain("RateLimiterUnavailable")
    end
  end

  describe "sessions" do
    it "records a session being started, from the service rather than the web layer" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      account = h.accounts.find_by_id("a1").or_fail

      entries = captured { h.service.start(account, KemalIdentity::AssuranceLevel::Password) }

      started = entry(entries, "session.started")
      started.data[:subject].should eq("a1")
      started.data[:assurance].should eq("Password")

      # Exactly one. The event used to live in `env.auth.start!`, and emitting it in both
      # places would double every login in the trail.
      messages(entries).count("session.started").should eq(1)
    end

    # A rotation replaced a session rather than starting one, and an investigator wants those
    # distinguishable.
    it "does not also record a rotation as a start" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      account = h.accounts.find_by_id("a1").or_fail
      before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)

      entries = captured { h.service.rotate(before.record, account) }

      messages(entries).should contain("session.rotated")
      messages(entries).should_not contain("session.started")
    end

    # How an investigator sees the session fixation defence actually firing: a login replaced an
    # identifier the client was already holding.
    it "records a rotation, naming the session it replaced" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      account = h.accounts.find_by_id("a1").or_fail
      before = h.service.start(account, KemalIdentity::AssuranceLevel::Remembered)

      entries = captured do
        h.service.rotate(before.record, account, assurance: KemalIdentity::AssuranceLevel::Password)
      end

      rotated = entry(entries, "session.rotated")
      rotated.data[:subject].should eq("a1")
      rotated.data[:from].should eq(before.record.id)
      rotated.data[:to].should_not eq(before.record.id)
    end

    it "records a single revocation" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      issued = h.service.start(
        h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password
      )

      entries = captured { h.service.revoke(issued.record.id) }
      entry(entries, "session.revoked").data[:session].should eq(issued.record.id)
    end

    # Revoking an already-revoked session is not an event. Logging it would put a line in the
    # trail for every double-submitted logout.
    it "does not record a revocation that changed nothing" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      issued = h.service.start(
        h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password
      )
      h.service.revoke(issued.record.id)

      entries = captured { h.service.revoke(issued.record.id) }
      messages(entries).should_not contain("session.revoked")
    end

    # The count is the part that matters: "revoked 4 sessions" tells an investigator four people
    # were signed out.
    it "records a bulk revocation with how many it ended" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      account = h.accounts.find_by_id("a1").or_fail
      3.times { h.service.start(account, KemalIdentity::AssuranceLevel::Password) }

      entries = captured { h.service.revoke_all("a1") }

      bulk = entry(entries, "session.revoked_all")
      bulk.data[:subject].should eq("a1")
      bulk.data[:count].should eq(3)
    end

    it "does not record a bulk revocation that ended nothing" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])

      entries = captured { h.service.revoke_all("a1") }
      messages(entries).should_not contain("session.revoked_all")
    end
  end

  # The most important event here: it reports a suspicion rather than an action somebody took.
  describe "remember-me replay" do
    it "records the detection at warning level, naming the family" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      random = KemalIdentity::Testing::DeterministicRandom.new
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
      sessions = KemalIdentity::Sessions::Service.new(
        sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
        clock: clock, random: random
      )
      service = KemalIdentity::Sessions::RememberService.new(
        remember: KemalIdentity::Testing::MemoryRememberRepository.new,
        accounts: accounts, sessions: sessions, clock: clock, random: random
      )

      token = service.remember(accounts.find_by_id("a1").or_fail).token.reveal
      service.restore(token)

      entries = captured { service.restore(token) }

      detected = entry(entries, "remember.replay_detected")
      detected.severity.should eq(Log::Severity::Warn)
      detected.data[:subject].should eq("a1")
    end
  end

  # docs/02 lists reset rate limiting among the denials worth recording, and the endpoint is
  # otherwise deliberately silent — the log is the only place the denial is visible at all.
  describe "password reset" do
    it "records a throttled request" do
      limiter = KemalIdentity::FixedWindowRateLimiter.new(
        limit: 1, window: 1.hour,
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      )
      h = KemalIdentity::SpecHelper.account_harness(rate_limiter: limiter)

      entries = captured do
        h.service.request_password_reset("ada@example.com")
        h.service.request_password_reset("ada@example.com")
      end

      entry(entries, "password_reset.throttled")
    end

    it "records whether the address was known, which the response does not" do
      h = KemalIdentity::SpecHelper.account_harness

      known = captured { h.service.request_password_reset("ada@example.com") }
      unknown = captured { h.service.request_password_reset("nobody@example.com") }

      entry(known, "password_reset.requested").data[:known].should be_true
      entry(unknown, "password_reset.requested").data[:known].should be_false
    end
  end

  # Every event goes through one named source, so an application can route the whole trail
  # somewhere durable with a single binding rather than hunting for call sites.
  describe "the source they are emitted on" do
    it "is kemal_identity for every event" do
      h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
      account = h.accounts.find_by_id("a1").or_fail

      entries = captured do
        issued = h.service.start(account, KemalIdentity::AssuranceLevel::Password)
        h.service.revoke(issued.record.id)
      end

      entries.should_not be_empty
      entries.each { |candidate| candidate.source.should start_with("kemal_identity") }
    end
  end
end

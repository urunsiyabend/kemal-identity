require "../spec_helper"

# OPS-02. `blueprints/0025-maturity-validation-results.md` measured two things a consumer could
# not have: a typed sink, and a failure mode that neither takes authentication down nor goes
# quiet. Both are asserted here.

private class RecordingSink < KemalIdentity::SecurityEventSink
  getter events = [] of KemalIdentity::SecurityEvent

  def record(event : KemalIdentity::SecurityEvent) : Nil
    @events << event
  end
end

private class BrokenSink < KemalIdentity::SecurityEventSink
  getter attempts = 0

  def record(event : KemalIdentity::SecurityEvent) : Nil
    @attempts += 1
    raise "SIEM unreachable"
  end
end

# The bridge is a Log backend, so events reach it through the same path production uses. Building
# one directly keeps the assertions about translation rather than about Log configuration.
private def deliver(sink : KemalIdentity::SecurityEventSink, &) : KemalIdentity::EventBridge
  bridge = KemalIdentity::EventBridge.new(sink)
  backend = ::Log::MemoryBackend.new
  ::Log.builder.bind("kemal_identity.*", :trace, backend)

  yield

  backend.entries.each { |entry| bridge.write(entry) }
  bridge
end

describe "OPS-02: a typed security event sink" do
  it "hands a consumer the correlation fields as getters, not as a bag" do
    sink = RecordingSink.new
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])

    deliver(sink) do
      h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    end

    started = sink.events.find { |event| event.name == "session.started" }.or_fail
    started.subject.should eq("a1")
    started.severity.should eq(::Log::Severity::Info)
    started.at.should_not be_nil
  end

  it "carries the reason on a failure, typed rather than parsed out of a message" do
    sink = RecordingSink.new
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    )
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts,
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
    )

    deliver(sink) { auth.authenticate(login: "nobody@example.com", password: "wrong", ip: "203.0.113.7") }

    failed = sink.events.find { |event| event.name == "authentication.failed" }.or_fail
    failed.reason.should eq("InvalidCredential")
    failed.ip.should eq("203.0.113.7")
  end

  it "separates event detail from the correlation fields" do
    sink = RecordingSink.new
    h = KemalIdentity::Testing.harness(accounts: [KemalIdentity::Testing.account])
    issued = h.service.start(
      h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password
    )

    deliver(sink) { h.service.revoke(issued.record.id) }

    revoked = sink.events.find { |event| event.name == "session.revoked" }.or_fail
    revoked.credential.should eq(issued.record.id)
    revoked.data.should be_empty
  end

  # Every event that mints or kills a credential must name it in the typed field, not bury an id
  # in the bag under a field name of its own. Found by reading a consumer app's log output, where
  # `api_token.issued` printed `token: "_OTDjk6pl9-..."` -- a token *id*, under a field name that
  # reads as though the secret itself were in the line (`blueprints/0025`, TOK-02).
  it "names the credential on every event that mints or kills one" do
    sink = RecordingSink.new
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    account = accounts.find_by_id("a1").or_fail

    sessions = KemalIdentity::Sessions::Service.new(
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 21),
    )
    api = KemalIdentity::ApiTokens::Service.new(
      tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 22),
    )

    session = uninitialized KemalIdentity::Sessions::Issued
    issued = uninitialized KemalIdentity::ApiTokens::Issued

    deliver(sink) do
      session = sessions.start(account, KemalIdentity::AssuranceLevel::Password)
      issued = api.issue(account: account, name: "ci")
      api.revoke(issued.record.id)
      sessions.revoke(session.record.id)
    end

    expected = {
      "session.started"   => session.record.id,
      "api_token.issued"  => issued.record.id,
      "api_token.revoked" => issued.record.id,
      "session.revoked"   => session.record.id,
    }

    expected.each do |name, id|
      event = sink.events.find { |candidate| candidate.name == name }.or_fail("no #{name} event")
      event.credential.should eq(id)
      # And the id is not also sitting in the bag under an older name.
      event.data.has_key?("token").should be_false
      event.data.has_key?("session").should be_false
    end
  end

  # docs/02-security-model.md's list of what must never be logged, checked at the sink rather than
  # at the log line -- a consumer's SIEM is one more place a secret could land.
  it "carries no credential material" do
    sink = RecordingSink.new
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [KemalIdentity::Testing.account]
    )
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts,
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
    )

    deliver(sink) { auth.authenticate(login: "ada@example.com", password: "hunter2-secret") }

    rendered = sink.events.map do |event|
      "#{event.name} #{event.subject} #{event.credential} #{event.reason} #{event.data}"
    end.join(" ")

    rendered.should_not contain("hunter2-secret")
    rendered.should_not contain("ada@example.com")
  end

  it "flags what an operator should be woken for" do
    KemalIdentity::SecurityEvent.new(
      name: "remember.replay_detected", severity: ::Log::Severity::Warn,
      at: KemalIdentity::Testing::FIXED_NOW
    ).alarming?.should be_true

    KemalIdentity::SecurityEvent.new(
      name: "session.started", severity: ::Log::Severity::Info,
      at: KemalIdentity::Testing::FIXED_NOW
    ).alarming?.should be_false
  end
end

describe "OPS-02: when the sink itself fails" do
  # The measured failure this exists because of: under `:direct` dispatch a raising backend left
  # `authenticate` as an exception and every login became a 500.
  it "does not let a raising sink reach the caller" do
    sink = BrokenSink.new
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    )
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts,
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
    )

    bridge = deliver(sink) { auth.authenticate(login: "nobody@example.com", password: "wrong") }

    sink.attempts.should be > 0
    bridge.failures.should eq(sink.attempts)
  end

  # And the other one: under `:async` the dispatcher fiber died and the trail went quiet with
  # nothing said. A rising count is what "the SIEM feed is broken" looks like from the inside.
  it "counts every drop, so a failing sink is not silent" do
    sink = BrokenSink.new
    bridge = KemalIdentity::EventBridge.new(sink)

    3.times do
      bridge.write(
        ::Log::Entry.new(
          source: "kemal_identity", severity: :info, message: "session.started",
          data: ::Log::Metadata.empty, exception: nil
        )
      )
    end

    bridge.failures.should eq(3)
  end

  it "keeps delivering to a healthy sink after a broken one failed" do
    healthy = RecordingSink.new
    broken = KemalIdentity::EventBridge.new(BrokenSink.new)
    good = KemalIdentity::EventBridge.new(healthy)

    entry = ::Log::Entry.new(
      source: "kemal_identity", severity: :info, message: "session.started",
      data: ::Log::Metadata.empty, exception: nil
    )

    broken.write(entry)
    good.write(entry)

    broken.failures.should eq(1)
    healthy.events.size.should eq(1)
  end
end

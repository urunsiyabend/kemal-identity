require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# OPS-02 after the change, from the consumer side. The question the first measurement answered
# with "no": can an application implement a typed sink, and does a broken one either take
# authentication down or go quiet?
private class SiemSink < KemalIdentity::SecurityEventSink
  getter events = [] of KemalIdentity::SecurityEvent

  def record(event : KemalIdentity::SecurityEvent) : Nil
    @events << event
  end
end

private class DeadSiem < KemalIdentity::SecurityEventSink
  def record(event : KemalIdentity::SecurityEvent) : Nil
    raise IO::Error.new("connection reset")
  end
end

private def authenticator
  KemalIdentity::Passwords::Authenticator.new(
    accounts: KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    ),
    hasher: KemalIdentity::Testing::FastTestHasher.new,
    clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
  )
end

describe "OPS-02: a consumer's typed sink" do
  it "is an abstract class the application implements" do
    sink = SiemSink.new
    bridge = KemalIdentity::EventBridge.new(sink)

    bridge.write(
      ::Log::Entry.new(
        source: "kemal_identity", severity: :warn, message: "remember.replay_detected",
        data: ::Log::Metadata.build({subject: "a1", credential: "sess-1"}), exception: nil
      )
    )

    event = sink.events.first
    event.name.should eq("remember.replay_detected")
    event.subject.should eq("a1") # a getter, not a hash lookup
    event.credential.should eq("sess-1")
    event.alarming?.should be_true # and it knows this one is worth a page
  end

  it "reaches the sink through the shard's own events" do
    sink = SiemSink.new
    KemalIdentity.event_sink = sink

    authenticator.authenticate(login: "nobody@example.com", password: "wrong")
    Fiber.yield # the bridge dispatches asynchronously, so a slow sink cannot sit on a request

    sink.events.map(&.name).should contain("authentication.failed")
  end

  # The first measurement's two failure modes, both gone.
  it "does not turn a dead SIEM into a failed login" do
    KemalIdentity.event_sink = DeadSiem.new

    outcome = authenticator.authenticate(login: "nobody@example.com", password: "wrong")

    # The credential decision is unchanged: refused on its merits, not on the sink.
    outcome.as(KemalIdentity::Failed).reason
      .should eq(KemalIdentity::FailureReason::InvalidCredential)
  end

  it "counts what a dead SIEM dropped, so the feed is not silently broken" do
    bridge = KemalIdentity::EventBridge.new(DeadSiem.new)

    2.times do
      bridge.write(
        ::Log::Entry.new(
          source: "kemal_identity", severity: :info, message: "session.started",
          data: ::Log::Metadata.empty, exception: nil
        )
      )
    end

    bridge.failures.should eq(2)
  end
end

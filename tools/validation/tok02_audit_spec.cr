require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# Found while reading the TOK-02 app's own log output: `api_token.issued` emits a field called
# `token`, whose value is the token *id* and looks exactly like a secret. That is also the field
# name `blueprints/0027` normalised everywhere else to `credential`.
#
# The question this measures: does the typed `SecurityEvent#credential` get populated for the
# events that mint a credential?
class RecordingSink < KemalIdentity::SecurityEventSink
  getter events = [] of KemalIdentity::SecurityEvent

  def record(event : KemalIdentity::SecurityEvent) : Nil
    @events << event
  end
end

describe "audit correlation for the events that mint a credential" do
  it "reports what the typed credential field holds" do
    sink = RecordingSink.new
    bridge = KemalIdentity::EventBridge.new(sink)
    KemalIdentity.event_sink = sink

    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

    app = KemalIdentity.configure(
      accounts: accounts,
      sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
      hasher: KemalIdentity::Testing::FastTestHasher.new,
      clock: clock,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 6),
      api_tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
    )

    account = KemalIdentity::Testing.account
    issued = app.api.not_nil!.issue(account: account, name: "ci", scopes: ["repo.read"])
    session = app.sessions.start(account, KemalIdentity::AssuranceLevel::Password)
    app.api.not_nil!.revoke(issued.record.id)

    sleep 50.milliseconds # the bridge dispatches asynchronously

    sink.events.each do |event|
      puts "#{event.name}: credential=#{event.credential.inspect} data=#{event.data}"
    end

    minting = sink.events.select { |e| e.name.in?({"api_token.issued", "session.started", "api_token.revoked"}) }
    minting.size.should eq(3)
    minting.each { |e| e.credential.should_not be_nil }
  end
end

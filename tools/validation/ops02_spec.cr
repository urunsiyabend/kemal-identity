require "spec"
require "kemal_identity"
# The in-memory doubles live in spec/support, not src, so this reaches into the shard's own
# private spec tree — the DEV-02 finding, hit here as a side effect of needing a fake repository.
require "../lib/kemal_identity/spec/spec_helper"

# OPS-02: send authentication and authorization events to a SIEM with request, actor,
# credential and tenant correlation. Pass conditions include "A typed event sink is injectable"
# and "correlation IDs can be added without global mutable state".
private class SiemBackend < ::Log::Backend
  getter captured = [] of ::Log::Entry

  def initialize
    super(:direct)
  end

  def write(entry : ::Log::Entry)
    @captured << entry
  end
end

describe "OPS-02: a security event sink" do
  it "can subscribe to the shard's events without replacing its logging" do
    siem = SiemBackend.new

    ::Log.setup do |c|
      c.bind "kemal_identity.*", :debug, siem
    end

    clock = KemalIdentity::SystemClock.new
    random = KemalIdentity::SecureRandomSource.new
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    )
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts, hasher: hasher, clock: clock
    )

    auth.authenticate(login: "nobody@example.com", password: "whatever")

    siem.captured.should_not be_empty
    entry = siem.captured.find { |e| e.message == "authentication.failed" }.not_nil!

    # The event carries a reason for the trail.
    entry.data[:reason].to_s.should eq("InvalidCredential")

    # Pass condition: "raw credentials and sensitive claims are structurally unavailable".
    rendered = siem.captured.map { |e| "#{e.message} #{e.data}" }.join(" ")
    rendered.should_not contain("whatever")
  end

  it "cannot receive a typed event object, only a log entry" do
    # The gap: there is no `SecurityEventSink` contract to implement. Everything arrives as a
    # `Log::Entry` whose `data` is a loosely-typed bag, so a SIEM adapter parses rather than
    # pattern-matches, and no compiler error tells it when a field is renamed.
    KemalIdentity.responds_to?(:event_sink).should be_false
    {{ KemalIdentity.constants.map(&.stringify) }}.any?(&.includes?("EventSink")).should be_false
  end
end

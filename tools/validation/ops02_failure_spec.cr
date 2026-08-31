require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# OPS-02 pass condition: "logging failure cannot bypass security".
# A SIEM backend that throws — the queue is full, the socket is gone.
private class BrokenBackend < ::Log::Backend
  getter attempts = 0

  def initialize
    super(:async)
  end

  def write(entry : ::Log::Entry)
    @attempts += 1
    raise "SIEM unreachable"
  end
end

describe "OPS-02: when the sink itself fails" do
  it "does not let a broken backend turn a rejection into an acceptance" do
    broken = BrokenBackend.new
    ::Log.setup { |c| c.bind "kemal_identity.*", :debug, broken }

    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    )
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts,
      hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 4),
      clock: KemalIdentity::SystemClock.new,
    )

    outcome = auth.authenticate(login: "nobody@example.com", password: "whatever")

    # Whatever happened to the log line, the answer is still no.
    outcome.should be_a(KemalIdentity::Failed)
    broken.attempts.should be > 0
  end
end

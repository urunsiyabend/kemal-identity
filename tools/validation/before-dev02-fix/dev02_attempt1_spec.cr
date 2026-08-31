require "spec"
require "kemal_identity"

# DEV-02, attempt 1: the obvious thing a consumer tries — require the one contract they need.
require "../lib/kemal_identity/spec/contract/clock_contract"

class FrozenClock < KemalIdentity::Clock
  def initialize(@now : Time); end

  def now : Time
    @now
  end
end

it_behaves_like_a_clock { FrozenClock.new(Time.utc) }

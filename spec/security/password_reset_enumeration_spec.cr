require "log/spec"
require "../spec_helper"

# docs/06-roadmap.md, on v0.2: "Enumeration behaviour on the reset endpoint is the thing to get
# right: identical response and identical timing whether or not the address exists, plus
# per-account rate limiting so the endpoint cannot be used to flood someone's inbox."
#
# A forgot-password form is the easiest place in an application to enumerate a customer list:
# it takes an address, it is unauthenticated, and it is expected to behave differently for
# somebody who has an account. Named for the attack rather than the method.
private def rendered(entries : Array(Log::Entry)) : String
  # An assertion that a token is absent passes trivially against nothing at all, so an empty
  # capture is a broken spec rather than a clean bill of health.
  if entries.empty?
    raise Spec::AssertionFailed.new("no log entries captured, so nothing was asserted", __FILE__, __LINE__)
  end

  entries.map { |entry| "#{entry.source} #{entry.message} #{entry.data}" }.join("\n")
end

private def captured(&) : Array(Log::Entry)
  backend = Log::MemoryBackend.new
  Log.builder.bind("kemal_identity.*", :trace, backend)
  yield
  backend.entries
end

describe "account enumeration through the reset endpoint" do
  it "returns nothing at all, for a known and an unknown address alike" do
    h = KemalIdentity::Testing.account_harness

    # `Nil` is the entire API. There is no outcome to branch on, so a caller cannot leak what
    # it was never told.
    h.service.request_password_reset("ada@example.com").should be_nil
    h.service.request_password_reset("nobody@example.com").should be_nil
  end

  it "sends a link only to an address that exists" do
    h = KemalIdentity::Testing.account_harness

    h.service.request_password_reset("nobody@example.com")
    h.notifier.delivered.should be_empty

    h.service.request_password_reset("ada@example.com")
    h.notifier.resets.size.should eq(1)
  end

  it "stores a token only for an address that exists" do
    h = KemalIdentity::Testing.account_harness

    h.service.request_password_reset("nobody@example.com")
    h.tokens.size.should eq(0)

    h.service.request_password_reset("ada@example.com")
    h.tokens.size.should eq(1)
  end

  # The other half, and the one that is usually missed. A generic response is worthless if the
  # existing-address path takes measurably longer.
  #
  # Distributions with a tolerance, never single samples for equality — the same discipline as
  # the login-path timing spec.
  it "spends comparable time on a known and an unknown address" do
    h = KemalIdentity::Testing.account_harness
    samples = 15
    tolerance = 3.0

    median = ->(spans : Array(Time::Span)) { spans.sort![spans.size // 2] }

    measure = ->(login : String) do
      h.service.request_password_reset(login)
      Array.new(samples) { Time.measure { h.service.request_password_reset(login) } }
    end

    known = median.call(measure.call("ada@example.com"))
    unknown = median.call(measure.call("nobody@example.com"))

    ratio = known.total_nanoseconds / unknown.total_nanoseconds
    ratio.should be < tolerance
    ratio.should be > (1.0 / tolerance)
  end

  it "mints a token even on the path that has nobody to send it to" do
    # The equalisation the service controls: the random draw and the digest happen before the
    # branch, so the unknown-address path is not short by that much work. Counting the draws is
    # how this is observable at all.
    random = KemalIdentity::Testing::DeterministicRandom.new
    h = KemalIdentity::Testing.account_harness
    service = KemalIdentity::Accounts::Service.new(
      accounts: h.accounts, tokens: h.tokens, notifier: h.notifier,
      sessions: h.session_service, hasher: h.hasher,
      policy: KemalIdentity::Passwords::LengthPolicy.for(h.hasher),
      clock: h.clock, random: random
    )

    service.request_password_reset("nobody@example.com")
    random.calls.should be > 0
  end

  it "says nothing different for a disabled account" do
    h = KemalIdentity::Testing.account_harness(accounts: [
      KemalIdentity::Testing.account(disabled_at: KemalIdentity::Testing::FIXED_NOW),
    ])

    h.service.request_password_reset("ada@example.com").should be_nil

    # And sends nothing: a disabled account is not a route back in.
    h.notifier.delivered.should be_empty
  end

  it "normalizes the address, so spelling is not a way to miss an account" do
    h = KemalIdentity::Testing.account_harness

    ["ADA@EXAMPLE.COM", "  ada@example.com  ", "Ada@Example.Com"].each do |variant|
      h.notifier.clear
      h.service.request_password_reset(variant)
      h.notifier.resets.size.should eq(1)
    end
  end

  it "does not send to the same address in a different tenant" do
    h = KemalIdentity::Testing.account_harness
    h.service.request_password_reset("ada@example.com", tenant_id: "t1")
    h.notifier.delivered.should be_empty
  end
end

# "plus per-account rate limiting so the endpoint cannot be used to flood someone's inbox"
describe "using the reset endpoint to flood an inbox" do
  it "stops sending once the limit is reached" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 3, window: 1.hour,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    )
    h = KemalIdentity::Testing.account_harness(rate_limiter: limiter)

    10.times { h.service.request_password_reset("ada@example.com") }

    h.notifier.resets.size.should eq(3)
  end

  it "throttles by address, so rotating source addresses does not help" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 2, window: 1.hour,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    )
    h = KemalIdentity::Testing.account_harness(rate_limiter: limiter)

    5.times { |i| h.service.request_password_reset("ada@example.com", ip: "10.0.0.#{i}") }

    h.notifier.resets.size.should eq(2)
  end

  it "is silent about being throttled" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 1, window: 1.hour,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    )
    h = KemalIdentity::Testing.account_harness(rate_limiter: limiter)

    # A denial that looked different from an acceptance would be an oracle in its own right,
    # and a louder one: it would confirm the address by refusing to talk about it.
    h.service.request_password_reset("ada@example.com").should be_nil
    h.service.request_password_reset("ada@example.com").should be_nil
  end

  it "does not throttle a different address" do
    limiter = KemalIdentity::FixedWindowRateLimiter.new(
      limit: 1, window: 1.hour,
      clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    )
    h = KemalIdentity::Testing.account_harness(accounts: [
      KemalIdentity::Testing.account(id: "a1", login: "ada@example.com"),
      KemalIdentity::Testing.account(id: "a2", login: "bob@example.com"),
    ], rate_limiter: limiter)

    2.times { h.service.request_password_reset("ada@example.com") }
    h.service.request_password_reset("bob@example.com")

    h.notifier.resets.size.should eq(2)
  end
end

describe "what the reset audit trail records" do
  it "never contains the reset token" do
    h = KemalIdentity::Testing.account_harness

    entries = captured { h.service.request_password_reset("ada@example.com") }
    token = h.notifier.last_reset_token.or_fail

    rendered(entries).should_not contain(token)
  end

  it "never contains the address that was asked about" do
    h = KemalIdentity::Testing.account_harness

    entries = captured { h.service.request_password_reset("ada@example.com") }
    rendered(entries).should_not contain("ada@example.com")
  end

  it "records whether the address was known, which the response does not" do
    h = KemalIdentity::Testing.account_harness

    entries = captured { h.service.request_password_reset("nobody@example.com") }
    rendered(entries).should contain("password_reset.requested")
  end
end

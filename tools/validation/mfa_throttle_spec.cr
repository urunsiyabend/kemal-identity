require "spec"
require "uri"
require "kemal_identity"
require "kemal_identity/testing"

# MFA-01 and MFA-04, re-measured: the *rate limiter* rather than the factors.
#
# The first pass over these two scenarios measured that throttling exists — a limit, a
# `retry_after`, a refusal when the limiter is unavailable — and stopped there. Three
# properties it did not measure, each of which the mainstream implementations get right in a
# different way:
#
#   * django-otp keeps `throttling_failure_count` and `throttling_failure_timestamp` on the
#     **device row**, so a static (recovery-code) device has its own bucket and its own
#     throttle factor, and the delay is `factor × 2^(n-1)`;
#   * `Passwords::Authenticator` in this very shard consumes **two** keys per attempt, an
#     account key and an `ip:` key. Auth0 buckets on the pair `(IP, user identifier)`. The MFA
#     path consumed one key and had no parameter to pass an address to;
#   * NIST SP 800-63B: "the verifier SHALL limit consecutive failed authentication attempts
#     using a specific authenticator on a single subscriber account to no more than 100 by
#     disabling that authenticator." A window that resets has no such bound.
#
# What was measured before the fix, with the configuration a real consumer had (twelve
# attempts per five minutes):
#
#   * twelve wrong TOTP codes left a **valid recovery code** refused as `RateLimited`, and a
#     replacement factor unconfirmable — one flow's failures closed the whole MFA surface;
#   * `verify(account_id, code)` took no address, so there was no dimension to spread across;
#   * **103,680 attempts allowed in thirty days**, no factor ever disabled, which against six
#     digits with `drift: 1` (three counters accepted, so ~3-in-a-million per guess) is a
#     **26.7%** chance of being guessed. Printed by this file's own run.

alias TOTP = KemalIdentity::MFA::TOTP

BOX_KEY = KemalIdentity::Secret.new("m" * 32)
NOWT    = Time.utc(2026, 9, 2, 12, 0, 0)

LIMIT  = 12
WINDOW = 5.minutes

record Rig,
  clock : KemalIdentity::Testing::TestClock,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  factors : KemalIdentity::Testing::MemoryMfaRepository,
  mfa : KemalIdentity::MFA::Service

def rig(
  limit : Int32 = LIMIT,
  window : Time::Span = WINDOW,
  max_consecutive_failures : Int32? = nil,
  recovery_rate_limiter : KemalIdentity::RateLimiter? = nil,
) : Rig
  clock = KemalIdentity::Testing::TestClock.new(NOWT)
  random = KemalIdentity::Testing::DeterministicRandom.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new
  accounts.insert(KemalIdentity::Accounts::Account.new(
    id: "ada", normalized_login: "ada@example.com", auth_version: 1,
    created_at: NOWT, updated_at: NOWT, password_digest: "digest", password_scheme: "test",
  ))

  factors = KemalIdentity::Testing::MemoryMfaRepository.new

  Rig.new(
    clock: clock, accounts: accounts, factors: factors,
    mfa: KemalIdentity::MFA::Service.new(
      factors: factors,
      secret_box: KemalIdentity::MFA::AesSecretBox.new(BOX_KEY, random),
      clock: clock, random: random, issuer: "Acme",
      rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(
        limit: limit, window: window, clock: clock
      ),
      recovery_rate_limiter: recovery_rate_limiter,
      max_consecutive_failures: max_consecutive_failures,
    )
  )
end

def secret_of(pending) : Bytes
  KemalIdentity::MFA::Base32.decode?(
    URI.parse(pending.provisioning_uri).query_params["secret"]
  ).not_nil!
end

def code_for(pending, clock, offset : Int32 = 0) : String
  TOTP.code(secret_of(pending), TOTP.counter(clock.now) + offset)
end

def enrolled(r : Rig)
  pending = r.mfa.enrol(r.accounts.find_by_id("ada").not_nil!, "phone")
  codes = r.mfa.confirm(pending.factor.id, code_for(pending, r.clock)).not_nil!.recovery_codes
  {pending, codes}
end

def rate_limited?(result) : Bool
  result.is_a?(KemalIdentity::Failed) &&
    result.reason == KemalIdentity::FailureReason::RateLimited
end

describe "each flow has its own quota" do
  it "leaves the recovery path open after the TOTP budget is gone" do
    r = rig
    _, codes = enrolled(r)

    # The realistic sequence: the app shows a TOTP field and a "this is a recovery code"
    # checkbox, and somebody whose phone is gone types stale codes first.
    LIMIT.times { rate_limited?(r.mfa.verify("ada", "000000")) }

    KemalIdentity::Testing.should_fail_with(
      r.mfa.verify("ada", "000000"), KemalIdentity::FailureReason::RateLimited
    )

    # The credential that exists for exactly this moment now works, in the same window.
    KemalIdentity::Testing.should_verify(r.mfa.redeem_recovery_code("ada", codes.first.reveal))
    r.mfa.unused_recovery_codes("ada").should eq(9)
  end

  it "leaves enrolling a replacement factor open too" do
    r = rig
    enrolled(r)

    LIMIT.times { r.mfa.verify("ada", "000000") }

    replacement = r.mfa.enrol(r.accounts.find_by_id("ada").not_nil!, "new phone")
    r.mfa.confirm(replacement.factor.id, code_for(replacement, r.clock)).should_not be_nil
  end

  it "gives recovery a limit of its own when one is passed" do
    r = rig(
      recovery_rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(
        limit: 3, window: 1.hour, clock: KemalIdentity::Testing::TestClock.new(NOWT)
      )
    )
    _, codes = enrolled(r)

    # Three wrong recovery codes, then the fourth is refused — while TOTP is untouched, since
    # the two now key differently.
    3.times do
      KemalIdentity::Testing.should_fail_with(
        r.mfa.redeem_recovery_code("ada", "z" * 43),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end

    rate_limited?(r.mfa.redeem_recovery_code("ada", codes.first.reveal)).should be_true
    r.mfa.verify("ada", "000000").as(KemalIdentity::Failed).reason
      .should eq(KemalIdentity::FailureReason::InvalidCredential)
  end
end

describe "an attempt can carry its source address" do
  it "consumes an account key and an address key, like the password path" do
    r = rig(limit: 4)
    enrolled(r)

    # Four from one address exhausts that address's key *and* four of the account's.
    4.times { r.mfa.verify("ada", "000000", ip: "203.0.113.7") }
    rate_limited?(r.mfa.verify("ada", "000000", ip: "203.0.113.7")).should be_true

    # A second address has its own key and finds the account key already half spent: it gets
    # what is left of the account's budget and no more. So one address cannot sweep many
    # accounts, and the account's own budget is still the ceiling.
    rate_limited?(r.mfa.verify("ada", "000000", ip: "198.51.100.9")).should be_true
  end

  it "still works when the caller has no address to give" do
    # A CLI, a job, a service driving the API. Inventing an address would be worse than the
    # missing dimension, so `ip` is nilable throughout.
    r = rig(limit: 2)
    pending, _ = enrolled(r)

    r.clock.advance(30.seconds)
    KemalIdentity::Testing.should_verify(r.mfa.verify("ada", code_for(pending, r.clock)))
  end

  it "does not let one address spend another account's budget" do
    r = rig(limit: 3)
    enrolled(r)

    3.times { r.mfa.verify("ada", "000000", ip: "203.0.113.7") }

    # The same address against a different account: the address key is spent, so this is
    # refused before the account is even considered. That is the dimension the MFA path did
    # not have — before, an address could work through accounts one at a time, each with a
    # fresh budget.
    rate_limited?(r.mfa.verify("someone-else", "000000", ip: "203.0.113.7")).should be_true
  end
end

describe "consecutive failures have an upper bound" do
  it "disables the factor at the limit and stops accepting its codes" do
    r = rig(max_consecutive_failures: 100)
    pending, codes = enrolled(r)

    # Ninety-nine wrong codes, spread over as many windows as it takes: the window is not the
    # bound any more, the factor's own counter is.
    99.times do |attempt|
      r.mfa.verify("ada", "000000")
      r.clock.advance(WINDOW) if (attempt + 1) % LIMIT == 0
    end

    factor = r.mfa.factors("ada").first
    factor.consecutive_failures.should eq(99)
    factor.disabled?.should be_false
    r.mfa.enrolled?("ada").should be_true

    # The hundredth.
    r.clock.advance(WINDOW)
    r.mfa.verify("ada", "000000")

    disabled = r.mfa.factors("ada").first
    disabled.consecutive_failures.should eq(100)
    disabled.disabled?.should be_true
    disabled.disabled_at.should_not be_nil

    # Still enrolled and still listed — the person has to be told which device stopped working
    # — but no longer usable, and no longer what "this account has MFA" means.
    disabled.confirmed?.should be_true
    disabled.usable?.should be_false
    r.mfa.enrolled?("ada").should be_false

    # And a **correct** code from that factor is now refused. This is the property the whole
    # change exists for: guessing stops rather than slowing down.
    r.clock.advance(WINDOW + 30.seconds)
    KemalIdentity::Testing.should_fail_with(
      r.mfa.verify("ada", code_for(pending, r.clock)),
      KemalIdentity::FailureReason::InvalidCredential
    )

    # Recovery still works. That is the point of the separate bucket and of a recovery code
    # being a 43-character secret rather than six digits: the way back in survives the factor
    # being switched off.
    KemalIdentity::Testing.should_verify(r.mfa.redeem_recovery_code("ada", codes.first.reveal))
  end

  it "counts consecutive, so one success clears the count" do
    r = rig(max_consecutive_failures: 100)
    pending, _ = enrolled(r)

    5.times { r.mfa.verify("ada", "000000") }
    r.mfa.factors("ada").first.consecutive_failures.should eq(5)

    r.clock.advance(30.seconds)
    KemalIdentity::Testing.should_verify(r.mfa.verify("ada", code_for(pending, r.clock)))

    r.mfa.factors("ada").first.consecutive_failures.should eq(0)
  end

  it "is off by default, and says so" do
    # Deliberate: switching the bound on can disable a factor, and a deployment that has been
    # running without it may have factors carrying hundreds of accumulated typos.
    rig.mfa.max_consecutive_failures.should be_nil

    r = rig
    enrolled(r)
    200.times do |attempt|
      r.mfa.verify("ada", "000000")
      r.clock.advance(WINDOW) if (attempt + 1) % LIMIT == 0
    end

    r.mfa.factors("ada").first.consecutive_failures.should eq(200)
    r.mfa.factors("ada").first.disabled?.should be_false
  end

  it "counts a wrong code against every factor it was offered to" do
    r = rig(max_consecutive_failures: 100)
    enrolled(r)
    second = r.mfa.enrol(r.accounts.find_by_id("ada").not_nil!, "tablet")
    r.mfa.confirm(second.factor.id, code_for(second, r.clock))

    r.mfa.verify("ada", "000000")

    # "Consecutive failed attempts using a specific authenticator": a code offered to the
    # account is offered to each usable factor, and each of them saw it fail.
    r.mfa.factors("ada").each(&.consecutive_failures.should eq(1))
  end
end

describe "the escalating strategy the shard now ships" do
  it "turns a flat month of guessing into a wall" do
    limiter = KemalIdentity::ExponentialBackoffRateLimiter.new(
      factor: 1.second, max_delay: 1.hour,
      clock: (clock = KemalIdentity::Testing::TestClock.new(NOWT))
    )

    r = Rig.new(
      clock: clock,
      accounts: (accounts = KemalIdentity::Testing::MemoryAccountRepository.new),
      factors: (factors = KemalIdentity::Testing::MemoryMfaRepository.new),
      mfa: KemalIdentity::MFA::Service.new(
        factors: factors,
        secret_box: KemalIdentity::MFA::AesSecretBox.new(
          BOX_KEY, KemalIdentity::Testing::DeterministicRandom.new
        ),
        clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
        issuer: "Acme", rate_limiter: limiter, max_consecutive_failures: 100,
      )
    )

    accounts.insert(KemalIdentity::Accounts::Account.new(
      id: "ada", normalized_login: "ada@example.com", auth_version: 1,
      created_at: NOWT, updated_at: NOWT, password_digest: "digest", password_scheme: "test",
    ))
    enrolled(r)

    # A guesser that waits exactly as long as it is told, for thirty days.
    deadline = NOWT + 30.days
    attempts = 0

    while clock.now < deadline
      result = r.mfa.verify("ada", "000000")
      attempts += 1 unless rate_limited?(result)

      break if r.mfa.factors("ada").first.disabled?

      wait = result.as(KemalIdentity::Failed).retry_after
      clock.advance(wait.nil? ? 1.second : wait + 1.millisecond)
    end

    chance = 1.0 - (1.0 - 3.0e-6) ** attempts
    puts "  after the fix: #{attempts} attempts in 30 days, " \
         "P(success) ≈ #{(chance * 100).round(4)}%, factor disabled: " \
         "#{r.mfa.factors("ada").first.disabled?}"

    # The flat window allowed 103,680. The bound is now the factor's counter, not the calendar.
    attempts.should be <= 100
    r.mfa.factors("ada").first.disabled?.should be_true
    chance.should be < 0.001
  end
end

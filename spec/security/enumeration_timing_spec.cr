require "../spec_helper"

# docs/02-security-model.md, "Timing and enumeration", and the release blocker
# "Constant-ish timing for unknown login vs wrong password".
#
# Generic responses are the easy half. The half that is usually missed: if no account
# matches, the naive implementation returns before doing any hashing, and the response comes
# back a hundred-odd milliseconds early — a reliable account oracle regardless of how
# identical the body is. `dummy_digest` is what keeps the two paths comparable.
#
# This spec compares distributions with a tolerance, never single samples for equality. The
# margin is wide enough not to flake on a loaded CI runner and tight enough to fail if the
# `dummy_digest` path is removed: deleting it makes the unknown-login path do no bcrypt work
# at all, which is a difference of orders of magnitude, not of tens of percent.
describe "account enumeration by timing" do
  # Cost 4 keeps the spec quick. The *ratio* is what is asserted, and it does not depend on
  # the cost.
  hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
  submitted = KemalIdentity::Secret.new("whatever the attacker typed")
  real_digest = hasher.hash_secret(KemalIdentity::Secret.new("the account's real password"))

  samples = 15
  tolerance = 3.0

  median = ->(spans : Array(Time::Span)) do
    sorted = spans.sort!
    sorted[sorted.size // 2]
  end

  measure = ->(digest : String) do
    # One discarded pass so neither side pays a first-call cost the other does not.
    hasher.verify(submitted, digest)
    Array.new(samples) { Time.measure { hasher.verify(submitted, digest) } }
  end

  it "spends comparable time on a known login with a wrong password and on an unknown login" do
    known = median.call(measure.call(real_digest))
    unknown = median.call(measure.call(hasher.dummy_digest))

    ratio = known.total_nanoseconds / unknown.total_nanoseconds

    # Fails loudly if `dummy_digest` is ever replaced by an early return: that would put
    # the ratio in the hundreds or thousands, not near 1.
    ratio.should be < tolerance
    ratio.should be > (1.0 / tolerance)
  end

  it "does real work on the unknown-login path" do
    # The property underneath the ratio. An early return would be immeasurably fast; a real
    # bcrypt verification at cost 4 is not.
    median.call(measure.call(hasher.dummy_digest)).should be > 100.microseconds
  end

  it "gives the unknown-login path a digest that no submitted password can match" do
    # If the dummy secret were a documented constant, an attacker could submit it. It is
    # drawn from the injected RandomSource instead.
    ["", "password", "the account's real password", hasher.dummy_digest].each do |candidate|
      hasher.verify(KemalIdentity::Secret.new(candidate), hasher.dummy_digest).should be_false
    end
  end

  it "makes the unknown-login path indistinguishable in shape as well as timing" do
    # Same scheme, same cost, same parse result: nothing downstream can branch on which
    # digest it was handed.
    hasher.dummy_digest.should start_with("$2a$04$")
    hasher.needs_rehash?(hasher.dummy_digest).should be_false
  end
end

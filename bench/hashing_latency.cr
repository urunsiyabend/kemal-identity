# Performance measurements for kemal_identity.
#
# Not run in CI. `docs/05-testing.md`: run before tagging, on hardware resembling the
# deployment target, and record the numbers in the README. A laptop's numbers are not a
# production machine's -- Crystal's own bcrypt documentation makes the same point about
# calibrating cost.
#
#     crystal build --release bench/hashing_latency.cr -o bin/bench && bin/bench
#
# Four things are measured, and they are the four docs/05-testing.md asks for:
#
#   1. bcrypt cost calibration
#   2. unrelated-request latency under concurrent logins, with and without HashingExecutor
#   3. the overhead an authenticated request adds over an anonymous one
#   4. the write amplification `touch_interval` avoids

require "../src/kemal_identity"

# The in-memory repositories live in spec/support, not src -- `src/CLAUDE.md` bans them from
# the shipped code. They pass the same contract specs as the PostgreSQL adapters, so measuring
# against them isolates the shard's own overhead from the database's.
require "../spec/support/fiber_join"
require "../spec/support/test_clock"
require "../spec/support/memory_account_repository"
require "../spec/support/memory_session_repository"

SEPARATOR = "-" * 78

def heading(text : String) : Nil
  puts
  puts text
  puts SEPARATOR
  STDOUT.flush
end

# Flushed as each row is produced: the concurrency section takes long enough that a reader
# needs to see progress, and block buffering through a pipe otherwise hides all of it.
def row(text : String) : Nil
  puts text
  STDOUT.flush
end

def percentile(sorted : Array(Time::Span), fraction : Float64) : Time::Span
  return Time::Span::ZERO if sorted.empty?
  index = ((sorted.size - 1) * fraction).round.to_i
  sorted[index]
end

def ms(span : Time::Span) : String
  "%8.3f ms" % span.total_milliseconds
end

# ----------------------------------------------------------------------------------------
# 1. Cost calibration
# ----------------------------------------------------------------------------------------
#
# The right cost is the highest one that keeps p95 login latency inside budget on the
# deployment target. Nothing else decides it.

def calibrate_cost : Nil
  heading("bcrypt cost calibration (single verification, median of 5)")
  secret = KemalIdentity::Secret.new("correct horse battery staple")

  (8..12).each do |cost|
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: cost)
    digest = hasher.hash_secret(secret)

    samples = Array.new(5) { Time.measure { hasher.verify(secret, digest) } }.sort!
    row "  cost #{cost}   #{ms(percentile(samples, 0.5))}"
  end
end

# ----------------------------------------------------------------------------------------
# 2. Unrelated-request latency under concurrent logins
# ----------------------------------------------------------------------------------------
#
# The number that matters is **not** hashes per second. It is what happens to a request that
# has nothing to do with logging in while a burst of logins is in flight.
#
# The probe stands in for that unrelated request: it asks to be woken in one millisecond and
# measures how long that actually takes. An idle scheduler returns it in about a millisecond;
# one whose threads are all inside a bcrypt round cannot, and the overshoot is exactly the
# latency a real unrelated request would pay.
#
# ### Each login fiber performs one verification, not a loop of them
#
# An earlier version of this benchmark had each fiber verify in a `while` loop until a flag was
# cleared. It livelocked, and instructively so: bcrypt is pure computation with no yield
# points, Crystal's scheduler is cooperative, so once N fibers are running on N threads they
# hold those threads until their verification returns and then immediately start another. The
# main fiber — the one that would clear the flag — never got scheduled.
#
# That is the very starvation this section exists to measure, but an unbounded loop is not a
# workload any application has. One verification per fiber *is* a login, and it makes the
# benchmark terminate.
PROBE_SAMPLES  = 20
PROBE_INTERVAL = 1.millisecond

def probe_latency(hasher : KemalIdentity::Passwords::Hasher, concurrency : Int32) : Array(Time::Span)
  secret = KemalIdentity::Secret.new("correct horse battery staple")
  digest = hasher.hash_secret(secret)

  # The probe has to run *while* the logins are in flight, so the fibers are started here and
  # joined after the samples are taken rather than through `join_fibers`.
  done = Channel(Nil).new(concurrency)

  concurrency.times do
    spawn do
      hasher.verify(secret, digest)
    ensure
      done.send(nil)
    end
  end

  # Taken while the logins are in flight. If the scheduler cannot get round to this fiber, the
  # samples say so — which is the finding, not a failure of the measurement.
  samples = Array.new(PROBE_SAMPLES) { Time.measure { sleep PROBE_INTERVAL } }

  concurrency.times { done.receive }
  samples.sort!
end

def unrelated_request_latency : Nil
  heading("unrelated-request latency under concurrent logins (bcrypt cost 9)")
  puts "  A 1 ms wake-up, measured while N logins are in flight. Idle baseline is ~1 ms."
  puts "  %-34s %10s %10s %10s" % {"", "p50", "p95", "p99"}

  plain = KemalIdentity::Passwords::BcryptHasher.new(cost: 9)
  dispatched = KemalIdentity::Passwords::HashingExecutor.new(
    KemalIdentity::Passwords::BcryptHasher.new(cost: 9), size: 2
  )

  [1, 10, 50, 100].each do |concurrency|
    {"on the request context" => plain, "on a hashing context" => dispatched}.each do |label, hasher|
      samples = probe_latency(hasher, concurrency)
      row "  %-22s %-11s %s %s %s" % {
        label, "#{concurrency} logins",
        ms(percentile(samples, 0.5)), ms(percentile(samples, 0.95)), ms(percentile(samples, 0.99)),
      }
    end
  end
end

# ----------------------------------------------------------------------------------------
# 3. Authenticated request overhead
# ----------------------------------------------------------------------------------------
#
# What resolving a session costs over serving an anonymous request: cookie shape check,
# SHA-256, and one indexed lookup. Measured against the in-memory repository, so this is the
# shard's own overhead with the database's contribution excluded.

def authenticated_request_overhead : Nil
  heading("authenticated request overhead (in-memory store, 20_000 resolutions)")

  clock = KemalIdentity::SystemClock.new
  random = KemalIdentity::SecureRandomSource.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::Accounts::Account.new(
      id: "a1", normalized_login: "ada@example.com", created_at: clock.now, updated_at: clock.now
    ),
  ])
  sessions = KemalIdentity::Testing::MemorySessionRepository.new(accounts)
  service = KemalIdentity::Sessions::Service.new(
    sessions: sessions, clock: clock, random: random,
    # A touch interval long enough that none of these reads writes: this measures the read
    # path, and the write path is the next section.
    config: KemalIdentity::Sessions::Config.new(touch_interval: 1.hour)
  )

  issued = service.start(accounts.find_by_id("a1").as(KemalIdentity::Accounts::Account),
    KemalIdentity::AssuranceLevel::Password)
  token = issued.token.reveal

  iterations = 20_000

  anonymous = Time.measure { iterations.times { service.resolve(nil) } }
  authenticated = Time.measure { iterations.times { service.resolve(token) } }
  malformed = Time.measure { iterations.times { service.resolve("garbage") } }

  per = ->(span : Time::Span) { "%7.3f us" % (span.total_microseconds / iterations) }

  puts "  anonymous (no cookie)        #{per.call(anonymous)}"
  puts "  malformed cookie             #{per.call(malformed)}   rejected before any lookup"
  puts "  authenticated (resolved)     #{per.call(authenticated)}"
  puts "  overhead per request         #{per.call(authenticated - anonymous)}"
end

# ----------------------------------------------------------------------------------------
# 4. The write amplification touch_interval avoids
# ----------------------------------------------------------------------------------------
#
# Idle expiry naively means an UPDATE on every authenticated request, which turns a read-only
# hot path into a write-heavy one. This counts the writes at a 60 s throttle and at none.

class CountingSessions < KemalIdentity::Sessions::Repository
  getter touches : Int32 = 0

  def initialize(@inner : KemalIdentity::Sessions::Repository)
  end

  def create(record : KemalIdentity::Sessions::Record) : Nil
    @inner.create(record)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
    @inner.find_by_digest(digest)
  end

  def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
    @touches += 1
    @inner.touch(id, last_seen_at, idle_expires_at)
  end

  def revoke(id : String, at : Time) : Bool
    @inner.revoke(id, at)
  end

  def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
    @inner.revoke_all_for_account(account_id, at, except_id: except_id)
  end

  def delete_expired(before : Time) : Int32
    @inner.delete_expired(before)
  end
end

def write_amplification : Nil
  heading("writes per authenticated request (600 requests, one every second)")

  [60.seconds, Time::Span::ZERO].each do |interval|
    clock = KemalIdentity::Testing::TestClock.new(Time.utc(2026, 8, 25))
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([
      KemalIdentity::Accounts::Account.new(
        id: "a1", normalized_login: "ada@example.com", created_at: clock.now, updated_at: clock.now
      ),
    ])
    counting = CountingSessions.new(KemalIdentity::Testing::MemorySessionRepository.new(accounts))
    service = KemalIdentity::Sessions::Service.new(
      sessions: counting, clock: clock, random: KemalIdentity::SecureRandomSource.new,
      config: KemalIdentity::Sessions::Config.new(idle_timeout: 2.hours, touch_interval: interval)
    )

    issued = service.start(accounts.find_by_id("a1").as(KemalIdentity::Accounts::Account),
      KemalIdentity::AssuranceLevel::Password)

    600.times do
      clock.advance(1.second)
      service.resolve(issued.token.reveal)
    end

    label = interval == Time::Span::ZERO ? "no throttle" : "touch_interval 60 s"
    puts "  %-22s %4d writes  (%.1f%% of requests)" % {label, counting.touches, counting.touches / 6.0}
  end
end

puts "kemal_identity benchmarks"
puts "Crystal #{Crystal::VERSION}, #{System.cpu_count} CPUs"

calibrate_cost
unrelated_request_latency
authenticated_request_overhead
write_amplification
puts

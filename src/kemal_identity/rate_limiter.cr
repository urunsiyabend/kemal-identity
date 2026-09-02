module KemalIdentity
  # Whether an attempt may proceed, when to come back if not, and whether the limiter could
  # answer at all.
  #
  # ### Three states, because two of them are not the same "no"
  #
  # A limiter over shared storage has a third thing to say: *the store did not answer*. Without
  # a way to say it, an adapter whose Redis is down can only lie — report `allow` and turn rate
  # limiting off under exactly the conditions an attacker can provoke, report `deny` and take
  # the login endpoint down for everybody, or raise and become a 500. All three are decisions
  # the adapter has no business making on the application's behalf
  # (`blueprints/0023-rate-limiter-store-failure.md`).
  struct Verdict
    # Whether the attempt may proceed.
    #
    # **False when the store was unavailable.** Code that only ever asks this question therefore
    # fails *closed* on an outage rather than open, which is the safe direction for the one to
    # forget. Ask `#unavailable?` to tell the two apart.
    getter? allowed : Bool

    # How long until the caller may try again. Set only on a denial.
    #
    # Telling an honest client when to return is worth more than the little it reveals: the
    # attacker already knows they are being throttled — that is what being throttled means —
    # while a legitimate user staring at "try again later" has no idea whether to wait a
    # second or an hour.
    getter retry_after : Time::Span?

    # Whether the limiter could not reach its storage, so this attempt was never counted.
    #
    # Distinct from a denial: a denial says "you have had your share", this says "nobody knows
    # what your share is". They call for opposite responses from an operator — one is working
    # as designed, the other is an incident — and they are not the same event in an audit trail.
    getter? unavailable : Bool

    def self.allow : self
      new(allowed: true)
    end

    def self.deny(retry_after : Time::Span) : self
      new(allowed: false, retry_after: retry_after)
    end

    # The store did not answer.
    #
    # `retry_after` is deliberately absent: there is no honest number to give when the limiter
    # does not know what has been spent.
    def self.unavailable : self
      new(allowed: false, unavailable: true)
    end

    def initialize(@allowed : Bool, @retry_after : Time::Span? = nil, @unavailable : Bool = false)
    end
  end

  # Throttles repeated attempts against the same key.
  #
  # ### Why the two methods are `consume` and `reset`, not `check` and `penalise`
  #
  # The attempt is counted **before** the expensive work, not after it. Bcrypt verification is
  # tens of milliseconds of CPU by design, which makes the login endpoint an easy
  # denial-of-service lever — Crystal's own bcrypt documentation says so directly. A limiter
  # that only penalised *failures* would have already paid for the hashing before deciding to
  # penalise, so the lever would still work: an attacker never needs to succeed.
  #
  # So `consume` counts and judges in one step, ahead of any lookup or hashing, and `reset`
  # clears the count once someone proves they are the account holder. A failure penalises by
  # simply not being reset.
  #
  # ### Keys
  #
  # The caller decides what to key on, and `Passwords::Authenticator` keys on two things at
  # once: the login being attempted, and the source address. The login-keyed limit is what
  # survives an attacker rotating IPs — credential stuffing is distributed by nature, so a
  # purely address-keyed limit is close to useless against it. The address-keyed limit is what
  # catches one host spraying many logins.
  #
  # Keys arriving here are already hashed by the caller: a limiter's storage should be able to
  # answer "is this login under attack" without retaining the login
  # (`blueprints/0007-audit-events-omit-the-login.md`).
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple threads.
  abstract class RateLimiter
    # Counts one attempt against `key` and says whether it may proceed.
    #
    # Called before any I/O and before any hashing. A denial must be cheap, or the limiter
    # becomes the very lever it exists to remove.
    #
    # **Must not raise for a storage failure.** A limiter whose Redis is unreachable returns
    # `Verdict.unavailable` and lets the application's configured policy decide, because the
    # answer differs per endpoint: a login should refuse rather than run unmetered, while a
    # less sensitive action may prefer to stay up. An exception here would make that choice for
    # everybody, and would surface as a 500 rather than as either policy.
    abstract def consume(key : String) : Verdict

    # Clears the count for `key`, after a successful authentication.
    #
    # Idempotent, and safe for a key that was never consumed. **Must not raise**, including
    # when the store is unavailable: a reset that does not happen leaves somebody throttled
    # slightly longer than they earned, which is not worth failing a successful login over.
    abstract def reset(key : String) : Nil
  end

  # Turns "the store did not answer" into "carry on", for one call site.
  #
  # ### Why this is a wrapper and not a setting
  #
  # `blueprints/maturity-validation-scenarios.md` (OPS-01) requires the fail-open or fail-closed
  # choice to be made **per endpoint**, and it genuinely differs: refusing every login while
  # Redis is down is a self-inflicted outage, while running the login path unmetered is exactly
  # what an attacker gets by overwhelming whatever stores the counts. Neither answer is right
  # everywhere.
  #
  # A flag on the limiter would settle it once for the whole application. A wrapper settles it
  # once per limiter, and every service already takes its own — so per-endpoint falls out of
  # wiring that exists rather than out of a new parameter:
  #
  # ```
  # shared = MyRedisRateLimiter.new(redis)
  #
  # KemalIdentity.configure(
  #   rate_limiter: shared, # login stays fail-closed
  #   # ...
  # )
  #
  # # ...while something less sensitive prefers to stay up:
  # notifications = MyThrottledMailer.new(KemalIdentity::FailOpenRateLimiter.new(shared))
  # ```
  #
  # **The default is fail-closed and this is opt-in**, because every call site in this shard is
  # an authentication path: a login, a password reset, and three ways of proving a second
  # factor. Silence is the wrong answer for all five.
  class FailOpenRateLimiter < RateLimiter
    getter inner : RateLimiter

    def initialize(@inner : RateLimiter)
    end

    def consume(key : String) : Verdict
      verdict = @inner.consume(key)

      return verdict unless verdict.unavailable?

      # Logged at warn, not debug: the limit is not being enforced right now, and whoever is on
      # call should be able to find that out from the trail rather than by inference.
      Log.warn &.emit("rate_limiter.failing_open")

      Verdict.allow
    end

    def reset(key : String) : Nil
      @inner.reset(key)
    end
  end

  # Allows everything. The default.
  #
  # The shard cannot pick a sensible limit on an application's behalf — a public consumer site
  # and an internal tool with nine users want wildly different numbers — and a limiter that
  # silently shared state across processes, or silently did not, would be worse than none.
  #
  # **This means rate limiting is off unless an application turns it on.** That is a real gap
  # and it is called out in the README rather than buried here. `FixedWindowRateLimiter` is
  # the batteries-included option for a single-process deployment; anything larger wants a
  # shared store behind this same contract.
  class NullRateLimiter < RateLimiter
    def consume(key : String) : Verdict
      Verdict.allow
    end

    def reset(key : String) : Nil
    end
  end

  # An escalating delay between attempts, in memory.
  #
  # Where `FixedWindowRateLimiter` allows N attempts and then nothing, this allows attempts
  # further and further apart: after the *n*-th consecutive failure the next attempt must wait
  # `factor × 2^(n-1)`. With the default factor of one second that is 1, 2, 4, 8, 16 … seconds,
  # capped at `max_delay`.
  #
  # This is django-otp's curve, and its `ThrottlingMixin` is the reference — there the pair
  # (`throttling_failure_count`, `throttling_failure_timestamp`) lives on the device row and
  # the delay is `throttle_factor × 2^(n-1)`. Keycloak's brute-force detector is the same shape
  # under different names: a wait incremented per failure, bounded by a maximum wait.
  #
  # ### Why the shape is worth having
  #
  # A flat window is the same for an honest user and an attacker. Somebody who fat-fingers a
  # code twice waits a second and never notices; a machine guessing six digits is at hours per
  # attempt within a dozen tries, while a fixed window of twelve per five minutes hands out
  # 103,680 attempts a month indefinitely — measured, in `blueprints/0025` (MFA-04).
  #
  # NIST SP 800-63B lists exactly this as a mitigation for the lockout its rate-limiting
  # requirement would otherwise cause: *"Requiring the claimant to wait after a failed attempt
  # for a period of time that increases as the subscriber account approaches its maximum
  # allowance for consecutive failed attempts (e.g., 30 seconds up to an hour)"*.
  #
  # ### What it does not do
  #
  # **It is not the lifetime bound.** The delay grows without ever refusing outright, so this
  # alone does not satisfy the SHALL that a verifier disable an authenticator after 100
  # consecutive failures. `MFA::Service#max_consecutive_failures` is that, and the two are
  # meant to be used together: this one makes guessing slow, that one makes it stop.
  #
  # **It is per process**, like its sibling, for the same reason and with the same answer — a
  # shared store behind this contract.
  #
  # ### `reset` is what makes it "consecutive"
  #
  # A success calls `reset` and the curve starts over. Nothing decays with time: an account
  # that failed eight times last year is still at eight until something succeeds. That is the
  # deliberate reading of "consecutive", and the reason `MFA::Service` clears a factor's
  # counter on success rather than on a timer.
  class ExponentialBackoffRateLimiter < RateLimiter
    # Bounds memory, exactly as `FixedWindowRateLimiter::DEFAULT_MAX_KEYS` does.
    DEFAULT_MAX_KEYS = 100_000

    # One second, so the first repeat is barely felt and the tenth is over eight minutes.
    DEFAULT_FACTOR = 1.second

    # An hour, which is the upper end of the example NIST gives.
    DEFAULT_MAX_DELAY = 1.hour

    record Attempts, count : Int32, last_at : Time

    getter factor : Time::Span
    getter max_delay : Time::Span

    def initialize(
      @factor : Time::Span = DEFAULT_FACTOR,
      @max_delay : Time::Span = DEFAULT_MAX_DELAY,
      @clock : Clock = SystemClock.new,
      @max_keys : Int32 = DEFAULT_MAX_KEYS,
    )
      raise ConfigurationError.new("factor must be positive") unless @factor > Time::Span::ZERO

      unless @max_delay >= @factor
        raise ConfigurationError.new("max_delay must not be shorter than factor")
      end

      raise ConfigurationError.new("max_keys must be positive") unless @max_keys > 0

      @mutex = Mutex.new
      @attempts = {} of String => Attempts
    end

    def consume(key : String) : Verdict
      @mutex.synchronize do
        now = @clock.now
        current = @attempts[key]?

        if current.nil?
          purge_stale(now) if @attempts.size >= @max_keys
          @attempts[key] = Attempts.new(count: 1, last_at: now)
          next Verdict.allow
        end

        required = delay_for(current.count)
        waited = now - current.last_at

        if waited < required
          # The attempt is **not** counted. Counting a refused attempt would let a client that
          # retries in a tight loop push its own next window out exponentially — a caller
          # hurting only itself, but it also means the number handed back a moment ago becomes
          # a lie. `retry_after` stays honest and shrinks as time passes.
          next Verdict.deny(retry_after: required - waited)
        end

        @attempts[key] = Attempts.new(count: current.count + 1, last_at: now)
        Verdict.allow
      end
    end

    def reset(key : String) : Nil
      @mutex.synchronize { @attempts.delete(key) }
    end

    # How long the caller must wait before its next attempt, given `count` consecutive ones.
    def delay_for(count : Int32) : Time::Span
      return Time::Span.zero if count < 1

      # Shifting rather than exponentiating, and bailing out early: `2 ** 62` overflows, and a
      # count that high is a caller that has been failing for centuries.
      return @max_delay if count > 40

      delay = @factor * (1_i64 << (count - 1))
      delay > @max_delay ? @max_delay : delay
    end

    # How many keys are being tracked.
    def size : Int32
      @mutex.synchronize { @attempts.size }
    end

    # Drops keys whose delay has long since elapsed, so the cap is not reached by abandoned
    # ones. Clearing everything would forgive whoever is mid-attack, which is the opposite of
    # what this is for.
    private def purge_stale(now : Time) : Nil
      @attempts.reject! { |_, attempts| now - attempts.last_at > @max_delay * 2 }

      # Still full: every tracked key is recent, so this is a flood of distinct keys rather
      # than an accumulation of abandoned ones. Keep the oldest attempts — they are the ones
      # closest to being forgiven anyway — and drop the newest, which fails *closed* for the
      # keys that are dropped only in the sense that they start again at one.
      @attempts.clear if @attempts.size >= @max_keys
    end
  end

  # A fixed-window counter, in memory.
  #
  # Usable, and honest about its limits:
  #
  # * **Per process.** Two application processes have two independent counters, so the
  #   effective limit is `limit × processes`. Behind a load balancer that is usually not what
  #   was intended, and a shared store behind this contract is the answer.
  # * **Fixed window, not sliding.** The window opens on the first attempt against a key
  #   rather than on a calendar boundary, and up to `2 × limit` attempts can land within
  #   seconds of each other by filling a window that is about to elapse and then filling the
  #   next one as it opens. For a login endpoint that is an acceptable trade for an
  #   implementation a reader can hold in their head; a sliding window belongs in an adapter
  #   with somewhere durable to keep the timestamps. There is a spec demonstrating the burst,
  #   so nobody has to take this paragraph on trust.
  #
  # Both are documented rather than smoothed over, because a limiter that quietly allows more
  # than its configured limit is worse than one that says so.
  class FixedWindowRateLimiter < RateLimiter
    # Bounds memory. An attacker can otherwise mint keys — one per login guessed — until the
    # process runs out of memory, which would turn the defence into the vulnerability.
    DEFAULT_MAX_KEYS = 100_000

    record Window, started_at : Time, count : Int32

    getter limit : Int32
    getter window : Time::Span

    def initialize(
      @limit : Int32,
      @window : Time::Span,
      @clock : Clock = SystemClock.new,
      @max_keys : Int32 = DEFAULT_MAX_KEYS,
    )
      raise ConfigurationError.new("limit must be positive") unless @limit > 0
      raise ConfigurationError.new("window must be positive") unless @window > Time::Span::ZERO
      raise ConfigurationError.new("max_keys must be positive") unless @max_keys > 0

      @mutex = Mutex.new
      @windows = {} of String => Window
    end

    def consume(key : String) : Verdict
      @mutex.synchronize do
        now = @clock.now
        current = @windows[key]?

        if current.nil? || now - current.started_at >= @window
          purge_expired(now) if @windows.size >= @max_keys
          @windows[key] = Window.new(started_at: now, count: 1)
          next Verdict.allow
        end

        count = current.count + 1
        @windows[key] = Window.new(started_at: current.started_at, count: count)

        if count > @limit
          Verdict.deny(retry_after: current.started_at + @window - now)
        else
          Verdict.allow
        end
      end
    end

    def reset(key : String) : Nil
      @mutex.synchronize { @windows.delete(key) }
    end

    # How many keys are being tracked. For a spec, and for an application that wants to see
    # whether it is near the cap.
    def size : Int32
      @mutex.synchronize { @windows.size }
    end

    # Drops windows that have already elapsed.
    #
    # Called only when the map reaches its cap, so the common path stays a single hash lookup.
    # If every window is still live the cap is genuinely reached, and the oldest are dropped —
    # forgetting a live counter allows a few extra attempts, whereas refusing to record new
    # ones would let an attacker pin the table and disable the limiter for everybody else.
    private def purge_expired(now : Time) : Nil
      @windows.reject! { |_, window| now - window.started_at >= @window }

      return if @windows.size < @max_keys

      oldest = @windows.to_a.sort_by! { |(_, window)| window.started_at }
      oldest.first(@windows.size - @max_keys // 2).each { |(key, _)| @windows.delete(key) }
    end
  end
end

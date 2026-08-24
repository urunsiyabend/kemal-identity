module KemalIdentity
  # Whether an attempt may proceed, and when to come back if not.
  struct Verdict
    getter? allowed : Bool

    # How long until the caller may try again. Set only on a denial.
    #
    # Telling an honest client when to return is worth more than the little it reveals: the
    # attacker already knows they are being throttled — that is what being throttled means —
    # while a legitimate user staring at "try again later" has no idea whether to wait a
    # second or an hour.
    getter retry_after : Time::Span?

    def self.allow : self
      new(allowed: true)
    end

    def self.deny(retry_after : Time::Span) : self
      new(allowed: false, retry_after: retry_after)
    end

    def initialize(@allowed : Bool, @retry_after : Time::Span? = nil)
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
    abstract def consume(key : String) : Verdict

    # Clears the count for `key`, after a successful authentication.
    #
    # Idempotent, and safe for a key that was never consumed.
    abstract def reset(key : String) : Nil
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

module KemalIdentity::Passwords
  # Whether this Crystal provides execution contexts.
  #
  # A feature check rather than a version comparison, because the feature is what matters:
  # `Fiber::ExecutionContext` is the default concurrency model from Crystal 1.21, and is
  # available earlier only behind `-Dexecution_context`. An application that builds with that
  # flag on 1.20 gets the real dispatcher here, which a version comparison would have denied
  # it.
  EXECUTION_CONTEXTS = {{ Fiber.has_constant?("ExecutionContext") }}

  # Runs a `Hasher`'s expensive operations on a dedicated execution context.
  #
  # ### The problem this solves
  #
  # Bcrypt verification at cost 12 is tens of milliseconds of **pure CPU**, by design, and
  # Crystal's scheduler is cooperative — a verification never yields. Run on the request fiber
  # it occupies a scheduler thread for its whole duration, and enough concurrent logins queue
  # every unrelated request behind them. The naive implementation is therefore a latency
  # problem for the entire application, not just for logins.
  #
  # Dispatching to a small, separately sized context bounds the damage: a burst of logins
  # degrades **login latency**, which is the thing that should degrade, while the main context
  # keeps serving everything else. Measured at 50 concurrent logins, unrelated-request p99 is
  # 1.17 ms with this and 2,176 ms without.
  #
  # ### Why it is a wrapper and not a change to `Hasher`
  #
  # `Hasher` stays synchronous and knows nothing about scheduling. Dispatch is a decorator over
  # the contract, so introducing it changed one line of wiring rather than the `Hasher` API.
  # It satisfies the `Hasher` contract itself, so it drops in anywhere a hasher goes, and it
  # runs the same contract spec.
  #
  # ### On a Crystal without execution contexts
  #
  # The class still exists and the API is identical, but there is nowhere to dispatch **to**:
  # before execution contexts a program cannot create a second scheduler, and running the hash
  # on another fiber of the same one moves nothing, because the work never yields.
  #
  # So it refuses to be built, rather than quietly becoming a pass-through:
  #
  # ```
  # KemalIdentity::ConfigurationError: HashingExecutor needs execution contexts, which this
  # Crystal (1.20.0) does not provide. Upgrade to 1.21, build with -Dexecution_context, or
  # pass allow_inline: true to hash on the request fiber and accept the latency cost.
  # ```
  #
  # `allow_inline: true` is the deliberate opt-out. It is named for what it does, it is one
  # grep away in review, and it is the only way to end up without the protection — because a
  # security property that silently disappears on an older compiler is worse than one that is
  # absent loudly. See `blueprints/0013-execution-contexts-are-optional.md`.
  #
  # ```
  # KemalIdentity.configure(
  #   accounts: accounts,
  #   sessions: sessions,
  #   hasher: KemalIdentity::Passwords::HashingExecutor.new(
  #     KemalIdentity::Passwords::BcryptHasher.new(cost: 12), size: 2
  #   ),
  # )
  # ```
  #
  # ### What is dispatched, and what is not
  #
  # Only `hash_secret` and `verify` — the two that actually burn CPU. `scheme`,
  # `max_secret_bytesize`, `needs_rehash?` and `dummy_digest` are a field read, a comparison,
  # and a string parse; hopping contexts for those would cost more than doing them.
  class HashingExecutor < Hasher
    # Small on purpose. This is a **ceiling on how much of the machine logins may take**, not a
    # throughput target: the whole point is that a login burst cannot starve everything else,
    # and a pool sized like the main context would defeat that. Two is a starting point, and
    # `bench/hashing_latency.cr` is how a deployment picks its own.
    DEFAULT_SIZE = 2

    getter inner : Hasher

    # Whether this instance actually dispatches, or runs on the calling fiber.
    #
    # False only where execution contexts are unavailable and `allow_inline` was passed.
    getter? dispatching : Bool

    # Two whole initializers rather than one with a conditional body: Crystal's "this
    # initialize doesn't explicitly initialize @context" check does not look inside a macro
    # `if`, and on a build without execution contexts there is no context to hold anyway.
    {% if Fiber.has_constant?("ExecutionContext") %}
      @context : Fiber::ExecutionContext

      def initialize(
        @inner : Hasher,
        size : Int32 = DEFAULT_SIZE,
        name : String = "kemal_identity-hashing",
        allow_inline : Bool = false,
      )
        raise ConfigurationError.new("size must be positive") unless size > 0

        @context = Fiber::ExecutionContext::Parallel.new(name, size)
        @dispatching = true
      end

      # Shares an existing context, for an application that already runs one for CPU-bound
      # work — and for specs, which would otherwise build a thread pool per example.
      def initialize(@inner : Hasher, context : Fiber::ExecutionContext)
        @context = context
        @dispatching = true
      end
    {% else %}
      def initialize(
        @inner : Hasher,
        size : Int32 = DEFAULT_SIZE,
        name : String = "kemal_identity-hashing",
        allow_inline : Bool = false,
      )
        raise ConfigurationError.new("size must be positive") unless size > 0

        unless allow_inline
          raise ConfigurationError.new(
            "HashingExecutor needs execution contexts, which this Crystal " \
            "(#{Crystal::VERSION}) does not provide. Upgrade to Crystal 1.21, build with " \
            "-Dexecution_context, or pass allow_inline: true to hash on the request fiber " \
            "and accept that a burst of logins will slow unrelated requests."
          )
        end

        @dispatching = false
      end
    {% end %}

    def scheme : String
      @inner.scheme
    end

    def max_secret_bytesize : Int32
      @inner.max_secret_bytesize
    end

    def dummy_digest : String
      @inner.dummy_digest
    end

    def needs_rehash?(digest : String) : Bool
      @inner.needs_rehash?(digest)
    end

    def hash_secret(secret : Secret) : String
      dispatch { @inner.hash_secret(secret) }
    end

    def verify(secret : Secret, digest : String) : Bool
      dispatch { @inner.verify(secret, digest) }
    end

    # Runs `block` on the hashing context and waits for it on the calling fiber.
    #
    # `Channel#receive` parks the caller and hands its scheduler thread back, which is the
    # entire mechanism: the request fiber is suspended rather than spinning, so the main
    # context is free to serve other requests while the hash runs elsewhere.
    #
    # The rescue is deliberately `Exception` and not a narrower class. This is a work
    # dispatcher: whatever the inner hasher raises — `ArgumentError` for an over-length secret,
    # `InfrastructureError` from a crypto backend — has to cross back to the caller and be
    # re-raised there. Letting anything escape the spawned fiber instead would lose the value
    # nobody ever sends, and park the caller on `receive` forever. `src/CLAUDE.md` bans the
    # *bare* rescue, which hides what it catches; this one names it and re-raises it unchanged.
    {% if Fiber.has_constant?("ExecutionContext") %}
      # Runs `block` on the hashing context and waits for it on the calling fiber.
      #
      # `Channel#receive` parks the caller and hands its scheduler thread back, which is the
      # entire mechanism: the request fiber is suspended rather than spinning, so the main
      # context is free to serve other requests while the hash runs elsewhere.
      #
      # The rescue is deliberately `Exception` and not a narrower class. This is a work
      # dispatcher: whatever the inner hasher raises — `ArgumentError` for an over-length
      # secret, `InfrastructureError` from a crypto backend — has to cross back to the caller
      # and be re-raised there. Letting anything escape the spawned fiber instead would lose
      # the value nobody ever sends, and park the caller on `receive` forever. `src/CLAUDE.md`
      # bans the *bare* rescue, which hides what it catches; this one names it and re-raises it
      # unchanged.
      #
      # Defined per branch rather than as one method with a conditional body: a captured block
      # parameter is not visible inside a macro `if` in the method body.
      private def dispatch(&block : -> T) : T forall T
        channel = Channel(T | Exception).new(1)

        @context.spawn do
          channel.send(block.call)
        rescue error : Exception
          channel.send(error)
        end

        result = channel.receive
        raise result if result.is_a?(Exception)
        result
      end
    {% else %}
      # Nowhere to dispatch to. Reached only when `allow_inline: true` was passed, which the
      # constructor demands on a Crystal without execution contexts.
      private def dispatch(&block : -> T) : T forall T
        block.call
      end
    {% end %}
  end
end

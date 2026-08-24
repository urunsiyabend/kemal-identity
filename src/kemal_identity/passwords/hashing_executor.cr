module KemalIdentity::Passwords
  # Runs a `Hasher`'s expensive operations on a dedicated execution context.
  #
  # ### The problem this solves
  #
  # Bcrypt verification at cost 12 is tens of milliseconds of **pure CPU**, by design. Crystal
  # 1.21 made execution contexts the default concurrency model, which changes what that costs:
  # run on the request fiber, a verification occupies a scheduler thread for its whole
  # duration, and enough concurrent logins queue every unrelated request behind them. The naive
  # implementation is therefore a latency problem for the entire application, not just for
  # logins — a handful of people signing in makes an unrelated page slow for everybody else.
  #
  # Dispatching to a small, separately sized context bounds the damage: a burst of logins
  # degrades **login latency**, which is the thing that should degrade, while the main context
  # keeps serving everything else. `docs/01-architecture.md` calls this one of the few places
  # this shard can be meaningfully better on Crystal than a transliterated Ruby or Node design.
  #
  # ### Why it is a wrapper and not a change to `Hasher`
  #
  # `Hasher` stays synchronous and knows nothing about scheduling. Dispatch is a decorator over
  # the contract, so introducing it changes one line of wiring rather than the `Hasher` API —
  # which is what `docs/01-architecture.md` means by warning that retrofitting this "changes
  # the `Hasher` call path". It satisfies the `Hasher` contract itself, so it drops in
  # anywhere a hasher goes, and it runs the same contract spec.
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

    def initialize(@inner : Hasher, size : Int32 = DEFAULT_SIZE, name : String = "kemal_identity-hashing")
      raise ConfigurationError.new("size must be positive") unless size > 0

      @context = Fiber::ExecutionContext::Parallel.new(name, size)
    end

    # Shares an existing context, for an application that already runs one for CPU-bound work —
    # and for specs, which would otherwise build a thread pool per example.
    def initialize(@inner : Hasher, context : Fiber::ExecutionContext)
      @context = context
    end

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
  end
end

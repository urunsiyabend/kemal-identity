module KemalIdentity::Authz
  # A short-lived cache of one account's grants.
  #
  # `docs/06-roadmap.md`: role and permission lists are not copied into long-lived tokens or
  # sessions, and if membership changes must take effect immediately they are read from the
  # store "or a short-lived versioned cache". This is that cache, and everything about it is
  # about keeping *short-lived* true.
  #
  # ### The TTL is the revocation delay, and it is capped
  #
  # Whatever the TTL is, that is how long somebody keeps access after it is taken away, in the
  # worst case, in every process that had cached them. Five seconds by default and a hard
  # ceiling of one minute — not because a longer one would not perform better, but because a
  # ten-minute cache is a ten-minute window in which a compromised account keeps working after
  # somebody has already noticed and revoked it. An application that wants no window at all
  # passes no cache; it is off by default.
  #
  # ### Invalidation helps one process, and the TTL is what actually bounds this
  #
  # `#invalidate` drops an account's entries, and `RBAC` calls it on every grant and revoke it
  # performs. Behind several processes or several machines, that only clears the cache of the
  # process that made the change; the others wait out the TTL. This is stated plainly rather
  # than papered over with a pub/sub mechanism that would be one more thing to run and one more
  # thing to be silently broken — if the invalidation channel fails, the TTL is what is still
  # keeping the promise, so the TTL had better be short enough to be the whole answer on its
  # own.
  #
  # ### It is bounded, and it drops everything when it fills
  #
  # The key includes the tenant asked about, and anybody signed in can ask about a tenant that
  # does not exist, so an unbounded map is an unbounded map an attacker fills. At the limit the
  # whole cache is cleared rather than evicted one entry at a time: no LRU bookkeeping on the
  # hot path, and the failure mode of a stampede is "the cache stops helping", not "the process
  # runs out of memory".
  class Cache
    DEFAULT_TTL = 5.seconds

    # A cache longer than this is not a cache, it is a copy of the grants with a delayed
    # revocation, which is the thing the roadmap forbids.
    MAX_TTL = 1.minute

    DEFAULT_MAX_ENTRIES = 10_000

    private record Entry, account_id : String, grants : Grants, expires_at : Time

    getter ttl : Time::Span
    getter max_entries : Int32

    def initialize(
      @clock : Clock,
      @ttl : Time::Span = DEFAULT_TTL,
      @max_entries : Int32 = DEFAULT_MAX_ENTRIES,
    )
      raise ConfigurationError.new("cache ttl must be positive") unless @ttl > Time::Span.zero

      if @ttl > MAX_TTL
        raise ConfigurationError.new(
          "cache ttl of #{@ttl} exceeds #{MAX_TTL}: the ttl is how long a revoked grant keeps working"
        )
      end

      raise ConfigurationError.new("max_entries must be positive") unless @max_entries > 0

      @mutex = Mutex.new
      @entries = {} of String => Entry
    end

    # The cached grants, or whatever the block returns, cached.
    #
    # The block runs outside the lock. Holding a mutex across a database round trip would make
    # every fiber in the process queue behind one slow query, and the cost of two fibers
    # occasionally loading the same account is one redundant read.
    def fetch(account_id : String, tenant_id : String?, & : -> Grants) : Grants
      key = key_for(account_id, tenant_id)
      now = @clock.now

      cached = @mutex.synchronize do
        entry = @entries[key]?
        entry.nil? || entry.expires_at <= now ? nil : entry.grants
      end

      return cached if cached

      grants = yield

      @mutex.synchronize do
        # See the note above: clearing beats evicting, because the alternative is bookkeeping
        # on the hot path to defend against a case that should never be reached.
        @entries.clear if @entries.size >= @max_entries

        @entries[key] = Entry.new(account_id, grants, now + @ttl)
      end

      grants
    end

    # Drops every entry for one account, across every tenant it was asked about.
    #
    # Linear in the size of the cache, which is fine: this runs when somebody's roles change,
    # not on the request path.
    def invalidate(account_id : String) : Nil
      @mutex.synchronize do
        @entries.reject! { |_, entry| entry.account_id == account_id }
      end
    end

    def clear : Nil
      @mutex.synchronize { @entries.clear }
    end

    def size : Int32
      @mutex.synchronize { @entries.size }
    end

    # Length-prefixed, so that an account id containing the separator cannot be made to collide
    # with another account's entry.
    private def key_for(account_id : String, tenant_id : String?) : String
      "#{account_id.bytesize}:#{account_id}:#{tenant_id}"
    end
  end
end

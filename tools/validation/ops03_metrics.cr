require "kemal_identity"

# OPS-03 — the consumer-side instrumentation the scenario asks for: "add instrumentation around
# public services and adapters **without modifying their source**."
#
# Everything here is a decorator over a published contract. Nothing reopens a shard class,
# nothing subclasses a concrete service, and nothing reads a private method.

# A metrics registry with one deliberate rule: a label value that looks like an identifier is
# refused. That is how the second pass condition — "subject, token, login and tenant are not
# metric labels by default" — gets *measured* rather than asserted, because a wrapper that
# accidentally labels by account id fails loudly here instead of quietly exploding a time
# series.
class Metrics
  record Observation, name : String, labels : Hash(String, String), seconds : Float64

  getter observations = [] of Observation
  getter counters = {} of String => Int32

  # Values a label is allowed to take. Everything a metric is labelled with in this attempt has
  # to come from this set, which is what "low cardinality" means concretely.
  ALLOWED = %w[
    database hashing remote cache limiter
    accounts sessions api_tokens authz
    authenticated failed anonymous permitted denied
    hit miss allowed limited jwks token_exchange
    invalid_credential unknown_account disabled_account expired revoked
    malformed_credential replayed_token stale_auth_version rate_limited
    insufficient_assurance not_permitted out_of_scope not_a_member tenant_mismatch
    unknown_permission
  ]

  def observe(name : String, seconds : Float64, **labels) : Nil
    hash = {} of String => String

    labels.each do |key, value|
      text = value.to_s
      unless ALLOWED.includes?(text)
        raise "metric #{name} labelled #{key}=#{text.inspect}, which is not a bounded value"
      end

      hash[key.to_s] = text
    end

    @observations << Observation.new(name, hash, seconds)
  end

  def increment(name : String) : Nil
    @counters[name] = (@counters[name]? || 0) + 1
  end

  def layers : Array(String)
    @observations.compact_map { |o| o.labels["layer"]? }.uniq!.sort!
  end

  def for_layer(layer : String) : Array(Observation)
    @observations.select { |o| o.labels["layer"]? == layer }
  end

  def label_values : Array(String)
    @observations.flat_map { |o| o.labels.values }.uniq!
  end
end

# `Time.monotonic` rather than the injected `Clock`: a duration is wall-clock work, and a test
# clock that only moves when a spec moves it would report every operation as instantaneous.
def timed(& : -> T) : {T, Float64} forall T
  started = Time.monotonic
  result = yield
  {result, (Time.monotonic - started).total_seconds}
end

# ---------------------------------------------------------------------------
# Database: one decorator per repository contract. `accounts`, `sessions`, `api_tokens` and
# `authz` are the four an authenticated request can touch.
# ---------------------------------------------------------------------------
class MeteredAccounts < KemalIdentity::Accounts::Repository
  def initialize(@inner : KemalIdentity::Accounts::Repository, @metrics : Metrics)
  end

  def find_by_id(id : String) : KemalIdentity::Accounts::Account?
    measure { @inner.find_by_id(id) }
  end

  def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
    measure { @inner.find_by_login(normalized_login, tenant_id) }
  end

  def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
    measure { @inner.update_password_digest(id, digest, scheme, at) }
  end

  def mark_email_verified(id : String, at : Time) : Bool
    measure { @inner.mark_email_verified(id, at) }
  end

  def bump_auth_version(id : String) : Int32?
    measure { @inner.bump_auth_version(id) }
  end

  private def measure(& : -> T) : T forall T
    result, seconds = timed { yield }
    @metrics.observe("repository.duration", seconds, layer: "database", store: "accounts")
    result
  end
end

class MeteredSessions < KemalIdentity::Sessions::Repository
  def initialize(@inner : KemalIdentity::Sessions::Repository, @metrics : Metrics)
  end

  def create(record : KemalIdentity::Sessions::Record) : Nil
    measure { @inner.create(record) }
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
    measure { @inner.find_by_digest(digest) }
  end

  def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
    measure { @inner.touch(id, last_seen_at, idle_expires_at) }
  end

  def revoke(id : String, at : Time) : Bool
    measure { @inner.revoke(id, at) }
  end

  def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
    measure { @inner.revoke_all_for_account(account_id, at, except_id) }
  end

  def delete_revoked_before(before : Time) : Int32
    measure { @inner.delete_revoked_before(before) }
  end

  def delete_expired(before : Time) : Int32
    measure { @inner.delete_expired(before) }
  end

  private def measure(& : -> T) : T forall T
    result, seconds = timed { yield }
    @metrics.observe("repository.duration", seconds, layer: "database", store: "sessions")
    result
  end
end

class MeteredAuthz < KemalIdentity::Authz::Repository
  def initialize(@inner : KemalIdentity::Authz::Repository, @metrics : Metrics)
  end

  # The hot one: every authorized request reads this, and it is the read a grant cache removes.
  def grants_for(account_id : String, tenant_id : String? = nil) : KemalIdentity::Authz::Grants
    measure { @inner.grants_for(account_id, tenant_id) }
  end

  def add_member(membership : KemalIdentity::Authz::Membership) : Bool
    measure { @inner.add_member(membership) }
  end

  def remove_member(account_id : String, tenant_id : String) : Bool
    measure { @inner.remove_member(account_id, tenant_id) }
  end

  def member?(account_id : String, tenant_id : String) : Bool
    measure { @inner.member?(account_id, tenant_id) }
  end

  def memberships_for(account_id : String) : Array(KemalIdentity::Authz::Membership)
    measure { @inner.memberships_for(account_id) }
  end

  def members_of(
    tenant_id : String,
    limit : Int32 = 100,
    offset : Int32 = 0,
  ) : Array(KemalIdentity::Authz::Membership)
    measure { @inner.members_of(tenant_id, limit, offset) }
  end

  def grant(assignment : KemalIdentity::Authz::Assignment) : Bool
    measure { @inner.grant(assignment) }
  end

  def revoke(account_id : String, role : String, tenant_id : String? = nil) : Bool
    measure { @inner.revoke(account_id, role, tenant_id) }
  end

  def assignments_for(account_id : String) : Array(KemalIdentity::Authz::Assignment)
    measure { @inner.assignments_for(account_id) }
  end

  def accounts_with_role(role : String, tenant_id : String? = nil) : Array(String)
    measure { @inner.accounts_with_role(role, tenant_id) }
  end

  def remove_account(account_id : String) : Int32
    measure { @inner.remove_account(account_id) }
  end

  private def measure(& : -> T) : T forall T
    result, seconds = timed { yield }
    @metrics.observe("repository.duration", seconds, layer: "database", store: "authz")
    result
  end
end

# ---------------------------------------------------------------------------
# Hashing: the one operation that is deliberately slow, and the one an operator most needs to
# see separately from the database. `Hasher` is a contract, so this is a decorator too.
# ---------------------------------------------------------------------------
class MeteredHasher < KemalIdentity::Passwords::Hasher
  def initialize(@inner : KemalIdentity::Passwords::Hasher, @metrics : Metrics)
  end

  def scheme : String
    @inner.scheme
  end

  def max_secret_bytesize : Int32
    @inner.max_secret_bytesize
  end

  def hash_secret(secret : KemalIdentity::Secret) : String
    result, seconds = timed { @inner.hash_secret(secret) }
    @metrics.observe("hash.duration", seconds, layer: "hashing")
    result
  end

  def verify(secret : KemalIdentity::Secret, digest : String) : Bool
    result, seconds = timed { @inner.verify(secret, digest) }
    @metrics.observe("hash.duration", seconds, layer: "hashing")
    result
  end

  def needs_rehash?(digest : String) : Bool
    @inner.needs_rehash?(digest)
  end

  def dummy_digest : String
    @inner.dummy_digest
  end
end

# ---------------------------------------------------------------------------
# Rate limiting: denials are a first-class operational signal, and the contract is public.
# ---------------------------------------------------------------------------
class MeteredLimiter < KemalIdentity::RateLimiter
  def initialize(@inner : KemalIdentity::RateLimiter, @metrics : Metrics)
  end

  def consume(key : String) : KemalIdentity::Verdict
    verdict, seconds = timed { @inner.consume(key) }

    # The *key* never becomes a label: it is built from a login or an address, which is exactly
    # the high-cardinality identifier this condition is about. The outcome is the label.
    @metrics.observe(
      "limiter.duration", seconds, layer: "limiter",
      outcome: verdict.allowed? ? "allowed" : "limited"
    )
    @metrics.increment("limiter.denied") unless verdict.allowed?

    verdict
  end

  def reset(key : String) : Nil
    @inner.reset(key)
  end
end

# ---------------------------------------------------------------------------
# The remote provider. Both places this shard talks to somebody else's server take an injected
# transport — `JWKS(fetcher:)` and `OIDC::Client(exchanger:)` — so remote latency is separable
# from everything above without touching either class.
# ---------------------------------------------------------------------------
class RemoteTimer
  def initialize(@metrics : Metrics)
  end

  def jwks_fetcher(document : String, delay : Time::Span = Time::Span.zero) : Proc(URI, Time::Span, String)
    ->(_uri : URI, _timeout : Time::Span) do
      result, seconds = timed do
        # Stands in for the network. A real one calls HTTP::Client here.
        spin(delay)
        document
      end

      @metrics.observe("provider.duration", seconds, layer: "remote", call: "jwks")
      result
    end
  end

  private def spin(delay : Time::Span) : Nil
    return if delay.zero?

    deadline = Time.monotonic + delay
    while Time.monotonic < deadline
      Fiber.yield
    end
  end
end

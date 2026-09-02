require "spec"
require "kemal_identity"
require "kemal_identity/testing"
require "../src/ops03_metrics"

# OPS-03 — metrics and tracing without secret leakage.
#
# Four pass conditions, and each is measured by *running* the instrumentation from
# `ops03_metrics.cr` through a real login, a real session read, a real bearer authentication, a
# real authorization decision and a real rate-limit denial, then looking at what came out.

NOW03 = Time.utc(2026, 9, 2, 12, 0, 0)

# A real key set, so the fetch is a real parse rather than an error path.
JWKS_BODY = %({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"rsa",) +
            %("n":"#{KemalIdentity::Testing::RSATestKey::MODULUS_BASE64URL}",) +
            %("e":"#{KemalIdentity::Testing::RSATestKey::EXPONENT_BASE64URL}"}]})

# A sink that keeps every field of every event, so a spec can search all of them for a secret
# rather than trusting that the interesting ones were checked.
class CollectingSink < KemalIdentity::SecurityEventSink
  getter events = [] of KemalIdentity::SecurityEvent

  def record(event : KemalIdentity::SecurityEvent) : Nil
    @events << event
  end

  def clear : Nil
    @events.clear
  end

  # Every string this sink saw, flattened: names, correlation fields, and the whole data bag.
  def all_strings : Array(String)
    @events.flat_map do |event|
      values = [event.name] of String
      values << event.subject.not_nil! if event.subject
      values << event.credential.not_nil! if event.credential
      values << event.tenant.not_nil! if event.tenant
      values << event.ip.not_nil! if event.ip
      values << event.reason.not_nil! if event.reason
      event.data.each { |key, value| values << key; values << value }
      values
    end
  end
end

# The sink is bound **inside** `wire`, not at file scope, and that is a measured requirement
# rather than a style choice: bound at the top of this file it received **zero** events, because
# Crystal's spec runner configures `::Log` after the file loads and `::Log.setup` replaces every
# binding. `KemalIdentity.event_sink_delivering?` is what answers that question now.
#
# Delivery is also asynchronous — `EventBridge` is an `:async` backend so a slow SIEM cannot sit
# on a request fiber — so a spec has to let the dispatcher run before it looks.
def flush_events : Nil
  200.times { Fiber.yield }
end

record Wiring,
  metrics : Metrics,
  sink : CollectingSink,
  clock : KemalIdentity::Testing::TestClock,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  sessions : KemalIdentity::Sessions::Service,
  passwords : KemalIdentity::Passwords::Authenticator,
  api : KemalIdentity::ApiTokens::Service,
  rbac : KemalIdentity::Authz::RBAC,
  limiter : MeteredLimiter,
  hasher : MeteredHasher

def wire(limit : Int32 = 5) : Wiring
  metrics = Metrics.new
  sink = CollectingSink.new
  KemalIdentity.event_sink = sink

  clock = KemalIdentity::Testing::TestClock.new(NOW03)
  random = KemalIdentity::Testing::DeterministicRandom.new
  hasher = MeteredHasher.new(KemalIdentity::Testing::FastTestHasher.new, metrics)

  inner_accounts = KemalIdentity::Testing::MemoryAccountRepository.new
  inner_accounts.insert(KemalIdentity::Accounts::Account.new(
    id: "ada",
    normalized_login: "ada@example.com",
    auth_version: 1,
    created_at: clock.now,
    updated_at: clock.now,
    password_digest: hasher.hash_secret(KemalIdentity::Secret.new("correct-horse")),
    password_scheme: hasher.scheme,
  ))

  accounts = MeteredAccounts.new(inner_accounts, metrics)
  session_repo = MeteredSessions.new(
    KemalIdentity::Testing::MemorySessionRepository.new(inner_accounts), metrics
  )

  sessions = KemalIdentity::Sessions::Service.new(session_repo, clock, random)

  limiter = MeteredLimiter.new(
    KemalIdentity::FixedWindowRateLimiter.new(limit: limit, window: 1.hour, clock: clock), metrics
  )

  passwords = KemalIdentity::Passwords::Authenticator.new(
    accounts: accounts, hasher: hasher, clock: clock, rate_limiter: limiter
  )

  api = KemalIdentity::ApiTokens::Service.new(
    tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(inner_accounts),
    clock: clock, random: random
  )

  catalog = KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new(
      KemalIdentity::Authz::Permission.new("invoices.read", "Read invoices")
    ),
    [KemalIdentity::Authz::Role.new("finance", ["invoices.read"])]
  )
  rbac = KemalIdentity::Authz::RBAC.new(
    catalog, MeteredAuthz.new(KemalIdentity::Testing::MemoryAuthzRepository.new, metrics),
    clock
  )

  Wiring.new(
    metrics: metrics, sink: sink, clock: clock, accounts: inner_accounts, sessions: sessions,
    passwords: passwords, api: api, rbac: rbac, limiter: limiter, hasher: hasher
  )
end

describe "OPS-03 — instrumentation is a decorator over published contracts" do
  it "times the database, the hashing and the remote provider separately" do
    w = wire

    # A login: one account read plus one password verification.
    outcome = w.passwords.authenticate(
      login: "ada@example.com", password: "correct-horse", tenant_id: nil, ip: "203.0.113.7"
    )
    outcome.should be_a(KemalIdentity::Authenticated)

    # A JWKS fetch through the injected transport, which is how remote latency is separable at
    # all — `JWKS.new(fetcher:)` and `OIDC::Client.new(exchanger:)` are the two seams.
    keys = KemalIdentity::JWT::JWKS.new(
      "https://issuer.example/.well-known/jwks.json",
      w.clock,
      fetcher: RemoteTimer.new(w.metrics).jwks_fetcher(JWKS_BODY, delay: 2.milliseconds),
    )
    keys.refresh_for(nil)

    w.metrics.layers.should eq(["database", "hashing", "limiter", "remote"])

    # And the three are distinguishable by more than a label: the shapes differ, which is the
    # point of separating them.
    w.metrics.for_layer("hashing").size.should be >= 1
    w.metrics.for_layer("database").size.should be >= 1
    w.metrics.for_layer("remote").sum(&.seconds).should be >= 0.002
  end

  it "counts rate-limit denials and never labels them with the key" do
    w = wire(limit: 2)

    4.times do
      w.passwords.authenticate(
        login: "ada@example.com", password: "wrong", tenant_id: nil, ip: "203.0.113.7"
      )
    end

    w.metrics.counters["limiter.denied"].should be > 0
    w.metrics.for_layer("limiter").map { |o| o.labels["outcome"] }.uniq!.sort!
      .should eq(["allowed", "limited"])
  end

  it "reports cache hits only by subtraction, which is the one signal with no hook" do
    metrics = Metrics.new
    clock = KemalIdentity::Testing::TestClock.new(NOW03)
    store = MeteredAuthz.new(KemalIdentity::Testing::MemoryAuthzRepository.new, metrics)

    catalog = KemalIdentity::Authz::RoleCatalog.new(
      KemalIdentity::Authz::PermissionRegistry.new(
        KemalIdentity::Authz::Permission.new("invoices.read", "Read invoices")
      ),
      [KemalIdentity::Authz::Role.new("finance", ["invoices.read"])]
    )

    rbac = KemalIdentity::Authz::RBAC.new(
      catalog, store, clock, cache: KemalIdentity::Authz::Cache.new(clock)
    )
    rbac.grant("ada", "finance")

    principal = KemalIdentity::Principal.new(
      subject: "ada", assurance: KemalIdentity::AssuranceLevel::Password, authenticated_at: NOW03
    )
    context = KemalIdentity::Authz::Context.new

    before = metrics.for_layer("database").size
    10.times { rbac.decide(principal, "invoices.read", context) }
    reads = metrics.for_layer("database").size - before

    # Ten decisions, one store read: the other nine were cache hits, and the only way to know
    # that is to count both sides. `Authz::Cache` exposes `#size` and no hit counter.
    reads.should eq(1)
    (10 - reads).should eq(9)
  end
end

describe "OPS-03 — what must not become a label" do
  it "keeps the account id, the login and the credential out of every label value" do
    w = wire

    issued = w.api.issue(w.accounts.find_by_id("ada").not_nil!, "ada-cli")
    w.api.authenticate(issued.token.reveal)

    session = w.sessions.start(
      w.accounts.find_by_id("ada").not_nil!, KemalIdentity::AssuranceLevel::Password
    )
    w.sessions.resolve(session.token.reveal)

    values = w.metrics.label_values
    values.should_not contain("ada")
    values.should_not contain("ada@example.com")
    values.should_not contain(issued.token.reveal)
    values.should_not contain(issued.record.id)
    values.should_not contain(session.token.reveal)
    values.should_not contain(session.record.id)

    # Every label value came from the bounded set, which is enforced by the registry itself:
    # `Metrics#observe` raises on anything else, so this suite would have failed above rather
    # than here if a wrapper had labelled by identity.
    values.each { |value| Metrics::ALLOWED.should contain(value) }
  end

  it "has a bounded domain for the failure category, and it is the shard's own enum" do
    # The label an operator actually wants — *why* authentication failed — is low-cardinality by
    # construction: it is an enum, and a small one.
    KemalIdentity::FailureReason.values.size.should be <= 16
    KemalIdentity::Authz::DenialReason.values.size.should be <= 10

    # Every member is a name, not a value read from a request.
    KemalIdentity::FailureReason.values.each do |reason|
      reason.to_s.should match(/\A[A-Za-z]+\z/)
    end
  end
end

describe "OPS-03 — whether the trail is connected at all" do
  it "reports a sink that a later Log setup unbound" do
    sink = CollectingSink.new
    KemalIdentity.event_sink = sink
    KemalIdentity.event_sink_delivering?.should be_true

    # What an application does when it configures logging after wiring the shard, and what
    # Crystal's spec runner does to a binding made at the top of a spec file.
    ::Log.setup(:info)
    KemalIdentity.event_sink_delivering?(yields: 200).should be_false

    # Bound again, after the setup: delivering.
    KemalIdentity.event_sink = sink
    KemalIdentity.event_sink_delivering?.should be_true
  end
end

describe "OPS-03 — no secret reaches a trace" do
  it "puts no raw credential in any field of any event" do
    w = wire

    session = w.sessions.start(
      w.accounts.find_by_id("ada").not_nil!, KemalIdentity::AssuranceLevel::Password
    )
    issued = w.api.issue(w.accounts.find_by_id("ada").not_nil!, "ada-cli")

    w.passwords.authenticate(
      login: "ada@example.com", password: "correct-horse", tenant_id: nil, ip: "203.0.113.7"
    )
    w.passwords.authenticate(
      login: "ada@example.com", password: "wrong", tenant_id: nil, ip: "203.0.113.7"
    )
    w.api.authenticate(issued.token.reveal)
    w.api.revoke(issued.record.id, "ada")
    w.sessions.revoke(session.record.id)

    flush_events
    strings = w.sink.all_strings
    strings.should_not be_empty

    # The three things that must never appear: the raw session token, the raw API token, and
    # the password. Not redacted — never present, because no call site has them.
    strings.should_not contain(session.token.reveal)
    strings.should_not contain(issued.token.reveal)
    strings.should_not contain("correct-horse")
    strings.should_not contain("wrong")

    # Nor the login, which `blueprints/0007` removed from events deliberately: an audit trail
    # that names the address turns "somebody tried to log in" into a list of addresses.
    strings.should_not contain("ada@example.com")

    # The *ids* are there, and that is the point of them — correlation with no secret.
    strings.should contain(session.record.id)
    strings.should contain(issued.record.id)
  end

  it "cannot be handed a header or a cookie, because nothing takes one" do
    # `SecurityEvent` has six typed fields and a `Hash(String, String)`. There is no request
    # object, no header map and no cookie jar anywhere in it, so an event *cannot* carry a raw
    # `Authorization` header even by mistake. That is a stronger property than redaction, and
    # it is what makes this condition checkable at all.
    event = KemalIdentity::SecurityEvent.new(
      name: "authentication.failed", severity: ::Log::Severity::Warn, at: NOW03
    )

    {{ KemalIdentity::SecurityEvent.methods.map(&.name.stringify).select { |n| !n.starts_with?("_") } }}
      .should_not contain("headers")

    event.data.should be_empty
    event.credential.should be_nil
  end

  it "redacts a secret that is printed by accident" do
    secret = KemalIdentity::Secret.new("correct-horse")

    secret.to_s.should_not contain("correct-horse")
    secret.inspect.should_not contain("correct-horse")
    "#{secret}".should_not contain("correct-horse")
  end
end

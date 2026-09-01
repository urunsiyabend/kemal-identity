# Validation attempts

The consumer-side code behind `blueprints/0025-maturity-validation-results.md`, kept so a later
revision can be validated against the same attempts rather than against a fresh reading.

These are **not** part of this shard's suite and are not run by `crystal spec`. They belong to a
separate project that depends on the shard the way an application does — which is the whole point,
since several scenarios are about what a consumer can reach from outside.

To run them, create a project alongside this one:

```
consumer_app/
  shard.yml          # copy consumer-shard.yml.example, fix the path
  spec/              # copy the *_spec.cr files
  src/               # copy http01_app.cr
```

then `shards install` and `crystal spec`. `http01_app.cr` is a server: build it, run it, and
probe it with `curl` — the HTTP-01 result is about what a client receives, so it was measured
that way rather than in-process.

| File | Scenario |
|---|---|
| `tok01_spec.cr` | TOK-01, AUT-03 — two differently scoped tokens for one account |
| `tok01_lookups_spec.cr` | TOK-01 hot path — counts `find_by_digest` calls per authentication |
| `dev02_after_spec.cr` | DEV-02 after the fix — `require "kemal_identity/testing"`, nothing reaching into `spec/` |
| `before-dev02-fix/` | The three attempts that produced DEV-02's original M2. They no longer run: the fix deleted the paths they used. See that directory's README |
| `ops02_spec.cr` | OPS-02 — subscribing to events, and the absence of a typed sink |
| `ops02_failure_spec.cr` | OPS-02 — a sink that raises, in both `Log` dispatch modes. **Pre-fix**: measured the two failure modes of a raw `Log::Backend` |
| `ops02_after_spec.cr` | OPS-02 after the fix — a typed `SecurityEventSink`, a dead SIEM that neither fails the login nor goes silent |
| `http01_app.cr` | HTTP-01 — an API-only Kemal app. Now uses the shipped `ErrorHandler`, since the shard emits the challenge itself; the consumer-written version it replaced is in the git history of this file |
| `shared_limiter.cr` | OPS-01 — a `RateLimiter` over a store more than one process can see |
| `ops01_spec.cr` | OPS-01 — the shard's own limiter contract plus atomicity, `retry_after`, key hygiene and store failure |
| `ops01_setup.cr`, `ops01_worker.cr` | OPS-01 — the cross-process check. **Not a spec**: see below |
| `legacy_users.cr` | IDP-03 — an `AccountRepository` over a consumer-owned `users` table, and a SHA-256 `LegacyVerifier` |
| `idp03_spec.cr` | IDP-03 — no `auth_accounts`, UUID subjects, soft deletion, lazy rehash |
| `idp03_contract_spec.cr` | IDP-03 — the shard's `AccountRepository` contract against that adapter. **Three tenancy examples fail by design**: the adapter is single-tenant |
| `tok03_spec.cr` | TOK-03 — session, JWT and consumer-written credential references; no reachable secret |
| `aut01_spec.cr` | AUT-01 — ownership rules, and the store-read count for a hundred-row list with and without the cache |
| `kv_sessions.cr` | OPS-04 — `SessionRepository` over a key-value store held to Redis-shaped rules |
| `ops04_spec.cr` | OPS-04 — the shard's session contract against that adapter, plus expiry-on-read and concurrent revoke |
| `ops07/{core,sqlite,pg}/` | OPS-07 — three whole projects. Build each and check what `lib/` holds |
| `http03_app.cr` | HTTP-03 — two accounts, two credential kinds. A server: build, run, probe every combination |
| `http03_bearer_first.cr` | HTTP-03 — the same app with a consumer-written bearer-first handler. **Contains a deliberately failing line**: see below |
| `jwt_family_spec.cr` | JWT-01 to JWT-04 — two issuers, chaining in both orders, hand-rolled `iss` routing, claim mapping, per-audience and per-issuer policy |
| `dev03_raw_http.cr` | DEV-03 — a whole server over raw `HTTP::Server`, no Kemal. A server: build, run, probe |
| `dev03_http07_spec.cr` | DEV-03's application object, and HTTP-07 — a job's principal with no request |
| `tok04_gateway.cr` | TOK-04 — a consumer-written `RequestAuthenticator` for a gateway-issued token |
| `tok04_spec.cr` | TOK-04 — the authenticator alone, and in a chain the consumer built |
| `tok04_order_spec.cr` | TOK-04 — every position among the shipped authenticators, every credential family. The evidence behind "extras go last" |
| `tok04_register_probe.cr` | TOK-04 — **does not compile, on purpose**: `configure(bearer:)` before the fix. The error is the finding |
| `tok05_spec.cr` | TOK-05 — four bearer families, the two shape collisions and both escapes, plus I/O counts and the oversized-credential timing |
| `tok04_app_chain.cr` | TOK-04 — registration by reaching into `AuthenticatorChain#authenticators`. A server: build, run, probe. Works, and is an accident |
| `tok04_app_only.cr` | TOK-04 — the gateway token as the *only* bearer credential, resolved by a handler of the consumer's own. A server. This is the one that loses the challenge and the CSRF exemption |
| `tok04_app_fixed.cr` | TOK-04 — the same app through `bearer_authenticators:`, with no handler of its own. A server |
| `idp_family_spec.cr` | IDP-01, IDP-02, IDP-04 — two providers, out-of-order callbacks, the provider-switch case, linking conflicts, tenant lookups |

## The ones that are supposed to fail

`tok04_register_probe.cr` does not compile, and that is the TOK-04 finding as the compiler stated
it: before `bearer_authenticators:` existed, `configure` had no parameter for a consumer's
authenticator and `Application` had no setter. Kept as it was written.

## The one that is supposed to fail

`idp03_contract_spec.cr` is expected to fail three tenancy examples. The adapter under test has
no tenant column because the application it belongs to has one tenant. That the shared contract
cannot be run without one is the finding.

## A note on the deterministic random double

`idp_family_spec.cr` gives each OIDC client its own `DeterministicRandom` seed. Without that,
two clients produce *identical* `state` and `nonce`, and a test asserting that concurrent flows
stay apart fails against the double rather than against the shard. Production uses
`SecureRandomSource` and does not have the problem.

## The protected-method probe

`http03_bearer_first.cr` calls `ctx.restore_remembered!`, which does not compile:

```
Error: protected method 'restore_remembered!' called for KemalIdentity::Kemal::RequestContext
```

That is the finding — a replacement handler cannot keep remember-me. Comment the line out to run
the app and probe its precedence.

**Do not check reachability with `crystal build --no-codegen` on a file that only defines a
class.** Crystal analyses the bodies of methods it reaches, and an unreferenced handler's `call`
is not reached, so a visibility error stays hidden. An earlier attempt at this concluded the
opposite for exactly that reason.

## The no-Kemal check

Building `dev03_raw_http.cr` is half of DEV-03; the other half is what the binary links:

```
nm -C /tmp/dev03 | grep -c 'KemalIdentity'          # must be large -- proves nm works here
nm -C /tmp/dev03 | grep -o 'Kemal::[A-Za-z]*' | grep -v KemalIdentity | wc -l   # must be 0
```

Both numbers matter. A zero on its own proves nothing, because a stripped binary answers zero to
everything. The recorded run was 189 and 0, against 748 for the Kemal app.

## The three minimal consumers

`ops07/` holds three separate projects rather than three spec files, because the property is
about dependency resolution and a spec cannot observe that:

```
for k in core sqlite pg; do
  (cd ops07/$k && shards install && ls lib/ && crystal build src/main.cr)
done
```

`core/lib` must contain neither `pg` nor `sqlite3`; the other two must contain exactly one of
them. Paths in each `shard.yml` point at this repository and need fixing if it moves.

## The cross-process rate limit check

Not a spec, because the property is about separate processes and a spec is one:

```
crystal build -o /tmp/ops01_setup  src/ops01_setup.cr
crystal build -o /tmp/ops01_worker src/ops01_worker.cr

/tmp/ops01_setup /tmp/ops01.db
for i in 1 2 3 4 5 6; do /tmp/ops01_worker /tmp/ops01.db 10 20 & done; wait
```

Sum what the workers print. It must equal the limit — 10 here, from 120 attempts. Before
`shared_limiter.cr` gained `journal_mode=WAL`, `busy_timeout` and `BEGIN IMMEDIATE`, the same
harness reported 22.

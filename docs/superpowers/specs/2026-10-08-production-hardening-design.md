# Production hardening — design

Date: 2026-10-08. Target release: **v0.13.0** (additive minor; not tagged or published here).

## Intent

Make the shard safe to run in a replicated production deployment without silently changing
behaviour for anyone already on v0.12.x. Every finding below was verified against the code on
`55bfedc` before being designed for; the brief that listed them was not treated as evidence.

Baseline before any change: `crystal spec` with `DATABASE_URL` set — **1939 examples, 0
failures, 0 errors, 0 pending** (PostgreSQL 18.6 in a container, Crystal 1.21.0).

## Verified findings

| # | Finding | Evidence |
|---|---|---|
| F1 | Login and MFA protections are off by default and nothing says so at boot | `Application#initialize` defaults `rate_limiter` to `NullRateLimiter`; `mfa_max_consecutive_failures` defaults to `nil` (NIST SP 800-63B SHALL unmet, per `MFA::Service` docs) |
| F2 | Every shipped limiter is per process | `FixedWindowRateLimiter`/`ExponentialBackoffRateLimiter` hold a `Hash` behind a `Mutex`; `blueprints/0025` OPS-01 measured 2.2× the global limit with six workers. The only shared limiter is a validation script under `tools/validation`, not shipped |
| F3 | The release gate never runs the PostgreSQL adapter | `release.yml` "Verify the tagged tree" runs `spec/unit spec/security spec/integration/sqlite_spec.cr`; `postgres_spec.cr` turns into one `pending` without `DATABASE_URL`. v0.11.0 shipped a PostgreSQL-only defect this way (roadmap). `publish` also does not confirm that the tag it publishes is the commit that was verified |
| F4 | README and roadmap disagree with the release | README pins `~> 0.9.0` (shard is 0.12.2); roadmap marks v0.12.0 "In progress"; the v0.3 "Known issue: drivers are hard dependencies" contradicts v0.7's "done" |
| F5 | Freshness cannot be declared on a permission | `Authz::Permission` has `minimum_assurance` only; roadmap v0.10 lists it open |
| F6 | No atomic way to revoke a set of API tokens | `ApiTokens::Repository` has `revoke(id)` and account-wide `revoke_all_for_account`; two `revoke` calls are two statements |

## Design

### D1 — Explicit production validation (F1)

`KemalIdentity.validate_production!(app = KemalIdentity.app, accept = [] of ProductionGap)`
plus `Application#production_gaps : Array(ProductionGap)`. Opt-in, like
`Kemal.validate_middleware_order!`: an application that never calls it sees no change, so no
existing consumer breaks. It raises one `ConfigurationError` naming **every** gap and its fix.

`ProductionGap` enum:

- `UnthrottledLogin` — `rate_limiter` is a `NullRateLimiter`.
- `FailOpenLogin` — `rate_limiter` is a `FailOpenRateLimiter` (the login path runs unmetered
  during a store outage).
- `ProcessLocalRateLimiter` — `rate_limiter` (or the limiter a `FailOpenRateLimiter` wraps) is
  one of the in-memory limiters. Acceptable for a single-process deployment, which says so by
  passing it in `accept`.
- `UnboundedMfaGuessing` — MFA is configured and `max_consecutive_failures` is nil.
- `UnthrottledMfaRecovery` — MFA is configured and its recovery limiter is a `NullRateLimiter`.
- `InsecureSessionCookie` — the session or remember-me cookie is not `Secure`.

Only shipped classes are recognised. An application's own limiter is trusted, because the
shard cannot see inside it. `accept` is how a deployment records a deliberate choice. The
alternative is not calling the check, and that hides every other gap along with it.

### D2 — Shared-storage fixed-window limiter (F2)

`KemalIdentity::Postgres::FixedWindowRateLimiter` and `KemalIdentity::SQLite::FixedWindowRateLimiter`
over a new `auth_rate_limits (key PK, attempts INTEGER, window_started_at TIMESTAMP)` table,
one migration per database.

`consume` is a single `INSERT … ON CONFLICT (key) DO UPDATE … RETURNING attempts,
window_started_at`. The row lock serialises concurrent writers across processes, and counting
and deciding happen in the same statement. An elapsed window is reopened in that statement
too. `attempts` is capped at `limit + 1` so that a flood cannot overflow it. Storage errors
return `Verdict.unavailable`, and `reset` swallows them, as `RateLimiter` requires. Time comes
from the injected `Clock` so the shared contract can drive it; the docs say that processes
need synchronised clocks, and that skew only moves window edges.

Unbounded key growth: both include a new core module `SweepableRateLimiter`
(`delete_expired(now) : Int32`). `Sweeper` sweeps `app.rate_limiter`, unwrapping a
`FailOpenRateLimiter`, when it includes the module. `SweepResult` gains `rate_limits`,
defaulted to 0.

The SQLite limiter is shared only between processes on one host and one file, and it is
documented that way. PostgreSQL is the recommended limiter for multi-host deployments.

### D3 — Release gate runs PostgreSQL and pins the tag (F3)

- `tools/release/verify.sh` holds the verification, so it can be run locally against a
  container. It checks the version agreement, builds the core and the examples, and runs the
  **full** suite with `KEMAL_IDENTITY_REQUIRE_DATABASE=1`.
- With that variable set, `postgres_spec.cr` and the multi-process spec **fail** rather than
  turn pending, so a gate without a database cannot pass vacuously.
- `release.yml` `verify` gets a `postgres:18` service and runs migrations and the script. It
  records `git rev-parse HEAD`, checks it equals `$TAG^{commit}`, and exports it as a job
  output.
- `publish` re-resolves the tag from the remote and refuses to publish if it no longer points
  at the verified commit. It then creates the release with `--verify-tag`.

### D4 — Consistency (F4)

README pins `~> 0.13.0`. The roadmap marks v0.12 released, removes the stale v0.3 "known
issue" (replaced by a pointer to v0.7), closes F2/F5/F6 in the table and gets a v0.13.0
section. `spec/unit/release_consistency_spec.cr` asserts that `shard.yml`, `VERSION`, the
README pin, a CHANGELOG section and a roadmap section all agree, so this cannot drift again
unnoticed.

### D5 — Permission freshness (F5)

`Permission.new(name, max_age: 5.minutes)` is an optional named argument, so existing calls
are unchanged. `RBAC#decide` checks freshness after strength and before scope, using
`Principal#fresh?(max_age, clock.now)`, the same rule `require_fresh!` uses. A stale
principal gets `Forbidden.stale_authentication(permission, tenant_id, max_age:)`, with reason
`InsufficientAssurance` and `step_up? == true`. No `DenialReason` member is added, because an
exhaustive `case` must keep compiling. `Forbidden#max_age` is new. `env.auth.authorize!`
puts it in the `StepUpRequirement`, so the 403 carries the RFC 9470 `max_age` exactly as
`require_fresh!` does. `RBAC#decide` still does not raise. Freshness is per decision and is
never cached: `Authz::Cache` holds grants, not decisions. A bearer token is never fresh, so
a `max_age` permission is unreachable from a token. This is documented.

### D6 — Atomic token-set revocation (F6)

`ApiTokens::Repository#revoke_family(ids : Array(String), account_id : String, at : Time) :
Array(String)` is **non-abstract**. Its default raises `NotImplementedError` with
instructions, so third-party adapters keep compiling, and calling the method on one fails
loudly instead of silently running two statements. The PostgreSQL, SQLite and in-memory
adapters implement it as one `UPDATE … WHERE account_id = ? AND id IN (…) AND revoked_at IS
NULL RETURNING id`. Every live, owned id flips at the same instant or none does. Ids that are
not owned are ignored, with the same no-oracle rule as the owner-scoped `revoke`.
`ApiTokens::Service#revoke_family(ids, account_id)` emits `api_token.revoked` per id, so the
audit trail and the event sink see the same events as single revocations. The shared contract
gains a separate `it_behaves_like_an_api_token_repository_with_family_revocation`, so existing
adapters that run the base contract are not failed by it.

## Deferred / out of scope

- Redis or other non-SQL limiter adapters: the contract allows them, and none is shipped.
- `ExponentialBackoffRateLimiter` over shared storage. It is only a kinder curve, and the
  lifetime bound already lives on the row.
- Auto-running `validate_production!` from `configure`. That would break deployments that
  currently boot, which is the thing the brief rules out.

## Testing

TDD per unit. Each new behaviour has a failing spec first.

- **Real PostgreSQL** (container): limiter contract (any-strategy and window suites), an
  outage returning `unavailable` against a closed pool, family revocation contract, and an
  atomicity probe: a concurrent single-statement reader must never see a half-revoked family.
- **Real multiple processes**: a compiled worker binary, six processes started together
  against one PostgreSQL database and one SQLite file. The summed allowances must equal the
  limit exactly. The in-memory limiter is run the same way as a control and must exceed it,
  which shows the probe can detect the failure.
- The release script runs locally end to end against the container.

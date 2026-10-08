# Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship v0.13.0 candidates for opt-in production validation, a shared-storage limiter, a PostgreSQL release gate, docs consistency, permission freshness, and atomic token-set revocation.

**Architecture:** Every change is additive. New core types live under `src/kemal_identity/`, and the SQL adapters live under `postgres/` and `sqlite/` next to the existing repositories. The release gate moves into a script that the workflow and a developer both run.

**Tech Stack:** Crystal 1.21 (floor 1.12), crystal-db, pg, sqlite3, Kemal, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-08-production-hardening-design.md`

## Global Constraints

- No signature on the v1.0 freeze list changes incompatibly; new arguments are named with defaults.
- No new abstract method on a published contract. A new repository method gets a raising default.
- `spec/unit` and `spec/security` stay database-free.
- Must compile on Crystal 1.12: no execution-context APIs, and no `Array(Class)` `===` tricks.
- Version 0.13.0 in `shard.yml` and `VERSION`, with a CHANGELOG section. No tag, push or publish.
- Match the surrounding comment style: say why, and reference the blueprint or scenario.

## Review Focus

1. A limiter whose database is down mid-request must return `unavailable`, not raise. Test: close the DB pool, then call `consume`.
2. Flooding one key with attempts must not overflow `attempts`. Test: the capped count stays at `limit + 1`.
3. `revoke_family` with an empty list, duplicate ids, or another account's ids must revoke nothing extra. Contract examples cover each.
4. A permission with `max_age` asked about by a bearer-token principal is refused, and asks for step-up. Unit test.
5. `validate_production!` with `FailOpenRateLimiter(FixedWindowRateLimiter)` reports both `FailOpenLogin` and `ProcessLocalRateLimiter`. Unit test.

---

### Task 1: `ProductionGap` and `validate_production!`

**Files:** Create `src/kemal_identity/production_check.cr`. Modify `src/kemal_identity.cr` (require), and `src/kemal_identity/application.cr` (keep `mfa_recovery_rate_limiter`, add `production_gaps`). Expose `MFA::Service#recovery_rate_limiter`. Test: `spec/unit/production_check_spec.cr`.

**Produces:** `enum KemalIdentity::ProductionGap { UnthrottledLogin, FailOpenLogin, ProcessLocalRateLimiter, UnboundedMfaGuessing, UnthrottledMfaRecovery, InsecureSessionCookie }`, `Application#production_gaps : Array(ProductionGap)`, `KemalIdentity.validate_production!(app : Application = KemalIdentity.app, accept : Enumerable(ProductionGap) = [] of ProductionGap) : Nil`.

- [ ] Failing specs: a default app reports `[UnthrottledLogin]`. A fixed-window limiter reports `ProcessLocalRateLimiter`. FailOpen(FixedWindow) reports both. MFA with a nil bound reports `UnboundedMfaGuessing`. An explicit `NullRateLimiter` recovery limiter reports `UnthrottledMfaRecovery`. An insecure cookie reports `InsecureSessionCookie`. `validate_production!` raises one message containing every gap name, returns nil when everything is accepted, and an app with a custom limiter passes.
- [ ] Implement, run `crystal spec spec/unit/production_check_spec.cr`, commit.

### Task 2: Shared fixed-window limiter (PostgreSQL + SQLite) and sweeping

**Files:** Create `src/kemal_identity/postgres/rate_limiter.cr`, `src/kemal_identity/sqlite/rate_limiter.cr`, and migrations `20261008090000_create_auth_rate_limits.sql` (both dialects). Modify `rate_limiter.cr` (add `module SweepableRateLimiter`), `sweeper.cr` (`SweepResult#rate_limits`), `postgres.cr`, `sqlite.cr`, and `production_check.cr` (the shared limiters are not process-local). Tests: `spec/integration/postgres_spec.cr`, `spec/integration/sqlite_spec.cr`, `spec/unit/sweeper_spec.cr`.

**Produces:** `Postgres::FixedWindowRateLimiter.new(db : DB::Database, limit : Int32, window : Time::Span, clock : Clock = SystemClock.new)`, the same for `SQLite::`, and `#delete_expired(now : Time) : Int32`.

- [ ] Failing specs: both adapters run `it_behaves_like_a_rate_limiter_of_any_strategy` and `it_behaves_like_a_rate_limiter`. A closed DB gives `unavailable?` and `reset` does not raise. 10,000 consumes keep the stored `attempts == limit + 1`. `delete_expired` removes only elapsed windows. The sweeper counts them.
- [ ] Implement. Run the PostgreSQL and SQLite specs with `DATABASE_URL`. Commit.

### Task 3: Multi-process proof

**Files:** Create `spec/support/rate_limit_worker.cr` and `spec/integration/multiprocess_rate_limit_spec.cr`.

- [ ] The worker takes `ARGV: adapter(postgres|sqlite|memory) url limit attempts key start_file`, waits for the start file, and prints its allowed count. The spec compiles it once, runs 6 workers × 20 attempts with limit 10, and asserts sum == 10 for postgres (only with `DATABASE_URL`) and sqlite, and sum > 10 for memory (the control).
- [ ] With `KEMAL_IDENTITY_REQUIRE_DATABASE=1` and no `DATABASE_URL`, both the PostgreSQL spec and this one fail instead of going pending. Commit.

### Task 4: Permission freshness

**Files:** Modify `authz/permission.cr` (`max_age : Time::Span? = nil`, which must be positive), `authz/decision.cr` (`Forbidden#max_age`, `.stale_authentication`), `authz/rbac.cr`, and `kemal/request_context.cr`. Test: `spec/unit/authz_rbac_spec.cr` (or the existing RBAC spec), plus an HTTP spec that the 403 carries `max_age`.

- [ ] Failing specs: a fresh password principal is permitted. A principal authenticated 6 minutes ago against a 5-minute `max_age` gets `InsufficientAssurance` with `step_up?`, `max_age == 5.minutes` and `minimum_assurance == nil`. Remembered and ApiToken principals are refused. Without `max_age`, behaviour is unchanged. `authorize!` raises `FreshAuthenticationRequiredError` with `requirement.max_age`.
- [ ] Implement, run, commit.

### Task 5: Atomic token-set revocation

**Files:** Modify `api_tokens/repository.cr` (non-abstract `revoke_family`), `api_tokens/service.cr`, `postgres/api_token_repository.cr`, `sqlite/api_token_repository.cr` and `testing/memory_api_token_repository.cr`. Add `it_behaves_like_an_api_token_repository_with_family_revocation` in the contract file. Tests: the contracts in the memory, SQLite and PostgreSQL specs, a PostgreSQL atomicity probe, and a service unit spec.

**Produces:** `Repository#revoke_family(ids : Array(String), account_id : String, at : Time) : Array(String)` and `Service#revoke_family(token_ids : Array(String), account_id : String) : Array(String)`.

- [ ] Failing contract examples: it revokes all owned live tokens with one `revoked_at`. It ignores other accounts' ids, already revoked ids, an empty list and duplicates. The default raises `NotImplementedError`. The PostgreSQL probe: during 200 rounds, a concurrent single-statement count of live family members is always 0 or 2.
- [ ] Implement, run, commit.

### Task 6: Release gate

**Files:** Create `tools/release/verify.sh`. Modify `.github/workflows/release.yml`, `docs/05-testing.md` and `spec/integration/postgres_spec.cr` (the require-database switch).

- [ ] The script, given `EXPECTED_VERSION`, checks the shard, `VERSION`, the CHANGELOG and the README pin. It builds the core and the examples, runs migrations, and runs the full suite with `KEMAL_IDENTITY_REQUIRE_DATABASE=1`. It must fail if the run reports a pending example.
- [ ] The workflow adds a postgres service, tag→SHA equality, a `verified_sha` output, and a publish-side recheck of the remote tag. Run the script locally against the container. Commit.

### Task 7: Docs, version, consistency spec

**Files:** `README.md`, `docs/06-roadmap.md`, `docs/02-security-model.md` (freshness/limiter notes), `CHANGELOG.md`, `shard.yml`, `src/kemal_identity/version.cr`, and the new `spec/unit/release_consistency_spec.cr`.

- [ ] Failing spec first (README pin vs VERSION), then the bump and the docs. Full suite, format, ameba. Commit.

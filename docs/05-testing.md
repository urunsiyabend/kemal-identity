# 05 — Testing

## Layers

| Layer | Directory | Needs a DB? | What it covers |
|---|---|---|---|
| Unit | `spec/unit` | no | hashing, digesting, cookie codec, expiry arithmetic, config validation |
| Contract | `spec/contract` | some | shared specs every adapter must pass |
| HTTP integration | `spec/integration` | yes | spec-kemal: login, logout, cookie flags, guards, error mapping |
| Security regression | `spec/security` | no | one spec per threat in `docs/02-security-model.md` |
| Concurrency | `spec/concurrency` | yes | atomic consumption, parallel session writes |
| Performance | `bench/` | yes | not run in CI; gates release manually |

`spec/unit` and `spec/security` must run with no `DATABASE_URL`. Keeping the security
regressions database-free means they run on every save, which is the point.

## Contract specs

Every abstract class gets one shared spec, and every implementation runs it — including the
in-memory doubles in `spec/support`. This is what keeps the in-memory adapter honest;
a test double that quietly behaves differently from PostgreSQL turns green specs into
false confidence.

```crystal
# spec/contract/session_repository_contract.cr
def it_behaves_like_a_session_repository(&build : -> SessionRepository)
  # create/find round trip
  # create refuses a duplicate token digest instead of overwriting
  # find_by_digest returns account status in the same result
  # find_by_digest returns nil when the session's account is gone (inner join, fails closed)
  # touch moves idle_expires_at and leaves absolute_expires_at alone
  # revoke stamps revoked_at -- the row still resolves, and SessionService is what turns it
  #   into Failed(Revoked); see the flow in docs/02-security-model.md. A repository that hid
  #   revoked rows could not serve a "list my devices" screen.
  # revoke_all_for_account with except_id spares exactly one, and does not re-stamp or count
  #   sessions that were already revoked
  # delete_expired removes only rows past absolute_expires_at
  # a digest that does not exist returns nil rather than raising
  # two simultaneous creates of the same digest: exactly one succeeds
end
```

Contracts to write: `SessionRepository`, `AccountRepository`, `Hasher`, `RateLimiter`,
`Clock`, `RandomSource`.

The `Hasher` contract is worth stating explicitly because it is the one people get subtly
wrong: `verify(p, hash_secret(p))` is true; `verify(other, hash_secret(p))` is false;
`needs_rehash?` is true for a digest at lower parameters than the current ones and false for
one at the current parameters; `dummy_digest` verifies false against every input and costs
the same as a real verification.

An over-length password is **never truncated**, and the two operations refuse it
differently. `hash_secret` **raises** — the caller has a bug, since `Policy` should have
rejected it. `verify` returns **false**: it is on the request path, fed by whatever a client
posted, and expected failures are values, so a 10 KB password field has to become a `Failed`
rather than a 500. The contract also asserts the property directly — a secret at the limit
and that secret with one byte appended must not verify against the same digest — and
`max_secret_bytesize` is in bytes, not characters, because 36 two-byte characters is 72
bytes. See `blueprints/0004-hasher-over-length-behaviour.md`.

The method is `hash_secret`, not `hash`: the latter collides with `Object#hash`.

## Determinism

Nothing in `src/` calls `Time.utc` or `Random::Secure` directly. Every time- and
randomness-dependent path takes an injected `Clock` and `RandomSource`.

```crystal
app = KemalIdentity::Application.new(
  clock:    TestClock.new(Time.utc(2026, 8, 24)),
  random:   DeterministicRandom.new(seed: 1),
  accounts: MemoryAccountRepository.new,
  sessions: MemorySessionRepository.new,
  notifier: RecordingNotifier.new,
  hasher:   FastTestHasher.new
)
```

`FastTestHasher` exists because a suite that runs real bcrypt at cost 12 in every login
spec will take minutes. It lives in `spec/support`, passes the `Hasher` contract, and is
unreachable from a production build. The real `BcryptHasher` is exercised in its own spec
and in the benchmark.

`TestClock` is what makes expiry testable at all — asserting that a session expires after
12 hours must not involve waiting or stubbing the system clock.

## Release blockers

Every one of these has a named spec. v0.1 does not ship until all pass.

**Session lifecycle**
- the session cookie is rejected after logout
- an expired session is rejected without waiting for the sweeper
- a revoked session is rejected
- the session id changes after login (fixation)
- an idle session expires; activity within `touch_interval` extends it; the accuracy
  tolerance is exactly one `touch_interval`
- absolute expiry fires regardless of activity
- disabling an account invalidates its live sessions on the next request
- changing a password revokes other sessions per the configured policy
- an `auth_version` bump invalidates sessions minted before it

**Credentials**
- unknown login and wrong password are indistinguishable in status, body and headers
- unknown login and wrong password are indistinguishable in timing, within tolerance
- a password longer than the algorithm's limit is rejected, not truncated
- a successful login at an outdated cost silently rehashes at the current one
- `verify` against a `dummy_digest` is false and costs a comparable amount of time

**Cookies**
- `Secure`, `HttpOnly`, `SameSite` and `Path` are set as configured
- a `__Host-` name combined with a `domain`, a non-root path, or `secure = false` fails at
  boot rather than at request time
- `secure = false` in production fails at boot
- the raw session token never appears in a database row

**CSRF**
- a cookie-authenticated `POST` without a token is rejected
- with a valid token it is accepted
- a token from another session is rejected
- **the login form itself is CSRF-protected**

**Kemal integration**
- guards run for `GET`, `HEAD`, `POST`, `DELETE` and `QUERY` on the same path — `HEAD` is
  the regression for the defects in `docs/04-kemal-integration.md`, and stays in the set
  now that Kemal 1.13.0 has fixed them, because the 1.10.0 floor has not; `QUERY` is new in
  1.13.0 and carries a body, so it is the case a method-allowlisting guard misses
- a `QUERY` request is not treated as a mutation by CSRF: it is safe and idempotent per
  RFC 10008, however much its request body looks like a form post
- `env.auth` is populated for anonymous requests without raising
- a malformed or garbage cookie yields anonymous plus a cleared cookie, not a 500
- an oversized cookie value is rejected before any database call
- `NotAuthenticatedError` maps to 401 and `FreshAuthenticationRequiredError` to 403

**Concurrency**
- two fibers consuming the same action token: exactly one succeeds
- two fibers consuming the same remember token: replay is detected and the family revoked
- concurrent logins for one account produce distinct sessions with distinct digests

**Rate limiting**
- the login path consumes before verifying the password, not after
- a failure penalises and a success resets
- a denial returns a `retry_after` and does not perform the bcrypt work
- an account-keyed denial applies across source addresses

**Logging**
- a login attempt produces an audit event containing no password, token or cookie
- an unhandled error from the auth path does not include secret material in its message

## Performance

Not in CI. Run before tagging, on hardware resembling the deployment target, and record the
numbers in the README:

- bcrypt cost calibration: the highest cost keeping p95 login latency under budget
- application-wide p95/p99 under 1, 10, 50 and 100 concurrent logins — the number that
  matters is what happens to *unrelated* requests, which is what a dedicated execution
  context for hashing is meant to protect
- authenticated request overhead: the added latency of cookie parse, digest and session
  lookup versus an anonymous request
- the write amplification `touch_interval` avoids, measured as writes per authenticated
  request at 60 s versus 0 s

## CI

Matrix: Crystal 1.21.0 × Kemal 1.13.0, plus a nightly against Kemal `master`. The nightly's
original purpose — noticing the `HEAD` and router-filter fixes on release — is served;
1.13.0 shipped them on 2026-08-24. It stays, to catch the next regression in this area.

Ameba runs from `master` (1.7.0-dev): no ameba release compiles against Crystal 1.21.

Every job runs: `crystal tool format --check`, `ameba`, `crystal spec`, and a build of
`examples/browser_session`. The example failing to compile is a CI failure — an example
that has drifted from the API is worse than no example.

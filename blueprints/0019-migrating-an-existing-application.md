# 0019 — Migrating an existing application, without a flag day

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.7

## Context

`docs/06-roadmap.md` has carried a "Migration path for existing Kemal apps" section since v0.1,
and until now nothing implemented it. Four steps, each reversible:

1. adapter over the existing `users` table — **already possible**, `AccountRepository` is
   abstract and always has been;
2. passwords, lazily — *"keep the old verifier for verification only"*;
3. sessions, through a `LegacySessionAuthenticator`;
4. authorization, separately — shipped in v0.6 as its own contract.

Steps 2 and 3 were the gap. `Hasher#needs_rehash?` was already documented to return true for a
digest it cannot parse, and `Passwords::Authenticator` already rehashes on that basis, so the
lazy-rehash machinery existed — with no way to *verify* the old digest in the first place, which
made the whole path unreachable.

The roadmap also names two anti-patterns, and both are the reason this milestone is small:
accepting long-lived legacy credentials indefinitely is not a migration, and forcing a global
password reset to change hashing algorithms is a support burden that lazy rehash makes
unnecessary.

## Decisions

### 1. `LegacyVerifier` can verify and cannot write

No `hash_secret`, and there never will be one. A legacy verifier exists so people can log in
with the password they already have; the digest is then immediately replaced by one from the
current `Hasher`. Giving it the ability to write would make it possible to keep creating rows in
the old format, and a migration that can still create them is not a migration.

`MigratingHasher#scheme` and `#hash_secret` are the current hasher's, always, so the count of
what is left to migrate can only go down.

### 2. This shard ships the contract and no implementations

There is no `Sha1Verifier`, no `Md5Verifier`, no `PhpPasswordVerifier`. Publishing one would be
this project publishing a working SHA-1 password check, and the first thing somebody does with a
class that exists is use it for something new. An implementation is five lines and belongs in
the application that has the legacy table.

The test double lives in the test-only tree, where it cannot reach a production build — the same
rule the RSA signing helper follows.

**Amended in v0.8.0:** both moved to `src/kemal_identity/testing/`, published as
`require "kemal_identity/testing"`. They still never reach a production build, but the reason is
now that nothing in `kemal_identity` requires that tree rather than that they are hidden under
`spec/` — see `blueprints/0025-maturity-validation-results.md` (DEV-02), which is why they were
published in the first place.

### 3. One verifier runs, routed by shape

`LegacyVerifier#handles?` looks at the digest and never at the secret. Trying every verifier in
turn would make a login cost the sum of every legacy scheme, and would make that cost depend on
which scheme the account uses — a slower version of the oracle in the next decision.

Getting `handles?` wrong in the permissive direction leaves `verify` to decide, so it fails
closed. Getting it wrong the other way leaves those accounts unable to log in, which is loud.

### 4. The migration-status timing oracle, which is not the enumeration one

`Hasher#dummy_digest` closes the oracle where unknown logins answer faster than real ones. This
introduces a different one.

Legacy schemes are fast — being fast is *why* they are being retired — and bcrypt is
deliberately slow. So a failed login against an un-migrated account returns in microseconds
while a failed login against a migrated one takes tens of milliseconds, and an attacker learns
**which accounts are still on the old scheme**: precisely the accounts whose digests are
cheapest to attack if the database ever leaks.

A failed legacy verification is therefore followed by a throwaway verification against the
current hasher's dummy digest. A successful one is not, because the caller rehashes immediately
and that rehash costs the same.

The spec counts the work rather than timing it. A spec that measured elapsed time would flake on
a loaded runner and would say no more than counting does.

### 5. A legacy password longer than the current hasher can represent is refused

Found by a spec, not by reasoning. Legacy schemes are usually unsalted digests with **no input
limit**, so an old table can hold accounts whose password is longer than bcrypt's 71 bytes.
Verifying one would succeed, and then the immediate rehash would raise — `hash_secret` refuses a
secret the algorithm cannot represent rather than truncating it, and `rehash_if_stale` rescues
`InfrastructureError` and not `ArgumentError`. Those accounts would have got a 500 on every
login.

So `MigratingHasher#verify` refuses them, which is what `Hasher#verify` is documented to do for
a secret the algorithm cannot represent. Those people have to go through a password reset. The
login is deliberately indistinguishable from a wrong password, and a `Log.warn` naming the
scheme and the byte count — never the secret — is how an operator finds out that such accounts
exist.

Truncating instead was never an option: if bcrypt cuts at 71 bytes, then 71 A's and 71 A's
followed by anything at all open the same account (`blueprints/0004`).

### 6. The block returns a subject, and nothing else

`LegacySessionHandler` takes a block that answers "who was this old cookie for". Not a
principal, not an assurance level, not a timestamp, and above all not a token. That is what
"secrets are never copied between the two systems" means concretely: whatever signed or keyed
the old session stays in the old system and dies with it.

Reading the old cookie is the application's job because only the application knows what wrote
it — kemal-session with a memory store, a signed cookie from something older, a row in a table
another framework owns. A shard that guessed would be guessing about the one thing it must not
get wrong.

### 7. An adopted session is `Remembered`

The old cookie proves somebody authenticated at some point, to a system this one cannot inspect.
It does not prove the account holder is present and it does not say when they last typed
anything. `AssuranceLevel::Remembered` is exactly that situation and already has the right
consequences: `Principal#fresh?` is false, so `require_fresh!` forces a real re-authentication
before anything sensitive and `require_assurance!` refuses it outright.

Claiming `Password` would let a cookie from the system being retired change an email address.

### 8. A separate handler, because it is meant to be deleted

Registered after `AuthenticationHandler`, so it runs only when the session cookie, a bearer
token and remember-me all found nothing. Deleting one `use` line is a smaller decision than
editing a configuration that also does five permanent things, and the day it is deleted is the
day the old sessions stop working — which is the point.

It runs on `Anonymous` only, never on a session cookie that was presented and rejected. Same
reasoning as remember-me (`blueprints/0012`): acting on a failed cookie races with logout, which
leaves a revoked cookie behind on purpose.

### 9. `pg` and `sqlite3` are development dependencies

Deferred since v0.3 and done here, because a **breaking packaging change belongs before the API
freeze, not after it**. Nothing under `src/kemal_identity.cr` requires either driver; only
`kemal_identity/postgres` and `kemal_identity/sqlite` do, and an application requiring one of
those already declares that driver for its own queries.

Listing them as dependencies made every consumer compile and link both — including one using
neither because it implements the repository contracts over its own storage, which
`docs/03-data-model.md` treats as the normal arrangement.

## Consequences

* **Breaking, deliberately:** an application requiring `kemal_identity/postgres` or
  `kemal_identity/sqlite` must now list that driver in its own `shard.yml`. Pre-1.0, called out
  in the changelog, and the alternative was carrying it past the freeze.
* Thirteen mutations of the two new pieces: eleven killed outright. Two survived and both were
  real spec weaknesses — the "a live session is not replaced" example named an account the
  legacy path would have refused anyway, so it proved nothing, and an explicit `assurance:`
  argument shadowed the principal's own, leaving one of the two dead. Both fixed; both mutants
  now killed. One further mutant is genuinely equivalent: dropping the empty-subject guard, since
  an empty id matches no account. It is kept because it saves a database round trip for a
  garbage cookie sent on every request.
* Counting what is left to migrate is a query against the application's own table
  (`WHERE password_scheme <> 'bcrypt'`) and **not** a method on `AccountRepository`. Adding an
  abstract method would break every existing implementor for a reporting convenience, weeks
  before the contracts freeze.
* Not done here: reading kemal-session's own cookie. See decision 6.

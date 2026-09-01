# Changelog

## v0.8.1 — 2026-09-01

Additive only. Every signature v0.8.0 published still means what it meant; each item here adds a
constructor argument, a module function or a contract option, and the defaults reproduce v0.8.0's
behaviour exactly.

All of it came out of running the validation catalogue rather than from a wish list —
`blueprints/0025-maturity-validation-results.md` names the scenario each item closes and records
the re-measurement.

### Credential precedence is a handler argument

A request can carry both a session cookie and an `Authorization: Bearer` header, and only one of
them can answer it. The order is now a choice:

```crystal
use KemalIdentity::Kemal::AuthenticationHandler.new(
  precedence: KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer
)
```

`Precedence::Cookie` is the default and is v0.8.0's behaviour unchanged. It has a sharp edge,
confirmed over HTTP rather than inferred: a session cookie that has idle-expired, been revoked or
been tampered with **masks a valid bearer token**, because a cookie that was presented and failed
ends the resolution rather than falling through. A same-origin SPA sending a stale cookie beside a
good token gets 401s.

`Precedence::Bearer` resolves the bearer credential first, and deliberately does **not** fall back
to the cookie when it fails — a request that presented a token is asking to be authenticated by
it, and falling through would let a stale session paper over a revoked one.

Remember-me keeps working under both, which is why this is an argument rather than an invitation
to replace the handler: a remembered login is restored only on a request carrying no session cookie
at all, and getting that ordering wrong widens the window in which parallel requests both present
the remember token and one reads as theft.

Documented in `docs/04-kemal-integration.md`.

### `JWT.unverified_issuer`, so several issuers can be routed

An application validating tokens from more than one issuer needs to know which validator to reach
for before any validator has run. Reading `iss` out of an unverified token is the only way to do
that, and everyone who needs it was writing their own base64 split:

```crystal
issuer = KemalIdentity::JWT.unverified_issuer(credential)
validator = VALIDATORS[issuer]?
```

Bounded before it decodes anything, and it reuses the validator's own strict base64url rather than
a second decoder that almost agrees — that is how one token comes to mean two different things.
The name says `unverified` because the value is routing input and nothing else; the chosen
validator still verifies everything.

### Providers can carry their own authorization parameters

```crystal
KemalIdentity::OIDC::Provider.new(
  # ...
  authorization_params: {"audience" => "https://api.example.com"}
)
```

Auth0 wants `audience`, Google wants `access_type` and `hd`, Microsoft wants `domain_hint`. The
nine parameters the flow builds itself — `response_type`, `client_id`, `redirect_uri`, `scope`,
`state`, `nonce`, `code_challenge`, `code_challenge_method`, `prompt` — are refused at
construction, not silently ignored: the dangerous version of this feature is the one that lets a
configuration file turn PKCE off.

### The account contract can be told an adapter is single-tenant

```crystal
it_behaves_like_an_account_repository(tenanted: false) { MyRepository.new(db) }
```

Replaces the tenancy examples with one that demands a tenant-scoped lookup answer `nil`, rather
than skipping them. An adapter that *ignores* `tenant_id` is the unsafe way to be single-tenant,
and it passed everything else.

### CI resolves three consumers and checks what each gets

`kemal_identity` has kept its database drivers out of `dependencies` since v0.7.0 so that an
application depending on it does not compile PostgreSQL bindings it never uses. Nothing kept that
true. Three throwaway projects now resolve the shard in CI, and the step was verified to fail when
`pg` is moved back.

### Documentation

- `docs/02-security-model.md` gains *Authorization rules an application writes itself*: what
  `Authz::Cache` costs on a list endpoint, measured — one store read per page with it, a hundred
  without, and its TTL is the revocation delay either way — next to the downcast in an ownership
  rule that fails **open** when written the obvious way.
- `docs/04-kemal-integration.md` documents credential precedence, both tables and the reasoning.

## v0.8.0 — 2026-08-29

**The last breaking release before the v1.0 API freeze.**

A scan of every contract v1.0 would freeze asked one question of each: if this froze exactly as it
is, would the scenarios in `blueprints/maturity-validation-scenarios.md` still be reachable? Most
gaps that scan found are closed by *adding* something, and adding is not breaking — so they can
wait. A minority needed a signature to move, and those are what this release is.
`blueprints/0020-api-freeze-blockers.md` records the scan and what it got wrong.

Then the catalogue itself was run, from a separate consumer project rather than from inside this
repository, because several of its scenarios are about what an application can reach from outside.
Twenty-three of fifty are recorded in `blueprints/0025-maturity-validation-results.md`. That pass
found six documentation defects — including an ownership example that failed open — and four gaps
worth closing before a release rather than after: the missing bearer challenge, the unreachable
contract specs, the untyped event sink, and a rate limiter that could not say its store was gone.

**If you are upgrading**, the four breaking changes are first below. Each says what to change.

### ⚠ Breaking: `Principal` names the credential that proved the request

`Principal.new`'s `session_id:` argument is replaced by `credential : CredentialRef?`.
`#session_id` remains as a reader, derived from it, so `logout!`, `mfa_verified!`, CSRF
anchoring and `redeem_recovery_code(except_session_id:)` are unaffected. Code that *constructed*
a `Principal` with `session_id:` — a custom `RequestAuthenticator`, a test double — passes a
`CredentialRef` instead.

Two personal access tokens issued to one account used to produce indistinguishable principals.
`ApiTokens::Service` had the token id in hand when it authenticated and dropped it, so an
application could not tell which token was asking, and a token created for reading reports could
perform a write its owner happened to be permitted. Closing that from outside the shard meant
either a second digest-and-query on every authenticated request or a copy of the whole
validation path.

```crystal
credential = env.auth.credential
credential.try(&.kind)   # Session | ApiToken | Jwt | Custom
credential.try(&.id)     # the session id, the token id, or the JWT's jti
```

`CredentialRef` carries `kind`, `id`, `name`, `expires_at` and `scopes`, and never the token,
the digest or a signature — so it is safe in a log line, and `authz.denied` now records which
credential was refused rather than only whose account.

`scopes` is `nil` everywhere for now, and `nil` means **unrestricted**, not *permits nothing*: a
session has no scopes either, and reading their absence as an empty set would deny every
signed-in browser. Per-token scopes and their intersection with account permissions are the
second half of `blueprints/0021-credential-reference.md` and land in this same release.

No new query anywhere. Every value comes from a row that was already read to authenticate the
request.

### ⚠ Breaking: `Authorizer#decide` takes a context, and a denial is built by name

`Authorizer#decide`'s abstract form is now
`decide(principal, permission, context : Authz::Context)`. The tenant-only form remains as a
concrete overload, so every existing **call site** is unchanged; an existing **implementation**
overrides the new signature and reads `context.tenant_id`.

`Authz::Context` carries the tenant, the object being acted on and environment attributes. It
does **not** carry the credential: `Principal#credential` is the single source, and a copy on
the context made the tenant-only overload skip scope attenuation while it existed. A context
object rather than more parameters because this method freezes at v1.0:
the last time it needed something new — a resource — there was nowhere to put it, so a route
with per-object rules had to bypass `env.auth` and re-implement the audit line, the step-up
mapping and the uniform 403 for itself.

```crystal
env.auth.authorize!(
  "invoices.edit",
  resource: KemalIdentity::Authz::Resource.new("invoice", invoice.id, {"owner_id" => invoice.owner_id}),
)
```

A resource is anything answering `authz_type` and `authz_id` — include `Authz::Authorizable` in
your own model, or use the shipped `Authz::Resource`. The module is frozen at those two methods:
a third would stop every implementor compiling, and a concrete addition would silently shadow a
name in every including class. Growth happens on `Authz::Context`, which injects nothing into
anybody's types.

**`Forbidden` is now built by named constructor**, not `new`:

```crystal
Forbidden.not_permitted(permission, tenant_id)
Forbidden.insufficient_assurance(permission, tenant_id)   # step_up: true
Forbidden.out_of_scope(permission, tenant_id)
Forbidden.policy(permission, code: "change_window_closed", step_up: false)
```

`DenialReason` gains `OutOfScope` and `Custom`, and `Forbidden` gains `code` — an application
authorizer's own reason, for the audit trail only. It never reaches the client; every denial
still renders one identical 403, because a denial that explains itself confirms which tenants
exist and who is in them.

`Forbidden#step_up?` now decides the control flow: `authorize!` raises
`FreshAuthenticationRequiredError` on it rather than on `reason.insufficient_assurance?`. Two
axes, one authority. The flag is not a parameter of the general constructor — `initialize` is
private — so `RBAC` cannot build an assurance denial and forget it and leave step-up silently
broken. The one place it is chosen is `.policy`, where this shard cannot know the answer.

### ⚠ Breaking: the shared half of federation moved out of the `OIDC` namespace

```
KemalIdentity::Federation::Identity        (was OIDC::Identity)
KemalIdentity::Federation::Link            (was OIDC::Link)
KemalIdentity::Federation::LinkRepository  (was OIDC::LinkRepository)
```

`OIDC::Provider`, `OIDC::Client`, `OIDC::Pending` and `OIDC::PendingCodec` are unchanged;
`Client#complete` now returns `Federation::Identity | Failed`. If you implement
`LinkRepository` or name `Identity` in a signature, change the namespace — nothing else about
those types moved.

The roadmap listed a type called `IdentityProvider` among the ones v1.0 freezes, and no such
type existed. Rather than invent it, v0.8 answers the question it was standing in for: **a
second federation protocol added after 1.0 must not require a breaking change.** Everything a
`SAML::Client` would touch was checked, and only these three names would have forced one —
protocol-neutral concepts sitting inside a protocol's namespace, one of which consumers
implement. `blueprints/0024-federation-namespace.md`.

`LinkRepository` is shared for a specific reason: `for_account` answers "which providers is this
account linked to", and the guard against unlinking somebody's last way in reads it. Against a
second table it answers from half the rows.

### ⚠ Refusals now carry the RFC 6750 challenge

`WWW-Authenticate` was absent from every response. It is a MUST in RFC 6750 §3 for a request that
carried no credentials or a token that did not grant access, and
`blueprints/0025-maturity-validation-results.md` measured its absence against a running server.

| Request | Status | Challenge |
|---|---|---|
| no credential presented | 401 | `Bearer realm="api"` |
| a bearer token that did not hold | 401 | `error="invalid_token"` |
| a token narrower than the action | 403 | `error="insufficient_scope"` |
| any other denial | 403 | no error code |

Only an out-of-scope credential is described, because RFC 6750 registers no code for "the account
does not hold this permission" — and that is the distinction worth keeping hidden. `scope=` is
never sent. Nothing is announced when the application configured no bearer credential.

`ForbiddenError` gains `challenge_error : String?`, set by `authorize!`, and it carries a
projection rather than the `DenialReason` — `"insufficient_scope"` or `nil`. The handler cannot
render a reason it was never given.

Set the realm with `ErrorHandler.new(realm: "your-api")`.

**⚠ Breaking: a request that presented a bearer credential is never redirected.** Before this, a
client sending `Authorization: Bearer` with no `Accept` header received `302 Location: /login`,
because the redirect was decided purely by content negotiation. It now receives 401 with the
challenge. If you have a client relying on that redirect, it will see a 401.

Statuses are otherwise unchanged; RFC 6750 asks for 403 on `insufficient_scope`, which is what
this already did. Whether `FreshAuthenticationRequiredError` should become 401 to match RFC 9470's
examples is deferred — that document requires no status code, so it is a compatibility decision
rather than a compliance one. `blueprints/0026-bearer-challenges.md`.

### Per-token scopes, intersected with account permissions

`ApiTokens::Service#issue` takes `scopes:`, `auth_api_tokens` gains a nullable `scopes` column,
and `RBAC` refuses a permission the presenting credential does not carry:

```crystal
KemalIdentity.app.api!.issue(account, "reporting", scopes: ["reports.read"])
```

Additive — no frozen contract moved, and `ApiTokens` is not on the freeze list. `Token#scopes`
and `Service#issue(scopes:)` are defaulted, so existing calls are unchanged, and a token issued
without scopes reads back `nil`, which means *unrestricted*.

The account's grant is checked first and the scope only ever narrows: naming a permission its
owner was never given grants nothing. There is no wildcard — `["*"]` is a scope named `*` and
matches nothing, for the same reason `Permission` refuses `*`. An out-of-scope denial does not
ask for step-up, because re-authenticating does not widen a token that was issued narrow.

This reverses the v0.4 position that "scopes are deliberately absent: a token authenticates, it
does not authorize". That was right while there was no authorizer for a scope to intersect
with; v0.6 shipped one.

⚠ **A permission left at the default assurance is unreachable by any token.**
`Permission#minimum_assurance` defaults to `Password` and `AssuranceLevel::ApiToken` is below
it, so declare the permissions automation may perform at `ApiToken` assurance. The assurance
answers "may a machine do this at all"; the scope answers "may this token".

⚠ **If you implement `ApiTokens::Repository`, persist the new column.** The field is defaulted,
so an adapter written before v0.8 keeps compiling and silently drops it — and a dropped scope
reads back as `nil`, which means unrestricted. The shared contract suite has three examples that
fail on exactly this.

### A rate limiter can say that its store is gone

`Verdict` gains a third state. A limiter over shared storage used to have three ways to lie
when Redis was unreachable — allow and run unmetered, deny and take the endpoint down, or raise
into a 500 — and all three made a decision that belongs to the application:

```crystal
def consume(key : String) : KemalIdentity::Verdict
  # ...
rescue Redis::Error
  KemalIdentity::Verdict.unavailable
end
```

Additive: `consume` and `reset` keep their signatures, and neither shipped limiter can produce
the new state — `NullRateLimiter` has no store and `FixedWindowRateLimiter`'s store is the
process. No existing deployment changes behaviour.

**The default is fail-closed.** All five of this shard's call sites — login, password reset, and
three ways of proving a second factor — refuse rather than run unmetered, and log
`rate_limiter.unavailable` at error level. An application that prefers availability on a given
path wraps that limiter in `FailOpenRateLimiter`; per endpoint, since each service takes its
own.

`Verdict.unavailable` reads as `allowed? == false`, so code that has not learned about the third
state fails closed rather than open. `FailureReason::RateLimiterUnavailable` is kept apart from
`RateLimited` because one is the limiter working and the other is an incident — the same
argument that keeps `InvalidClaim` apart from `InvalidCredential`. Neither is visible in a
response.

`blueprints/0023-rate-limiter-store-failure.md`.

### A typed security event sink

```crystal
class SiemSink < KemalIdentity::SecurityEventSink
  def record(event : KemalIdentity::SecurityEvent) : Nil
    @queue.push({name: event.name, actor: event.subject, at: event.at})
  end
end

bridge = KemalIdentity.event_sink = SiemSink.new
```

`SecurityEvent` types the fields a SIEM correlates on — `subject`, `credential`, `tenant`, `ip`,
`reason`, plus `name`, `severity` and `at` — and leaves event-specific detail in `data`. A rename
of a correlation field is now a compile error for a consumer rather than a silent breakage.

Fed by an `EventBridge` over the events the shard already emits, so nothing was added beside
sixty-four call sites and the `Log` output is untouched.

**A failing sink is counted, never fatal and never silent.** An exception from `record` cannot
reach the caller — measured before this: a raising `Log::Backend` under `:direct` dispatch turned
every login into a 500, and under `:async` it killed the dispatcher fiber and the trail went quiet
with nothing said. `bridge.failures` is the number to alarm on. `Log` remains the fallback, so a
broken sink loses the SIEM copy and not the audit trail.

⚠ **Breaking for a log pipeline keyed on field names.** Writing the bridge showed the emissions
were inconsistent: `authz.*` events used `account:` where everything else used `subject:`, and
`session.revoked`/`session.ended` used `session:` where `authz.denied` already used `credential:`.
Both are normalised — `subject` and `credential` — in the `Log` output as well as in the sink.

`blueprints/0027-security-event-sink.md`.

### The test doubles and shared contracts are published API

```crystal
require "kemal_identity/testing"            # in-memory doubles, fixtures, assertions
require "kemal_identity/testing/contracts"  # the shared contract specs

it_behaves_like_a_session_repository { |accounts| MyRedisSessionRepository.new(redis, accounts) }
```

If you implement any contract in this shard, you can now check it against the same examples the
shipped adapters run, and build fixtures from the same doubles. Before this they lived under
`spec/` and were reachable only by requiring this repository's own `spec_helper` — a private
path, undocumented, and pulling in every double whether wanted or not.

**Requiring `kemal_identity` compiles none of it.** Verified against a built binary: a production
consumer has zero `Spec::` and zero `KemalIdentity::Testing` symbols, and
`spec/unit/source_hygiene_spec.cr` now asserts that no production entry point requires the tree.

⚠ **Breaking for anyone who was reaching into `spec/`:** `KemalIdentity::SpecHelper` is now
`KemalIdentity::Testing`, alongside the doubles that were already there. `spec/support/*` and
`spec/contract/*` moved to `src/kemal_identity/testing/` and
`src/kemal_identity/testing/contracts/`.

Two limits are documented rather than left to be discovered: the contracts exercise concurrency
with fibers in one process, so a store shared between processes needs its own test; and
`it_behaves_like_an_account_repository` requires multi-tenant behaviour, so a single-tenant
adapter cannot pass three of its examples.

### `Identity#email_verified` is now `Bool?`

`nil` means the issuer asserted nothing, `false` means it said the address is not verified,
`true` means it says it verified it. Previously both of the first two arrived as `false`, so a
policy of "only accept issuers that verify addresses" could not be written.

`#email_verified?` still answers a `Bool` and still treats `nil` as unverified, so the security
behaviour is unchanged. It is written out rather than generated, because `getter?` over a `Bool?`
returns `Bool?` — falsy in a conditional, but not a boolean, and a security predicate should not
have a third answer.

## v0.7.0 — 2026-08-29

Adoption. The migration path `docs/06-roadmap.md` has described since v0.1, made real, plus one
packaging change that had to happen before the v1.0 freeze rather than after it.

### ⚠ Breaking: the database drivers are yours to declare

`pg` and `sqlite3` moved from `dependencies` to `development_dependencies`. An application that
requires `kemal_identity/postgres` or `kemal_identity/sqlite` must now list that driver in its
own `shard.yml` — which it already had to, for its own queries.

Nothing in `kemal_identity` itself requires either driver. Listing them made every consumer
compile and link both, including one using neither because it implements the repository
contracts over its own storage, which `docs/03-data-model.md` treats as the normal arrangement.
Deferred since v0.3; done now because a breaking packaging change belongs before an API freeze.

### Passwords, lazily

- `Passwords::LegacyVerifier` — verify-only by construction. No `hash_secret`, so a migration
  cannot keep creating rows in the old format and the count of old digests can only go down.
- `Passwords::MigratingHasher` — the current hasher plus one or more legacy verifiers. A correct
  password against a legacy digest logs in and is rehashed immediately; nobody is forced through
  a reset. It is a `Hasher` wherever a hasher goes and runs the same contract spec.
- Digests are routed to exactly **one** verifier by shape (`handles?`, which never sees the
  secret). Trying every verifier in turn would make a login cost the sum of every legacy scheme.
- **This shard ships no legacy verifier implementations**, deliberately: a published
  `Sha1Verifier` is a published working SHA-1 password check. Yours is five lines.
- A failed legacy verification pays for a throwaway verification against the current hasher's
  dummy digest. Legacy schemes are fast and bcrypt is slow, so without it the response time says
  which accounts are still on the cheap scheme — precisely the ones worth attacking if the
  database leaks. Distinct from the enumeration oracle `dummy_digest` already closes.
- A legacy password longer than the current hasher can represent is **refused** rather than
  verified-then-500ing on the rehash, with a `Log.warn` naming the scheme and the byte count so
  an operator learns those accounts exist. Truncating was never an option.

### Sessions, adopted once

- `Kemal::LegacySessionHandler` takes a block that returns **a subject and nothing else** — not a
  principal, not a timestamp, and above all not a token. Whatever signed the old session stays in
  the old system and dies with it.
- The adopted session is `AssuranceLevel::Remembered`, so `require_fresh!` still forces a real
  login before anything sensitive. An old cookie proves somebody authenticated at some point, to
  a system this one cannot inspect.
- It runs only when the session cookie, a bearer token and remember-me have all found nothing, so
  a live session is never replaced — and only on `Anonymous`, never on a rejected cookie, for the
  reason `blueprints/0012-remember-me.md` gives.
- Registered as its own handler because it is meant to be deleted. The day the `use` line goes is
  the day the old sessions stop working.
- `RequestContext#adopt_legacy_session!` returns nil rather than raising for an unknown or
  disabled account.

Thirteen mutations of the two new pieces: eleven killed outright, and the two survivors were both
real spec weaknesses — an example that named an account the legacy path would have refused
anyway, and an explicit argument shadowing the value it duplicated. Both fixed, both now killed.

## v0.6.0 — 2026-08-29

Authorization and tenancy — `docs/06-roadmap.md`'s v0.6, and the last milestone before the v1.0
API freeze. Additive and **off by default**: an application that passes no `authorizer:` is
unchanged, and `Principal` still carries no roles.

### Authorization

- `Authz::Authorizer`, a contract, plus `Authz::RBAC` as the implementation this shard ships
  and `Authz::DenyAll` for anything half-configured — the only safe thing an unconfigured
  authorizer can do is permit nothing.
- **Roles are code; only assignments are data.** `Authz::RoleCatalog` is built at boot from
  literals in the application, and there is no `auth_roles` table. A role definition in a table
  is one UPDATE away from rewriting what everybody holding it can do, with nothing about the
  application having changed. The cost — roles cannot be administered at runtime — is stated in
  `blueprints/0018-authorization-and-tenancy.md` rather than hidden.
- A role granting a permission nobody declared raises at **boot**, so a rename that misses one
  definition fails on the machine of whoever made the change rather than denying an action in
  production for a month. A mistyped permission at a call site denies with
  `DenialReason::UnknownPermission`.
- **No wildcards.** `Permission::PATTERN` refuses `*` at construction: a wildcard is a grant of
  permissions that do not exist yet, and whoever holds `admin.*` silently acquires the next one
  somebody adds.
- `Permission#minimum_assurance` — assurance is a property of the action, declared once, not a
  rule repeated at every call site where somebody might forget it. A denial for weak assurance
  raises `FreshAuthenticationRequiredError` so the application can prompt for a second factor
  instead of showing a dead end.
- `env.auth.authorize!`, `#authorize` and `#can?`. New `ForbiddenError`, mapped to 403 by
  `ErrorHandler` with one body for every denial reason — `DenialReason` is for the audit log,
  and a response that varied with it would confirm that a guessed tenant exists.

### Tenancy

- New tables `auth_tenant_memberships` and `auth_role_assignments`, PostgreSQL and SQLite, both
  running the same 30-example contract.
- A role held inside a tenant is **inert without a membership**, so removing somebody from a
  tenant is a single call that revokes everything at once — `remove_member` deletes that
  tenant's assignments too, and re-inviting them does not restore the roles they used to hold.
- A principal bound to one tenant asking about another is refused before membership is read.
  That is the identifier-in-the-URL attack, and it must not depend on a database row being
  correct.
- A grant with no tenant is global: it applies everywhere, including inside every tenant, and is
  not gated by membership. `Assignment#granted_by` exists because that is the dangerous kind.
- The unique index on the global scope is **partial** (`WHERE tenant_id IS NULL`), because a
  plain unique index does not collide on NULL. Dropping it makes both the contract example and
  a sixteen-fiber concurrency example fail, which is how it was verified.

### Nothing is carried in a session

- A revocation bites on the very next request, with the same session, asserted over HTTP. That
  is the reason `Principal` carries no roles.
- `Authz::Cache` is off by default, five seconds when on, and refuses a TTL over one minute:
  the TTL *is* the revocation delay. It is bounded and clears itself at the limit rather than
  evicting one entry at a time — the key space is attacker-influenced, and the failure mode of
  a stampede should be "the cache stops helping", not "the process runs out of memory".
- `RBAC#grant`, `#revoke` and `#remove_member` invalidate it, which helps the process that made
  the change and no other. Documented as such rather than papered over with a pub/sub channel
  that would be one more thing to be silently broken.

Twenty mutations of the module, the adapters and the double: twenty killed, none surviving.

## v0.5.0 — 2026-08-28

Federated identity and MFA, the two halves of `docs/06-roadmap.md`'s v0.5. Additive; nothing
was removed or changed in behaviour.

### Second factors

- `MFA::TOTP` (RFC 6238), checked against the RFC's own SHA-1, SHA-256 and SHA-512 vectors,
  plus an RFC 4648 base32 codec because Crystal ships only base64.
- `MFA::Service`: two-step enrolment, a rate limit consumed **before** the code is checked,
  single-use counters, drift bounded at two steps, and ten recovery codes issued at the moment
  a first factor turns MFA on. What makes TOTP safe is these, not the arithmetic.
- `MFA::SecretBox` — AES-256-CBC with encrypt-then-MAC, verified before decrypting. The one
  secret in this shard that is encrypted rather than hashed, because the server has to read it
  back to compute a code. GCM would be the obvious choice and Crystal's `OpenSSL::Cipher` does
  not expose the authentication tag.
- `AssuranceLevel::MFA` and `env.auth.mfa_verified!`, which **rotates the session**: an id an
  attacker learned while it was worth `Password` must not silently become one worth `MFA`.
- Redeeming a recovery code signs the account's other sessions out, as
  `docs/02-security-model.md` requires.
- New tables `auth_mfa_factors` and `auth_mfa_recovery_codes`, PostgreSQL and SQLite, both
  running the same 34-example contract — including the two single-use operations run
  concurrently.

### Signing in with a provider

- `OIDC::Client`: Authorization Code with PKCE and nothing else. `state` compared in constant
  time before anything is exchanged, `nonce` compared inside the ID token, `S256` only, exact
  redirect matching, `iss`/`aud`/`azp`, a 15-minute flow TTL, and timeouts on every call out.
- `return_to` is restricted to a same-site path and validated **on the way in**, before it has
  round-tripped through the provider — including the `//evil.example.com` and `/\evil` forms a
  browser reads as absolute.
- `OIDC::LinkRepository` over `auth_external_identities`, keyed on `(issuer, subject)` with
  **no email column at all**. Addresses change and are claimed rather than proved; looking an
  account up by one is account takeover with extra steps.
- The provider's access and refresh tokens are discarded rather than stored. Keeping one your
  application never uses turns a breach here into a breach of every user's account there.
- `OIDC::PendingCodec` signs the flow state for a cookie, so applications do not hand-roll
  carrying the PKCE verifier through a redirect.

### JWT

- **RS256, RS384 and RS512.** `jwt/rsa.cr` reopens `lib LibCrypto` for the five functions
  Crystal's standard library omits, and builds the public key as a DER `SubjectPublicKeyInfo`
  for `d2i_PUBKEY` — the one route stable across OpenSSL 1.1.1 and 3.x. Verification only;
  signing is bound in `spec/support/` so it cannot become API by accident.
- A `JWT::Key` now holds a shared secret **or** a public key, and refuses to pair either with
  the wrong algorithm — the confusion attack written into configuration rather than a token.
- `JWT::JWKS`, a cached key source with a TTL *and* a floor between refetches provoked by an
  unknown `kid`. A failed refetch keeps serving the last good key set; a failed first fetch
  raises.
- `JWT::Validator` accepts a `KeySource` as well as a fixed `Keyring`, and gained `#validate`,
  which keeps the claim set an OIDC callback needs.

### Everything else

- `blueprints/0016-second-factors.md` and `blueprints/0017-federated-identity.md` record the
  decisions, including which defences are deliberately unobservable and why.

## v0.4.0 — 2026-08-26

API authentication: bearer tokens as a `RequestAuthenticator`, in the order
`docs/06-roadmap.md` set out — opaque personal access tokens first, JWT second and off by
default. Additive; nothing was removed or changed in behaviour.

### Personal access tokens

- `ApiTokens::Service`, with digest-only storage, revocation that takes effect on the very next
  request, an optional expiry (`nil` really does mean never, and the sweeper never touches
  one), and a `last_used_at` throttled to one write per five minutes.
- A fixed, searchable `ki_` prefix, configurable per application, so a secret scanner can
  recognise a leaked credential in a commit or a paste and say whose it is.
- `ApiTokens::Repository` with PostgreSQL and SQLite adapters and an in-memory double, all
  running the same 28-example contract. New table `auth_api_tokens` in both dialects.

### JWT validation

- `JWT::Validator`, off unless an application passes one. HS256/HS384/HS512, an algorithm
  allow-list, `kid` rotation, and required `iss`, `aud`, `exp` and `purpose`.
- `alg: none` is unrepresentable: no `Algorithm` can express it, the allow-list refuses the
  string at boot, and the header's `alg` is compared against the *key's* algorithm — which is
  also what defeats algorithm confusion, since the key names the algorithm and the token
  selects nothing.
- An unknown `kid` is rejected rather than retried against the ring, so a compromised key can
  actually be withdrawn. A token naming no `kid` resolves only when the ring holds one key.
- Clock skew is bounded at five minutes, and `max_lifetime` (one hour by default) rejects a
  token claiming to be valid for longer.
- **The revocation trade-off is documented rather than hidden.** A stateless JWT cannot be
  revoked before its `exp`; the two honest answers are a very short lifetime or a `jti`
  denylist that costs the statelessness. `JWT::RevocationStore` says so in full, and the
  optional `accounts:` argument is the same admission about disabled accounts.

### Everything else

- `AssuranceLevel::ApiToken = 15`, between `Remembered` and `Password`. Never fresh, so
  `require_fresh!` refuses a token-bearing request outright — an automated client cannot
  re-authenticate interactively. No persisted enum value was renumbered.
- `AuthenticatorChain` resolves one `Authorization: Bearer` header against several
  authenticators, routing on shape and stopping at any credential that was recognised and then
  failed on its merits.
- Neither bearer credential compares `auth_version`: a password change must not silently break
  a deploy key whose holder is a machine with no way to notice.
- The CSRF bearer exemption keys on the session cookie **as presented**, so a request carrying
  an expired or garbage cookie cannot expire its way out of CSRF protection.
- New `FailureReason::InvalidClaim`, for a token that verified cryptographically and then
  failed on a claim — a signal worth alerting on, and kept out of the response like every other
  reason.
- `Sweeper` now also drops expired API tokens and spent `jti` entries.
- `blueprints/0015-bearer-credentials.md` records the decisions, including why there are no
  scopes and which JWT defences are deliberately redundant.

## v0.3.0 — 2026-08-26

Compatibility release. No behaviour changes, no API removals.

- **The Crystal floor drops from 1.21.0 to 1.12.0.** `HashingExecutor` is now compiled
  conditionally: where `Fiber::ExecutionContext` is unavailable it refuses to be built rather
  than silently hashing on the request fiber, unless the application passes
  `allow_inline: true`. Crystal 1.21 is still recommended — the executor is the one thing worth
  upgrading for, holding unrelated-request p99 latency at 1.17 ms against 2,176 ms without it
  at 50 concurrent logins. See `blueprints/0013-execution-contexts-are-optional.md`.
- CI now runs Crystal 1.21.0, 1.14.0 and 1.12.0, plus the Kemal floor, so both floors are
  tested claims rather than comments. The example and the benchmarks are built on **every**
  matrix entry: the specs alone pass down to Crystal 1.4, but they never compile `Kemal.run`,
  which needs `Process.on_terminate` from 1.12 — a green suite is not a floor.
- Specs and benchmarks no longer use `WaitGroup` (Crystal 1.13+) or Kemal's `query` DSL
  (Kemal 1.13+) unconditionally. Both were test conveniences that had quietly set the
  supported floor for the whole library.

## v0.2.0 — 2026-08-25

First release. It contains both the v0.1 and v0.2 milestones of `docs/06-roadmap.md`: the two
were finished back to back with no release between them, and tagging a `v0.1.0` that already
held v0.2 features would have misrepresented both.

### Authentication

- Password login with bcrypt, timing equalisation against account enumeration, and lazy
  rehashing so a cost increase never forces a password reset.
- Server-side opaque sessions: digest-only storage, expiry evaluated on every read rather than
  by a sweeper, rotation on login, and revocation that takes effect on the next request.
- Cookie policy defaulting to `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`, with
  incoherent combinations refused at boot rather than discarded by the browser in production.
- Password hashing on a dedicated execution context. At 50 concurrent logins this holds
  unrelated-request p99 latency at 1.17 ms against 2,176 ms without it.

### Kemal integration

- `env.auth`, `require!`, `require_fresh!`, `PathGuard` and `ErrorHandler`.
- Guards match on the path alone for every HTTP method, so they are unaffected by the four
  filter-dispatch defects in Kemal 1.10.0 – 1.12.0 and covered HTTP QUERY without a change
  when Kemal 1.13.0 added it.
- CSRF protection using a masked, session-bound HMAC — including the login form, which is the
  case most implementations miss.
- Rate limiting on the password verification path, consumed before any lookup or hashing.
  **Off by default**: `NullRateLimiter` allows everything until an application opts in.

### Account lifecycle

- Password reset and email confirmation over single-use, atomically consumed action tokens.
  The reset endpoint reveals nothing by response or by timing, and is rate limited per address
  so it cannot be used to flood an inbox.
- Remember-me with rotating single-use tokens and family revocation, so a stolen cookie is
  detected on the next visit by either party. A replay revokes the family, ends every session
  for the account, and notifies the account holder.
- A `Notifier` contract. No SMTP, no templates: the application delivers.

### Storage

- PostgreSQL adapters for accounts, sessions, action tokens and remember-me tokens, all
  running the same contract specs as the in-memory doubles.
- Migrations published as files to copy in, never run by the shard.

### Supported versions

Crystal **1.21.0** or later, Kemal **1.10.0** or later. Both floors measured by running the
suite downwards until it failed; CI runs the Kemal floor as its own job.

### Known limitations

- Rate limiting is off unless configured, and `FixedWindowRateLimiter` counts per process.
- Two requests presenting the same remember-me cookie simultaneously are indistinguishable
  from a theft. See `blueprints/0012-remember-me.md`.
- No SQLite adapter, no session sweeper, no API tokens. Those are v0.3 and v0.4.
- The API is not frozen until v1.0.

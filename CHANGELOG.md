# Changelog

## v0.10.0 — 2026-09-02

The catalogue's third pass: eight scenarios — AUT-06, AUT-07, HTTP-02, OPS-03, TOK-08, TOK-09,
MFA-01 and MFA-04 — every one measured from a separate consumer project before anything here was
written. That is the whole remaining high-frequency set apart from WebAuthn and a rolling
upgrade.

A minor rather than a patch, for the three ⚠ items below. **Four of the entries are defects in
code the first two passes had already validated**, which is the result worth taking away from
this release: the first pass moved signatures, the second added machinery, and the third found
that rules this project had already decided were applied in one place and not in the next.
`blueprints/0025-maturity-validation-results.md` has a section per scenario with the evidence.

### Fixed: nearly half of every recovery-code list could not be redeemed

Found by trying to redeem a code the shard had generated seconds earlier and being told it was
`MalformedCredential`.

`RandomSource#token` is base64url, whose alphabet includes `-`. `redeem_recovery_code` stripped
`-` before checking the length, because a recovery code is *typed* and applications display them
in groups. Both decisions are sensible; together they were a defect. A code containing a hyphen
was shortened by one character, failed the length check, and could never be used.

Measured over two thousand freshly generated codes:

```
length=43; 935/2000 contain a hyphen (46.8%)
```

So roughly **half of every recovery list issued by v0.4 through v0.9 is unusable** — on the one
credential that exists for the day somebody has lost everything else. It survived three
releases because the suite redeemed *one* code per example, and one code passes half the time.

Fixed in both directions:

* generation redraws rather than substituting, so no issued code contains `-`. Substituting
  would make one character twice as likely and quietly cost a bit of entropy;
* redemption tries two readings — whitespace stripped, then whitespace and `-` stripped — so
  **codes already in people's hands keep working**, and a code typed with the separators an
  application displayed works too.

Nothing to do on upgrade. Lists issued before this become redeemable for the first time. The
regressions assert every code in a list of twenty-five rather than the first one.

### ⚠ Behaviour change: recovery is not a second factor

`AssuranceLevel::Recovery = 25` is new, between `Password` and `MFA`, and
`env.auth.recovery_verified!` is what a recovery route calls:

```crystal
case KemalIdentity.app.mfa!.redeem_recovery_code(subject, code, except_session_id: current)
in KemalIdentity::MFA::Verified then env.auth.recovery_verified!   # not mfa_verified!
in KemalIdentity::Failed        then render_the_same_error_for_every_reason
end
```

`RequestContext#mfa_verified!` used to be documented for both a verified factor **and** a
redeemed recovery code, so spending a printed code produced a principal indistinguishable from
one that had proved a hardware key. A permission declared `minimum_assurance: MFA` — "changing
payout details needs phishing-resistant MFA" — was therefore satisfied by a list of codes held
by whoever found the piece of paper.

A session at `Recovery` reaches everything a password reaches and nothing that asks for `MFA`,
which is the point: recovery restores access, it does not stand in for a device. Prompt for
re-enrolment there.

⚠ **An exhaustive `case` over `AssuranceLevel` stops compiling.** Appending was always the plan —
the enum's gaps of ten exist for it — and no persisted value changed.

⚠ **Update your recovery route.** `mfa_verified!` still works and still grants `MFA`; if you call
it after a recovery you keep the old, weaker behaviour.

### ⚠ Privilege boundary: factor removal is scoped to its owner

`MFA::Service#remove(factor_id)` took only the factor id, so `DELETE /mfa/factors/:id` written
the obvious way removed whichever factor the caller named — including somebody else's. A factor
id is not secret material: it appears in `mfa.verified` and `mfa.factor_removed` audit lines and
in every management listing. This is the defect v0.9.0 fixed in `ApiTokens::Service#revoke`, in a
second place, and here the harm is worse: removing a second factor does not end an account's
access, it **weakens** it, and the next password-only login succeeds where it would have demanded
a code.

```crystal
mfa.remove(factor_id, account_id)                     # settings screen; refuses a last factor
mfa.remove(factor_id, account_id, allow_last: true)   # "turn MFA off", said out loud
mfa.remove(factor_id)                                 # administrative, unchanged
```

The scoped form answers `false` for another account's factor and for one that does not exist —
the same answer, so the difference cannot be used to discover whether an id is real — and
defaults `allow_last` to **false**, while the administrative form defaults it to true. A settings
screen should not be able to turn MFA off by accident.

`confirm` takes an optional `account_id` for the same reason, though it is the cheaper guard:
confirming somebody else's pending enrolment also needs a code from their secret.

⚠ **Behaviour change: removing the account's last confirmed factor now voids its recovery
codes**, for the reason `#disable` already did — a list that survives into a later re-enrolment is
a full bypass of the new factor. Removing one of two devices still leaves them alone.

### ⚠ Breaking for adapter authors: `ApiTokens::Repository#expire`

A rotation needs the old credential to keep working for a bounded window and then stop. An
expiry could only be chosen **at issuance**, and a rotation happens months later, so the only
ways to close the window were to revoke immediately (no overlap) or to schedule a revoke (the
window closes when a job runs, and never if it does not).

```crystal
replacement = api.issue(account, "deploy-key (rotated)", scopes: old.scopes)
api.expire(old.id, account.id, at: Time.utc + 15.minutes)
```

Both work until the deadline; after it the old one fails as `Expired` on the authentication path
itself. `expire` **never lengthens** a token's life, and the comparison is in the statement rather
than a read followed by a write, so two callers cannot interleave into a later deadline than
either asked for.

⚠ **A third-party `ApiTokens::Repository` will not compile until it implements one method.** The
shared contract has seven examples for it, so the rule arrives as a failing spec rather than as
prose. Taken deliberately before the v1.0 freeze rather than after it.

There is still no token *family*: `revoke_all` is account-scoped and atomic, two `revoke` calls
are two statements, and an application that needs a set to fall together implements the
repository over its own table where it owns the transaction.

### A deployment can cap how long a token may live

```crystal
KemalIdentity.configure(
  # ...
  api_token_lifetime: KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days, default: 7.days),
)
```

Absent by default, because a deployment that wants non-expiring deploy keys is not wrong.
Issuance raises `ApiTokens::PolicyError` — **before the secret is generated and before anything is
written** — for an unbounded token and for one that would outlive the maximum. The error carries
the violation and the limit, and both are safe to show: somebody creating a credential is not
somebody proving they hold one.

A policy is a rule about creation. It is **not** consulted on the authentication path, so
tightening it does not shorten the tokens that already exist and cannot turn a configuration
change into an outage for every client holding an older one. Applying a new limit retroactively
is a walk over `list` calling `expire`, which cannot lengthen anything by accident.

### Pages and an API in one process

```crystal
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login", api_prefixes: ["/api"])
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(prefix: "/app", credentials: [KemalIdentity::CredentialKind::Session])
use KemalIdentity::Kemal::PathGuard.new(prefix: "/api", credentials: [KemalIdentity::CredentialKind::ApiToken])
```

Two of the three things a mixed monolith needs were previously hand-written handlers, and the
third already worked.

`credentials:` says which kinds a subtree accepts. A credential of another kind is a **403**, not
a 401 — it is valid, it is the wrong door, and 401 would tell a working client to authenticate
again in a loop. The check runs after authentication, so an anonymous request is still a 401 and
nobody learns which classes a subtree takes without holding one. An empty list is refused at boot.

`api_prefixes:` names subtrees that must never be redirected. Without it the decision is a guess
made from the request — JSON in `Accept`, `X-Requested-With`, an `Authorization` header — and a
client that sends none of them received `302 Location: /login` for a path that serves no HTML.

CSRF needed no argument: `CSRFHandler` already exempted a request authenticated by a bearer token
**and nothing else**, and a request carrying a token *and* a cookie stays protected.

`KemalIdentity::Kemal::PathPrefix.covers?` is public, because an application writing its own
handler needs the same rule and the tempting one-liner is wrong: `/api` covers `/api/items` and
not `/apiary`.

`examples/mixed_monolith/app.cr` is the whole arrangement with a `curl` line per case.

### A step-up challenge says what would satisfy it

```
POST /email   Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication", max_age="300"
POST /payout  Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication"
```

Three different refusals used to send one challenge, so an API client could not tell "type your
password again" from "produce a second factor". `FreshAuthenticationRequiredError` now carries the
window `require_fresh!` was given and `ErrorHandler` emits RFC 9470's `max_age`; its **absence** is
the strength case, deliberately rather than a `max_age="0"` that would tell a client to retry
something that cannot succeed. No `acr_values`, because those are a deployment's own vocabulary
and this shard has an ordering — `blueprints/0028-step-up-challenge-parameters.md`.

### You can ask whether security events are still arriving

```crystal
Log.setup_from_env
KemalIdentity.event_sink = SiemSink.new

abort "security events are not reaching the sink" unless KemalIdentity.event_sink_delivering?
```

`::Log.setup` and `setup_from_env` replace the whole configuration, binding included. So wiring a
sink and *then* configuring logging left no sink, with nothing raised and `EventBridge#failures`
at **zero** — the silence v0.8's typed sink exists to prevent, reached through a door it did not
watch, since an unbound bridge is not a failing one.

The check emits one named `sink.probe` event and waits for the bridge to see it. It answers
**true** for a sink that raises on every event, because that sink is bound and `#failures` is the
number for it: two questions, two answers.

Worth knowing where it was found: a sink bound at the top of a **spec file** receives nothing,
because Crystal's spec runner configures `Log` after the file loads. The same code in a plain
program receives everything — so the tests somebody writes to check their SIEM wiring are the
ones that cannot see it working.

### The tenant a session copies is a stale grant, and now says so

`Sessions::Service#start` copies `account.tenant_id` onto the session row and `#resolve` rebuilds
the principal from that row, so it is the one authorization input a session carries. Measured:
after confining an account to a tenant, a session that already existed was still unconstrained
**eleven hours later**, and stopped only when the session did.

No code changed — `Sessions::Lookup` deliberately does not carry the account's tenant, and
widening it would add a column to every authenticated request for a value that changes
approximately never. What changed is that `docs/02-security-model.md` now lists a tenant change
beside password change and account disable among the events that must revoke an account's
sessions, `Accounts::Repository#bump_auth_version` names it, and three examples pin both levers.

`Principal#tenant_id` also stopped claiming to be "unused in v0.1"; `Authz::RBAC#decide` reads it
on every tenant-scoped decision.

### Fixed: the in-memory token double lost a token's scopes

`MemoryApiTokenRepository#touch` rebuilt the row without `scopes`, and `touch` runs on the
**authentication path** — so authenticating a newly issued attenuated token made it
**unrestricted** from its second request onward. Production was never affected, since both SQL
adapters `UPDATE` one column, which means the only thing this could break was a consumer's test,
in the direction of granting more than production would.

Four contract examples now demand that attenuation survive `touch`, `revoke`, `expire` and a bulk
revocation, so no adapter can lose it quietly either. This is what v0.8's shared contracts are
for.

### The packaged assertions cover a second-factor result

`Testing.should_fail_with` and a new `Testing.should_verify` accept `MFA::VerificationResult`,
which is `Verified | Failed` rather than an `Outcome` and so fell through to the cast those
helpers exist to replace. A packaged assertion that covers three of the four result unions is one
somebody stops using.

### Documentation

* `docs/02-security-model.md` — token rotation, token lifetime policy, metrics and tracing
  without secret leakage, recovery's own assurance level, and the tenant a session copies;
* `docs/04-kemal-integration.md` — pages and an API in one process, under its own heading;
* `blueprints/0028-step-up-challenge-parameters.md` — what a step-up challenge may say;
* `blueprints/0027-security-event-sink.md` decision 6 — why an unbound sink is worse than a
  failing one;
* `blueprints/0025-maturity-validation-results.md` — twenty-nine of the catalogue's fifty
  scenarios now have a measured result, with the third pass summarised at the top.

## v0.9.0 — 2026-09-01

The catalogue's second pass, and the reason this is a minor rather than a patch: no signature
moved, but two changes alter behaviour an application may be observing — one of them a privilege
boundary. Both are marked ⚠ below.

Everything here came out of running `blueprints/maturity-validation-scenarios.md` from a separate
consumer project, or out of writing the examples. Four of the six items are defects the shard had
and nothing was testing.

### An application can register its own bearer authenticator

```crystal
KemalIdentity.configure(
  # ...
  bearer_authenticators: [GatewayAuthenticator.new(secret).as(KemalIdentity::RequestAuthenticator)],
)
```

`RequestAuthenticator` was always implementable and had nowhere to go: `Application#bearer` was
assembled from `api_tokens:` and `jwt:` and from nothing else. That mattered more than
registration, because `bearer` is also what `Kemal::ErrorHandler` asks before sending an RFC 6750
challenge and what `Kemal::CSRFHandler` asks before exempting a token-only mutation. An
application whose only bearer credential was its own got neither: no `WWW-Authenticate` on any
401, and `403 invalid CSRF token` on a `POST` carrying nothing but an `Authorization` header.

Your authenticators go after the shipped ones, in the order given. **One owner per shape:** the
chain stops at the first authenticator that recognises a credential and rejects it, so an
authenticator of yours that handles a shape the shard also handles will never see it. Either own
the shape entirely — hold every issuer's validator yourself and do not configure `jwt:`, which is
what `JWT.unverified_issuer` is for — or move the shapes apart with `api_token_prefix:`. See
`docs/01-architecture.md`.

### Six runnable examples, and CI compiles all of them

`examples/` now holds `browser_session`, `api_tokens`, `ownership`, `custom_bearer`,
`multi_issuer_jwt` and `service_account`, each a single self-contained `app.cr` over SQLite with
no setup. `examples/README.md` says which problem each one is for. The CI step that used to build
one example now globs the directory, so an example added without a CI line cannot rot.

Three of them exist because the validation catalogue kept recording "capability complete, no
worked example" as the reason a scenario stopped at M3.

### `ApiTokens::Service#revoke` can be scoped to the token's owner

```crystal
APP.api!.revoke(token_id, principal.subject)   # a user revoking their own
APP.api!.revoke(token_id)                      # administrative: revokes whoever's it is
```

Writing `DELETE /tokens/:id` for the new API example turned up that only the one-argument form
existed, so the obvious route ends whichever token the caller names. A token id is not secret
material — it appears in `api_token.issued` and `api_token.revoked` audit lines and in any
listing built on `#list`. The two-argument form answers `false` both for somebody else's token
and for one that does not exist, so a caller learns nothing from the difference.

### ⚠ Behaviour change: no password reset for an account with no password

`request_password_reset` now refuses, silently, when the account's `password_digest` is nil —
alongside the refusals already there for an unknown login and a disabled account. The response
does not change and the three remain indistinguishable.

Completing a reset does not *reset* a password on such an account, it **creates** one, turning a
workload identity — a CI job, a daemon — into one that can be logged into interactively. The proof
of identity in that flow is reaching a mailbox, and a service account's login is often a team
alias. The same applied to a human who signs in only through a federated provider.

Setting a *first* password is a profile action for somebody already signed in: call
`Accounts::Repository#update_password_digest` behind your own session guard. Recovery is for a
credential that exists. Django filters the same case out of its reset form
(`has_usable_password()`).

### ⚠ Breaking for log readers: three events renamed their credential field

`session.started`, `api_token.issued` and `api_token.revoked` now emit `credential:` instead of
`session:` and `token:`. They were the three events that *mint or kill* a credential, and the
three that left `SecurityEvent#credential` nil with the id buried in `data` — so the typed
correlation field a SIEM reads was empty for exactly the events an incident starts from.
`api_token.issued` called it `token:`, which reads as though the secret itself were in the log
line; the value was always the id.

This completes the normalisation v0.8.0 started and did not test. `spec/security/event_sink_spec.cr`
now names the four events and the id each must carry.

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

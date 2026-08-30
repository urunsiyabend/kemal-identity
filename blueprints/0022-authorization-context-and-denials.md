# 0022 — What an authorization check receives, and what a denial says

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

A user may edit their own invoice. The route wants to write:

```crystal
put "/invoices/:id" do |env|
  invoice = Invoice.find(env.params.url["id"])
  env.auth.authorize!("invoices:edit", resource: invoice)
end
```

It cannot. `Authorizer#decide(principal, permission, tenant_id)` has nowhere to put the
invoice, and `env.auth.authorize!` — which v1.0 freezes — only ever calls that three-argument
form:

```crystal
case decision = @app.authorizer!.decide(principal, permission, tenant)
```

An application can subclass `Authorizer` and add a resource-aware method of its own, but
nothing will call it. The route has to reach past `env.auth` to the authorizer directly, and
in doing so gives up three things `env.auth.authorize!` was doing for it: the `authz.denied`
audit line, the mapping from an assurance denial to a step-up prompt, and the single uniform
403 body that keeps denial reasons away from clients. It then re-implements all three at every
resource-aware route.

This blocks AUT-01 (high), AUT-03, TOK-02, AUT-02, AUT-04 and AUT-05.

`blueprints/0020` decision 6 is the same signature seen from the other end. `DenialReason` has
five members, so an authorizer denying for a reason of its own — a closed change window, an
incident lockdown — reports `NotPermitted` and the audit trail loses what happened. And because
`authorize!` decides whether to raise `FreshAuthenticationRequiredError` by asking
`decision.reason.insufficient_assurance?`, an authorizer that wants to say "a stronger
credential would fix this" has to borrow that member and distort it.

Both live on `decide`'s signature and its return type. Opening that signature twice would be
two breaking releases where one will do.

## What was measured

Crystal decides part of this outright, so it was compiled rather than assumed.

**An untyped slot is not expressible.** Spring's `authorize(Supplier<Authentication>, Object
secureObject)` has no Crystal translation:

```
getter resource : Object?   →  Error: can't use Object in unions yet, use a more specific type
getter resource : Object    →  Error: can't use Object as the type of an instance variable yet
getter resource : Reference? →  Error: can't use Reference in unions yet
```

`Object` works as a method restriction and nowhere else. It cannot be stored in a struct, which
is what a context object is.

**Crystal's interface mechanism is a module with abstract defs.** `Comparable(T)`,
`Enumerable(T)`, `Iterable(T)`, `Iterator(T)` and `Indexable(T)` are all modules carrying
`abstract def`. This is how the standard library says "any type with this shape".

**Adding an abstract def to a published module is breaking.** Every implementor stops
compiling:

```
Error: abstract `def Authorizable#authz_tenant()` must be implemented by Invoice
```

**Adding a concrete def is not breaking, and is worse.** It compiles, and where the including
class already defines that name, the class's definition wins silently. So a later addition
would not break a consumer's build — it would change what the authorizer reads, without
anybody being told.

**Appending a defaulted field to a struct is not breaking.** Positional construction, named
construction and existing read sites all keep working. This is what makes a small `Forbidden`
safe to start with.

## Prior art

- **Laravel** — `Gate::allows('update-post', $post)`; the resource is the second argument, and
  further context an array. A denial can be an object: `Response::deny('You must be an
  administrator.')`, `Response::denyWithStatus(404)`.
- **Django REST Framework** — `has_object_permission(self, request, view, obj)`; the resource is
  positional. A permission class carries `message` and `code` attributes for the denial.
- **ASP.NET Core** — `AuthorizationHandlerContext.Resource` is an `object?`, and the
  documentation notes that using it couples a policy to a particular framework. Resource-based
  authorization is instead written against `AuthorizationHandler<TRequirement, TResource>`.
- **Open Policy Agent** — one `input` document per decision, with no enforced schema.
- **oso (Rust)** — Rust has no root type either. Types are registered with the library and
  recovered by downcasting from `dyn Any`, which needed a runtime reflection layer.

Two things are common to all of them: the resource reaches the authorizer, and the denial
carries a reason that is not drawn from a closed set.

## Decisions

### 1. A resource is anything that can name its type and its id

```crystal
module KemalIdentity::Authz::Authorizable
  abstract def authz_type : String
  abstract def authz_id : String
end
```

A **module**, not an abstract class, because Crystal has single inheritance and an
application's `Invoice` usually already descends from an ORM model. Requiring a base class
would make this unadoptable for exactly the applications `docs/03-data-model.md` treats as
normal.

Two methods, and the authorizer can work from those alone: `"invoice"` and `"42"` are enough
to key a relationship lookup or to serialise a request to a remote policy engine. An
authorizer that wants the real object downcasts for it, and a wrong guess is `nil` rather than
an exception:

```crystal
invoice = context.resource.as?(Invoice)
return Forbidden.not_permitted(permission) if invoice.nil?
return Forbidden.not_permitted(permission) unless invoice.owner_id == principal.subject
```

### 2. `Authorizable` never grows

**Two abstract defs, frozen at 1.0, and no concrete defs either.**

The measurements above give the reason rather than a preference. A third `abstract def` breaks
every implementor's build. A concrete def does not break the build and instead injects a name
into every including class, where a collision resolves in the class's favour — so the
authorizer would silently read the consumer's meaning of a name this shard chose. The first
failure is loud and the second is not, which makes the second the one to rule out.

`spec/unit/authorizable_spec.cr` holds a fixture implementing exactly these two methods. A
third abstract def added later does not fail a test; it fails the suite's compilation. Verified
by adding one: the build stops at `Authz::Resource` — this shard's own implementation guards it
before the spec fixture is even reached — with `abstract def
KemalIdentity::Authz::Authorizable#authz_tenant() must be implemented by
KemalIdentity::Authz::Resource`. The constraint is enforced by the compiler rather than by this
paragraph.

Growth happens on `AuthzContext` instead — see decision 4.

### 3. The shard ships one implementation, for applications that will not touch their models

```crystal
struct KemalIdentity::Authz::Resource
  include Authorizable

  getter authz_type : String
  getter authz_id : String
  getter attributes : Hash(String, String)?
end
```

```crystal
env.auth.authorize!(
  "invoices:edit",
  resource: Authz::Resource.new("invoice", invoice.id, {"owner_id" => invoice.owner_id}),
)
```

The cost is visible and belongs to the route: it decides which attributes the policy needs. A
route that passes the wrong ones gets a denial, not a wrong answer, because a policy reading a
missing attribute denies.

### 4. `AuthzContext` is where this design is allowed to grow

```crystal
struct KemalIdentity::Authz::AuthzContext
  getter tenant_id : String?
  getter resource : Authorizable?
  getter attributes : Hash(String, String)?
  getter credential : CredentialRef?
end

abstract def decide(principal : Principal, permission : String, context : AuthzContext) : Decision
```

A context object rather than more positional parameters, so that the next thing an authorizer
needs does not reopen a frozen signature. The shard constructs it, appending a defaulted field
is not breaking, and unlike a module it injects nothing into anybody's types.

`attributes` is the valve below that: environment data — a device posture, a region, a change
window — that needs no type change at all.

The existing three-argument form stays as a concrete overload building a context, so every
current call site and every current implementor keeps working:

```crystal
def decide(principal : Principal, permission : String, tenant_id : String? = nil) : Decision
  decide(principal, permission, AuthzContext.new(tenant_id: tenant_id))
end
```

**No `at : Time` on the context.** An authorizer that reasons about time has a `Clock`
injected, as `RBAC` already does — `src/CLAUDE.md` bans `Time.utc` outside `SystemClock` and
`spec/unit/source_hygiene_spec.cr` enforces it. A timestamp on the context would be a second
source of "now" that no injected clock controls.

**Amended during implementation: the credential is not on the context.** It was, for exactly
that convenience, and it was wrong. The tenant-only `decide` overload built a context without
one, so every call through that form skipped scope attenuation and an attenuated token came back
unrestricted — a fail-open, produced by a field with two homes and no rule keeping them equal.
The same objection this document raises against two authorities for step-up, missed once and
caught by a failing example. `Principal#credential` is the single source, and the principal is
the first argument to `decide`, so it is never further away than the copy would have been.

### 5. A denial names its own reason, for the audit trail and not for the client

```crystal
enum DenialReason
  NotPermitted
  NotAMember
  TenantMismatch
  InsufficientAssurance
  UnknownPermission
  Custom            # the authorizer's own reason, named by `code`
end
```

`Forbidden` gains `code : String?`. Laravel and Django REST Framework both reach for a
free-form denial rather than a closed set, and both are right that five members cannot describe
every application's policy.

**Where this shard diverges from both: the free-form reason never reaches the response.**
Laravel propagates a gate's message into the HTTP response; DRF renders `message`. Here,
`NotAMember` and `NotPermitted` tell an attacker whether a tenant they guessed at exists and
whether they are inside it, so every denial still renders one identical 403 and `code` is
audit-only. That was already this document's position for the enum; extending the reason model
does not extend what leaks.

### 6. "Would authenticating again help?" is a separate axis, and it decides the control flow

```crystal
# Whether stronger or fresher authentication may allow this request to succeed.
#
# Not "the caller is missing something" — "authenticating again, or harder, may change this
# answer". Joining a tenant or enrolling a managed device does not qualify: those are
# remediations, and no amount of re-authentication performs them.
getter? step_up : Bool
```

```crystal
raise FreshAuthenticationRequiredError.new("stronger authentication required") if decision.step_up?
```

`authorize!` stops asking `reason.insufficient_assurance?`. Keeping both would leave two
sources of truth with no rule for the case where they disagree. From here:

- `step_up?` determines control flow.
- `reason` and `code` explain, for the audit trail and for diagnosis.

### 7. For the shard's own reasons, `step_up` cannot be chosen, so it cannot drift

Making the flag an ordinary constructor argument would introduce a failure the compiler cannot
catch: `RBAC` builds an `InsufficientAssurance` denial and forgets `step_up: true`, step-up
silently stops working, and the user sees a flat 403 where a prompt belonged. Today that is
impossible, because the enum member *is* the signal. Splitting the axes must not buy
extensibility with that guarantee.

So the flag is not a parameter of the general constructor. It is fixed by named constructors,
in the shape `Verdict.allow` / `Verdict.deny` already use in this shard:

```crystal
Forbidden.not_permitted(permission, tenant_id)          # step_up: false
Forbidden.not_a_member(permission, tenant_id)           # step_up: false
Forbidden.tenant_mismatch(permission, tenant_id)        # step_up: false
Forbidden.unknown_permission(permission, tenant_id)     # step_up: false
Forbidden.insufficient_assurance(permission, tenant_id) # step_up: true

Forbidden.policy(permission, code: "change_window_closed", step_up: false, tenant_id: tenant_id)
```

`RBAC` never names the flag and therefore cannot forget it. The one place a caller chooses is
`.policy`, which is the one place the choice carries information this shard does not already
have.

### 8. `step_up` is a `Bool`, not a struct with room in it

The alternative considered was `step_up : StepUp?`, empty at first, so that later detail —
which assurance level, what maximum authentication age — could be added without changing the
field's type. It buys something real: `Bool` cannot be widened to `StepUp?` later without a
break.

It is rejected on the two fields that would fill it.

**The required assurance is already reachable.** `Permission#minimum_assurance` holds it, and
the caller knows which permission it asked about. Putting it in the denial copies data the
catalogue already answers — the same objection `Principal` makes to carrying roles.

**A maximum authentication age contradicts a decision already recorded.** `Principal` says it
plainly: the freshness window belongs to the caller, `require_fresh!(within: 5.minutes)` is a
call-site decision, and storing a precomputed deadline bakes one caller's policy in. A denial
carrying `max_auth_age` would be this shard telling the application what the application's own
policy is.

**And the case that seems to demand them does not.** RFC 9470's challenge carries `acr_values`
and `max_age`, so an eventual `WWW-Authenticate` for step-up (HTTP-01, additive and after 1.0)
will want both. That challenge is built in the Kemal layer, which has the application, the role
catalogue and the route's own freshness policy in hand. The values are computable where the
challenge is written; they do not need to travel inside a `Decision` to get there.

Against that, an empty struct is precisely what `blueprints/0021` decision 7 argued against
when it refused to ship a scope field nothing populated: freezing a contract nobody has
exercised is how a type ends up meaning something slightly different from what it says. If a
third fact about step-up ever turns out to be genuinely un-derivable, it arrives as a defaulted
field on `Forbidden`, which was measured to be non-breaking.

## Consequences

**`env.auth` grows a resource and an attributes argument**, and `authorize!` keeps everything it
was doing — the audit line, the step-up mapping, the uniform 403 — for resource-aware routes
that previously had to bypass it.

**`RBAC` does not change behaviour.** It ignores `resource` and `attributes`, as an RBAC
implementation should; roles in code and assignments in the database (`blueprints/0018`) is
unaffected. What changes is that an application can now install something else without giving
up the surrounding machinery.

**AUT-05 comes close to free.** `authz_type`, `authz_id` and `attributes` are already the shape
of an OPA `input` document, so a network-backed authorizer serialises the context rather than
inventing a wire format.

**Two constraints are enforced by compilation rather than by review.** A third abstract def on
`Authorizable` fails the suite's build, and `Forbidden`'s named constructors leave no argument
for `RBAC` to get wrong.

**The one thing this does not decide** is whether `Authz::Cache` keys should include the
resource. A per-resource decision cache has a different invalidation problem from the
per-account one `blueprints/0018` documented, and caching an ownership answer for five seconds
is not obviously the same trade. Deferred, and the cache stays off by default meanwhile.

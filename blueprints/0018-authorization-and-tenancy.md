# 0018 — Authorization: roles in code, grants in the database

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.6

## Context

`docs/06-roadmap.md`: "`Authorizer` contract, an RBAC extension, tenant membership.
Deliberately last: it is a different responsibility from authentication, and shipping it early
would encourage baking policy into the auth core. Role and permission lists do not get copied
into long-lived tokens or sessions. If membership changes must take effect immediately, they
are read from the authorization store or a short-lived versioned cache."

Two sentences, and the second one is the whole design. Almost every authorization bug that
matters is a *staleness* bug: somebody's access was taken away and something, somewhere, was
still holding a copy of the old answer.

## Decisions

### 1. Roles are code, assignments are data

`RoleCatalog` is built at boot from literals in the application. The database holds only who
holds which role. There is no `auth_roles` table and no `auth_role_permissions` table, which is
the thing every general-purpose RBAC library ships.

**A role definition in a table is a privilege-escalation surface.** One UPDATE — through an
injection, an over-permissive admin screen, a restored backup from before a permission was
tightened — silently rewrites what everybody holding that role can do, and nothing about the
application changed. In code the same change is a diff somebody reviews, in a pull request,
next to the routes it affects.

**And a missing permission becomes a boot failure instead of a mystery.** Renaming
`invoices.refund` and forgetting one role definition raises on the machine of whoever made the
change, rather than denying an action in production for a month while everyone assumes the
person complaining has the wrong account.

The cost is real and is accepted: roles cannot be administered at runtime. An application that
genuinely needs that implements `Authorizer` against its own tables — that is why
authorization is a contract and not a table. What it does not get is this shard pretending a
mutable table of grants is the same security property as a reviewed one.

### 2. No wildcards, ever

No `invoices.*`, no prefix matching, no hierarchy. A wildcard grant is a grant of permissions
**that do not exist yet**: whoever holds `admin.*` today silently acquires
`admin.billing.export_everything` the day it is added, and nobody reviewing that pull request
sees a privilege change.

Enumerating them is more typing, and the typing is the point — the diff that adds a permission
is the diff that decides who gets it. `Permission::PATTERN` refuses `*` at construction, so
this cannot be re-introduced by a config file.

### 3. Membership and roles are separate rows, and a tenant role is inert without a membership

Holding `finance` in tenant A grants nothing unless there is also a membership row for A. Two
rows to say one thing, and the redundancy is deliberate: removing somebody from a tenant is
then a **single row** that revokes everything at once, and it cannot be defeated by a role
assignment that was missed in the cleanup.

`Repository#remove_member` deletes that tenant's assignments as well, and the two are one
operation. Leaving them would be safe today, since `RBAC` ignores a non-member's tenant roles —
but it would make re-inviting somebody silently restore every role they used to hold, which is
not what anybody means by "add them back".

A **global** assignment (`tenant_id` NULL) is not gated this way: it applies everywhere,
including inside every tenant. That is what makes it the dangerous kind of grant, and why
`Assignment#granted_by` exists.

### 4. The cross-tenant check runs before anything is read

A principal bound to tenant A asking about tenant B is refused on the principal's own binding,
before membership is consulted. This is the horizontal escalation attempt — the identifier in
the URL swapped for somebody else's — and it is the one check that must not depend on a
database row being correct.

A principal with **no** tenant is unconstrained by it, which is the single-tenant deployment and
the overwhelming majority of them. A check naming **no** tenant is not a mismatch either: it is
a question about global scope, and a route that forgets to pass the tenant it is operating on
gets a denial rather than a quiet upgrade.

### 5. Assurance is a property of the permission

`Permission#minimum_assurance` — `invoices.refund` needs MFA wherever it is called from. A rule
written at each call site is a rule that is missing at the call site somebody forgot.

The floor defaults to `Password` rather than `Remembered`: a session restored from a cookie
proves possession of a stored token, not the presence of the account holder, and that is too
weak a basis for any deliberate action.

A denial for weak assurance raises `FreshAuthenticationRequiredError` rather than
`ForbiddenError`, so the application can prompt for a second factor instead of showing a dead
end. That does tell the caller they hold the grant — the same thing `require_fresh!` has always
told them, and the alternative is an application that cannot offer step-up at all.

### 6. Three exception classes, three meanings, one body

* nobody signed in → `NotAuthenticatedError` → 401. Logging in would help.
* signed in, no grant → `ForbiddenError` → 403. Logging in again would not.
* signed in, grant, weak assurance → `FreshAuthenticationRequiredError` → 403, step up.

`DenialReason` distinguishes `NotAMember` from `NotPermitted` and never reaches the response.
The two responses are byte-identical, asserted over HTTP, because a body that varied with the
reason would confirm both that a guessed tenant exists and that the caller is outside it.

### 7. The cache TTL is the revocation delay, so it is capped at a minute

`Authz::Cache` is off by default. When it is on, five seconds by default and `MAX_TTL` of one
minute — not because a longer one would not perform better, but because a ten-minute cache is a
ten-minute window in which a compromised account keeps working after somebody has already
noticed and revoked it.

`RBAC#grant` / `#revoke` / `#remove_member` invalidate it. Behind several processes that only
clears the one that made the change, and the others wait out the TTL. Stated plainly rather
than papered over with a pub/sub channel that would be one more thing to run and one more thing
to be silently broken — if the invalidation channel fails, the TTL is what is still keeping the
promise, so the TTL has to be short enough to be the whole answer on its own.

The map is bounded and **clears itself** at the limit rather than evicting one entry at a time.
The key includes the tenant asked about and anybody signed in can ask about a tenant that does
not exist, so the key space is attacker-influenced; the failure mode of a stampede should be
"the cache stops helping", not "the process runs out of memory". No LRU bookkeeping on the hot
path to defend against a case that should never be reached.

### 8. Nothing expires, and the sweeper has nothing to do here

No `expires_at` on an assignment. A time-limited grant sounds useful and is a trap: it puts the
moment somebody loses access into a column nobody watches, and an access review reading the
table sees a row that looks live. Temporary access is granted and then revoked, and the
revocation is a row that disappears plus an audit line naming who removed it.

## Consequences

* `Principal` still carries no roles and no permissions, and nothing in this milestone writes
  any into a session or a token. A revocation bites on the very next request, with the same
  session — asserted over HTTP.
* Two migrations per dialect, and the unique indexes are load-bearing. The global scope needs a
  **partial** index (`WHERE tenant_id IS NULL`), because a plain unique index does not collide
  on NULL; dropping it makes both the contract example and the sixteen-fiber concurrency
  example fail, which is how that was verified rather than by reading the manual.
* Twenty mutations of the module, the two adapters and the double: twenty killed, none
  surviving. The ones worth naming are "membership ignored for tenant roles", "cache entries
  never expire" and "cache key ignores the tenant" — each of which passes a suite written
  without the corresponding example.
* Not done here: a path-prefix authorization guard along the lines of `PathGuard`. Authorization
  is per-action, and a prefix-to-permission map encourages exactly the coarse check that lets
  `/admin/billing` inherit whatever `/admin` required.

# 00 — Scope

## What Kemal Identity is

An authentication library for Crystal web applications: it establishes *who is
making this request* and gives the application a typed, revocable answer.

The default and recommended path is a **server-side opaque session** for
first-party browser applications, with password credentials, the account
lifecycle flows that surround them (confirmation, reset, remember-me), and a
Kemal handler that populates `env.auth`.

## What Kemal Identity is not

- **Not an authorization system.** It answers "who", not "may they". The
  `Authorizer` contract shipped in v0.6 and `Authz::RBAC` with it, but both live
  outside the core and stay there permanently: `Principal` carries no roles, no
  handler consults an authorizer, and an application that wants policy evaluation,
  ACLs or attribute-based rules implements the contract rather than asking this
  shard to grow them.
- **Not an OAuth2 authorization server.** Being an OAuth/OIDC *client* is a
  planned extension. Issuing tokens to third parties is a different product and
  will not be built here. (Laravel's Sanctum/Passport split is the precedent.)
- **Not an ORM integration.** The core knows about repositories, not models.
  There is no `User < Granite::Base` requirement, no migration framework
  dependency, no assumption of a `users` table.
- **Not a user management system.** No admin UI, no invitation workflow, no
  profile fields, no email templates. A `Notifier` contract hands delivery to
  the application.
- **Not a password policy engine.** Hashing is in scope. Deciding whether a
  password is acceptable is a `PasswordPolicy` the application supplies. No
  hard-coded composition rules ship as a default. (See `docs/02-security-model.md`
  for why.)
- **Not a JWT library.** A JWT `RequestAuthenticator` is a future extension,
  off by default, for resource-server use — never as the browser session
  mechanism.

## Non-goals that are frequently proposed

Recorded here so they can be declined by pointing at a line rather than
re-arguing:

| Proposal | Answer |
|---|---|
| "Make JWT the default session so we're stateless" | No. Revocation is the whole point of a session. See `docs/02-security-model.md`. |
| "Add `admin?` / `role` to `Principal`" | No. That is authorization, and it is stale the moment it is copied. |
| "Serialize the User object into the session" | No. The session carries an account id and security metadata only. |
| "Ship an MD5/SHA1 hasher for compatibility" | Only as a read-only legacy *verifier* that forces an immediate rehash. Never as something you can configure for new passwords. |
| "Make the session store pluggable to Redis in v0.1" | Not in v0.1. The revocation consistency model has to be specified first. |
| "Auto-discover strategies at runtime" | No. Crystal compiles; registration is explicit. |

## Naming

The distribution and namespace are **`kemal_identity`** / `KemalIdentity::`.

The similarly named `kemal-auth` distribution and `KemalAuth` namespace belong
to `aloli-crystal/kemal-auth` (published February 2026, BCrypt + JWT + Kemal
cookie sessions + SMTP password reset). This project deliberately uses the
distinct `kemal_identity` distribution and `KemalIdentity` namespace so package
references and stack traces remain unambiguous. The core stays framework-agnostic;
the Kemal layer is one adapter among possible others.

The README leads with "Authentication for Crystal web applications — Kemal
integration included", so the search term still lands.

**Before publishing:** open an issue on `aloli-crystal/kemal-auth` describing
this project. The Crystal ecosystem is small and two competing auth shards helps
nobody. Collaboration or an explicit "different goals, both exist" is a better
outcome than silent duplication.

## Version targets

Verified as of 2026-08-24:

| Target | Decision |
|---|---|
| Crystal | **1.21.0** is the CI main line (released 2026-07-16; execution contexts became the default concurrency model here). |
| Crystal floor | **1.12.0**, measured 2026-08-26 under Docker against real PostgreSQL. The *specs* pass from 1.4 upwards, but that is not the floor: `Kemal.run` calls `Process.on_terminate`, added in Crystal 1.12, so on 1.11 the specs are green while no actual application compiles. The floor is where a real application works. CI builds the example and the benchmarks on every matrix entry precisely so this cannot be missed again. |
| Crystal, recommended | **1.21.0**. `HashingExecutor` needs `Fiber::ExecutionContext`, which arrived as the default in 1.21. Below that it refuses to be built unless the application passes `allow_inline: true` and accepts that a burst of logins will slow unrelated requests — a loud absence rather than a silent one. See `blueprints/0013-execution-contexts-are-optional.md`. |
| Kemal | **1.13.0** (released 2026-08-24) is the CI main line. It fixes the four filter defects below; the floor does not, so the design in `docs/04-kemal-integration.md` stands. See `blueprints/0003-kemal-1.13.0-fixes-the-filter-defects.md`. |
| Kemal floor | **1.10.0**, measured 2026-08-25. The full suite passes on 1.10.0, 1.10.1, 1.11.0, 1.12.0 and 1.13.0; 1.9.0 fails with `undefined method 'use' for top-level`, since path-scoped `use` arrived in 1.10.0 — exactly as predicted. CI runs the floor as its own job. |
| Database | PostgreSQL is the only first-class adapter for v0.1. SQLite is added for the test matrix in P1. MySQL after that. |
| ORM | None. `crystal-db` in the repository shard; Granite/Jennifer adapters are separate and later. |
| Resolved | Verified by `shards install` on 2026-08-24: crystal 1.21.0, kemal 1.13.0, crystal-db 0.14.0, crystal-pg 0.30.0. Pinned in `shard.lock`. |
| Migrations | No tool dependency. Neither published micrate can run on this stack — see `blueprints/0002-no-micrate-dependency.md`. The published `.sql` files keep micrate's directives; `bin/migrate` reads them. |
| Lint | ameba `master` (1.7.0-dev). No ameba *release* compiles against Crystal 1.21. |

**Kemal security caveat:** Kemal 1.10.0 – 1.12.0 contains four defects that directly
affect authentication middleware, plus a multipart temp-file leak. All five are fixed in
**1.13.0**. Because the supported floor is 1.10.0, Kemal Identity still must not depend on
the fixed behaviour: every consumer between the floor and 1.13.0 has the defects. See
`docs/04-kemal-integration.md` — this is load-bearing, not a footnote.

## Shard layout

Two shards, not seven. The seven-shard split proposed in early design work
front-loads release coordination and a version matrix before any contract has
been proven in use.

```
kemal_identity          core contracts, session/password/account services,
                        Kemal handlers, in-memory testing adapters,
                        PostgreSQL repository. One dependency: kemal.

kemal_identity_argon2   Argon2id PasswordHasher. Separate because it needs a C
                        binding, which is the only real reason to split a shard.
```

JWT does not need its own shard: Crystal's stdlib has the OpenSSL primitives, so
it can ship as `require "kemal_identity/jwt"` — compiled in only if required. Same for
OIDC. Split later, if and when a contract has stabilized and an adapter needs an
independent release cadence.

# 01 — Architecture

## The central split

The single most important structural decision: **do not force everything into
one `Strategy` abstraction.**

Passport.js is the cautionary example. "Log in with a password", "read a session
cookie" and "log in with Google" are all called authentication, so they were
given one interface — but they have different inputs, different outputs, and
different lifecycles. Kemal Identity keeps three separate concepts:

| Concept | Question it answers | Runs | Contract |
|---|---|---|---|
| **RequestAuthenticator** | Who is making *this request*? | Every request | `authenticate(...) : AuthenticationResult` |
| **CredentialAuthenticator** | Does this secret prove this identity? | At login only | `authenticate(identifier, secret) : AuthenticationResult` |
| **Federation client** | What does an external issuer assert? | Redirect + callback | `authorize(...)` / `complete(...)`, returning `Federation::Identity` |

A `SessionCookie` reads an already-established session. A `Password` verifies a
credential and *establishes* one. An `OIDC::Client` runs a two-leg browser
protocol and returns a foreign identity that then has to be mapped to a local
account. They share a return type at the point where they converge — a
`Principal` — and nothing else.

The third row is deliberately not an abstract contract. It was named
`IdentityProvider` here before federation was built, and when it was built the
honest shape turned out to be one client per protocol over a shared identity
model — `Federation::Identity` and `Federation::LinkRepository`, which every
protocol writes through. `blueprints/0024-federation-namespace.md` records why
inventing the interface first would have meant designing SAML's without SAML.

## Layers

```
┌──────────────────────────────────────────────────────────┐
│ Kemal layer                     src/kemal_identity/kemal/     │
│ AuthenticationHandler, RequireAuthentication,            │
│ RequireFresh, CSRF integration, env.auth                 │
│ The only layer that knows HTTP::Server::Context exists.  │
├──────────────────────────────────────────────────────────┤
│ Services                        src/kemal_identity/           │
│ SessionService, PasswordAuthenticator, AccountService,   │
│ RememberService  — orchestration, no persistence         │
├──────────────────────────────────────────────────────────┤
│ Contracts                       src/kemal_identity/           │
│ Principal, AuthenticationResult, PasswordHasher,         │
│ SessionRepository, AccountRepository, RateLimiter,       │
│ Clock, RandomSource, Notifier                            │
├──────────────────────────────────────────────────────────┤
│ Adapters               src/kemal_identity/{postgres,testing}/ │
│ PostgreSQL repositories, in-memory fakes                 │
└──────────────────────────────────────────────────────────┘
```

Dependencies point downward only. A core file that needs `HTTP::Server::Context`
is a design error: extract the two or three values it actually reads (a cookie
string, a request method, a path) and pass those.

Why this matters concretely: it is what makes `spec/unit/` runnable without a
server and `spec/contract/` runnable against every adapter. It also leaves the
door open for an Amber or Lucky layer without touching the core.

## Module map

```
KemalIdentity
├── Principal              struct — who, when, at what assurance
├── AuthenticationResult   Authenticated | Failed  (union, see docs/02-security-model.md)
├── FailureReason          enum
├── AssuranceLevel         enum
├── Clock / SystemClock
├── RandomSource / SecureRandomSource
├── Errors
│   ├── InfrastructureError
│   └── ConfigurationError
│
├── Passwords
│   ├── Hasher             abstract
│   ├── BcryptHasher       stdlib Crypto::Bcrypt
│   ├── LegacyVerifier     abstract, read-only, forces rehash
│   ├── Policy             abstract — application-supplied
│   └── Authenticator      identifier + secret → result
│
├── Sessions
│   ├── Service            start / load / rotate / revoke
│   ├── Repository         abstract
│   ├── Record             struct
│   ├── Cookie             building and parsing, security prefixes
│   └── RememberService    one-time rotating token, family revocation
│
├── Accounts
│   ├── Repository         abstract
│   ├── Account            struct
│   ├── Service            confirmation, reset
│   ├── ActionToken        struct + purpose enum
│   └── Notifier           abstract — the app sends the mail
│
├── RateLimiter            abstract + Verdict
│
├── Testing                in-memory repositories, TestClock,
│                          DeterministicRandom, RecordingNotifier
│
└── Kemal
    ├── AuthenticationHandler
    ├── RequireAuthentication
    ├── RequireFresh
    ├── PathMatcher          ← our own; see docs/04-kemal-integration.md
    ├── CSRF
    └── RequestContext       env.auth
```

## Key decisions and their reasons

### `Principal#subject` is a `String`

Not a generic parameter. `KemalIdentity::RequestAuthenticator(T)` would propagate `T`
through every handler, every service and every repository in the type graph, and
the first user who wants a UUID in one place and an Int64 in another has an
unresolvable API. The account identifier crosses the auth boundary as a string;
the repository adapter converts to and from its native key type.

The cost is real and should be stated in the README: you will write
`user_id.to_i64` at the boundary. That is one conversion in application code
instead of a viral type parameter in library code.

### One identifier, not two

`Account#id` is *the* canonical subject. There is no separate "auth account id"
and "application user id" to keep in sync. If an application wants Kemal Identity's
account id to equal its own user id, the adapter simply returns that. If it
wants them distinct, the adapter maps them, and Kemal Identity never knows.

This is why `AccountRepository` is fully abstract and the shipped
`auth_accounts` table is a *reference implementation*, not a requirement. An
application that already has a `users` table with a password digest writes an
adapter over it and adds no tables at all beyond `auth_sessions` and
`auth_action_tokens`.

### Assurance and freshness are on the `Principal`

Not a boolean `logged_in?`. Three things the application routinely needs to know
are indistinguishable under a boolean:

- authenticated with a password just now,
- authenticated with a password two hours ago,
- restored silently from a remember-me cookie, having last typed a password
  three weeks ago.

Flask-Login's fresh/non-fresh split is the prior art; Kemal Identity generalizes it to
`AssuranceLevel` (how strongly) plus `authenticated_at` (how recently), so
`require_fresh!(within: 5.minutes)` is a caller decision rather than a
configured global. See `docs/01-architecture.md`.

### Password hashing gets its own execution context

Crystal 1.21 made execution contexts the default concurrency model. bcrypt
verification is CPU-bound for tens of milliseconds; running it on the request
fiber's context blocks every other fiber scheduled there. Kemal Identity runs hashing
and verification on a dedicated, small execution context so a burst of logins
degrades login latency rather than the whole application.

This is the one place where Kemal Identity can be meaningfully better than a
transliterated Devise, and it is why the benchmark suite measures application
latency under concurrent logins rather than hashes per second. See
`docs/02-security-model.md`.

### Configuration is boot-time and immutable

`KemalIdentity.configure` builds a frozen configuration object. Nothing mutates it
afterwards. Adapters must be safe for concurrent use from multiple fibers on
multiple threads — which, post-1.21, may genuinely be multiple threads.

Invalid configuration fails at boot, loudly: `Secure` cookies with a `__Host-`
prefix and a `Domain` set is a `ConfigurationError` raised at startup, not a
cookie silently rejected by the browser in production.

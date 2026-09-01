# Kemal Identity

[![CI](https://github.com/urunsiyabend/kemal-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/urunsiyabend/kemal-identity/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Authentication and identity primitives for Crystal applications, with first-class Kemal
integration.

Kemal Identity provides revocable server-side sessions, password authentication, CSRF
protection, bearer credentials, MFA, federated sign-in, and optional role-based authorization.
The core is framework-independent; the Kemal adapter adds request context and middleware.

## Features

- Opaque, server-side sessions with idle and absolute expiry
- Password authentication with bcrypt and lazy hash migration
- Secure cookie defaults and session fixation protection
- CSRF protection for authenticated and anonymous forms
- Password reset, email confirmation, and remember-me flows
- Opaque API tokens and opt-in JWT validation
- TOTP second factors and recovery codes
- OpenID Connect sign-in
- Optional RBAC with tenant-aware assignments
- PostgreSQL and SQLite adapters
- Structured security events and expired-record sweeping

Kemal Identity does not provide registration screens, profile management, application-specific
user models, or an OAuth2 authorization server. Applications own those concerns and integrate
them through repository and service contracts.

## Requirements

- Crystal 1.12 or newer
- Kemal 1.10 or newer; Kemal 1.13 or newer is recommended

Crystal 1.21 or newer is recommended when using `HashingExecutor`, which isolates CPU-intensive
password hashing from request execution. The project is currently pre-1.0, so minor releases may
contain breaking API changes; consult the [changelog](CHANGELOG.md) before upgrading.

## Installation

Add the shard to your application's `shard.yml`:

```yaml
dependencies:
  kemal_identity:
    github: urunsiyabend/kemal-identity
    version: ~> 0.9.0
```

Then install dependencies:

```bash
shards install
```

Database drivers are intentionally not transitive dependencies. Add the driver used by your
application:

```yaml
dependencies:
  kemal_identity:
    github: urunsiyabend/kemal-identity
    version: ~> 0.9.0
  pg:
    github: will/crystal-pg
```

Use `sqlite3` from `crystal-lang/crystal-sqlite3` instead of `pg` for SQLite.

## Quick start

The following example uses the reference PostgreSQL account and session repositories. Apply the
SQL files under [`migrations/postgres`](migrations/postgres) before starting the application.

```crystal
require "kemal"
require "kemal_identity/kemal"
require "kemal_identity/postgres"

db = DB.open(ENV["DATABASE_URL"])

KemalIdentity.configure(
  accounts: KemalIdentity::Postgres::AccountRepository.new(db),
  sessions: KemalIdentity::Postgres::SessionRepository.new(db),
  csrf: KemalIdentity::CSRFConfig.new(secret: ENV["CSRF_SECRET"]),
  rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(
    limit: 10,
    window: 5.minutes
  ),
  hasher: KemalIdentity::Passwords::HashingExecutor.new(
    KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
    size: 2
  )
)

# Order matters: error handling wraps authentication, and CSRF runs after it.
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new

get "/dashboard" do |env|
  principal = env.auth.require!
  "Signed in as #{principal.subject}"
end

Kemal.run
```

`CSRF_SECRET` must contain at least 32 bytes of cryptographically random material. Do not
register identity middleware at position `0`; it must remain behind Kemal's initialization
handler.

### Sign in and sign out

Kemal Identity exposes services rather than imposing routes, templates, or response formats:

```crystal
post "/login" do |env|
  result = KemalIdentity.app.passwords.authenticate(
    login: env.params.body["email"],
    password: env.params.body["password"],
    tenant_id: nil,
    ip: env.request.remote_address.to_s
  )

  case result
  in KemalIdentity::Authenticated
    env.auth.start!(result.principal)
    env.redirect "/dashboard"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # Keep the response identical for every failure reason.
    env.response.status_code = 401
    "Invalid email or password"
  end
end

post "/logout" do |env|
  env.auth.logout!
  env.redirect "/"
end
```

Call `env.auth.require!` inside individual routes, or guard an entire path subtree:

```crystal
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
use KemalIdentity::Kemal::PathGuard.new(prefix: "/account/security", within: 5.minutes)
```

`require!` produces a 401 response through `ErrorHandler`. Fresh-authentication and
authorization failures produce 403 responses. `env.auth.principal?`, `authenticated?`, `can?`,
and `authorize!` are available for optional rendering and authorization checks.

### CSRF-protected forms

Render the request-bound token in every form that performs an unsafe request, including the
login form:

```html
<input type="hidden" name="_csrf" value="<%= env.auth.csrf_token %>">
```

API clients may send the same value in the `X-CSRF-Token` header. Requests authenticated only
with a bearer token are exempt; requests that also present a session cookie remain protected.

## Storage and migrations

Require only the adapter your application uses:

```crystal
require "kemal_identity/postgres"
# or
require "kemal_identity/sqlite"
```

Migration sets are published separately for each database:

- [`migrations/postgres`](migrations/postgres)
- [`migrations/sqlite`](migrations/sqlite)

Copy or reference these SQL files from your application's migration tooling. The library never
changes schema during application startup.

`Postgres::AccountRepository` and `SQLite::AccountRepository` use the included `auth_accounts`
schema as reference implementations. Existing applications can implement
`KemalIdentity::Accounts::Repository` over their own users table. Session repositories accept
an alternate account table name:

```crystal
sessions = KemalIdentity::Postgres::SessionRepository.new(
  db,
  accounts_table: "users"
)
```

For SQLite, enable write-ahead logging and a busy timeout:

```crystal
db = DB.open("sqlite3://./identity.db?journal_mode=wal&busy_timeout=5000")
```

PostgreSQL is the recommended adapter for multi-process, write-heavy deployments.

## Optional capabilities

Optional services are disabled until all of their required dependencies are configured:

| Capability | Configuration |
| --- | --- |
| Password reset and email confirmation | `action_tokens:` and `notifier:` |
| Remember me | `remember_tokens:` |
| Opaque API tokens | `api_tokens:` |
| JWT validation | `jwt:` |
| TOTP MFA | `mfa_factors:`, `mfa_secret_key:`, and `mfa_issuer:` |
| Authorization | `authorizer:` |

This fail-closed wiring prevents partially configured security features from appearing to work.
See the [architecture](docs/01-architecture.md), [security model](docs/02-security-model.md), and
[data model](docs/03-data-model.md) for complete integration details.

## Production notes

- `NullRateLimiter` is the default and permits every attempt. Configure a shared limiter in
  multi-process deployments; `FixedWindowRateLimiter` is process-local.
- The default `__Host-kemal_identity` cookie is `Secure`, host-only, HTTP-only, and
  `SameSite=Lax`. To share sessions across subdomains, use a non-`__Host-` name and explicitly
  set a domain.
- For local HTTP development only, use a non-prefixed cookie name with `secure: false` and
  `allow_insecure: true`.
- `Principal#subject` is a `String`; convert it to your application's identifier type at the
  boundary.
- JWT support is off by default. If early revocation is required, configure a revocation store
  or prefer opaque API tokens.
- Run cleanup from one scheduler or cron job in multi-process deployments:

```crystal
KemalIdentity::Sweeper.new(KemalIdentity.app).sweep
```

Expired and revoked credentials are rejected during reads; sweeping only reclaims storage.

## Logging

Security events use Crystal's `Log` infrastructure under the `kemal_identity.*` namespace:

```crystal
Log.setup do |config|
  backend = Log::IOBackend.new
  config.bind "kemal_identity.*", :info, backend
end
```

Route these events to your audit pipeline and alert on high-signal events such as replay
detection, MFA recovery-code use, and repeated authentication failures. Secrets, raw tokens,
and password digests are not included in emitted events.

## Development

```bash
shards install
crystal tool format --check
shards build ameba
bin/ameba
crystal spec spec/unit spec/security spec/integration/sqlite_spec.cr
```

PostgreSQL integration specs additionally require `DATABASE_URL` and the PostgreSQL migrations.
See [testing](docs/05-testing.md) for the full test matrix.

## Documentation

- [Examples](examples/) — six runnable applications, each a single file: a browser site, a
  JSON API with scoped tokens, per-object authorization, a credential this shard does not ship,
  several JWT issuers, and a workload identity
- [Scope](docs/00-scope.md)
- [Architecture](docs/01-architecture.md)
- [Security model](docs/02-security-model.md)
- [Data model](docs/03-data-model.md)
- [Kemal integration](docs/04-kemal-integration.md)
- [Testing](docs/05-testing.md)
- [Changelog](CHANGELOG.md)

## License

Kemal Identity is available under the [MIT License](LICENSE).

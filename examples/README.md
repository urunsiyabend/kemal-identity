# Examples

Six runnable applications. CI compiles every one of them on every matrix entry, on every
supported Crystal and at the Kemal floor — an example that has drifted from the API is worse than
no example.

Each is a single `app.cr` with no setup: SQLite, schema applied on first boot, seed data created
in the file. Pick the one whose problem is yours and read it top to bottom; the comments are the
documentation, and they say *why* rather than *what*.

| Example | Run it | What it is for |
|---|---|---|
| [`browser_session`](browser_session/app.cr) | `crystal run examples/browser_session/app.cr` | A first-party website: log in, be remembered, step up before a sensitive action, reset a forgotten password, confirm an address, log out. Start here if you serve HTML. |
| [`api_tokens`](api_tokens/app.cr) | `crystal run examples/api_tokens/app.cr` | An API with no cookies: scoped bearer tokens, RFC 6750 challenges that say *why*, a management listing, and revocation scoped to the token's owner. Start here if you serve JSON. |
| [`ownership`](ownership/app.cr) | `crystal run examples/ownership/app.cr` | "May this person refund **this** invoice." An `Authz::Authorizer` of your own wrapping the shipped RBAC — including the downcast that fails **open** when written the obvious way, and what the grant cache costs on a list endpoint. |
| [`custom_bearer`](custom_bearer/app.cr) | `crystal run examples/custom_bearer/app.cr` | A credential this shard does not ship — a gateway-issued token — accepted alongside the ones it does, through `bearer_authenticators:`. Read this before writing an authentication handler of your own. |
| [`multi_issuer_jwt`](multi_issuer_jwt/app.cr) | `crystal run examples/multi_issuer_jwt/app.cr` | A resource server taking JWTs from several partners: one validator per issuer, routed with `JWT.unverified_issuer`, and why two validators cannot simply be chained. |
| [`service_account`](service_account/app.cr) | `crystal run examples/service_account/app.cr` | A workload identity — a CI job, a daemon. Provision without human-only fields, issue a scoped credential, prove every interactive path is closed, deprovision. Prints a trace rather than serving. |

Each server example prints the credentials it seeded, with `curl` lines in its header comment.

## What none of them do

**Register accounts, send mail, or render templates.** Creating an account is the application's
job (`docs/00-scope.md`), delivery is a `Notifier` you write, and HTML here is inline strings
because the point is the authentication wiring and nothing else.

**Run migrations the way you should.** These apply `migrations/sqlite/*.sql` themselves on boot.
A real application copies those files into its own migration tooling — a library that mutates the
schema on boot is one that will mutate it at the wrong moment (`docs/03-data-model.md`).

**Use production cookie settings.** They pass `secure: false, allow_insecure: true` because they
serve plain HTTP on localhost. The defaults are `__Host-` prefixed and `Secure`, and
`allow_insecure` is refused at boot unless you ask for it explicitly.

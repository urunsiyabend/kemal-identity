# 03 — Data model

## Relationship to the application's schema

The shard owns tables prefixed `auth_`. It does not own, touch, or require the
application's `users` table.

```
application users / customers / admins
          ▲
          │  account id  (canonical string, opaque to the shard)
          │
     auth_accounts ──┬── auth_sessions
                     ├── auth_action_tokens        (v0.2)
                     ├── auth_external_identities  (v0.5)
                     └── auth_mfa_factors          (v0.5)
```

`auth_accounts` is a **reference implementation of `AccountRepository`**, not a
requirement. An application that already has `users.email` and `users.password_digest` can
implement `AccountRepository` against that table and never create `auth_accounts`. This
distinction has to stay sharp in the code and the docs, because it is the difference
between "adoptable incrementally" and "rewrite your user model first".

What that means concretely: `auth_sessions.account_id` is a plain string column with no
foreign key to `auth_accounts` in the shipped migration. Adding the FK is correct when the
app does use `auth_accounts`, and is offered as a separate optional migration.

## v0.1 tables

### `auth_accounts` (optional, reference)

| Column | Type | Note |
|---|---|---|
| `id` | text PK | the only identifier: what `Principal#subject` carries and what `auth_sessions.account_id` references. No separate `subject_id` — see `blueprints/0005-one-account-identifier.md` |
| `tenant_id` | text null | unused in v0.1; present so tenancy is not a breaking migration |
| `normalized_login` | text not null | stored, not computed |
| `email_verified_at` | timestamptz null | |
| `disabled_at` | timestamptz null | |
| `auth_version` | int not null default 1 | bumped to invalidate all sessions |
| `password_digest` | text null | null = no password credential (external identity only) |
| `password_scheme` | text null | e.g. `bcrypt`; drives `needs_rehash?` |
| `created_at`, `updated_at` | timestamptz not null | |

Unique on `(tenant_id, normalized_login)`. In PostgreSQL a null `tenant_id` does not
collide under a plain unique constraint, so single-tenant deployments need
`UNIQUE (normalized_login) WHERE tenant_id IS NULL` as a partial index alongside it. This
is exactly the kind of detail that is easy to get wrong later and cheap to get right now.

Password digest lives in the same row rather than a separate `auth_password_credentials`
table. The separate table buys multiple concurrent password credentials per account, which
nothing in the roadmap needs, and costs a join on the login path.

### `auth_sessions`

```sql
-- +micrate Up
CREATE TABLE auth_sessions (
  id                  TEXT PRIMARY KEY,
  account_id          TEXT        NOT NULL,
  tenant_id           TEXT,
  token_digest        BYTEA       NOT NULL,
  auth_version        INTEGER     NOT NULL,
  assurance           SMALLINT    NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL,
  authenticated_at    TIMESTAMPTZ NOT NULL,
  mfa_verified_at     TIMESTAMPTZ,
  last_seen_at        TIMESTAMPTZ NOT NULL,
  idle_expires_at     TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_auth_sessions_digest  ON auth_sessions (token_digest);
CREATE INDEX        idx_auth_sessions_account ON auth_sessions (account_id)
  WHERE revoked_at IS NULL;
CREATE INDEX        idx_auth_sessions_sweep   ON auth_sessions (absolute_expires_at);

-- +micrate Down
DROP TABLE auth_sessions;
```

Notes on the choices:

- `token_digest` is `BYTEA`, not a hex `CHAR(64)`. Half the storage, and no encoding to get
  inconsistent between adapters.
- The unique index on `token_digest` is what makes the hot path a single index lookup, and
  it also makes a digest collision a database error rather than a silent security failure.
- `idx_auth_sessions_account` is partial. "Log out everywhere" and "list my devices" only
  ever care about live sessions, and the partial index stays small as revoked rows
  accumulate before the sweeper runs.
- `authenticated_at` and `mfa_verified_at` are stored; `fresh_until` is not. Decision D5.
- `assurance` is a `SMALLINT` of the enum value. Store the numeric value, not the name, and
  never renumber the enum — append only.

### `auth_action_tokens` (schema in v0.1, flows in v0.2)

```sql
-- +micrate Up
CREATE TABLE auth_action_tokens (
  id           TEXT PRIMARY KEY,
  account_id   TEXT        NOT NULL,
  purpose      TEXT        NOT NULL,   -- reset | confirm | invite
  token_digest BYTEA       NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_auth_action_tokens_digest ON auth_action_tokens (token_digest);
CREATE INDEX idx_auth_action_tokens_lookup
  ON auth_action_tokens (account_id, purpose, expires_at) WHERE used_at IS NULL;

-- +micrate Down
DROP TABLE auth_action_tokens;
```

Consumption is atomic and must be written as a conditional update, never a read-then-write:

```sql
UPDATE auth_action_tokens
   SET used_at = $1
 WHERE token_digest = $2 AND used_at IS NULL AND expires_at > $1
```

Then check the affected row count. A count of zero means expired, already used, or unknown —
and the three are indistinguishable to the caller by design.

## The hot path, and why the lookup is one query

Per authenticated request:

```
parse cookie → validate shape → SHA-256 → indexed lookup → expiry/revocation/status checks
```

That lookup must return session state *and* account status together (decision D7):

```sql
SELECT s.*, a.disabled_at AS account_disabled_at, a.auth_version AS account_auth_version
  FROM auth_sessions s
  JOIN auth_accounts a ON a.id = s.account_id
 WHERE s.token_digest = $1
```

Two round-trips per request — one for the session, one for the account — roughly doubles
the fixed cost of every authenticated page view for no benefit. When the application
implements `AccountRepository` against its own `users` table, its `SessionRepository`
implementation is responsible for producing the same joined result; the contract spec
asserts the result shape, not the SQL.

What must **not** happen on this path: loading the full domain user, its roles, or its
linked identities. `Principal` carries the minimum security context. The application loads
its own user object when it actually needs one.

## Migrations

Micrate's `-- +micrate Up` / `-- +micrate Down` **file format**, PostgreSQL only in v0.1.
Migrations live in `migrations/postgres/` and are published as files the application copies
in, not run automatically by the shard. An auth library that mutates the schema on boot is a
library that will one day mutate it at the wrong moment.

The format, not the tool: neither published micrate runs on this stack — 0.3.3 requires the
`logger` module Crystal dropped in 0.35, and 0.15.1 requires `db ~> 0.11.0` against
crystal-pg's `db ~> 0.14.0`. This repository reads the same directives with its own
`bin/migrate`, so a consuming application whose tooling already understands them applies
these files unchanged. See `blueprints/0002-no-micrate-dependency.md`.

Since a second dialect is planned, keep the SQL close to portable — but do not pretend one
file will serve all three. `BYTEA` vs `BLOB` and `TIMESTAMPTZ` vs `TEXT` are real
differences, and the plan is per-dialect migration sets sharing a contract test, not a
lowest-common-denominator schema.

## Sweeper

```crystal
KemalIdentity::Sessions::Sweeper.new(app).run_every(1.hour)
```

Deletes rows past `absolute_expires_at` and revoked rows older than a retention window.
Purely a disk-reclamation job — correctness never depends on it having run. Ships as an
opt-in fiber the application starts, not something the shard spawns on its own; a library
that silently starts background work is a library that surprises people in a
multi-process deployment.

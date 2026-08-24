# 0005 — One account identifier

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/accounts/account.cr` and
`migrations/postgres/20260824120000_create_auth_accounts.sql`.

## Context

Two design documents describe account identity differently.

`docs/01-architecture.md`, under "One identifier, not two":

> `Account#id` is *the* canonical subject. There is no separate "auth account id" and
> "application user id" to keep in sync. If an application wants Kemal Identity's account id
> to equal its own user id, the adapter simply returns that. If it wants them distinct, the
> adapter maps them, and Kemal Identity never knows.

`docs/03-data-model.md`'s reference table lists two columns: `id text PK`, and
`subject_id text not null` — "what `Principal#subject` carries".

Those cannot both hold. With a separate `subject_id`, there are two identifiers in play on
the hot path: `auth_sessions.account_id` joins on `auth_accounts.id`, while
`Principal#subject` carries `subject_id`. Every write has to keep them consistent, and the
consequence of them drifting is not a broken page — it is a session resolving to the wrong
subject, which is the worst class of bug this shard can have.

It is also the exact arrangement `docs/01-architecture.md` rejects, by name, with a reason.

## Decision

**`Account#id` is the only identifier.** It is what `Principal#subject` carries, what
`auth_sessions.account_id` references, and what `Repository#find_by_id` takes.
`subject_id` is removed from the reference migration and from `docs/03-data-model.md`.

An application that needs the shard's identifier to differ from its own user id does that
mapping inside its `Repository` implementation — which is what `docs/01-architecture.md`
prescribes, and what makes the abstract repository worth having. The mapping then lives in
one adapter, under test, instead of being a column two writers have to agree about.

## Consequences

- One less column, and no synchronisation invariant to get wrong.
- `Principal#subject == Account#id`, always, with nothing in between. A reader of a session
  row can see which account it belongs to without consulting a second mapping.
- An application wanting an opaque external subject writes it in its adapter. That is
  strictly more capable than a column, since it can compute the value rather than store it.
- `docs/03-data-model.md`'s account table is updated. The `auth_sessions` and
  `auth_action_tokens` tables are unaffected — both already reference `account_id` with no
  foreign key, precisely so that an application using its own `users` table has nothing to
  point at.

## Alternative considered

Keeping the column and declaring it a seam for applications that fork the reference schema.
Rejected: nothing in the shard would read it, so it would be a `NOT NULL` column whose only
documented purpose is to be ignored. A column that exists to be unused is worse than no
column, because the next reader has to work out whether ignoring it is a bug.

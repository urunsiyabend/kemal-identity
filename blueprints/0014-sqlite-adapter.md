# 0014 — The SQLite adapter, and what its concurrency specs do not prove

## Status

Accepted, 2026-08-26. Implemented in `src/kemal_identity/sqlite/`.

## Why a third implementation

`docs/06-roadmap.md` puts a SQLite adapter in v0.3, "which also makes CI cheaper". That is the
smaller half of the reason.

The larger half is that the in-memory doubles and the PostgreSQL adapters were written by the
same reasoning within days of each other. A third implementation in a genuinely different
dialect — different types, different placeholders, a different locking model — is what turns
the contract specs from a shared convention into a constraint. All 111 contract examples pass
against SQLite without a single change to any contract, which is the result worth having.

It also means the whole suite runs anywhere `crystal spec` does. `spec/integration/postgres_spec.cr`
reports pending without a server; the SQLite specs never do.

## Dialect differences that mattered

| | PostgreSQL | SQLite |
|---|---|---|
| Digest column | `BYTEA` | `BLOB` |
| Timestamps | `TIMESTAMPTZ` | `TEXT`, UTC, exact round trip |
| Assurance | `SMALLINT` | `INTEGER`, narrowed on read |
| Placeholders | `$1`, reusable | `?`, positional — `except_id` is bound twice |
| Null-tenant lookup | `IS NULL` | `IS NULL` — same trap, same fix |

`docs/03-data-model.md` calls for per-dialect migration sets rather than one
lowest-common-denominator schema, and this is why: four of the five rows above are schema
differences that no shared file could express honestly.

## Inserts use `ON CONFLICT DO NOTHING`, not a rescue

The PostgreSQL adapters catch the driver's exception and check for SQLSTATE `23505`. The first
version of this adapter did the same with `SQLite3::Exception`, and it did not work.

crystal-sqlite3 surfaces a constraint failure when the statement is **finalised**, not when
`exec` returns. The exception is raised from inside `ensure`-time cleanup, so a `rescue` around
the insert never sees it — and the stray exception then propagates out of the connection pool
at close, aborting the run after the examples have already reported.

So the inserts say `ON CONFLICT DO NOTHING` and raise `InfrastructureError` when
`rows_affected` is zero. Race-free, entirely within one statement, and it covers the primary
key as well as the unique index — on these tables both mean the same thing to a caller.

## What the concurrency specs prove here, and what they do not

This is the part worth recording.

Every repository contract has a concurrency example asserting that exactly one of many
simultaneous callers spends a token. On PostgreSQL these are real: replacing a conditional
`UPDATE` with a read-then-write fails them in every run
(`blueprints/0011-action-token-atomicity.md`).

On SQLite the same mutation **passes**. Measured against a deliberately racy implementation:

| Fibers | Rounds catching the race (out of 30) |
|---|---|
| 24 | 0 |
| 64 | 0 |

The reason is not that SQLite makes read-then-write safe. It is that a SQLite call is an
in-process C function with no I/O boundary, so it never yields the fiber. On a single-threaded
scheduler each fiber therefore runs its `SELECT` and its `UPDATE` back to back with nothing
scheduled in between, and the interleaving the example is looking for cannot occur. The
connection pool is not the limiter — it is unbounded, and twenty-four fibers do get
twenty-four distinct connections.

Two consequences, both stated rather than assumed:

- **The single-statement shape is a contract requirement, not an optimisation.** On SQLite it
  is verified by reading the adapter, not by racing it. `#consume` is one conditional
  `UPDATE ... RETURNING`, and `RememberRepository#consume` runs its update before its lookup,
  for the same reasons as in PostgreSQL.
- **This could change.** Under a multi-threaded execution context two fibers can genuinely be
  inside SQLite at once, and a read-then-write would then be racy in fact as well as in
  principle. The shape is what makes that a non-question.

The general lesson is the one from `blueprints/0011`, sharpened: a green concurrency spec
proves the absence of an observed symptom, never the presence of atomicity. Here it does not
even prove the former.

## Operational notes

`journal_mode=wal` and a `busy_timeout` belong in the connection string. SQLite serialises
writers across the whole file; without WAL a reader blocks a writer, and without a busy timeout
a contended write fails immediately with `database is locked` rather than waiting. Neither is a
correctness problem for this shard — every write is a single statement — but both turn ordinary
contention into errors.

The specs use a temporary **file**, never `:memory:`. Each connection to an in-memory SQLite
gets its own private database, so a pool of more than one would hand every fiber an empty
schema and the contract examples would pass while testing nothing.

## A spec-ordering trap, recorded because it cost time

Cleanup was first written as `at_exit`. Crystal's spec runner registers *its* `at_exit` when
`spec` is required — before this file's top-level code — and handlers run last-registered-first.
The cleanup therefore closed the database and deleted the file **before a single example ran**,
and all 111 failed with `no such table`. `Spec.after_suite` is the correct hook.

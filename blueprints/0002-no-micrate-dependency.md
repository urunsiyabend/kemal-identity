# 0002 — No micrate dependency

## Status

Accepted, 2026-08-24. Implemented as `tools/migrate.cr`.

## Context

`docs/03-data-model.md` specifies micrate, with its `-- +micrate Up` / `-- +micrate Down`
directives, as the migration tool. Neither published micrate can be used on this stack:

- **micrate 0.3.3** — what `shards` resolves when the dependency is unconstrained — fails
  to compile: `require "logger"`, and `logger` was removed from Crystal's standard library
  in 0.35 (2020). It is also a library rather than a binary, declaring no target and
  depending on `crystal-db` only, so the driver has to be required by whoever builds the
  CLI.
- **micrate 0.15.1**, the current release, compiles (it uses `Log`) but cannot resolve:
  it requires `db ~> 0.11.0`, while `crystal-pg 0.30.0` requires `db ~> 0.14.0`. There is
  no version of `crystal-db` that satisfies both.

Its `migrations_dir` is also hardcoded to `db/migrations` with no setter — and
`migrations_by_version` embeds the literal string a second time — which conflicts with the
per-dialect `migrations/postgres/` layout that `docs/03-data-model.md` requires so that
SQLite and MySQL can get sibling directories instead of one lowest-common-denominator
schema. A symlink bridges that, but only for a micrate that runs at all.

## Decision

The repository depends on no migration tool. `tools/migrate.cr` (built as `bin/migrate`)
applies the files in `migrations/postgres/`, and exists to give the integration and
concurrency specs a schema. It supports `up`, `down` and `status`, tracks applied versions
in `kemal_identity_schema_migrations`, and runs each migration in its own transaction.

**The published `.sql` files keep the `-- +micrate Up` / `-- +micrate Down` directives.**
The runner parses exactly those directives, so one set of files serves both this repository
and any consuming application whose own tooling — micrate on a compatible stack, or Amber —
already understands them. That is the property worth preserving; the tool that reads them is
not.

Two implementation details that were not obvious:

- Statements go through `PG::Connection#exec_all`, not `exec`. PostgreSQL's extended
  (prepared) protocol accepts exactly one command per statement, so a multi-statement
  migration body fails with `cannot insert multiple commands into a prepared statement`.
  crystal-pg's `unprepared` is an alias for the prepared builder and does not help;
  `exec_all` is the simple-protocol path. Splitting the section on `;` was rejected — it
  breaks the first time a migration carries a dollar-quoted function body.
- `migrations/postgres/optional/` is a directory, and the runner filters candidates through
  `File.file?`, so the optional foreign-key migration is never picked up by `up`.

## Consequences

- One fewer dependency, and no dev dependency that cannot resolve.
- This runner is repository tooling, not a shard feature. It stays out of `src/`. An auth
  library that runs migrations for you is one that will run them at the wrong moment
  (`docs/03-data-model.md`).
- `docs/03-data-model.md`'s reference to micrate as *the* tool is now a reference to the
  *file format*. The document has been updated accordingly.
- The version table is ours (`kemal_identity_schema_migrations`) and is deliberately not
  micrate's `micrate_db_version`. Nothing else reads this database, and pretending to be
  interoperable with a tool that cannot run here would be worse than being explicit.

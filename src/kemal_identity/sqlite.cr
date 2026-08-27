require "sqlite3"
require "../kemal_identity"

require "./sqlite/account_repository"
require "./sqlite/session_repository"
require "./sqlite/action_token_repository"
require "./sqlite/remember_repository"
require "./sqlite/api_token_repository"
require "./sqlite/mfa_repository"

# The SQLite adapters.
#
# Required separately from the core and from the PostgreSQL adapters, so an application links
# only the driver it uses.
#
# ```
# require "kemal_identity/sqlite"
#
# db = DB.open("sqlite3://./identity.db?journal_mode=wal&busy_timeout=5000")
#
# KemalIdentity.configure(
#   accounts: KemalIdentity::SQLite::AccountRepository.new(db),
#   sessions: KemalIdentity::SQLite::SessionRepository.new(db),
# )
# ```
#
# ### Use `journal_mode=wal` and a `busy_timeout`
#
# SQLite serialises writers across the whole database rather than per row. Without
# write-ahead logging a reader blocks a writer, and without a busy timeout a concurrent write
# fails immediately with `database is locked` instead of waiting its turn. Neither is a
# correctness problem for this shard — every write here is a single statement — but both turn
# ordinary contention into visible errors.
#
# ### What SQLite is and is not for here
#
# It exists so the contract specs have a third implementation, and because a single-process
# deployment or a test suite should not need a database server. It is a real adapter, not a
# toy: it runs every contract spec the PostgreSQL adapters run.
#
# It is still SQLite. One writer at a time across the entire file means a busy application
# behind several processes wants PostgreSQL, and `docs/03-data-model.md` keeps the dialects as
# sibling migration sets rather than pretending one schema serves both.
module KemalIdentity::SQLite
end

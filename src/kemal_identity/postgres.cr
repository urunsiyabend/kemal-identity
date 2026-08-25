require "pg"
require "../kemal_identity"

require "./postgres/account_repository"
require "./postgres/session_repository"
require "./postgres/action_token_repository"

# The PostgreSQL adapters.
#
# Required separately from the core, so that an application using its own storage — or the
# in-memory doubles in a spec — never links a database driver it does not use.
#
# ```
# require "kemal_identity/postgres"
#
# db = DB.open(ENV["DATABASE_URL"])
#
# KemalIdentity.configure(
#   accounts: KemalIdentity::Postgres::AccountRepository.new(db),
#   sessions: KemalIdentity::Postgres::SessionRepository.new(db),
# )
# ```
#
# The migrations live in `migrations/postgres/` and are copied into the application's own
# tooling — they are not run from here. An auth library that mutates the schema on boot is one
# that will mutate it at the wrong moment (`docs/03-data-model.md`).
#
# Both classes run the same contract specs as the in-memory doubles in `spec/support`. That is
# the only thing that makes those doubles trustworthy: a double that quietly behaves
# differently from PostgreSQL turns a green suite into false confidence.
module KemalIdentity::Postgres
end

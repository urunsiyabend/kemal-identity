require "kemal"
require "../kemal_identity"

require "./kemal/request_context"
require "./kemal/authentication_handler"
require "./kemal/path_guard"
require "./kemal/csrf_handler"
require "./kemal/error_handler"

# The Kemal adapter.
#
# This is the only layer that knows `HTTP::Server::Context` exists. Everything under
# `src/kemal_identity/{core,accounts,sessions,passwords}` is framework-agnostic, which is what
# makes `spec/unit` runnable without a server and leaves the door open to an Amber or Lucky
# adapter without touching the core (`docs/01-architecture.md`).
#
# ### Wiring
#
# ```
# require "kemal"
# require "kemal_identity/kemal"
#
# KemalIdentity.configure(
#   accounts: MyAccountRepository.new,
#   sessions: KemalIdentity::Postgres::SessionRepository.new(db),
# )
#
# use KemalIdentity::Kemal::ErrorHandler.new          # outermost: catches what guards raise
# use KemalIdentity::Kemal::AuthenticationHandler.new # populates env.auth; never rejects
# use KemalIdentity::Kemal::CSRFHandler.new           # after authentication: the token binds to the session
# use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
# ```
#
# Order matters and is not obvious, so it is spelled out in the README. Two rules: nothing
# authentication-related is registered at position `0` (that position takes over Kemal's
# temporary-file cleanup), and `ErrorHandler` goes outside anything that raises.
module KemalIdentity::Kemal
end

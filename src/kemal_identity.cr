require "base64"
require "digest/sha256"
require "crypto/subtle"

require "./kemal_identity/version"
require "./kemal_identity/log"
require "./kemal_identity/core/errors"
require "./kemal_identity/core/assurance_level"
require "./kemal_identity/core/failure_reason"
require "./kemal_identity/core/clock"
require "./kemal_identity/core/random_source"
require "./kemal_identity/core/secret"
require "./kemal_identity/core/principal"
require "./kemal_identity/core/outcome"

require "./kemal_identity/passwords/hasher"
require "./kemal_identity/passwords/bcrypt_hasher"
require "./kemal_identity/passwords/hashing_executor"

require "./kemal_identity/accounts/login"
require "./kemal_identity/accounts/account"
require "./kemal_identity/accounts/repository"

require "./kemal_identity/sessions/record"
require "./kemal_identity/sessions/lookup"
require "./kemal_identity/sessions/repository"
require "./kemal_identity/sessions/config"
require "./kemal_identity/sessions/token"
require "./kemal_identity/sessions/cookie"
require "./kemal_identity/sessions/service"

require "./kemal_identity/passwords/policy"
require "./kemal_identity/passwords/authenticator"

require "./kemal_identity/rate_limiter"
require "./kemal_identity/csrf"
require "./kemal_identity/application"

# Authentication for Crystal web applications.
#
# The core is framework-agnostic: nothing under `src/kemal_identity/core` knows that
# `HTTP::Server::Context` exists. Require `kemal_identity/kemal` for the Kemal adapter.
module KemalIdentity
end

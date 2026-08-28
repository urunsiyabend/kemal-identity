require "uri"
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
require "./kemal_identity/core/opaque_token"
require "./kemal_identity/core/principal"
require "./kemal_identity/core/outcome"
require "./kemal_identity/core/request_authenticator"
require "./kemal_identity/core/authenticator_chain"

require "./kemal_identity/passwords/hasher"
require "./kemal_identity/passwords/bcrypt_hasher"
require "./kemal_identity/passwords/legacy_verifier"
require "./kemal_identity/passwords/migrating_hasher"
require "./kemal_identity/passwords/hashing_executor"

require "./kemal_identity/accounts/login"
require "./kemal_identity/accounts/account"
require "./kemal_identity/accounts/repository"
require "./kemal_identity/accounts/action_token"
require "./kemal_identity/accounts/action_token_repository"
require "./kemal_identity/accounts/notifier"

require "./kemal_identity/sessions/record"
require "./kemal_identity/sessions/lookup"
require "./kemal_identity/sessions/repository"
require "./kemal_identity/sessions/remember_token"
require "./kemal_identity/sessions/remember_repository"
require "./kemal_identity/sessions/config"
require "./kemal_identity/sessions/token"
require "./kemal_identity/sessions/cookie"
require "./kemal_identity/sessions/service"
require "./kemal_identity/sessions/remember_service"

require "./kemal_identity/passwords/policy"
require "./kemal_identity/passwords/authenticator"
require "./kemal_identity/api_tokens/token"
require "./kemal_identity/api_tokens/repository"
require "./kemal_identity/api_tokens/service"

require "./kemal_identity/oidc/provider"
require "./kemal_identity/oidc/pending"
require "./kemal_identity/oidc/link"
require "./kemal_identity/oidc/client"
require "./kemal_identity/oidc/pending_codec"

require "./kemal_identity/mfa/base32"
require "./kemal_identity/mfa/totp"
require "./kemal_identity/mfa/secret_box"
require "./kemal_identity/mfa/factor"
require "./kemal_identity/mfa/repository"
require "./kemal_identity/mfa/service"

require "./kemal_identity/jwt/algorithm"
require "./kemal_identity/jwt/rsa"
require "./kemal_identity/jwt/key"
require "./kemal_identity/jwt/jwks"
require "./kemal_identity/jwt/revocation_store"
require "./kemal_identity/jwt/validator"

require "./kemal_identity/authz/permission"
require "./kemal_identity/authz/role"
require "./kemal_identity/authz/decision"
require "./kemal_identity/authz/membership"
require "./kemal_identity/authz/repository"
require "./kemal_identity/authz/authorizer"
require "./kemal_identity/authz/cache"
require "./kemal_identity/authz/rbac"

require "./kemal_identity/accounts/service"

require "./kemal_identity/rate_limiter"
require "./kemal_identity/csrf"
require "./kemal_identity/application"
require "./kemal_identity/sweeper"

# Authentication for Crystal web applications.
#
# The core is framework-agnostic: nothing under `src/kemal_identity/core` knows that
# `HTTP::Server::Context` exists. Require `kemal_identity/kemal` for the Kemal adapter.
module KemalIdentity
end

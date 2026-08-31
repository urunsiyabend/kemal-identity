# The shared contract specs every implementation of a `kemal_identity` contract should run.
#
# ```
# require "kemal_identity/testing/contracts"
#
# it_behaves_like_a_session_repository { MyRedisSessionRepository.new(redis) }
# ```
#
# A double that behaves differently from the shipped adapters turns a green suite into false
# confidence, which is the whole reason these exist -- and the reason they are published rather
# than kept in this repository's `spec/` tree.
#
# ### What they do and do not check
#
# Each contract asserts the behaviour its abstract class documents: return values, the
# atomic operations, the loud failures, and fiber-level concurrency where the contract requires
# it. Two limits are worth knowing before trusting a green run:
#
# * **Concurrency is tested with fibers in one process.** A store shared between *processes* can
#   pass every example here and still lose updates -- measured, and recorded under OPS-01 in
#   `blueprints/0025-maturity-validation-results.md`, where a limiter passed all twelve examples
#   while allowing 2.2x its global limit across six processes. If your adapter is backed by
#   shared storage, test that separately.
# * **`it_behaves_like_an_account_repository` requires multi-tenant behaviour.** Three of its
#   examples cover tenant scoping, so a single-tenant adapter over an existing `users` table with
#   no tenant column cannot pass them. That is IDP-03's recorded gap; the rest of the contract
#   still applies.
require "spec"

require "../testing"

require "./contracts/account_repository_contract"
require "./contracts/action_token_repository_contract"
require "./contracts/api_token_repository_contract"
require "./contracts/authz_repository_contract"
require "./contracts/clock_contract"
require "./contracts/federation_link_repository_contract"
require "./contracts/hasher_contract"
require "./contracts/jwt_revocation_store_contract"
require "./contracts/mfa_repository_contract"
require "./contracts/random_source_contract"
require "./contracts/rate_limiter_contract"
require "./contracts/remember_repository_contract"
require "./contracts/session_repository_contract"

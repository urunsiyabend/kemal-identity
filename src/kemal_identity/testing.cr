# Test doubles, fixtures and assertions for applications building on this shard.
#
# ```
# require "kemal_identity/testing"
# ```
#
# Everything here is `KemalIdentity::Testing`: in-memory implementations of every repository
# contract, a clock that only moves when a spec moves it, a seeded random source, a fast hasher,
# and the assertion helpers this shard's own suite uses.
#
# **Not required by `kemal_identity` itself.** An application that never requires this compiles
# none of it, which is why the in-memory repositories can live in `src/` without costing a
# production consumer anything.
#
# ### Why this is published rather than private
#
# An adapter author writing a Redis session store or a repository over an existing `users` table
# needs the same doubles and the same shared contracts this suite runs. Before v0.8 those lived
# under `spec/`, reachable only by requiring this repository's own `spec_helper` -- a private
# path, undocumented, and pulling in every double whether wanted or not. That was measured as
# DEV-02's result in `blueprints/0025-maturity-validation-results.md`, and this file is the
# answer to it.
#
# The shared contracts are a separate require, because they define `describe`/`it` blocks and so
# pull in `spec`:
#
# ```
# require "kemal_identity/testing/contracts"
#
# it_behaves_like_a_session_repository { MyRedisSessionRepository.new(redis) }
# ```
require "spec"

require "../kemal_identity"

require "./testing/or_fail"
require "./testing/assertions"
require "./testing/fiber_join"
require "./testing/clock"
require "./testing/random"
require "./testing/hasher"
require "./testing/legacy_verifiers"
require "./testing/notifier"
require "./testing/rsa_key"
require "./testing/jwt_forge"

require "./testing/memory_account_repository"
require "./testing/memory_session_repository"
require "./testing/memory_action_token_repository"
require "./testing/memory_remember_repository"
require "./testing/memory_api_token_repository"
require "./testing/memory_revocation_store"
require "./testing/memory_mfa_repository"
require "./testing/memory_link_repository"
require "./testing/memory_authz_repository"

require "./testing/fixtures"

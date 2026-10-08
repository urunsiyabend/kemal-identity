# Compiled, never run, by CI and by `tools/release/verify.sh`: a program that requires the core
# and the published test doubles and **no adapter**, which is what a consumer on its own storage
# builds. The suite cannot stand in for it, because the suite is one binary that requires both
# adapters, and a type that only exists there changes how the core type-checks.
#
# It caught one: v0.13.0's `Sweeper#sweep` summed rate-limit sweeps with `Enumerable#sum`, whose
# element type is `NoReturn` when nothing includes `SweepableRateLimiter` — so the sweeper
# compiled in this repository and failed in every core-only application that called it.
require "../../src/kemal_identity"
require "../../src/kemal_identity/testing"

accounts = KemalIdentity::Testing::MemoryAccountRepository.new
app = KemalIdentity::Application.new(
  accounts: accounts,
  sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
  hasher: KemalIdentity::Testing::FastTestHasher.new,
)

KemalIdentity::Sweeper.new(app).sweep
KemalIdentity.validate_production!(app, accept: KemalIdentity::ProductionGap.values)

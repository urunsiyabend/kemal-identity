require "kemal_identity"
require "kemal_identity/testing"
require "../src/tok04_gateway"

# TOK-04's fifth pass condition: "Registration needs no custom HTTP handler."
accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

app = KemalIdentity.configure(
  accounts: accounts,
  sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
  hasher: KemalIdentity::Testing::FastTestHasher.new,
  clock: clock,
  bearer: GatewayAuthenticator.new("gateway-shared-secret", clock),
)

puts app.bearer.class

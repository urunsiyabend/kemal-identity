require "spec"
require "kemal_identity"
require "sqlite3"
require "kemal_identity/testing"
require "../src/legacy_users"
require "kemal_identity/testing/contracts"

CONTRACT_DB = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/idp03_contract.db"

# The shard's own AccountRepository contract, run against an adapter over a consumer-owned
# `users` table. Seeding is the adapter's job, which the contract says explicitly.
it_behaves_like_an_account_repository(tenanted: false) do |accounts|
  File.delete?(CONTRACT_DB)
  db = DB.open("sqlite3://#{CONTRACT_DB}")
  LegacyUserRepository.migrate!(db)

  accounts.each do |account|
    db.exec(
      "INSERT INTO users (id, email, email_lower, password_hash, password_scheme, auth_epoch, " \
      "confirmed_at, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      account.id,
      # The application's own NOT NULL column, derived from what the contract supplied.
      account.normalized_login,
      account.normalized_login,
      account.password_digest,
      account.password_scheme || "sha256",
      account.auth_version,
      account.email_verified_at,
      account.disabled_at,
      account.created_at,
      account.updated_at,
    )
  end

  LegacyUserRepository.new(db)
end

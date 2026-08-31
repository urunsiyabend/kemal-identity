require "spec"
require "kemal_identity"

# DEV-02, after the change: the published require, no reaching into the shard's spec tree.
require "kemal_identity/testing"
require "kemal_identity/testing/contracts"

require "kemal_identity/sqlite"
require "sqlite3"

DEV02B_DB = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/dev02b.db"

private def fresh_db(accounts)
  File.delete?(DEV02B_DB)
  db = DB.open("sqlite3://#{DEV02B_DB}")
  Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
    body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
    body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
      .reject(&.strip.empty?).each { |stmt| db.exec(stmt) }
  end
  accounts.each do |account|
    db.exec(
      "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at, disabled_at) " \
      "VALUES (?, ?, ?, ?, ?, ?)",
      account.id, account.normalized_login, account.auth_version,
      account.created_at, account.updated_at, account.disabled_at
    )
  end
  db
end

# The doubles are reachable by their published names.
describe "DEV-02: the published testing entry point" do
  it "gives a consumer the in-memory doubles" do
    KemalIdentity::Testing::MemoryAccountRepository.new(
      [KemalIdentity::Testing.account]
    ).find_by_id("a1").should_not be_nil
  end

  it "gives a consumer the fixtures and the fixed clock" do
    KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
      .now.should eq(KemalIdentity::Testing::FIXED_NOW)
  end

  it "gives a consumer the assertion helpers" do
    KemalIdentity::Testing.should_authenticate(
      KemalIdentity::Authenticated.new(KemalIdentity::Testing.principal)
    ).subject.should eq("account-1")
  end
end

# And the contracts run against the consumer's own adapter, by the published name.
it_behaves_like_an_api_token_repository do |accounts|
  KemalIdentity::SQLite::ApiTokenRepository.new(fresh_db(accounts))
end

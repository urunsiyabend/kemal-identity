require "spec"
require "kemal_identity"
require "kemal_identity/sqlite"
require "sqlite3"

# TOK-01 pass condition: "No second token lookup is required merely to rediscover the token ID."
# Counted, not asserted: the repository is wrapped and every digest lookup tallied.
private class CountingTokenRepository < KemalIdentity::ApiTokens::Repository
  getter digest_lookups = 0

  def initialize(@inner : KemalIdentity::ApiTokens::Repository)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::ApiTokens::Lookup?
    @digest_lookups += 1
    @inner.find_by_digest(digest)
  end

  def create(token : KemalIdentity::ApiTokens::Token) : Nil
    @inner.create(token)
  end

  def touch(id : String, last_used_at : Time) : Bool
    @inner.touch(id, last_used_at)
  end

  def revoke(id : String, at : Time) : Bool
    @inner.revoke(id, at)
  end

  def revoke_all_for_account(account_id : String, at : Time) : Int32
    @inner.revoke_all_for_account(account_id, at)
  end

  def list_for_account(account_id : String) : Array(KemalIdentity::ApiTokens::Token)
    @inner.list_for_account(account_id)
  end

  def delete_expired(before : Time) : Int32
    @inner.delete_expired(before)
  end
end

DB2 = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/tok01b.db"

describe "TOK-01: hot-path cost" do
  it "resolves a token, its id and its scopes in one lookup" do
    File.delete?(DB2)
    db = DB.open("sqlite3://#{DB2}")
    Dir.glob("/home/urunsiyabend/personal/development/kemal_identity/migrations/sqlite/*.sql").sort.each do |path|
      body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
      body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';')
        .reject(&.strip.empty?).each { |stmt| db.exec(stmt) }
    end
    db.exec(
      "INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      "acct-1", "ada@example.com", 1, Time.utc, Time.utc
    )

    counting = CountingTokenRepository.new(KemalIdentity::SQLite::ApiTokenRepository.new(db))
    api = KemalIdentity::ApiTokens::Service.new(
      tokens: counting, clock: KemalIdentity::SystemClock.new,
      random: KemalIdentity::SecureRandomSource.new
    )
    accounts = KemalIdentity::SQLite::AccountRepository.new(db)
    issued = api.issue(accounts.find_by_id("acct-1").not_nil!, "ci", scopes: ["reports.read"])

    counting.digest_lookups.should eq(0)

    principal = api.authenticate(issued.token.reveal).as(KemalIdentity::Authenticated).principal

    # One lookup, and it produced the identity, the token id and the scopes together.
    counting.digest_lookups.should eq(1)
    principal.credential.not_nil!.id.should eq(issued.record.id)
    principal.credential.not_nil!.scopes.should eq(["reports.read"])

    db.close
  end
end

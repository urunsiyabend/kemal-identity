require "../spec_helper"

# `ApiTokens::Service#revoke_family`, and the default every third-party repository inherits.
# The atomicity itself is the repository contract's job, and a PostgreSQL probe watches it from
# a second connection (`spec/integration/postgres_spec.cr`).

# A repository written before `revoke_family` existed: every abstract method and nothing else,
# which is what a third-party adapter looks like on upgrade. It must still compile.
private class NotFamilyAware < KemalIdentity::ApiTokens::Repository
  def initialize(accounts : KemalIdentity::Testing::MemoryAccountRepository)
    @inner = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)
  end

  def create(token : KemalIdentity::ApiTokens::Token) : Nil
    @inner.create(token)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::ApiTokens::Lookup?
    @inner.find_by_digest(digest)
  end

  def touch(id : String, last_used_at : Time) : Bool
    @inner.touch(id, last_used_at)
  end

  def revoke(id : String, at : Time) : Bool
    @inner.revoke(id, at)
  end

  def expire(id : String, at : Time) : Bool
    @inner.expire(id, at)
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

private def family_service
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::Testing.account(id: "a1", login: "a1@example.com"),
    KemalIdentity::Testing.account(id: "a2", login: "a2@example.com"),
  ])
  tokens = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)
  service = KemalIdentity::ApiTokens::Service.new(
    tokens: tokens,
    clock: KemalIdentity::Testing::TestClock.new,
    random: KemalIdentity::Testing::DeterministicRandom.new,
  )
  {service, accounts}
end

describe "KemalIdentity::ApiTokens::Service#revoke_family" do
  it "ends every token named, so none of them authenticates afterwards" do
    service, accounts = family_service
    ada = accounts.find_by_id("a1").or_fail
    old = service.issue(ada, "deploy-key")
    replacement = service.issue(ada, "deploy-key (rotated)")

    service.revoke_family([old.record.id, replacement.record.id], "a1")
      .sort.should eq([old.record.id, replacement.record.id].sort)

    service.authenticate(old.token.reveal).should be_a(KemalIdentity::Failed)
    service.authenticate(replacement.token.reveal).should be_a(KemalIdentity::Failed)
  end

  it "does not touch somebody else's token named in the list" do
    service, accounts = family_service
    mine = service.issue(accounts.find_by_id("a1").or_fail, "mine")
    theirs = service.issue(accounts.find_by_id("a2").or_fail, "theirs")

    service.revoke_family([mine.record.id, theirs.record.id], "a1").should eq([mine.record.id])
    service.authenticate(theirs.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  # The same event a single revocation emits, once per token, so an audit pipeline and the
  # security event sink see a family revocation as the revocations it is.
  it "records each revocation the way a single one is recorded" do
    service, accounts = family_service
    ada = accounts.find_by_id("a1").or_fail
    first = service.issue(ada, "one")
    second = service.issue(ada, "two")

    backend = Log::MemoryBackend.new
    Log.builder.bind("kemal_identity.*", :trace, backend)
    service.revoke_family([first.record.id, second.record.id], "a1")

    revoked = backend.entries.select { |entry| entry.message == "api_token.revoked" }
    revoked.map(&.data[:credential].to_s).sort!.should eq([first.record.id, second.record.id].sort)
  end
end

describe "KemalIdentity::ApiTokens::Service#revoke_family audit trail" do
  # The two-argument `revoke` logs `api_token.revoke_refused`; naming a token that was not
  # ended is the same event whether one id was named or several.
  it "records each id it did not revoke, without saying why" do
    service, accounts = family_service
    mine = service.issue(accounts.find_by_id("a1").or_fail, "mine")
    theirs = service.issue(accounts.find_by_id("a2").or_fail, "theirs")

    backend = Log::MemoryBackend.new
    Log.builder.bind("kemal_identity.*", :trace, backend)
    service.revoke_family([mine.record.id, theirs.record.id, "nope"], "a1")

    refused = backend.entries.select { |entry| entry.message == "api_token.revoke_refused" }
    refused.map(&.data[:credential].to_s).sort!.should eq([theirs.record.id, "nope"].sort)
    refused.map(&.data[:reason].to_s).uniq!.should eq(["not_revoked"])
  end
end

describe "KemalIdentity::ApiTokens::Service#revoke_family bounds" do
  it "refuses a list longer than a family, before touching storage" do
    service, _ = family_service
    ids = (1..KemalIdentity::ApiTokens::Service::MAX_FAMILY_SIZE + 1).map { |i| "t#{i}" }

    expect_raises(ArgumentError, /revoke_all/) { service.revoke_family(ids, "a1") }
  end
end

describe "KemalIdentity::ApiTokens::Repository#revoke_family by default" do
  # Loud rather than two statements dressed up as one.
  it "raises for an adapter that has not implemented it" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new
    repo = NotFamilyAware.new(accounts)

    expect_raises(NotImplementedError, /revoke_family/) do
      repo.revoke_family(["t1"], "a1", KemalIdentity::Testing::FIXED_NOW)
    end
  end
end

require "spec"
require "kemal_identity"
require "sqlite3"
require "../lib/kemal_identity/spec/spec_helper"
require "../src/shared_limiter"

OPS01_DB = "/tmp/claude-1000/-home-urunsiyabend-personal-development-kemal-identity/9df7d08f-9594-41d3-ab1d-58a460f591ea/scratchpad/consumer/ops01.db"

private def fresh_store
  File.delete?(OPS01_DB)
  db = DB.open("sqlite3://#{OPS01_DB}")
  SharedStoreRateLimiter.prepare!(db)
  SharedStoreRateLimiter.migrate!(db)
  db
end

# The shard's shared contract also runs against this adapter, and passing it is necessary but
# not sufficient — see the note in the cross-process section below.
require "../lib/kemal_identity/spec/contract/rate_limiter_contract"

it_behaves_like_a_rate_limiter(limit: 5, window: 1.minute) do
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  File.delete?(OPS01_DB)
  db = DB.open("sqlite3://#{OPS01_DB}")
  SharedStoreRateLimiter.prepare!(db)
  SharedStoreRateLimiter.migrate!(db)
  {SharedStoreRateLimiter.new(db, limit: 5, window: 1.minute, clock: clock).as(KemalIdentity::RateLimiter), clock}
end

describe "OPS-01: a limiter over a shared store" do
  # Pass condition: "Consume-and-decide is atomic" and "no process-local race changes the
  # global limit". Sixteen fibers against one store, and the number allowed must be the limit
  # exactly -- not the limit plus however many raced.
  it "allows exactly the limit under concurrent fibers" do
    db = fresh_store
    limiter = SharedStoreRateLimiter.new(db, limit: 5, window: 1.hour)

    results = Channel(Bool).new
    32.times { spawn { results.send(limiter.consume("login:ada").allowed?) } }

    allowed = 0
    32.times { allowed += 1 if results.receive }

    allowed.should eq(5)
    db.close
  end

  # Pass condition: "retry_after is stable".
  it "reports a retry_after that does not grow with further attempts" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
    db = fresh_store
    limiter = SharedStoreRateLimiter.new(db, limit: 1, window: 10.minutes, clock: clock)

    limiter.consume("login:ada").allowed?.should be_true

    first = limiter.consume("login:ada").retry_after.not_nil!
    second = limiter.consume("login:ada").retry_after.not_nil!

    first.should eq(second)
    first.should eq(10.minutes)
    db.close
  end

  # Pass condition: "keys and log data do not retain raw login identifiers". The shard hashes
  # the login before it reaches the limiter, so the store cannot retain it even if it wanted to.
  it "never sees the login somebody typed" do
    db = fresh_store
    limiter = SharedStoreRateLimiter.new(db, limit: 3, window: 1.hour)

    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account
    )
    auth = KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts,
      hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 4),
      clock: KemalIdentity::SystemClock.new,
      rate_limiter: limiter,
    )

    auth.authenticate(login: "ada@example.com", password: "wrong", ip: "203.0.113.7")

    stored = [] of String
    db.query("SELECT key FROM rate_limits") { |rs| rs.each { stored << rs.read(String) } }

    stored.should_not be_empty
    stored.each do |key|
      key.should_not contain("ada@example.com")
      key.should_not contain("ada")
    end
    db.close
  end

  # Pass condition: "storage failure has an explicit fail-open/fail-closed policy chosen per
  # endpoint". The store is pointed somewhere unwritable.
  describe "when the store is gone" do
    # A store that was working and then stopped answering. Two simulations were tried and
    # rejected first, and both are worth recording:
    #
    #   * pointing the adapter at a path that never existed raises `DB::ConnectionRefused` from
    #     `DB.open` — construction, not `#consume`, so the adapter's rescue never runs;
    #   * closing the database and querying again did **not** fail, because crystal-db's pool
    #     opens a fresh connection to the file.
    #
    # Dropping the table is a real store-level failure that reaches the query, which is where
    # the contract says the adapter has to convert it rather than raise.
    broken = -> do
      db = fresh_store
      limiter = SharedStoreRateLimiter.new(db, limit: 5, window: 1.hour)
      limiter.consume("warmup").allowed?.should be_true
      db.exec("DROP TABLE rate_limits")
      limiter
    end

    it "reports unavailable rather than raising or guessing" do
      verdict = broken.call.consume("login:ada")

      verdict.unavailable?.should be_true
      verdict.allowed?.should be_false
      verdict.retry_after.should be_nil
    end

    it "fails the login closed by default" do
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
        [] of KemalIdentity::Accounts::Account
      )
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: accounts,
        hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 4),
        clock: KemalIdentity::SystemClock.new,
        rate_limiter: broken.call,
      )

      outcome = auth.authenticate(login: "ada@example.com", password: "wrong")

      outcome.should be_a(KemalIdentity::Failed)
      outcome.as(KemalIdentity::Failed).reason
        .should eq(KemalIdentity::FailureReason::RateLimiterUnavailable)
    end

    it "carries on for an endpoint the application chose to keep available" do
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
      auth = KemalIdentity::Passwords::Authenticator.new(
        accounts: accounts,
        hasher: KemalIdentity::Testing::FastTestHasher.new,
        clock: KemalIdentity::SystemClock.new,
        rate_limiter: KemalIdentity::FailOpenRateLimiter.new(broken.call),
      )

      # The account has no password digest, so this still fails -- but on the credential, not
      # on the limiter. The point is that the limiter no longer refuses the attempt outright.
      outcome = auth.authenticate(login: "ada@example.com", password: "whatever")

      outcome.as(KemalIdentity::Failed).reason
        .should_not eq(KemalIdentity::FailureReason::RateLimiterUnavailable)
    end
  end
end

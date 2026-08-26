require "../spec_helper"

# `absolute_timeout` defaults to something long here on purpose. A revoked row is swept by
# expiry at its absolute deadline regardless, so the retention window only reclaims anything
# when it is shorter than the session's remaining lifetime -- with the shard's twelve-hour
# default, expiry always wins and the window never fires. Two of these examples were written
# against the twelve-hour default first and failed for exactly that reason, which is how the
# interaction came to be documented on `DEFAULT_REVOKED_RETENTION`.
private def sweeper_harness(
  revoked_retention : Time::Span = KemalIdentity::Sweeper::DEFAULT_REVOKED_RETENTION,
  absolute_timeout : Time::Span = 60.days,
)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  random = KemalIdentity::Testing::DeterministicRandom.new
  hasher = KemalIdentity::Testing::FastTestHasher.new

  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
  sessions = KemalIdentity::Testing::MemorySessionRepository.new(accounts)
  action_tokens = KemalIdentity::Testing::MemoryActionTokenRepository.new
  remember_tokens = KemalIdentity::Testing::MemoryRememberRepository.new

  app = KemalIdentity::Application.new(
    accounts: accounts,
    sessions: sessions,
    hasher: hasher,
    clock: clock,
    random: random,
    session_config: KemalIdentity::Sessions::Config.new(absolute_timeout: absolute_timeout),
    action_tokens: action_tokens,
    remember_tokens: remember_tokens,
    notifier: KemalIdentity::Testing::RecordingNotifier.new,
    cookie: KemalIdentity::Sessions::CookieConfig.new(
      name: "kemal_identity", secure: false, allow_insecure: true
    ),
  )

  {
    KemalIdentity::Sweeper.new(app, revoked_retention: revoked_retention),
    app, clock, accounts, sessions, action_tokens, remember_tokens,
  }
end

private def start_session(app, accounts) : KemalIdentity::Sessions::Issued
  app.sessions.start(accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
end

describe KemalIdentity::Sweeper do
  describe "#sweep" do
    it "removes sessions past their absolute deadline" do
      sweeper, app, clock, accounts, sessions, _, _ = sweeper_harness(absolute_timeout: 12.hours)
      start_session(app, accounts)

      clock.advance(13.hours)

      sweeper.sweep.expired_sessions.should eq(1)
      sessions.size.should eq(0)
    end

    # The rule the whole design rests on. A sweeper that has never run must cost storage and
    # nothing else -- kemal-session #116 is what happens when expiry waits for a GC pass.
    it "leaves a live session alone" do
      sweeper, app, _, accounts, sessions, _, _ = sweeper_harness
      start_session(app, accounts)

      sweeper.sweep.should be_a(KemalIdentity::SweepResult)
      sessions.size.should eq(1)
    end

    it "removes revoked sessions once they are past the retention window" do
      sweeper, app, clock, accounts, sessions, _, _ = sweeper_harness(revoked_retention: 7.days)
      issued = start_session(app, accounts)
      app.sessions.revoke(issued.record.id)

      clock.advance(8.days)

      sweeper.sweep.revoked_sessions.should eq(1)
      sessions.size.should eq(0)
    end

    # The row is the evidence behind "you were signed out of this device".
    it "keeps a freshly revoked session inside the window" do
      sweeper, app, clock, accounts, sessions, _, _ = sweeper_harness(revoked_retention: 7.days)
      issued = start_session(app, accounts)
      app.sessions.revoke(issued.record.id)

      clock.advance(1.day)

      sweeper.sweep.revoked_sessions.should eq(0)
      sessions.size.should eq(1)
    end

    it "removes expired action tokens" do
      sweeper, app, clock, _, _, action_tokens, _ = sweeper_harness
      app.accounts_service!.request_password_reset("ada@example.com")
      action_tokens.size.should eq(1)

      clock.advance(2.hours)

      sweeper.sweep.action_tokens.should eq(1)
      action_tokens.size.should eq(0)
    end

    it "leaves a live action token alone" do
      sweeper, app, _, _, _, action_tokens, _ = sweeper_harness
      app.accounts_service!.request_password_reset("ada@example.com")

      sweeper.sweep.action_tokens.should eq(0)
      action_tokens.size.should eq(1)
    end

    it "removes expired remember-me tokens" do
      sweeper, app, clock, accounts, _, _, remember = sweeper_harness
      app.remember!.remember(accounts.find_by_id("a1").or_fail)

      clock.advance(31.days)

      sweeper.sweep.remember_tokens.should eq(1)
      remember.size.should eq(0)
    end

    # A spent remember-me token's row *is* the evidence of a replay. Sweeping it early would
    # make a stolen token coming back look unknown rather than replayed, so nobody is told.
    it "keeps a spent remember-me token until it expires, so replay stays detectable" do
      sweeper, app, clock, accounts, _, _, _ = sweeper_harness
      issued = app.remember!.remember(accounts.find_by_id("a1").or_fail)
      app.remember!.restore(issued.token.reveal)

      clock.advance(1.day)
      sweeper.sweep.remember_tokens.should eq(0)

      app.remember!.restore(issued.token.reveal)
        .should be_a(KemalIdentity::Sessions::ReplayDetected)
    end

    it "reports what it removed across every table" do
      sweeper, app, clock, accounts, _, _, _ = sweeper_harness(absolute_timeout: 12.hours)
      start_session(app, accounts)
      app.accounts_service!.request_password_reset("ada@example.com")
      app.remember!.remember(accounts.find_by_id("a1").or_fail)

      clock.advance(31.days)
      result = sweeper.sweep

      result.expired_sessions.should eq(1)
      result.action_tokens.should eq(1)
      result.remember_tokens.should eq(1)
      result.total.should eq(3)
      result.empty?.should be_false
    end

    it "reports an empty sweep as empty" do
      sweeper, _, _, _, _, _, _ = sweeper_harness
      sweeper.sweep.empty?.should be_true
    end

    # An application that configured neither service has nothing of theirs to sweep, and
    # asking `Application` for a service it never received would raise.
    it "works on an application with no action or remember tokens configured" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
      app = KemalIdentity::Application.new(
        accounts: accounts,
        sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
        hasher: KemalIdentity::Testing::FastTestHasher.new,
        clock: clock,
        random: KemalIdentity::Testing::DeterministicRandom.new,
        cookie: KemalIdentity::Sessions::CookieConfig.new(
          name: "kemal_identity", secure: false, allow_insecure: true
        ),
      )

      result = KemalIdentity::Sweeper.new(app).sweep
      result.action_tokens.should eq(0)
      result.remember_tokens.should eq(0)
    end
  end

  describe "#run_every" do
    # It does not start itself. Four processes behind a load balancer would otherwise run four
    # sweepers against one database.
    it "is not running until it is started" do
      sweeper, _, _, _, _, _, _ = sweeper_harness
      sweeper.running?.should be_false
    end

    it "reports itself running once started" do
      sweeper, _, _, _, _, _, _ = sweeper_harness
      sweeper.run_every(1.hour)
      sweeper.running?.should be_true

      sweeper.stop
      sweeper.running?.should be_false
    end

    it "refuses a non-positive interval" do
      sweeper, _, _, _, _, _, _ = sweeper_harness
      expect_raises(KemalIdentity::ConfigurationError) { sweeper.run_every(Time::Span::ZERO) }
    end

    it "refuses a negative retention window" do
      _, app, _, _, _, _, _ = sweeper_harness
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Sweeper.new(app, revoked_retention: -1.day)
      end
    end

    # The first sweep waits for the first interval rather than running at boot: a process that
    # restarts often would otherwise sweep on every start.
    it "does not sweep immediately on start" do
      sweeper, app, clock, accounts, _, _, _ = sweeper_harness(absolute_timeout: 12.hours)
      start_session(app, accounts)
      clock.advance(13.hours)

      sweeper.run_every(1.hour)
      Fiber.yield

      app.session_repository.as(KemalIdentity::Testing::MemorySessionRepository).size.should eq(1)
      sweeper.stop
    end
  end

  # A database hiccup must not silently end all future sweeping: the failure mode would be a
  # table growing forever with nothing in the logs to explain it.
  describe "when the store fails" do
    # `running?` alone proves nothing here -- it reads a flag that stays true whether or not
    # the fiber behind it is still alive. An earlier version of this example asserted exactly
    # that and passed happily with the rescue deleted. The claim is that the loop *keeps
    # sweeping*, so the only honest assertion is that a later sweep actually happened.
    it "keeps sweeping after an infrastructure error" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
      failing = FailingSweepRepository.new(
        KemalIdentity::Testing::MemorySessionRepository.new(accounts)
      )

      app = KemalIdentity::Application.new(
        accounts: accounts,
        sessions: failing,
        hasher: KemalIdentity::Testing::FastTestHasher.new,
        clock: clock,
        random: KemalIdentity::Testing::DeterministicRandom.new,
        cookie: KemalIdentity::Sessions::CookieConfig.new(
          name: "kemal_identity", secure: false, allow_insecure: true
        ),
      )

      sweeper = KemalIdentity::Sweeper.new(app)
      sweeper.run_every(1.millisecond)

      # A real timer loop is the thing under test, so this waits on the clock rather than
      # advancing a TestClock -- the one place in the suite where that is unavoidable. Bounded
      # by iteration count rather than by a deadline, so a broken loop fails fast instead of
      # hanging, and so nothing here depends on `Time.monotonic`, which is deprecated on the
      # newest Crystal and absent from the oldest one this shard supports.
      2_000.times do
        break if failing.attempts >= 3
        sleep 1.millisecond
      end

      sweeper.stop

      # Every attempt raises. Three of them means the first two did not kill the fiber.
      failing.attempts.should be >= 3
    end

    it "still raises when called directly, so a cron job sees the failure" do
      clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
      app = KemalIdentity::Application.new(
        accounts: accounts,
        sessions: FailingSweepRepository.new(
          KemalIdentity::Testing::MemorySessionRepository.new(accounts)
        ),
        hasher: KemalIdentity::Testing::FastTestHasher.new,
        clock: clock,
        random: KemalIdentity::Testing::DeterministicRandom.new,
        cookie: KemalIdentity::Sessions::CookieConfig.new(
          name: "kemal_identity", secure: false, allow_insecure: true
        ),
      )

      expect_raises(KemalIdentity::InfrastructureError) { KemalIdentity::Sweeper.new(app).sweep }
    end
  end
end

# Fails every sweep, and counts how many times it was asked. The count is what proves the loop
# survived: a fiber killed by the first failure never reaches the second.
class FailingSweepRepository < KemalIdentity::Sessions::Repository
  @attempts = Atomic(Int32).new(0)

  def initialize(@inner : KemalIdentity::Sessions::Repository)
  end

  def attempts : Int32
    @attempts.get
  end

  def create(record : KemalIdentity::Sessions::Record) : Nil
    @inner.create(record)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
    @inner.find_by_digest(digest)
  end

  def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
    @inner.touch(id, last_seen_at, idle_expires_at)
  end

  def revoke(id : String, at : Time) : Bool
    @inner.revoke(id, at)
  end

  def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
    @inner.revoke_all_for_account(account_id, at, except_id: except_id)
  end

  def delete_revoked_before(before : Time) : Int32
    @inner.delete_revoked_before(before)
  end

  def delete_expired(before : Time) : Int32
    @attempts.add(1)
    raise KemalIdentity::InfrastructureError.new("session store unavailable")
  end
end

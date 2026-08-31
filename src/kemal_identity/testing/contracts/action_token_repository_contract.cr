# Shared spec for `KemalIdentity::Accounts::ActionTokenRepository`. Every implementation runs
# it, the in-memory double included.
#
# The block is handed the tokens to seed and returns a repository containing exactly those.
def it_behaves_like_an_action_token_repository(&build : Array(KemalIdentity::Accounts::ActionToken) -> KemalIdentity::Accounts::ActionTokenRepository)
  now = KemalIdentity::Testing::FIXED_NOW
  reset = KemalIdentity::Accounts::ActionPurpose::Reset
  confirm = KemalIdentity::Accounts::ActionPurpose::Confirm

  digest = ->(value : String) { KemalIdentity::Secret.new(value).digest }

  token = ->(id : String, account_id : String, raw : String, purpose : KemalIdentity::Accounts::ActionPurpose, expires_in : Time::Span) do
    KemalIdentity::Accounts::ActionToken.new(
      id: id,
      account_id: account_id,
      purpose: purpose,
      token_digest: digest.call(raw),
      created_at: now,
      expires_at: now + expires_in,
    )
  end

  describe "#create and #consume" do
    it "spends a valid token and returns it" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])

      spent = repo.consume(digest.call("raw-1"), reset, now)
      spent.should_not be_nil
      spent.or_fail.id.should eq("t1")
      spent.or_fail.account_id.should eq("a1")
    end

    it "reports when it was spent" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now + 5.minutes)
        .or_fail.used_at.should eq(now + 5.minutes)
    end

    # Single use. A reset link that works twice is a reset link an attacker can replay out of
    # a mailbox they briefly saw.
    it "refuses the same token a second time" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])

      repo.consume(digest.call("raw-1"), reset, now).should_not be_nil
      repo.consume(digest.call("raw-1"), reset, now).should be_nil
    end

    it "returns nil for a digest nobody issued, rather than raising" do
      build.call([] of KemalIdentity::Accounts::ActionToken)
        .consume(digest.call("never-issued"), reset, now).should be_nil
    end

    it "returns nil for an empty digest" do
      build.call([] of KemalIdentity::Accounts::ActionToken)
        .consume(Bytes.new(0), reset, now).should be_nil
    end

    it "refuses an expired token" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now + 2.hours).should be_nil
    end

    it "treats the expiry instant itself as expired" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now + 1.hour).should be_nil
    end

    it "accepts a token a moment before it expires" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now + 59.minutes).should_not be_nil
    end

    # A token issued to confirm an address must not reset a password, or anybody who can
    # trigger a confirmation message has an account takeover.
    it "refuses a token presented for the wrong purpose" do
      repo = build.call([token.call("t1", "a1", "raw-1", confirm, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now).should be_nil
    end

    it "leaves a token refused for the wrong purpose still spendable for its own" do
      repo = build.call([token.call("t1", "a1", "raw-1", confirm, 1.hour)])

      repo.consume(digest.call("raw-1"), reset, now).should be_nil
      repo.consume(digest.call("raw-1"), confirm, now).should_not be_nil
    end

    it "refuses a duplicate digest instead of overwriting" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.create(token.call("t2", "a1", "raw-1", reset, 1.hour))
      end
    end

    it "keeps tokens for different accounts apart" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a2", "raw-2", reset, 1.hour),
      ])

      repo.consume(digest.call("raw-2"), reset, now).or_fail.account_id.should eq("a2")
    end
  end

  # Issuing a new link invalidates the old ones, so a link in a stale email -- or in an inbox
  # somebody else now controls -- stops working.
  describe "#revoke_all_for_account" do
    it "spends every outstanding token of that purpose and reports how many" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a1", "raw-2", reset, 1.hour),
      ])

      repo.revoke_all_for_account("a1", reset, now).should eq(2)
      repo.consume(digest.call("raw-1"), reset, now).should be_nil
      repo.consume(digest.call("raw-2"), reset, now).should be_nil
    end

    it "leaves other purposes alone" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a1", "raw-2", confirm, 1.hour),
      ])

      repo.revoke_all_for_account("a1", reset, now).should eq(1)
      repo.consume(digest.call("raw-2"), confirm, now).should_not be_nil
    end

    it "leaves other accounts alone" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a2", "raw-2", reset, 1.hour),
      ])

      repo.revoke_all_for_account("a1", reset, now).should eq(1)
      repo.consume(digest.call("raw-2"), reset, now).should_not be_nil
    end

    it "does not count tokens that were already spent" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a1", "raw-2", reset, 1.hour),
      ])
      repo.consume(digest.call("raw-1"), reset, now)

      repo.revoke_all_for_account("a1", reset, now).should eq(1)
    end

    it "returns zero when there is nothing outstanding" do
      build.call([] of KemalIdentity::Accounts::ActionToken)
        .revoke_all_for_account("a1", reset, now).should eq(0)
    end
  end

  describe "#delete_expired" do
    it "removes only rows past their expiry" do
      repo = build.call([
        token.call("t1", "a1", "raw-1", reset, 1.hour),
        token.call("t2", "a1", "raw-2", reset, 3.hours),
      ])

      repo.delete_expired(now + 2.hours).should eq(1)
      repo.consume(digest.call("raw-2"), reset, now).should_not be_nil
    end

    it "leaves a live token alone" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.delete_expired(now).should eq(0)
      repo.consume(digest.call("raw-1"), reset, now).should_not be_nil
    end

    it "removes a spent token once it is also past its expiry" do
      repo = build.call([token.call("t1", "a1", "raw-1", reset, 1.hour)])
      repo.consume(digest.call("raw-1"), reset, now)

      repo.delete_expired(now + 2.hours).should eq(1)
    end
  end

  # docs/05-testing.md, concurrency blockers: "two fibers consuming the same action token:
  # exactly one succeeds". This is why the contract insists on a conditional update rather than
  # a read followed by a write.
  #
  # ### This example is probabilistic, and it is sized deliberately
  #
  # An earlier version spawned eight fibers once. Against the in-memory double that is enough —
  # its atomicity is a mutex, so a broken one fails every time. Against PostgreSQL it is not:
  # a read-then-write adapter loses this race only when two callers complete their SELECT
  # before either commits its UPDATE, and with eight fibers that happened in roughly one run in
  # ten. A mutation test found the gap — the racy adapter passed the whole suite.
  #
  # Measured on the racy implementation, each round of 24 fibers catches it about a quarter of
  # the time, so thirty rounds miss with probability near 1e-4. That is a regression test, not a
  # proof: atomicity in SQL ultimately rests on `consume` being one statement, which is
  # something a reader has to confirm by looking. Both are true and neither is sufficient alone.
  describe "concurrent consumers" do
    it "lets exactly one of many simultaneous callers spend the token, in every round" do
      rounds = 30
      fibers = 24

      rounds.times do |round|
        repo = build.call([token.call("t#{round}", "a1", "contested-#{round}", reset, 1.hour)])

        winners = Atomic(Int32).new(0)

        join_fibers(fibers) do
          winners.add(1) if repo.consume(digest.call("contested-#{round}"), reset, now)
        end

        # Two winners means one password reset link setting two passwords.
        winners.get.should eq(1)
      end
    end
  end
end

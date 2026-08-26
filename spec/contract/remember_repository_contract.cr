# Shared spec for `KemalIdentity::Sessions::RememberRepository`. Every implementation runs it.
#
# The block is handed the tokens to seed and returns a repository containing exactly those.
def it_behaves_like_a_remember_repository(&build : Array(KemalIdentity::Sessions::RememberToken) -> KemalIdentity::Sessions::RememberRepository)
  now = KemalIdentity::SpecHelper::FIXED_NOW
  digest = ->(value : String) { KemalIdentity::Secret.new(value).digest }

  token = ->(id : String, account_id : String, family_id : String, raw : String, expires_in : Time::Span) do
    KemalIdentity::Sessions::RememberToken.new(
      id: id,
      account_id: account_id,
      family_id: family_id,
      token_digest: digest.call(raw),
      created_at: now,
      expires_at: now + expires_in,
    )
  end

  describe "#consume" do
    it "spends a live token and returns it" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])

      accepted = repo.consume(digest.call("raw-1"), now)
      accepted.should be_a(KemalIdentity::Sessions::RememberAccepted)
      accepted.as(KemalIdentity::Sessions::RememberAccepted).token.id.should eq("r1")
    end

    it "records when it was spent" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now + 1.hour)
        .as(KemalIdentity::Sessions::RememberAccepted).token.used_at.should eq(now + 1.hour)
    end

    # The detection. A single-use token presented twice means two parties hold it.
    it "reports a second presentation as a replay, naming the family" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now)

      replayed = repo.consume(digest.call("raw-1"), now)
      replayed.should be_a(KemalIdentity::Sessions::RememberReplayed)
      replayed.as(KemalIdentity::Sessions::RememberReplayed).family_id.should eq("f1")
      replayed.as(KemalIdentity::Sessions::RememberReplayed).account_id.should eq("a1")
    end

    it "keeps reporting a replay on every later presentation" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now)

      3.times do
        repo.consume(digest.call("raw-1"), now).should be_a(KemalIdentity::Sessions::RememberReplayed)
      end
    end

    it "returns unknown for a digest nobody issued" do
      build.call([] of KemalIdentity::Sessions::RememberToken)
        .consume(digest.call("never-issued"), now)
        .should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    it "returns unknown for an empty digest, rather than raising" do
      build.call([] of KemalIdentity::Sessions::RememberToken)
        .consume(Bytes.new(0), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    # Expiry is not evidence of theft: it is somebody coming back after a month.
    it "returns unknown for an expired token, not a replay" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now + 31.days)
        .should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    it "treats the expiry instant itself as expired" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now + 30.days)
        .should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    # A revoked family has already raised its alarm. Reporting a replay would send a second
    # one for the same incident.
    it "returns unknown for a revoked token, not a replay" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.revoke_family("f1", now)

      repo.consume(digest.call("raw-1"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    it "keeps tokens in different families apart" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f2", "raw-2", 30.days),
      ])

      repo.consume(digest.call("raw-1"), now)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberAccepted)
    end

    it "refuses a duplicate digest instead of overwriting" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.create(token.call("r2", "a1", "f2", "raw-1", 30.days))
      end
    end
  end

  describe "#revoke_family" do
    it "kills every token in the family and reports how many" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f1", "raw-2", 30.days),
      ])

      repo.revoke_family("f1", now).should eq(2)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    # A stolen cookie on one machine says nothing about the others.
    it "leaves the account's other families signed in" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f2", "raw-2", 30.days),
      ])

      repo.revoke_family("f1", now)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberAccepted)
    end

    # The spent token that triggered the detection has to be killed too, or the row lingers as
    # a used-but-live token in a family that is supposed to be dead.
    it "kills tokens that were already spent" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f1", "raw-2", 30.days),
      ])
      repo.consume(digest.call("raw-1"), now)

      repo.revoke_family("f1", now).should eq(2)
    end

    it "returns zero for a family that does not exist" do
      build.call([] of KemalIdentity::Sessions::RememberToken)
        .revoke_family("nope", now).should eq(0)
    end
  end

  # What logging out calls. It must not spend the token: a spent token presented again is a
  # replay, so a user who pressed "log out" would be told their cookie may have been stolen.
  describe "#revoke_family_by_digest" do
    it "kills the family the token belongs to" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f1", "raw-2", 30.days),
      ])

      repo.revoke_family_by_digest(digest.call("raw-1"), now).should eq(2)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    # The property that makes this method exist at all.
    it "leaves the token unspent, so returning with it is not read as a replay" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.revoke_family_by_digest(digest.call("raw-1"), now)

      repo.consume(digest.call("raw-1"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    it "leaves other families alone" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f2", "raw-2", 30.days),
      ])

      repo.revoke_family_by_digest(digest.call("raw-1"), now)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberAccepted)
    end

    it "returns zero for a digest nobody issued" do
      build.call([] of KemalIdentity::Sessions::RememberToken)
        .revoke_family_by_digest(digest.call("never-issued"), now).should eq(0)
    end
  end

  describe "#revoke_all_for_account" do
    it "kills every family the account has" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a1", "f2", "raw-2", 30.days),
      ])

      repo.revoke_all_for_account("a1", now).should eq(2)
      repo.consume(digest.call("raw-1"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberUnknown)
    end

    it "leaves another account alone" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 30.days),
        token.call("r2", "a2", "f2", "raw-2", 30.days),
      ])

      repo.revoke_all_for_account("a1", now).should eq(1)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberAccepted)
    end
  end

  describe "#delete_expired" do
    it "removes only rows past their expiry" do
      repo = build.call([
        token.call("r1", "a1", "f1", "raw-1", 10.days),
        token.call("r2", "a1", "f1", "raw-2", 40.days),
      ])

      repo.delete_expired(now + 20.days).should eq(1)
      repo.consume(digest.call("raw-2"), now).should be_a(KemalIdentity::Sessions::RememberAccepted)
    end

    it "leaves a live token alone" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.delete_expired(now).should eq(0)
    end

    # Delete a spent token early and a stolen one coming back looks unknown rather than
    # replayed, so nobody is told. Its history has to outlive its usefulness.
    it "keeps a spent token until it expires, so replay stays detectable" do
      repo = build.call([token.call("r1", "a1", "f1", "raw-1", 30.days)])
      repo.consume(digest.call("raw-1"), now)

      repo.delete_expired(now + 1.day).should eq(0)
      repo.consume(digest.call("raw-1"), now + 1.day)
        .should be_a(KemalIdentity::Sessions::RememberReplayed)
    end
  end

  # Two callers presenting one single-use token is exactly the situation this design exists to
  # notice, so the concurrent case is not merely "one wins" — the losers must see a replay.
  #
  # Sized like the action-token contract, and for the same reason: a read-then-write
  # implementation loses this race only sometimes, so one round of a handful of fibers is not
  # enough to catch it. See blueprints/0011-action-token-atomicity.md.
  describe "concurrent consumers" do
    it "accepts exactly one and reports the rest as replays, in every round" do
      rounds = 20
      fibers = 24

      rounds.times do |round|
        repo = build.call([token.call("r#{round}", "a1", "f#{round}", "contested-#{round}", 30.days)])

        accepted = Atomic(Int32).new(0)
        replayed = Atomic(Int32).new(0)

        join_fibers(fibers) do
          case repo.consume(digest.call("contested-#{round}"), now)
          in KemalIdentity::Sessions::RememberAccepted then accepted.add(1)
          in KemalIdentity::Sessions::RememberReplayed then replayed.add(1)
          in KemalIdentity::Sessions::RememberUnknown  then nil
          end
        end

        # Two acceptances would mean one stolen cookie silently working twice.
        accepted.get.should eq(1)
        replayed.get.should eq(fibers - 1)
      end
    end
  end
end

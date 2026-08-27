# Shared spec for `KemalIdentity::MFA::Repository`. Every implementation runs it.
def it_behaves_like_an_mfa_repository(&build : -> KemalIdentity::MFA::Repository)
  now = KemalIdentity::SpecHelper::FIXED_NOW

  factor = ->(id : String, account_id : String) do
    KemalIdentity::MFA::Factor.new(
      id: id,
      account_id: account_id,
      sealed_secret: "sealed-#{id}".to_slice,
      created_at: now,
      label: "phone #{id}",
    )
  end

  digest = ->(value : String) { KemalIdentity::Secret.new(value).digest }

  code = ->(id : String, account_id : String, raw : String) do
    KemalIdentity::MFA::RecoveryCode.new(
      id: id, account_id: account_id, code_digest: digest.call(raw), created_at: now
    )
  end

  describe "#create_factor and #find_factor" do
    it "round trips a factor" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      found = repo.find_factor("f1").or_fail
      found.account_id.should eq("a1")
      found.label.should eq("phone f1")
      found.sealed_secret.should eq("sealed-f1".to_slice)
      found.kind.should eq(KemalIdentity::MFA::FactorKind::TOTP)
    end

    # A default change must not break an already-enrolled authenticator, which keeps computing
    # whatever it was given at enrolment.
    it "preserves the parameters the factor was enrolled with" do
      repo = build.call
      repo.create_factor(
        KemalIdentity::MFA::Factor.new(
          id: "f1", account_id: "a1", sealed_secret: "s".to_slice, created_at: now,
          digits: 8, period: 60.seconds, algorithm: KemalIdentity::MFA::TOTP::Algorithm::SHA512
        )
      )

      found = repo.find_factor("f1").or_fail
      found.digits.should eq(8)
      found.period.should eq(60.seconds)
      found.algorithm.should eq(KemalIdentity::MFA::TOTP::Algorithm::SHA512)
    end

    it "starts a factor unconfirmed and never used" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      found = repo.find_factor("f1").or_fail
      found.confirmed_at.should be_nil
      found.confirmed?.should be_false
      found.last_used_counter.should be_nil
    end

    it "returns nil for a factor nobody enrolled, rather than raising" do
      build.call.find_factor("nope").should be_nil
    end

    # A collision means the id source is broken, and silently replacing an enrolled factor is
    # how somebody loses access to their account.
    it "refuses a duplicate id instead of overwriting" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.create_factor(factor.call("f1", "a2"))
      end
    end
  end

  describe "#factors_for_account" do
    it "lists an account's factors, unconfirmed ones included" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.create_factor(factor.call("f2", "a1"))
      repo.confirm_factor("f1", 100_i64, now)

      repo.factors_for_account("a1").map(&.id).sort!.should eq(["f1", "f2"])
    end

    it "does not list another account's factors" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.create_factor(factor.call("f2", "a2"))

      repo.factors_for_account("a2").map(&.id).should eq(["f2"])
    end

    it "returns an empty array for an account with none" do
      build.call.factors_for_account("a1").should be_empty
    end
  end

  describe "#confirm_factor" do
    it "marks the factor confirmed and records the counter that proved it" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      repo.confirm_factor("f1", 100_i64, now).should be_true

      found = repo.find_factor("f1").or_fail
      found.confirmed_at.should eq(now)
      found.confirmed?.should be_true
      found.last_used_counter.should eq(100_i64)
    end

    it "returns false for a factor that does not exist" do
      build.call.confirm_factor("nope", 1_i64, now).should be_false
    end

    # A double-submitted form is normal; the caller still learns nothing changed, and the first
    # timestamp is the one an audit trail wants.
    it "returns false for an already-confirmed factor and does not re-stamp it" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.confirm_factor("f1", 100_i64, now)

      repo.confirm_factor("f1", 200_i64, now + 1.hour).should be_false

      found = repo.find_factor("f1").or_fail
      found.confirmed_at.should eq(now)
      found.last_used_counter.should eq(100_i64)
    end
  end

  # The replay defence. A code stays arithmetically correct for its whole window plus the drift
  # either side, which is exactly the window an attacker who watched somebody type it works in.
  describe "#consume_counter" do
    it "accepts a counter above the last one used" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.confirm_factor("f1", 100_i64, now)

      repo.consume_counter("f1", 101_i64, now + 30.seconds).should be_true
      repo.find_factor("f1").or_fail.last_used_counter.should eq(101_i64)
    end

    it "refuses the counter that was just used" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.confirm_factor("f1", 100_i64, now)

      repo.consume_counter("f1", 100_i64, now).should be_false
      repo.find_factor("f1").or_fail.last_used_counter.should eq(100_i64)
    end

    # Within the drift window, an older code is still arithmetically valid. It must not work.
    it "refuses a counter below the last one used" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.confirm_factor("f1", 100_i64, now)

      repo.consume_counter("f1", 99_i64, now).should be_false
      repo.find_factor("f1").or_fail.last_used_counter.should eq(100_i64)
    end

    it "accepts any counter on a factor that has never been used" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      repo.consume_counter("f1", 1_i64, now).should be_true
    end

    it "returns false for a factor that does not exist" do
      build.call.consume_counter("nope", 1_i64, now).should be_false
    end

    it "affects only the factor named" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.create_factor(factor.call("f2", "a1"))
      repo.consume_counter("f1", 100_i64, now)

      repo.find_factor("f2").or_fail.last_used_counter.should be_nil
    end
  end

  describe "#delete_factor and #delete_factors_for_account" do
    it "removes one factor" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))

      repo.delete_factor("f1").should be_true
      repo.find_factor("f1").should be_nil
    end

    it "returns false for a factor that was not there" do
      build.call.delete_factor("nope").should be_false
    end

    it "removes every factor for an account and returns how many" do
      repo = build.call
      repo.create_factor(factor.call("f1", "a1"))
      repo.create_factor(factor.call("f2", "a1"))
      repo.create_factor(factor.call("f3", "a2"))

      repo.delete_factors_for_account("a1").should eq(2)
      repo.factors_for_account("a1").should be_empty
      repo.factors_for_account("a2").size.should eq(1)
    end

    it "returns zero for an account with no factors" do
      build.call.delete_factors_for_account("a1").should eq(0)
    end
  end

  describe "#replace_recovery_codes" do
    it "stores codes an account can then spend" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])

      repo.unused_recovery_codes("a1").should eq(1)
      repo.consume_recovery_code("a1", digest.call("raw-1"), now).should be_true
    end

    # Regenerating is exactly what somebody does when they think the old codes leaked, so the
    # old ones must not survive it.
    it "voids the previous codes" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])
      repo.replace_recovery_codes("a1", [code.call("c2", "a1", "raw-2")])

      repo.consume_recovery_code("a1", digest.call("raw-1"), now).should be_false
      repo.consume_recovery_code("a1", digest.call("raw-2"), now).should be_true
    end

    it "does not touch another account's codes" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])
      repo.replace_recovery_codes("a2", [code.call("c2", "a2", "raw-2")])

      repo.replace_recovery_codes("a1", [code.call("c3", "a1", "raw-3")])

      repo.consume_recovery_code("a2", digest.call("raw-2"), now).should be_true
    end

    it "accepts an empty set, which leaves an account with none" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])
      repo.replace_recovery_codes("a1", [] of KemalIdentity::MFA::RecoveryCode)

      repo.unused_recovery_codes("a1").should eq(0)
    end
  end

  describe "#consume_recovery_code" do
    it "spends a code exactly once" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])

      repo.consume_recovery_code("a1", digest.call("raw-1"), now).should be_true
      repo.consume_recovery_code("a1", digest.call("raw-1"), now + 1.hour).should be_false
    end

    it "returns false for a code nobody issued" do
      build.call.consume_recovery_code("a1", digest.call("never"), now).should be_false
    end

    it "returns false for an empty digest" do
      build.call.consume_recovery_code("a1", Bytes.new(0), now).should be_false
    end

    # Scoped to the account, so one person's code cannot be spent against another's.
    it "refuses a code belonging to another account" do
      repo = build.call
      repo.replace_recovery_codes("a1", [code.call("c1", "a1", "raw-1")])

      repo.consume_recovery_code("a2", digest.call("raw-1"), now).should be_false
      repo.unused_recovery_codes("a1").should eq(1)
    end

    it "leaves the other codes spendable" do
      repo = build.call
      repo.replace_recovery_codes("a1", [
        code.call("c1", "a1", "raw-1"),
        code.call("c2", "a1", "raw-2"),
      ])

      repo.consume_recovery_code("a1", digest.call("raw-1"), now)

      repo.unused_recovery_codes("a1").should eq(1)
      repo.consume_recovery_code("a1", digest.call("raw-2"), now).should be_true
    end
  end

  # The two single-use operations, run for real. `blueprints/0011-action-token-atomicity.md`
  # explains the sizing: against the in-memory double a broken implementation fails every time,
  # because its atomicity is a mutex. Against a database it does not — a read-then-write adapter
  # loses the race only when two callers finish their SELECT before either commits, which at
  # eight fibers happened in roughly one run in ten and let a racy adapter pass a whole suite.
  # Thirty rounds of twenty-four is what makes this a regression test rather than a coin toss.
  describe "concurrent consumers" do
    # Two winners means an intercepted code worked twice, which is the entire thing the counter
    # exists to prevent.
    it "lets exactly one of many simultaneous callers spend a TOTP counter, in every round" do
      rounds = 30
      fibers = 24

      rounds.times do |round|
        repo = build.call
        repo.create_factor(factor.call("f#{round}", "a1"))
        repo.confirm_factor("f#{round}", 100_i64, now)

        winners = Atomic(Int32).new(0)

        join_fibers(fibers) do
          winners.add(1) if repo.consume_counter("f#{round}", 101_i64, now)
        end

        winners.get.should eq(1)
      end
    end

    # Two winners means one recovery code let two requests past the second factor.
    it "lets exactly one of many simultaneous callers spend a recovery code, in every round" do
      rounds = 30
      fibers = 24

      rounds.times do |round|
        repo = build.call
        repo.replace_recovery_codes("a1", [code.call("c#{round}", "a1", "contested-#{round}")])

        winners = Atomic(Int32).new(0)

        join_fibers(fibers) do
          winners.add(1) if repo.consume_recovery_code("a1", digest.call("contested-#{round}"), now)
        end

        winners.get.should eq(1)
      end
    end
  end

  describe "#unused_recovery_codes" do
    it "counts only the unspent ones" do
      repo = build.call
      repo.replace_recovery_codes("a1", [
        code.call("c1", "a1", "raw-1"),
        code.call("c2", "a1", "raw-2"),
        code.call("c3", "a1", "raw-3"),
      ])

      repo.consume_recovery_code("a1", digest.call("raw-2"), now)

      repo.unused_recovery_codes("a1").should eq(2)
    end

    it "returns zero for an account with none" do
      build.call.unused_recovery_codes("a1").should eq(0)
    end
  end
end

require "../spec_helper"

private NEW_PASSWORD = "a brand new passphrase"

private def request_reset(h) : String
  h.service.request_password_reset("ada@example.com")
  h.notifier.last_reset_token.or_fail("no reset token was delivered")
end

private def request_confirmation(h) : String
  h.service.request_email_confirmation("a1")
  h.notifier.last_confirmation_token.or_fail("no confirmation token was delivered")
end

describe KemalIdentity::Accounts::Service do
  describe "#request_password_reset" do
    it "delivers a link naming the account and its address" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.request_password_reset("ada@example.com")

      requested = h.notifier.resets.first
      requested.account_id.should eq("a1")
      requested.login.should eq("ada@example.com")
      requested.expires_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW + 1.hour)
    end

    # The application cannot build a URL out of a digest, so the raw token has to cross this
    # boundary. It is a Secret, so an accidental interpolation prints [REDACTED] rather than a
    # working password reset.
    it "hands over a raw token that redacts itself" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.request_password_reset("ada@example.com")

      token = h.notifier.resets.first.token
      token.reveal.should_not be_empty
      "link=#{token}".should_not contain(token.reveal)
    end

    it "stores only the digest of that token" do
      h = KemalIdentity::SpecHelper.account_harness
      raw = request_reset(h)

      # The stored side is unusable as a link: presenting the digest does not spend the token.
      h.service.reset_password(KemalIdentity::Secret.new(raw).digest.hexstring, NEW_PASSWORD)
        .should be_a(KemalIdentity::Accounts::ActionRejected)
      h.service.reset_password(raw, NEW_PASSWORD)
        .should be_a(KemalIdentity::Accounts::PasswordWasReset)
    end

    # A link sitting in a mailbox somebody else now controls stops working the moment the real
    # owner asks for a fresh one.
    it "invalidates the previous link when a new one is issued" do
      h = KemalIdentity::SpecHelper.account_harness
      first = request_reset(h)
      second = request_reset(h)

      first.should_not eq(second)
      h.service.reset_password(first, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::ActionRejected)
      h.service.reset_password(second, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::PasswordWasReset)
    end
  end

  describe "#reset_password" do
    it "sets the new password" do
      h = KemalIdentity::SpecHelper.account_harness
      raw = request_reset(h)

      h.service.reset_password(raw, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::PasswordWasReset)

      digest = h.accounts.find_by_id("a1").or_fail.password_digest.or_fail
      h.hasher.verify(KemalIdentity::Secret.new(NEW_PASSWORD), digest).should be_true
    end

    it "records the scheme that produced the digest" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.reset_password(request_reset(h), NEW_PASSWORD)

      h.accounts.find_by_id("a1").or_fail.password_scheme.should eq(h.hasher.scheme)
    end

    it "refuses the same link twice" do
      h = KemalIdentity::SpecHelper.account_harness
      raw = request_reset(h)

      h.service.reset_password(raw, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::PasswordWasReset)

      rejected = h.service.reset_password(raw, "another passphrase entirely")
      rejected.should be_a(KemalIdentity::Accounts::ActionRejected)
      rejected.as(KemalIdentity::Accounts::ActionRejected).reason
        .should eq(KemalIdentity::Accounts::ActionRejected::Reason::InvalidToken)
    end

    it "refuses an expired link" do
      h = KemalIdentity::SpecHelper.account_harness(reset_ttl: 1.hour)
      raw = request_reset(h)

      h.clock.advance(2.hours)

      h.service.reset_password(raw, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::ActionRejected)
    end

    it "refuses a token nobody issued, and a malformed one, identically" do
      h = KemalIdentity::SpecHelper.account_harness

      ["", "garbage", "a" * 43, "a" * 100_000].each do |candidate|
        h.service.reset_password(candidate, NEW_PASSWORD)
          .should be_a(KemalIdentity::Accounts::ActionRejected)
      end
    end

    # A confirmation link must not reset a password, or anybody able to trigger a confirmation
    # message has an account takeover.
    it "refuses a confirmation token" do
      h = KemalIdentity::SpecHelper.account_harness
      confirmation = request_confirmation(h)

      h.service.reset_password(confirmation, NEW_PASSWORD)
        .should be_a(KemalIdentity::Accounts::ActionRejected)
    end

    describe "when the new password fails the policy" do
      it "says so specifically, because the holder of the link is choosing it" do
        h = KemalIdentity::SpecHelper.account_harness
        rejected = h.service.reset_password(request_reset(h), "short").as(KemalIdentity::Accounts::ActionRejected)

        rejected.reason.should eq(KemalIdentity::Accounts::ActionRejected::Reason::PasswordUnacceptable)
        rejected.policy_violations.should eq([KemalIdentity::Passwords::PolicyViolation::TooShort])
      end

      it "leaves the old password in place" do
        h = KemalIdentity::SpecHelper.account_harness
        before = h.accounts.find_by_id("a1").or_fail.password_digest
        h.service.reset_password(request_reset(h), "short")

        h.accounts.find_by_id("a1").or_fail.password_digest.should eq(before)
      end

      # docs/02-security-model.md, token rule five: consumed on use even when the surrounding
      # operation then fails. Otherwise one emailed link becomes unlimited attempts.
      it "still spends the link" do
        h = KemalIdentity::SpecHelper.account_harness
        raw = request_reset(h)

        h.service.reset_password(raw, "short").should be_a(KemalIdentity::Accounts::ActionRejected)

        # Even with an acceptable password now, the link is gone. The user asks for another.
        h.service.reset_password(raw, NEW_PASSWORD).should be_a(KemalIdentity::Accounts::ActionRejected)
      end
    end

    describe "the sessions it ends" do
      it "revokes every session and reports how many" do
        h = KemalIdentity::SpecHelper.account_harness
        account = h.accounts.find_by_id("a1").or_fail
        tokens = Array.new(3) do
          h.session_service.start(account, KemalIdentity::AssuranceLevel::Password).token
        end

        result = h.service.reset_password(request_reset(h), NEW_PASSWORD)
          .as(KemalIdentity::Accounts::PasswordWasReset)

        result.revoked_sessions.should eq(3)
        tokens.each do |token|
          h.session_service.resolve(token.reveal).should be_a(KemalIdentity::Failed)
        end
      end

      # Belt as well as braces: revocation handles the sessions that exist, the version bump
      # handles anything created alongside the reset.
      it "bumps auth_version as well as revoking" do
        h = KemalIdentity::SpecHelper.account_harness
        before = h.accounts.find_by_id("a1").or_fail.auth_version

        h.service.reset_password(request_reset(h), NEW_PASSWORD)

        h.accounts.find_by_id("a1").or_fail.auth_version.should eq(before + 1)
      end

      it "leaves another account's sessions alone" do
        h = KemalIdentity::SpecHelper.account_harness(accounts: [
          KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com"),
          KemalIdentity::SpecHelper.account(id: "a2", login: "bob@example.com"),
        ])
        other = h.session_service.start(
          h.accounts.find_by_id("a2").or_fail, KemalIdentity::AssuranceLevel::Password
        )

        h.service.reset_password(request_reset(h), NEW_PASSWORD)

        h.session_service.resolve(other.token.reveal).should be_a(KemalIdentity::Authenticated)
      end
    end

    # Revoking sessions alone would be a hole with an attacker in it: a remember-me cookie
    # outlives any session, so somebody holding a stolen one would be signed straight back in
    # on their next request -- after the victim reset their password specifically to evict
    # them.
    it "forgets every remembered browser too" do
      h = KemalIdentity::SpecHelper.account_harness
      account = h.accounts.find_by_id("a1").or_fail
      laptop = h.remember_service.remember(account).token.reveal
      phone = h.remember_service.remember(account).token.reveal

      h.service.reset_password(request_reset(h), NEW_PASSWORD)

      h.remember_service.restore(laptop).should be_a(KemalIdentity::Sessions::NotRemembered)
      h.remember_service.restore(phone).should be_a(KemalIdentity::Sessions::NotRemembered)
    end

    # And is not read as theft: the tokens were revoked, not spent, so nobody is told their
    # cookie may have been stolen because they reset their own password.
    it "does not report those forgotten browsers as replays" do
      h = KemalIdentity::SpecHelper.account_harness
      laptop = h.remember_service.remember(h.accounts.find_by_id("a1").or_fail).token.reveal

      h.service.reset_password(request_reset(h), NEW_PASSWORD)
      h.notifier.clear
      h.remember_service.restore(laptop)

      h.notifier.replays.should be_empty
    end

    # Unsolicited on purpose: it is how somebody learns that an attacker who reached their
    # mailbox has taken the account.
    it "tells the account holder their password changed" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.reset_password(request_reset(h), NEW_PASSWORD)

      changed = h.notifier.password_changes
      changed.size.should eq(1)
      changed.first.account_id.should eq("a1")
      changed.first.login.should eq("ada@example.com")
    end

    it "sends no such message when the reset was refused" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.reset_password("garbage", NEW_PASSWORD)

      h.notifier.password_changes.should be_empty
    end
  end

  describe "#request_email_confirmation" do
    it "delivers a link for an account that exists" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.request_email_confirmation("a1").should be_true

      requested = h.notifier.confirmations.first
      requested.account_id.should eq("a1")
      requested.expires_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW + 1.day)
    end

    # Unlike a reset request, this takes an account id the application already holds, so there
    # is no untrusted identifier to enumerate with and no reason to be silent.
    it "reports an unknown account plainly" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.request_email_confirmation("nope").should be_false
      h.notifier.delivered.should be_empty
    end

    it "invalidates the previous confirmation link" do
      h = KemalIdentity::SpecHelper.account_harness
      first = request_confirmation(h)
      second = request_confirmation(h)

      h.service.confirm_email(first).should be_a(KemalIdentity::Accounts::ActionRejected)
      h.service.confirm_email(second).should be_a(KemalIdentity::Accounts::EmailWasConfirmed)
    end
  end

  describe "#confirm_email" do
    it "marks the address as verified" do
      h = KemalIdentity::SpecHelper.account_harness
      h.accounts.find_by_id("a1").or_fail.email_verified?.should be_false

      h.service.confirm_email(request_confirmation(h)).should be_a(KemalIdentity::Accounts::EmailWasConfirmed)

      h.accounts.find_by_id("a1").or_fail.email_verified?.should be_true
    end

    it "refuses the same link twice" do
      h = KemalIdentity::SpecHelper.account_harness
      raw = request_confirmation(h)

      h.service.confirm_email(raw).should be_a(KemalIdentity::Accounts::EmailWasConfirmed)
      h.service.confirm_email(raw).should be_a(KemalIdentity::Accounts::ActionRejected)
    end

    it "refuses a reset token" do
      h = KemalIdentity::SpecHelper.account_harness
      h.service.confirm_email(request_reset(h)).should be_a(KemalIdentity::Accounts::ActionRejected)
    end

    # Proving an address is not a credential change. Logging everybody out would be a surprise
    # with no security benefit.
    it "leaves sessions and auth_version untouched" do
      h = KemalIdentity::SpecHelper.account_harness
      account = h.accounts.find_by_id("a1").or_fail
      issued = h.session_service.start(account, KemalIdentity::AssuranceLevel::Password)

      h.service.confirm_email(request_confirmation(h))

      h.session_service.resolve(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
      h.accounts.find_by_id("a1").or_fail.auth_version.should eq(account.auth_version)
    end
  end

  describe "configuration" do
    it "refuses a non-positive reset lifetime" do
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::SpecHelper.account_harness(reset_ttl: Time::Span::ZERO)
      end
    end
  end
end

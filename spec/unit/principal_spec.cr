require "../spec_helper"

describe KemalIdentity::Principal do
  now = KemalIdentity::SpecHelper::FIXED_NOW

  it "rejects an empty subject" do
    expect_raises(ArgumentError) do
      KemalIdentity::Principal.new(
        subject: "",
        assurance: KemalIdentity::AssuranceLevel::Password,
        authenticated_at: now,
      )
    end
  end

  describe "#session_id" do
    # Derived from `#credential` rather than stored beside it. These examples are what stops
    # the two drifting apart again.
    it "reports the id of a session credential" do
      principal = KemalIdentity::SpecHelper.principal(session_id: "sess-7")
      principal.session_id.should eq("sess-7")
      principal.credential.try(&.kind).should eq(KemalIdentity::CredentialKind::Session)
    end

    it "is nil for a bearer credential that has an id of its own" do
      principal = KemalIdentity::SpecHelper.principal(
        credential: KemalIdentity::CredentialRef.new(
          kind: KemalIdentity::CredentialKind::ApiToken,
          id: "tok-9",
        )
      )

      # There is no session to spare on "log out everywhere else" and none to anchor CSRF on,
      # which is exactly what nil says. The token is still named, on `#credential`.
      principal.session_id.should be_nil
      principal.credential.try(&.id).should eq("tok-9")
    end

    it "is nil when no credential produced the principal" do
      principal = KemalIdentity::SpecHelper.principal(session_id: nil)
      principal.credential.should be_nil
      principal.session_id.should be_nil
    end
  end

  describe "#fresh?" do
    it "is fresh inside the window" do
      principal = KemalIdentity::SpecHelper.principal(authenticated_at: now - 1.minute)
      principal.fresh?(within: 5.minutes, now: now).should be_true
    end

    it "is fresh exactly at the window boundary" do
      principal = KemalIdentity::SpecHelper.principal(authenticated_at: now - 5.minutes)
      principal.fresh?(within: 5.minutes, now: now).should be_true
    end

    it "is stale past the window" do
      principal = KemalIdentity::SpecHelper.principal(authenticated_at: now - 6.minutes)
      principal.fresh?(within: 5.minutes, now: now).should be_false
    end

    # A remember-me cookie proves possession of a stored token, not the presence of the
    # account holder. Step-up must force a real re-authentication out of `Remembered`.
    it "is never fresh at Remembered assurance, however recent" do
      principal = KemalIdentity::SpecHelper.principal(
        assurance: KemalIdentity::AssuranceLevel::Remembered,
        authenticated_at: now,
      )
      principal.fresh?(within: 5.minutes, now: now).should be_false
    end

    it "is fresh at MFA assurance inside the window" do
      principal = KemalIdentity::SpecHelper.principal(
        assurance: KemalIdentity::AssuranceLevel::MFA,
        authenticated_at: now - 1.minute,
      )
      principal.fresh?(within: 5.minutes, now: now).should be_true
    end
  end

  describe "#at_least?" do
    it "orders Remembered below Password below MFA" do
      remembered = KemalIdentity::SpecHelper.principal(assurance: KemalIdentity::AssuranceLevel::Remembered)
      password = KemalIdentity::SpecHelper.principal(assurance: KemalIdentity::AssuranceLevel::Password)
      mfa = KemalIdentity::SpecHelper.principal(assurance: KemalIdentity::AssuranceLevel::MFA)

      remembered.at_least?(KemalIdentity::AssuranceLevel::Password).should be_false
      password.at_least?(KemalIdentity::AssuranceLevel::Password).should be_true
      password.at_least?(KemalIdentity::AssuranceLevel::MFA).should be_false
      mfa.at_least?(KemalIdentity::AssuranceLevel::Password).should be_true
    end
  end
end

describe KemalIdentity::AssuranceLevel do
  # The numeric value is persisted in `auth_sessions.assurance`. Renumbering silently
  # reclassifies every session row already on disk, so the values are asserted here.
  it "has stable persisted values" do
    KemalIdentity::AssuranceLevel::Remembered.value.should eq(10)
    KemalIdentity::AssuranceLevel::Password.value.should eq(20)
    KemalIdentity::AssuranceLevel::MFA.value.should eq(30)
  end
end

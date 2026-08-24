require "../spec_helper"

private def build(accounts : Array(KemalIdentity::Accounts::Account), hasher = KemalIdentity::Testing::FastTestHasher.new)
  repo = KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  {repo, clock, KemalIdentity::Passwords::Authenticator.new(accounts: repo, hasher: hasher, clock: clock)}
end

describe KemalIdentity::Passwords::Authenticator do
  hasher = KemalIdentity::Testing::FastTestHasher.new
  password = "correct horse battery"
  digest = hasher.hash_secret(KemalIdentity::Secret.new(password))

  describe "#authenticate" do
    it "authenticates a correct password" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      auth.authenticate(login: "ada@example.com", password: password)
        .should be_a(KemalIdentity::Authenticated)
    end

    it "returns a principal naming the account" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      principal = KemalIdentity::SpecHelper.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: password)
      )

      principal.subject.should eq("a1")
      principal.assurance.should eq(KemalIdentity::AssuranceLevel::Password)
      principal.authenticated_at.should eq(KemalIdentity::SpecHelper::FIXED_NOW)
    end

    # Verifying a credential does not start a session. Rotation on login — the fixation
    # defence — is the session layer's decision, and it happens after this returns.
    it "carries no session, because it does not create one" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      KemalIdentity::SpecHelper.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: password)
      ).session_id.should be_nil
    end

    it "is fresh, so a step-up guard immediately after login passes" do
      _, clock, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      principal = KemalIdentity::SpecHelper.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: password)
      )
      principal.fresh?(within: 5.minutes, now: clock.now).should be_true
    end

    it "carries the account's tenant" do
      _, _, auth = build([
        KemalIdentity::SpecHelper.account(tenant_id: "t1", password_digest: digest),
      ], hasher)

      KemalIdentity::SpecHelper.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: password, tenant_id: "t1")
      ).tenant_id.should eq("t1")
    end

    it "finds an account within its tenant" do
      _, _, auth = build([
        KemalIdentity::SpecHelper.account(id: "a1", login: "ada@example.com", password_digest: digest),
        KemalIdentity::SpecHelper.account(id: "a2", login: "ada@example.com", tenant_id: "t1", password_digest: digest),
      ], hasher)

      KemalIdentity::SpecHelper.should_authenticate(
        auth.authenticate(login: "ada@example.com", password: password, tenant_id: "t1")
      ).subject.should eq("a2")
    end

    it "rejects a password that differs by one character" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      KemalIdentity::SpecHelper.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: "correct horse batterY"),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end

    it "rejects a password that is a prefix of the right one" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      KemalIdentity::SpecHelper.should_fail_with(
        auth.authenticate(login: "ada@example.com", password: "correct horse batter"),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end

    it "never raises for input a client controls" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)

      ["", " ", "a" * 100_000, "\\u0000", "ada@example.com"].each do |hostile|
        auth.authenticate(login: hostile, password: hostile).should be_a(KemalIdentity::Failed)
      end
    end

    it "treats an empty login as an ordinary failure" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)
      KemalIdentity::SpecHelper.should_fail_with(
        auth.authenticate(login: "", password: password),
        KemalIdentity::FailureReason::InvalidCredential
      )
    end
  end

  # The seam for step 8. It is recorded now so that wiring a rate limiter does not change the
  # signature every application already calls.
  describe "the ip argument" do
    it "is accepted and does not affect the outcome" do
      _, _, auth = build([KemalIdentity::SpecHelper.account(password_digest: digest)], hasher)

      with_ip = auth.authenticate(login: "ada@example.com", password: password, ip: "203.0.113.7")
      without = auth.authenticate(login: "ada@example.com", password: password)

      with_ip.should be_a(KemalIdentity::Authenticated)
      without.should be_a(KemalIdentity::Authenticated)
    end
  end
end

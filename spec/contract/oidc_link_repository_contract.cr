# Shared spec for `KemalIdentity::OIDC::LinkRepository`. Every implementation runs it.
def it_behaves_like_a_link_repository(&build : -> KemalIdentity::OIDC::LinkRepository)
  now = KemalIdentity::SpecHelper::FIXED_NOW
  google = "https://accounts.google.com"
  okta = "https://acme.okta.com"

  link = ->(id : String, account_id : String, issuer : String, subject : String) do
    KemalIdentity::OIDC::Link.new(
      id: id, account_id: account_id, issuer: issuer, subject: subject, created_at: now
    )
  end

  describe "#link and #find" do
    it "round trips a link" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      found = repo.find(google, "sub-1").or_fail
      found.account_id.should eq("a1")
      found.issuer.should eq(google)
      found.subject.should eq("sub-1")
      found.last_authenticated_at.should be_nil
    end

    it "returns nil for a pair nobody linked, rather than raising" do
      build.call.find(google, "nobody").should be_nil
    end

    # `subject` is stable within an issuer and meaningless outside it: two providers can hand
    # out the same `sub` and mean two different people.
    it "treats the same subject at two issuers as two identities" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "shared-sub"))
      repo.link(link.call("l2", "a2", okta, "shared-sub"))

      repo.find(google, "shared-sub").or_fail.account_id.should eq("a1")
      repo.find(okta, "shared-sub").or_fail.account_id.should eq("a2")
    end

    # Otherwise one provider account ends up attached to two local ones, and whichever row is
    # found first decides who somebody logs in as.
    it "refuses to link a pair that is already linked" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.link(link.call("l2", "a2", google, "sub-1"))
      end
    end

    # Including to the same account: a repeat is a bug in the caller, not a no-op to absorb.
    it "refuses to link the same pair to the same account twice" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.link(link.call("l2", "a1", google, "sub-1"))
      end
    end

    it "refuses a duplicate id" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      expect_raises(KemalIdentity::InfrastructureError) do
        repo.link(link.call("l1", "a2", google, "sub-2"))
      end
    end

    # One person, two providers, one account. The normal arrangement.
    it "lets one account hold links at several issuers" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))
      repo.link(link.call("l2", "a1", okta, "sub-2"))

      repo.find(google, "sub-1").or_fail.account_id.should eq("a1")
      repo.find(okta, "sub-2").or_fail.account_id.should eq("a1")
    end
  end

  describe "#for_account" do
    it "lists an account's links, oldest first" do
      repo = build.call
      repo.link(
        KemalIdentity::OIDC::Link.new(
          id: "l1", account_id: "a1", issuer: google, subject: "sub-1", created_at: now
        )
      )
      repo.link(
        KemalIdentity::OIDC::Link.new(
          id: "l2", account_id: "a1", issuer: okta, subject: "sub-2", created_at: now + 1.hour
        )
      )

      repo.for_account("a1").map(&.id).should eq(["l1", "l2"])
    end

    it "does not list another account's links" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))
      repo.link(link.call("l2", "a2", google, "sub-2"))

      repo.for_account("a2").map(&.id).should eq(["l2"])
    end

    it "returns an empty array for an account with none" do
      build.call.for_account("a1").should be_empty
    end
  end

  describe "#unlink" do
    it "removes one link" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      repo.unlink(google, "sub-1").should be_true
      repo.find(google, "sub-1").should be_nil
    end

    it "returns false for a pair that was not linked" do
      build.call.unlink(google, "nobody").should be_false
    end

    it "leaves the account's other links alone" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))
      repo.link(link.call("l2", "a1", okta, "sub-2"))

      repo.unlink(google, "sub-1")

      repo.for_account("a1").map(&.id).should eq(["l2"])
    end

    # And the pair becomes linkable again, possibly to a different account.
    it "frees the pair to be linked again" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))
      repo.unlink(google, "sub-1")

      repo.link(link.call("l2", "a2", google, "sub-1"))
      repo.find(google, "sub-1").or_fail.account_id.should eq("a2")
    end
  end

  describe "#touch" do
    it "records when the link was last used" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))

      repo.touch(google, "sub-1", now + 5.minutes).should be_true
      repo.find(google, "sub-1").or_fail.last_authenticated_at.should eq(now + 5.minutes)
    end

    it "returns false for a pair that was not linked" do
      build.call.touch(google, "nobody", now).should be_false
    end

    it "affects only the pair named" do
      repo = build.call
      repo.link(link.call("l1", "a1", google, "sub-1"))
      repo.link(link.call("l2", "a1", okta, "sub-2"))

      repo.touch(google, "sub-1", now + 5.minutes)

      repo.find(okta, "sub-2").or_fail.last_authenticated_at.should be_nil
    end
  end
end

# Shared spec for `KemalIdentity::JWT::RevocationStore`. Every implementation runs it.
def it_behaves_like_a_revocation_store(&build : -> KemalIdentity::JWT::RevocationStore)
  now = KemalIdentity::Testing::FIXED_NOW

  describe "#revoked? and #revoke" do
    it "refuses a jti from the moment it is revoked" do
      store = build.call
      store.revoked?("j1").should be_false

      store.revoke("j1", now + 15.minutes)

      store.revoked?("j1").should be_true
    end

    it "reports an unknown jti as live rather than raising" do
      build.call.revoked?("never-issued").should be_false
    end

    it "affects only the jti named" do
      store = build.call
      store.revoke("j1", now + 15.minutes)

      store.revoked?("j2").should be_false
    end

    # A "sign out everywhere" may well be replayed, and the second one must not blow up.
    it "tolerates revoking the same jti twice" do
      store = build.call
      store.revoke("j1", now + 15.minutes)
      store.revoke("j1", now + 15.minutes)

      store.revoked?("j1").should be_true
    end

    # The entry has to outlive every token carrying the id, so the later expiry wins. Taking
    # the earlier one would sweep the entry while a token was still verifiable.
    it "keeps the furthest expiry when a jti is revoked twice with different ones" do
      store = build.call
      store.revoke("j1", now + 1.hour)
      store.revoke("j1", now + 1.minute)

      store.delete_expired(now + 30.minutes).should eq(0)
      store.revoked?("j1").should be_true
    end
  end

  describe "#delete_expired" do
    # Past its `exp` the signature no longer verifies, so the entry proves nothing and the
    # store stays bounded by what was revoked within one token lifetime.
    it "drops entries whose tokens have expired and returns how many" do
      store = build.call
      store.revoke("j1", now + 1.minute)
      store.revoke("j2", now + 1.hour)

      store.delete_expired(now + 30.minutes).should eq(1)
      store.revoked?("j1").should be_false
      store.revoked?("j2").should be_true
    end

    it "drops an entry expiring exactly at the sweep instant" do
      store = build.call
      store.revoke("j1", now)

      store.delete_expired(now).should eq(1)
    end

    it "returns zero when there is nothing to drop" do
      build.call.delete_expired(now).should eq(0)
    end
  end
end

require "../spec_helper"

describe KemalIdentity::CredentialRef do
  ref = ->(scopes : Array(String)?) do
    KemalIdentity::CredentialRef.new(
      kind: KemalIdentity::CredentialKind::ApiToken,
      id: "tok-1",
      scopes: scopes,
    )
  end

  describe "#permits? and #unrestricted?" do
    # The distinction this whole struct turns on. `nil` is a lockout if read as an empty set,
    # and `[]` is a privilege escalation if read as unset.
    it "permits everything when scopes are absent" do
      ref.call(nil).unrestricted?.should be_true
      ref.call(nil).permits?("releases:write").should be_true
      ref.call(nil).permits?("anything:at:all").should be_true
    end

    it "permits nothing when scopes are present and empty" do
      empty = ref.call([] of String)

      empty.unrestricted?.should be_false
      empty.permits?("releases:write").should be_false
      empty.permits?("reports:read").should be_false
    end

    it "permits only what it lists" do
      scoped = ref.call(["reports:read"])

      scoped.permits?("reports:read").should be_true
      scoped.permits?("releases:write").should be_false
    end

    it "matches a scope exactly, with no prefix or hierarchy" do
      scoped = ref.call(["reports"])

      scoped.permits?("reports:read").should be_false
      scoped.permits?("reports").should be_true
    end

    # `blueprints/0018` refuses `*` in a permission because a wildcard grants permissions that
    # do not exist yet. A wildcard *scope* is the same hazard aimed at tokens, so `*` is a
    # scope literally named `*` and nothing else. Unrestricted is `nil`.
    it "treats a star as a literal scope rather than a wildcard" do
      starred = ref.call(["*"])

      starred.unrestricted?.should be_false
      starred.permits?("releases:write").should be_false
      starred.permits?("*").should be_true
    end
  end

  describe "safety" do
    # Nothing here needs redacting because nothing secret ever reaches it. This asserts the
    # shape of the contract: an id and a label, never material.
    it "carries no secret material" do
      credential = KemalIdentity::CredentialRef.new(
        kind: KemalIdentity::CredentialKind::ApiToken,
        id: "tok-1",
        name: "deploy-token",
      )

      credential.id.should eq("tok-1")
      credential.name.should eq("deploy-token")
      credential.responds_to?(:digest).should be_false
      credential.responds_to?(:secret).should be_false
      credential.responds_to?(:token).should be_false
    end
  end

  describe KemalIdentity::CredentialKind do
    # Appended to, never renumbered or renamed: consumers write `case credential.kind` over
    # these, and a rename breaks code that compiled yesterday.
    it "has the members consumers switch on" do
      KemalIdentity::CredentialKind.names.should eq(%w[Session ApiToken Jwt Custom])
    end
  end
end

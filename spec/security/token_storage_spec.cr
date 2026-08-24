require "../spec_helper"

# docs/05-testing.md, cookie blockers: "the raw session token never appears in a database
# row". This is what makes a leaked database backup useless for hijacking a session — the
# rows hold no value a browser could present.
describe "session token storage" do
  it "stores only the digest, never the raw token" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    stored = h.sessions.find_by_digest(issued.record.token_digest).or_fail.session
    raw = issued.token.reveal

    stored.token_digest.should eq(KemalIdentity::Secret.new(raw).digest)
    stored.token_digest.hexstring.should_not contain(raw)
    String.new(stored.token_digest).should_not contain(raw)
    stored.id.should_not eq(raw)
  end

  it "cannot be resolved from the digest, only from the token" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    # Someone holding the row cannot turn it back into a cookie.
    h.service.resolve(issued.record.token_digest.hexstring).should be_a(KemalIdentity::Failed)
    h.service.resolve(issued.record.id).should be_a(KemalIdentity::Failed)
  end

  it "redacts the token in inspect and interpolation" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)
    raw = issued.token.reveal

    issued.token.to_s.should_not contain(raw)
    issued.token.inspect.should_not contain(raw)
    "token=#{issued.token}".should_not contain(raw)
  end

  it "redacts the digest when a session record is inspected" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    issued.record.inspect.should contain("[REDACTED]")
    issued.record.inspect.should_not contain(issued.record.token_digest.hexstring)
  end

  it "gives every session a distinct token and digest" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    account = h.accounts.find_by_id("a1").or_fail

    issued = Array.new(10) { h.service.start(account, KemalIdentity::AssuranceLevel::Password) }

    issued.map(&.token.reveal).uniq!.size.should eq(10)
    issued.map(&.record.token_digest.hexstring).uniq!.size.should eq(10)
    issued.map(&.record.id).uniq!.size.should eq(10)
  end
end

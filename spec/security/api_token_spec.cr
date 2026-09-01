require "../spec_helper"

# Bearer tokens, from `docs/06-roadmap.md`'s v0.4: opaque personal access tokens first, because
# they reuse the digest-and-revoke machinery and carry none of JWT's revocation problem.
#
# Named for the properties that matter rather than for the methods.
private def token_harness(touch_interval : Time::Span = KemalIdentity::ApiTokens::Service::DEFAULT_TOUCH_INTERVAL)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  random = KemalIdentity::Testing::DeterministicRandom.new
  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
  repo = KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts)

  service = KemalIdentity::ApiTokens::Service.new(
    tokens: repo, clock: clock, random: random, touch_interval: touch_interval
  )

  {service, repo, accounts, clock}
end

private def issue(service, accounts, name : String = "laptop", expires_at : Time? = nil)
  service.issue(accounts.find_by_id("a1").or_fail, name, expires_at: expires_at)
end

describe "a personal access token" do
  it "authenticates the account that owns it" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    principal = KemalIdentity::Testing.should_authenticate(service.authenticate(issued.token.reveal))
    principal.subject.should eq("a1")
  end

  # Below Password, so `require_fresh!` refuses it outright. An automated client cannot
  # re-authenticate interactively, so a destructive action should not be reachable with a token.
  it "authenticates at ApiToken assurance, which is never fresh" do
    service, _, accounts, clock = token_harness
    issued = issue(service, accounts)

    principal = KemalIdentity::Testing.should_authenticate(service.authenticate(issued.token.reveal))

    principal.assurance.should eq(KemalIdentity::AssuranceLevel::ApiToken)
    principal.at_least?(KemalIdentity::AssuranceLevel::Password).should be_false
    principal.fresh?(within: 5.minutes, now: clock.now).should be_false
  end

  # A bearer token is presented per request and establishes nothing.
  it "carries no session" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    KemalIdentity::Testing.should_authenticate(service.authenticate(issued.token.reveal))
      .session_id.should be_nil
  end

  # `blueprints/0021-credential-reference.md` opens on this failure: the token id is in hand
  # when the token is authenticated, and used to be dropped, so an application had no way to
  # tell which of an account's tokens was asking.
  it "names the token that proved the request" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts, "deploy-token")

    principal = KemalIdentity::Testing.should_authenticate(service.authenticate(issued.token.reveal))
    credential = principal.credential.should_not be_nil

    credential.kind.should eq(KemalIdentity::CredentialKind::ApiToken)
    credential.id.should eq(issued.record.id)
    credential.name.should eq("deploy-token")
  end

  # The property the whole change exists for. Two tokens for one account used to produce two
  # byte-identical principals, so a token issued for reading could perform a write its owner
  # happened to be permitted.
  it "distinguishes two tokens belonging to the same account" do
    service, _, accounts, _ = token_harness
    reporting = issue(service, accounts, "reporting-token")
    deploying = issue(service, accounts, "deploy-token")

    one = KemalIdentity::Testing.should_authenticate(service.authenticate(reporting.token.reveal))
    two = KemalIdentity::Testing.should_authenticate(service.authenticate(deploying.token.reveal))

    one.subject.should eq(two.subject)
    one.credential.try(&.id).should_not eq(two.credential.try(&.id))
  end

  # Unattenuated until scopes exist. `nil` is not an empty set: reading it as one would deny
  # every request a token makes, which is the fail-closed edge of `CredentialRef#scopes`.
  it "is unattenuated, since no scope has been issued to it" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    principal = KemalIdentity::Testing.should_authenticate(service.authenticate(issued.token.reveal))
    credential = principal.credential.should_not be_nil

    credential.scopes.should be_nil
    credential.unrestricted?.should be_true
    credential.permits?("releases:write").should be_true
  end

  # A fixed, searchable prefix is what lets a secret scanner recognise one of these in a commit
  # or a paste. A bare base64 blob is indistinguishable from any other base64 blob.
  it "carries a searchable prefix so a leaked token can be recognised" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    issued.token.reveal.should start_with("ki_")
  end

  it "redacts itself, so an accidental log line is not a credential" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    "token=#{issued.token}".should_not contain(issued.token.reveal)
  end

  # The stored side must be useless to whoever holds it.
  it "is stored only as a digest" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)
    raw = issued.token.reveal

    issued.record.token_digest.should eq(KemalIdentity::Secret.new(raw).digest)
    service.authenticate(issued.record.token_digest.hexstring).should be_a(KemalIdentity::Failed)
    service.authenticate(issued.record.id).should be_a(KemalIdentity::Failed)
  end

  it "gives every token a distinct secret" do
    service, _, accounts, _ = token_harness
    tokens = Array.new(10) { |i| issue(service, accounts, "token-#{i}").token.reveal }

    tokens.uniq!.size.should eq(10)
  end
end

describe "revoking an API token" do
  # The whole reason opaque tokens come before JWT: revocation takes effect on the next request
  # because validity is read from storage rather than asserted by a signature.
  it "takes effect on the very next request" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    service.authenticate(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    service.revoke(issued.record.id).should be_true

    KemalIdentity::Testing.should_fail_with(
      service.authenticate(issued.token.reveal), KemalIdentity::FailureReason::Revoked
    )
  end

  it "leaves the account's other tokens working" do
    service, _, accounts, _ = token_harness
    first = issue(service, accounts, "laptop")
    second = issue(service, accounts, "ci")

    service.revoke(first.record.id)

    service.authenticate(second.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  # A route that lets a client name the token to revoke -- `DELETE /tokens/:id` -- is the obvious
  # thing to write, and with the one-argument form it revokes anybody's token. Token ids are not
  # secret: they appear in audit lines and in management listings.
  describe "scoped to an owner" do
    it "revokes a token the account owns" do
      service, _, accounts, _ = token_harness
      issued = issue(service, accounts)

      service.revoke(issued.record.id, "a1").should be_true

      KemalIdentity::Testing.should_fail_with(
        service.authenticate(issued.token.reveal), KemalIdentity::FailureReason::Revoked
      )
    end

    it "refuses to revoke a token belonging to somebody else, and says nothing about it" do
      accounts = KemalIdentity::Testing::MemoryAccountRepository.new([
        KemalIdentity::Testing.account,
        KemalIdentity::Testing.account(id: "a2", login: "grace@example.com"),
      ])
      service = KemalIdentity::ApiTokens::Service.new(
        tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
        random: KemalIdentity::Testing::DeterministicRandom.new,
      )

      victim = service.issue(accounts.find_by_id("a1").or_fail, "laptop")

      service.revoke(victim.record.id, "a2").should be_false
      # Same answer for an id that does not exist at all, so the caller learns nothing.
      service.revoke("no-such-token", "a2").should be_false

      # And the token still works, which is the property that matters.
      service.authenticate(victim.token.reveal).should be_a(KemalIdentity::Authenticated)
    end
  end

  it "revokes every token at once when asked" do
    service, _, accounts, _ = token_harness
    tokens = Array.new(3) { |i| issue(service, accounts, "token-#{i}") }

    service.revoke_all("a1").should eq(3)

    tokens.each do |issued|
      service.authenticate(issued.token.reveal).should be_a(KemalIdentity::Failed)
    end
  end
end

describe "an API token that should not authenticate" do
  it "is rejected once it has expired" do
    service, _, accounts, clock = token_harness
    issued = issue(service, accounts, expires_at: KemalIdentity::Testing::FIXED_NOW + 30.days)

    clock.advance(31.days)

    KemalIdentity::Testing.should_fail_with(
      service.authenticate(issued.token.reveal), KemalIdentity::FailureReason::Expired
    )
  end

  # A deploy key with no expiry is a deliberate choice, and a sweep must never reach it.
  it "never expires when it was issued without an expiry" do
    service, _, accounts, clock = token_harness
    issued = issue(service, accounts)

    clock.advance(1000.days)

    service.authenticate(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
    service.delete_expired.should eq(0)
  end

  it "stops working the moment the account is disabled" do
    service, _, accounts, clock = token_harness
    issued = issue(service, accounts)

    accounts.disable("a1", clock.now)

    KemalIdentity::Testing.should_fail_with(
      service.authenticate(issued.token.reveal), KemalIdentity::FailureReason::DisabledAccount
    )
  end

  # Deliberate divergence from sessions: a password change must not silently break a deploy key
  # whose holder is a machine with no way to notice. Revoking tokens is explicit.
  it "survives an auth_version bump, unlike a session" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)

    accounts.bump_auth_version("a1")

    service.authenticate(issued.token.reveal).should be_a(KemalIdentity::Authenticated)
  end

  it "is anonymous when nothing was presented" do
    service, _, _, _ = token_harness

    service.authenticate(nil).should be_a(KemalIdentity::Anonymous)
    service.authenticate("").should be_a(KemalIdentity::Anonymous)
  end

  it "fails rather than going anonymous when something unusable was presented" do
    service, _, _, _ = token_harness
    service.authenticate("ki_garbage").should be_a(KemalIdentity::Failed)
  end

  it "never raises for anything a client controls" do
    service, _, _, _ = token_harness

    ["ki_", "garbage", "ki_" + "a" * 43, "a" * 2_000_000, "ki_" + "!" * 43].each do |candidate|
      service.authenticate(candidate).should be_a(KemalIdentity::Failed)
    end
  end

  it "rejects a value without the prefix before touching the store" do
    service, _, accounts, _ = token_harness
    issued = issue(service, accounts)
    without_prefix = issued.token.reveal.sub("ki_", "")

    KemalIdentity::Testing.should_fail_with(
      service.authenticate(without_prefix), KemalIdentity::FailureReason::MalformedCredential
    )
  end
end

# The same write-amplification trap sessions have: without a throttle, every authenticated API
# request becomes a write, and an API's request rate is where that hurts most.
describe "recording when a token was last used" do
  it "does not write on every request" do
    service, repo, accounts, clock = token_harness(touch_interval: 5.minutes)
    issued = issue(service, accounts)

    service.authenticate(issued.token.reveal)
    first = repo.find_by_digest(issued.record.token_digest).or_fail.token.last_used_at

    clock.advance(1.minute)
    service.authenticate(issued.token.reveal)

    repo.find_by_digest(issued.record.token_digest).or_fail.token.last_used_at.should eq(first)
  end

  it "writes once the interval has passed" do
    service, repo, accounts, clock = token_harness(touch_interval: 5.minutes)
    issued = issue(service, accounts)

    service.authenticate(issued.token.reveal)
    clock.advance(6.minutes)
    service.authenticate(issued.token.reveal)

    repo.find_by_digest(issued.record.token_digest).or_fail
      .token.last_used_at.should eq(KemalIdentity::Testing::FIXED_NOW + 6.minutes)
  end
end

describe "issuing" do
  it "refuses a disabled account" do
    service, _, accounts, clock = token_harness
    accounts.disable("a1", clock.now)

    expect_raises(ArgumentError) { issue(service, accounts) }
  end

  it "refuses an expiry in the past" do
    service, _, accounts, _ = token_harness

    expect_raises(ArgumentError) do
      issue(service, accounts, expires_at: KemalIdentity::Testing::FIXED_NOW - 1.hour)
    end
  end

  it "refuses a token with no name, because a management screen needs one" do
    service, _, accounts, _ = token_harness

    expect_raises(ArgumentError) { issue(service, accounts, name: "  ") }
  end

  it "refuses a prefix that is not url-safe" do
    _, repo, _, clock = token_harness

    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::ApiTokens::Service.new(
        tokens: repo, clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
        prefix: "bad prefix!"
      )
    end
  end
end

require "../spec_helper"

# docs/02-security-model.md, remember-me: a stolen cookie must be *detectable*.
#
# The threat is a cookie copied off a laptop, out of a backup, or through a subdomain. An
# ordinary long-lived session gives an attacker a month of access that nobody ever notices.
# Rotating single-use tokens do not stop the theft — nothing here can — but they guarantee that
# the next visit by either party surfaces it.
#
# Named for the attack.
private def harness(ttl : Time::Span = 30.days)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  random = KemalIdentity::Testing::DeterministicRandom.new
  notifier = KemalIdentity::Testing::RecordingNotifier.new

  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::SpecHelper.account])
  sessions_repo = KemalIdentity::Testing::MemorySessionRepository.new(accounts)
  remember_repo = KemalIdentity::Testing::MemoryRememberRepository.new

  sessions = KemalIdentity::Sessions::Service.new(
    sessions: sessions_repo, clock: clock, random: random
  )

  service = KemalIdentity::Sessions::RememberService.new(
    remember: remember_repo, accounts: accounts, sessions: sessions,
    clock: clock, random: random, notifier: notifier, ttl: ttl
  )

  {service, sessions, accounts, notifier, clock, remember_repo}
end

private def remember_now(service, accounts) : String
  service.remember(accounts.find_by_id("a1").or_fail).token.reveal
end

describe "a stolen remember-me cookie" do
  # The core scenario. The thief gets in once; the real user's next visit is what exposes it.
  it "is detected when the legitimate user visits after the thief" do
    service, _, accounts, _, _, _ = harness
    stolen = remember_now(service, accounts)

    # The thief uses the copy first, and it works. Nothing can prevent that.
    service.restore(stolen).should be_a(KemalIdentity::Sessions::Restored)

    # The real user still holds the same token, because they never used it after the copy was
    # taken. Presenting it is a replay.
    service.restore(stolen).should be_a(KemalIdentity::Sessions::ReplayDetected)
  end

  # The mirror image, and the reason this works at all: it does not matter who goes first.
  it "is detected when the thief visits after the legitimate user" do
    service, _, accounts, _, _, _ = harness
    original = remember_now(service, accounts)

    restored = service.restore(original).as(KemalIdentity::Sessions::Restored)
    restored.remember.token.reveal.should_not eq(original)

    # The thief's copy is now the spent one.
    service.restore(original).should be_a(KemalIdentity::Sessions::ReplayDetected)
  end

  it "ends the whole family, so neither party stays remembered" do
    service, _, accounts, _, _, _ = harness
    stolen = remember_now(service, accounts)

    thief = service.restore(stolen).as(KemalIdentity::Sessions::Restored)
    service.restore(stolen).should be_a(KemalIdentity::Sessions::ReplayDetected)

    # The token the thief rotated into dies with the family.
    service.restore(thief.remember.token.reveal).should be_a(KemalIdentity::Sessions::NotRemembered)
  end

  # More than docs/02 literally asks for. Killing only the family would leave the session the
  # thief already minted alive for its full lifetime: the detection fires and the intruder
  # stays signed in.
  it "ends the sessions the thief already obtained" do
    service, sessions, accounts, _, _, _ = harness
    stolen = remember_now(service, accounts)

    thief = service.restore(stolen).as(KemalIdentity::Sessions::Restored)
    sessions.resolve(thief.session_token.reveal).should be_a(KemalIdentity::Authenticated)

    detected = service.restore(stolen).as(KemalIdentity::Sessions::ReplayDetected)

    detected.revoked_sessions.should be > 0
    sessions.resolve(thief.session_token.reveal).should be_a(KemalIdentity::Failed)
  end

  it "tells the account holder, because it may be their only warning" do
    service, _, accounts, notifier, clock, _ = harness
    stolen = remember_now(service, accounts)
    service.restore(stolen)
    service.restore(stolen)

    replays = notifier.replays
    replays.size.should eq(1)
    replays.first.account_id.should eq("a1")
    replays.first.login.should eq("ada@example.com")
    replays.first.at.should eq(clock.now)
  end

  it "reports the detection to the caller rather than silently signing them in" do
    service, _, accounts, _, _, _ = harness
    stolen = remember_now(service, accounts)
    service.restore(stolen)

    detected = service.restore(stolen).as(KemalIdentity::Sessions::ReplayDetected)
    detected.account_id.should eq("a1")
    detected.revoked_tokens.should be > 0
  end

  # A cookie stolen from one machine says nothing about the others, so signing every device
  # out of *remembered* state would punish the user for the thief.
  it "leaves the account's other browsers remembered" do
    service, _, accounts, _, _, _ = harness
    laptop = remember_now(service, accounts)
    phone = remember_now(service, accounts)

    service.restore(laptop)
    service.restore(laptop).should be_a(KemalIdentity::Sessions::ReplayDetected)

    service.restore(phone).should be_a(KemalIdentity::Sessions::Restored)
  end
end

describe "rotation of the remember-me cookie" do
  it "issues a different token on every visit" do
    service, _, accounts, _, _, _ = harness
    token = remember_now(service, accounts)

    seen = [token]
    3.times do
      token = service.restore(token).as(KemalIdentity::Sessions::Restored).remember.token.reveal
      seen << token
    end

    seen.uniq!.size.should eq(4)
  end

  it "keeps the family across rotations, so a replay of any old link still names it" do
    service, _, accounts, _, _, _ = harness
    first = remember_now(service, accounts)

    second = service.restore(first).as(KemalIdentity::Sessions::Restored)
    third = service.restore(second.remember.token.reveal).as(KemalIdentity::Sessions::Restored)

    third.remember.family_id.should eq(second.remember.family_id)

    # An ancestor token, replayed several rotations later, still condemns the same family.
    detected = service.restore(first).as(KemalIdentity::Sessions::ReplayDetected)
    detected.family_id.should eq(second.remember.family_id)
  end
end

describe "the assurance of a restored session" do
  # Possession of a cookie is not the presence of the account holder.
  it "is Remembered, below Password" do
    service, _, accounts, _, _, _ = harness
    restored = service.restore(remember_now(service, accounts)).as(KemalIdentity::Sessions::Restored)

    restored.principal.assurance.should eq(KemalIdentity::AssuranceLevel::Remembered)
    restored.principal.at_least?(KemalIdentity::AssuranceLevel::Password).should be_false
  end

  # The step-up guard's whole purpose: anything sensitive forces a real re-authentication.
  it "is never fresh, however recently it was restored" do
    service, _, accounts, _, clock, _ = harness
    restored = service.restore(remember_now(service, accounts)).as(KemalIdentity::Sessions::Restored)

    restored.principal.fresh?(within: 5.minutes, now: clock.now).should be_false
    restored.principal.fresh?(within: 1.second, now: clock.now).should be_false
  end
end

describe "a remember-me cookie that is merely unusable" do
  it "is not reported as theft when it has expired" do
    service, _, accounts, notifier, clock, _ = harness(ttl: 30.days)
    token = remember_now(service, accounts)

    clock.advance(31.days)

    service.restore(token).should be_a(KemalIdentity::Sessions::NotRemembered)
    notifier.replays.should be_empty
  end

  it "is not reported as theft when the family was already revoked" do
    service, _, accounts, notifier, _, _ = harness
    token = remember_now(service, accounts)

    service.forget(service.restore(token).as(KemalIdentity::Sessions::Restored).remember.family_id)
    notifier.clear

    service.restore(token).should be_a(KemalIdentity::Sessions::NotRemembered)
    notifier.replays.should be_empty
  end

  it "is not reported at all when nobody issued it" do
    service, _, _, notifier, _, _ = harness

    ["", "garbage", "a" * 43, "a" * 100_000].each do |candidate|
      service.restore(candidate).should be_a(KemalIdentity::Sessions::NotRemembered)
    end

    notifier.replays.should be_empty
  end

  it "stops working once the account is disabled" do
    service, _, accounts, _, clock, _ = harness
    token = remember_now(service, accounts)

    accounts.disable("a1", clock.now)

    service.restore(token).should be_a(KemalIdentity::Sessions::NotRemembered)
  end
end

describe "forgetting" do
  it "ends one browser's remembered state" do
    service, _, accounts, _, _, _ = harness
    laptop = remember_now(service, accounts)
    phone = remember_now(service, accounts)

    laptop_family = service.restore(laptop).as(KemalIdentity::Sessions::Restored).remember.family_id
    service.forget(laptop_family)

    service.restore(phone).should be_a(KemalIdentity::Sessions::Restored)
  end

  it "ends every browser at once when asked" do
    service, _, accounts, _, _, _ = harness
    laptop = remember_now(service, accounts)
    phone = remember_now(service, accounts)

    service.forget_all("a1").should be > 0

    service.restore(laptop).should be_a(KemalIdentity::Sessions::NotRemembered)
    service.restore(phone).should be_a(KemalIdentity::Sessions::NotRemembered)
  end

  it "refuses to remember a disabled account in the first place" do
    service, _, accounts, _, clock, _ = harness
    accounts.disable("a1", clock.now)

    expect_raises(ArgumentError) do
      service.remember(accounts.find_by_id("a1").or_fail)
    end
  end
end

describe "what the remember-me store keeps" do
  it "stores only the digest, never the raw token" do
    service, _, accounts, _, _, repo = harness
    raw = remember_now(service, accounts)

    # Presenting the digest is not presenting the token.
    service.restore(KemalIdentity::Secret.new(raw).digest.hexstring)
      .should be_a(KemalIdentity::Sessions::NotRemembered)
    service.restore(raw).should be_a(KemalIdentity::Sessions::Restored)
    repo.size.should be > 0
  end

  it "hands the browser a token that redacts itself" do
    service, _, accounts, _, _, _ = harness
    issued = service.remember(accounts.find_by_id("a1").or_fail)

    "cookie=#{issued.token}".should_not contain(issued.token.reveal)
  end
end

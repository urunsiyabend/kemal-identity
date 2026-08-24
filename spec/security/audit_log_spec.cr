require "log/spec"
require "../spec_helper"

# docs/05-testing.md logging blockers:
#   - a login attempt produces an audit event containing no password, token or cookie
#   - an unhandled error from the auth path does not include secret material in its message
#
# docs/02-security-model.md lists login success and failure with reason among the events that
# must reach a structured log, and lists passwords, raw tokens, cookies, Authorization headers
# and digests among the things that must never.
private PASSWORD = "correct horse battery staple"

private def build(disabled_at : Time? = nil, digest : String? = nil)
  hasher = KemalIdentity::Testing::FastTestHasher.new
  repo = KemalIdentity::Testing::MemoryAccountRepository.new([
    KemalIdentity::SpecHelper.account(
      disabled_at: disabled_at,
      password_digest: digest || hasher.hash_secret(KemalIdentity::Secret.new(PASSWORD)),
    ),
  ])
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  {repo, hasher, KemalIdentity::Passwords::Authenticator.new(accounts: repo, hasher: hasher, clock: clock)}
end

# Everything a captured entry could possibly reveal, flattened: source, message, and every
# metadata value. Asserting on the message alone would miss a secret smuggled into a
# structured field, which is exactly where one would end up by accident.
private def rendered(entries : Array(Log::Entry)) : String
  # A "does not contain the password" assertion passes trivially against nothing at all, so
  # an empty capture is a broken spec rather than a clean bill of health. Failing here means
  # every caller below inherits the guard.
  if entries.empty?
    raise Spec::AssertionFailed.new("no log entries were captured, so nothing was asserted", __FILE__, __LINE__)
  end

  entries.map { |entry| "#{entry.source} #{entry.message} #{entry.data}" }.join("\n")
end

# Collects every entry the shard emits during the block.
#
# `Log.capture` yields a checker that consumes its entries as it matches them, which suits an
# assertion about one event but not an assertion about *all* of them — and "no entry anywhere
# contains this password" is the shape of every spec below. A `MemoryBackend` keeps the lot.
private def captured(&) : Array(Log::Entry)
  backend = Log::MemoryBackend.new
  Log.builder.bind("kemal_identity.*", :trace, backend)
  yield
  backend.entries
end

describe "the audit trail" do
  it "records a successful login" do
    _, _, auth = build

    Log.capture("kemal_identity") do |logs|
      auth.authenticate(login: "ada@example.com", password: PASSWORD, ip: "203.0.113.7")
      logs.check(:info, /authentication.succeeded/)
    end
  end

  it "records a failed login with its reason" do
    _, _, auth = build

    Log.capture("kemal_identity") do |logs|
      auth.authenticate(login: "ada@example.com", password: "wrong")
      logs.check(:info, /authentication.failed/)
      logs.entry.data[:reason].should eq("InvalidCredential")
    end
  end

  # The distinction the response is forbidden to make is exactly the one the log must.
  it "records a disabled account distinctly from a wrong password" do
    _, _, auth = build(disabled_at: KemalIdentity::SpecHelper::FIXED_NOW)

    Log.capture("kemal_identity") do |logs|
      auth.authenticate(login: "ada@example.com", password: PASSWORD)
      logs.check(:info, /authentication.failed/)
      logs.entry.data[:reason].should eq("DisabledAccount")
    end
  end

  it "records the account and the source address" do
    _, _, auth = build

    Log.capture("kemal_identity") do |logs|
      auth.authenticate(login: "ada@example.com", password: PASSWORD, ip: "203.0.113.7")
      logs.check(:info, /authentication.succeeded/)
      logs.entry.data[:subject].should eq("a1")
      logs.entry.data[:ip].should eq("203.0.113.7")
    end
  end

  it "records a rehash" do
    weak = KemalIdentity::Testing::FastTestHasher.new(rounds: 1)
    _, _, auth = build(digest: weak.hash_secret(KemalIdentity::Secret.new(PASSWORD)))

    Log.capture("kemal_identity") do |logs|
      auth.authenticate(login: "ada@example.com", password: PASSWORD)
      logs.check(:info, /password.rehashed/)
    end
  end
end

describe "secret material in the audit trail" do
  it "never contains the submitted password, on success" do
    _, _, auth = build

    entries = captured do
      auth.authenticate(login: "ada@example.com", password: PASSWORD, ip: "203.0.113.7")
    end

    rendered(entries).should_not contain(PASSWORD)
    rendered(entries).should_not contain("correct horse")
  end

  it "never contains the submitted password, on failure" do
    _, _, auth = build

    entries = captured do
      auth.authenticate(login: "ada@example.com", password: "hunter2-was-my-guess")
    end

    rendered(entries).should_not contain("hunter2")
  end

  it "never contains the stored password digest" do
    repo, _, auth = build
    digest = repo.find_by_id("a1").or_fail.password_digest.or_fail

    entries = captured do
      auth.authenticate(login: "ada@example.com", password: PASSWORD)
    end

    rendered(entries).should_not contain(digest)
  end

  it "never contains the newly written digest after a rehash" do
    weak = KemalIdentity::Testing::FastTestHasher.new(rounds: 1)
    repo, _, auth = build(digest: weak.hash_secret(KemalIdentity::Secret.new(PASSWORD)))

    entries = captured do
      auth.authenticate(login: "ada@example.com", password: PASSWORD)
    end

    rendered(entries).should_not contain(repo.find_by_id("a1").or_fail.password_digest.or_fail)
  end

  # The login is deliberately absent: an email address in a log file outlives the request and
  # is read by people who never authenticated to anything. See src/kemal_identity/log.cr.
  it "does not record the login that was attempted" do
    _, _, auth = build

    entries = captured do
      auth.authenticate(login: "ada@example.com", password: "wrong")
    end

    rendered(entries).should_not contain("ada@example.com")
  end

  it "does not record an unknown login either" do
    _, _, auth = build

    entries = captured do
      auth.authenticate(login: "victim@example.com", password: "wrong")
    end

    rendered(entries).should_not contain("victim@example.com")
  end
end

describe "secret material in error messages" do
  # docs/05-testing.md: an unhandled error from the auth path must not include secret
  # material. The over-length path is the one place the authentication path can raise while
  # holding a password.
  it "keeps the password out of an over-length hashing error" do
    hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
    error = expect_raises(ArgumentError) do
      hasher.hash_secret(KemalIdentity::Secret.new("hunter2" + "a" * 100))
    end

    error.message.to_s.should_not contain("hunter2")
    error.to_s.should_not contain("hunter2")
  end

  it "keeps the digest out of a session lookup failure" do
    h = KemalIdentity::SpecHelper.harness(accounts: [KemalIdentity::SpecHelper.account])
    issued = h.service.start(h.accounts.find_by_id("a1").or_fail, KemalIdentity::AssuranceLevel::Password)

    error = expect_raises(KemalIdentity::InfrastructureError) do
      h.sessions.create(issued.record)
    end

    error.message.to_s.should_not contain(issued.record.token_digest.hexstring)
    error.message.to_s.should_not contain(issued.token.reveal)
  end
end

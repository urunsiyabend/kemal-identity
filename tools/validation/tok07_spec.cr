require "spec"
require "kemal_identity"
require "kemal_identity/testing"

# TOK-07 — a CI job or daemon acting on its own behalf. Not a human, so no password, no email
# confirmation, no browser session, and none of the interactive recovery paths.
CLOCK7 = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

# The application's own marker for which accounts are workloads. There is no field for it on
# `Accounts::Account`, so this is where the distinction lives.
WORKLOADS = Set{"svc-deploy"}

class TypedSink < KemalIdentity::SecurityEventSink
  getter lines = [] of String

  def record(event : KemalIdentity::SecurityEvent) : Nil
    kind = WORKLOADS.includes?(event.subject) ? "workload" : "human"
    @lines << "#{event.name} #{kind} #{event.subject} #{event.credential}"
  end
end

record Rig,
  accounts : KemalIdentity::Testing::MemoryAccountRepository,
  api : KemalIdentity::ApiTokens::Service,
  passwords : KemalIdentity::Passwords::Authenticator,
  service : KemalIdentity::Accounts::Service,
  sessions : KemalIdentity::Sessions::Service

private def rig : Rig
  # The service account: no password digest, no verified email, a login that is not an address.
  service_account = KemalIdentity::Accounts::Account.new(
    id: "svc-deploy",
    normalized_login: "svc-deploy",
    auth_version: 1,
    password_digest: nil,
    password_scheme: nil,
    email_verified_at: nil,
    created_at: KemalIdentity::Testing::FIXED_NOW,
    updated_at: KemalIdentity::Testing::FIXED_NOW,
  )

  hasher = KemalIdentity::Testing::FastTestHasher.new
  human = KemalIdentity::Testing.account(
    id: "ada", login: "ada@example.com",
    password_digest: hasher.hash_secret(KemalIdentity::Secret.new("correct horse battery"))
  )

  accounts = KemalIdentity::Testing::MemoryAccountRepository.new([service_account, human])
  sessions = KemalIdentity::Sessions::Service.new(
    sessions: KemalIdentity::Testing::MemorySessionRepository.new(accounts),
    clock: CLOCK7, random: KemalIdentity::Testing::DeterministicRandom.new(seed: 31)
  )

  Rig.new(
    accounts: accounts,
    api: KemalIdentity::ApiTokens::Service.new(
      tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      clock: CLOCK7, random: KemalIdentity::Testing::DeterministicRandom.new(seed: 32)
    ),
    passwords: KemalIdentity::Passwords::Authenticator.new(
      accounts: accounts, hasher: hasher, clock: CLOCK7
    ),
    service: KemalIdentity::Accounts::Service.new(
      accounts: accounts,
      tokens: KemalIdentity::Testing::MemoryActionTokenRepository.new,
      notifier: KemalIdentity::Testing::RecordingNotifier.new,
      sessions: sessions,
      hasher: hasher,
      policy: KemalIdentity::Passwords::LengthPolicy.for(hasher),
      clock: CLOCK7,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 33),
    ),
    sessions: sessions,
  )
end

describe "TOK-07 — a workload identity" do
  it "needs none of the human-only fields to exist in the repository" do
    r = rig
    account = r.accounts.find_by_id("svc-deploy").or_fail

    account.password_digest.should be_nil
    account.password_scheme.should be_nil
    account.email_verified_at.should be_nil
    account.disabled?.should be_false

    # And it is reachable by login like any other account, which is what a provisioning script
    # needs to be idempotent.
    r.accounts.find_by_login("svc-deploy").or_fail.id.should eq("svc-deploy")
  end

  it "authenticates with its own credential and nothing else" do
    r = rig
    account = r.accounts.find_by_id("svc-deploy").or_fail
    issued = r.api.issue(account: account, name: "deploy-pipeline", scopes: ["deploy.run"])

    principal = r.api.authenticate(issued.token.reveal).as(KemalIdentity::Authenticated).principal
    principal.subject.should eq("svc-deploy")
    principal.assurance.should eq(KemalIdentity::AssuranceLevel::ApiToken)
    principal.credential.or_fail.kind.should eq(KemalIdentity::CredentialKind::ApiToken)
  end

  it "cannot be logged into interactively, whatever password is presented" do
    r = rig

    ["", "svc-deploy", "hunter2"].each do |attempt|
      outcome = r.passwords.authenticate(login: "svc-deploy", password: attempt)
      outcome.should be_a(KemalIdentity::Failed)
    end
  end

  it "mints no reset token for an account that has no password to reset" do
    r = rig
    notifier = KemalIdentity::Testing::RecordingNotifier.new
    hasher = KemalIdentity::Testing::FastTestHasher.new
    tokens = KemalIdentity::Testing::MemoryActionTokenRepository.new

    service = KemalIdentity::Accounts::Service.new(
      accounts: r.accounts,
      tokens: tokens,
      notifier: notifier,
      sessions: r.sessions,
      hasher: hasher,
      policy: KemalIdentity::Passwords::LengthPolicy.for(hasher),
      clock: CLOCK7,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 34),
    )

    # No raise, because a reset request must not reveal whether an account exists. The question
    # is whether a usable reset token was minted for a credential that does not exist.
    service.request_password_reset(login: "svc-deploy")
    workload_resets = notifier.resets.size
    workload_tokens = tokens.size

    service.request_password_reset(login: "ada@example.com")
    puts "workload: #{workload_resets} reset mail, #{workload_tokens} action tokens"
    puts "human:    #{notifier.resets.size - workload_resets} reset mail, #{tokens.size - workload_tokens} action tokens"

    workload_resets.should eq(0)
    workload_tokens.should eq(0)
  end

  it "loses access promptly when it is deprovisioned" do
    r = rig
    account = r.accounts.find_by_id("svc-deploy").or_fail
    issued = r.api.issue(account: account, name: "deploy-pipeline")

    r.api.authenticate(issued.token.reveal).should be_a(KemalIdentity::Authenticated)

    r.accounts.disable("svc-deploy", at: CLOCK7.now)

    outcome = r.api.authenticate(issued.token.reveal)
    outcome.should be_a(KemalIdentity::Failed)
    outcome.as(KemalIdentity::Failed).reason.disabled_account?.should be_true
  end

  it "distinguishes workload from human in the audit trail" do
    sink = TypedSink.new
    bridge = KemalIdentity::EventBridge.new(sink)
    backend = ::Log::MemoryBackend.new
    ::Log.builder.bind("kemal_identity.*", :trace, backend)

    r = rig
    r.api.issue(account: r.accounts.find_by_id("svc-deploy").or_fail, name: "deploy-pipeline")
    r.api.issue(account: r.accounts.find_by_id("ada").or_fail, name: "ada-cli")

    backend.entries.each { |entry| bridge.write(entry) }

    issued = sink.lines.select(&.starts_with?("api_token.issued"))
    issued.count(&.includes?("workload")).should eq(1)
    issued.count(&.includes?(" human ")).should eq(1)
    # The credential id is on the event, so a workload's token can be traced without a join.
    issued.each { |line| line.split(' ').last.should_not be_empty }
  end
end

# A workload identity: a CI job or a daemon acting on its own behalf, not impersonating a human.
#
# Not a server. Provisioning, using and deprovisioning a service account is a sequence of
# operations, so this prints the sequence and what each step answered.
#
# CI compiles this on every matrix entry.
#
#     crystal run examples/service_account/app.cr
#
# What it demonstrates, in order: a service account needs none of the human-only fields; it
# authenticates only by its own credential; every interactive path is closed to it — including
# password reset, which for a passwordless account would *create* a password rather than reset
# one; and deprovisioning takes effect on the next request with nothing to expire.

require "../../src/kemal_identity"
require "../../src/kemal_identity/sqlite"

DATABASE = DB.open("sqlite3://#{ENV["DB_PATH"]? || "./kemal_identity_service_example.db"}?journal_mode=wal&busy_timeout=5000")

Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';').each do |statement|
    next if statement.strip.empty?
    DATABASE.exec(statement) rescue nil # already applied
  end
end

# Delivery is the application's job; nothing here should ever reach it, and the example counts
# rather than trusting that.
class CountingNotifier < KemalIdentity::Accounts::Notifier
  getter delivered = 0

  def deliver(notification : KemalIdentity::Accounts::Notification) : Nil
    @delivered += 1
    puts "    [mail] #{notification.class.name.split("::").last} — this should not happen"
  end
end

NOTIFIER = CountingNotifier.new

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(DATABASE),
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),
  action_tokens: KemalIdentity::SQLite::ActionTokenRepository.new(DATABASE),
  notifier: NOTIFIER,
  hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
)

APP = KemalIdentity.app
ID  = "svc-deploy"

# ---------------------------------------------------------------------------------------
# 1. Provision.
#
# There is no `create_service_account`, because creating accounts is the application's job in
# every case (`docs/00-scope.md`). What matters is that nothing in the row is human-shaped:
#
#   password_digest    nil — there is no password, and no remote way to set one
#   password_scheme    nil
#   email_verified_at  nil — nobody is going to click a link
#   normalized_login   need not be an address at all
#
# Every one of those is nilable in `Accounts::Account`, which is what makes a workload identity a
# first-class account rather than a human account with holes in it.
# ---------------------------------------------------------------------------------------
DATABASE.exec("DELETE FROM auth_accounts WHERE id = ?", ID)
DATABASE.exec(<<-SQL, ID, ID, Time.utc, Time.utc)
  INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at)
  VALUES (?, ?, 1, ?, ?)
  SQL

account = APP.accounts.find_by_id(ID) || raise "provisioning failed"
puts "1. provisioned #{account.normalized_login}"
puts "   password_digest=#{account.password_digest.inspect} email_verified_at=#{account.email_verified_at.inspect}"

# Found by login as well as by id, which is what makes a provisioning script idempotent: run it
# twice and it finds what it created rather than creating a second one.
puts "   find_by_login(#{ID.inspect}) → #{APP.accounts.find_by_login(ID).try(&.id).inspect}"

# ---------------------------------------------------------------------------------------
# 2. Issue its credential.
#
# Scoped, because a deploy pipeline needs one verb and a token that can do everything has the
# whole account as its blast radius. `expires_at` gives it a life even if nobody rotates it.
# ---------------------------------------------------------------------------------------
issued = APP.api!.issue(
  account, "deploy-pipeline", expires_at: Time.utc + 90.days, scopes: ["deploy.run"]
)
puts
puts "2. issued token id=#{issued.record.id}"
puts "   scopes=#{issued.record.scopes.inspect} expires_at=#{issued.record.expires_at}"
puts "   TOKEN=#{issued.token.reveal}"
puts "   (the raw value exists exactly once, here — only its digest is stored)"

principal = APP.api!.authenticate(issued.token.reveal).as(KemalIdentity::Authenticated).principal
puts "   authenticates as #{principal.subject} at #{principal.assurance} assurance"

# ---------------------------------------------------------------------------------------
# 3. Every interactive path is closed, by construction rather than by convention.
# ---------------------------------------------------------------------------------------
puts
puts "3. interactive paths"

["", ID, "hunter2"].each do |attempt|
  outcome = APP.passwords.authenticate(login: ID, password: attempt)
  puts "   password login with #{attempt.inspect} → #{outcome.class.name.split("::").last}"
end

# A reset request for an account with no password digest mints nothing and sends nothing. It
# returns normally, and is indistinguishable from an unknown login and from a disabled account —
# a reset endpoint that answered differently would be an account oracle.
#
# The reason it refuses at all is a privilege boundary: completing a reset *creates* a password
# where there was none, and the only proof that flow asks for is reaching a mailbox. A service
# account's login is very often a team alias.
before = NOTIFIER.delivered
APP.accounts_service!.request_password_reset(ID)
puts "   password reset request → #{NOTIFIER.delivered - before} mails sent"

# Setting a first password, when an application genuinely wants to, is a profile action for
# somebody already signed in — `Accounts::Repository#update_password_digest` behind your own
# session guard. Recovery is for a credential that exists.

# ---------------------------------------------------------------------------------------
# 4. Deprovision.
#
# Two ways, answering different questions.
#
# Revoking the token ends that credential and leaves the account. Disabling the account ends
# everything it has, now and later — every token, every session, and anything issued before
# somebody noticed. Both take effect on the next call, because validity is read from storage
# rather than asserted by a signature: no cache to invalidate, no TTL to wait out.
# ---------------------------------------------------------------------------------------
puts
puts "4. deprovisioning"

# Note which side does the writing. `Accounts::Repository` has no `disable` — the application
# owns its accounts table, so turning an account off is its `UPDATE`. The shard only ever *reads*
# `disabled_at`, on every authentication, and refuses. That split is why an application can keep
# its existing `users` table and its existing admin screens.
DATABASE.exec("UPDATE auth_accounts SET disabled_at = ? WHERE id = ?", Time.utc, ID)
reason = APP.api!.authenticate(issued.token.reveal).as(KemalIdentity::Failed).reason
puts "   account disabled → the same token now answers #{reason}"

DATABASE.exec("UPDATE auth_accounts SET disabled_at = NULL WHERE id = ?", ID)

# Scoped to the owner. `revoke(id)` alone is the administrative form: it ends whichever token the
# caller names, which is wrong for anything a client can reach.
APP.api!.revoke(issued.record.id, ID)
reason = APP.api!.authenticate(issued.token.reveal).as(KemalIdentity::Failed).reason
puts "   token revoked    → #{reason}"

# And the strongest form, for the day a workload's credential leaks: every token it holds, in one
# call, returning how many.
puts "   revoke_all       → #{APP.api!.revoke_all(ID)} remaining token(s) ended"

puts
puts "One thing this shard deliberately does not decide: which accounts are workloads."
puts "There is no `service_account?` flag, because what counts as one is a product question."
puts "An application needing the distinction in its audit trail keeps the set itself and tags"
puts "at its `SecurityEventSink` — every event already carries `subject` and `credential`."

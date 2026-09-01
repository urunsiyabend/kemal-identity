# Per-object authorization: "may this person refund *this* invoice", not "may this person refund".
#
# The shipped `Authz::RBAC` answers the second question and deliberately not the first — a role
# grants a permission everywhere or nowhere. An application whose rules turn on the object being
# acted on implements `Authz::Authorizer` itself and wraps the shipped one. That is the whole
# reason authorization is a contract here rather than a table.
#
# CI compiles this on every matrix entry.
#
#     crystal run examples/ownership/app.cr
#
#     curl -i localhost:3000/invoices/1 -H "Authorization: Bearer $ADA_TOKEN"   # hers
#     curl -i localhost:3000/invoices/2 -H "Authorization: Bearer $ADA_TOKEN"   # Grace's
#     curl -i localhost:3000/invoices/9 -H "Authorization: Bearer $ADA_TOKEN"   # nobody's
#     curl -i localhost:3000/invoices   -H "Authorization: Bearer $ADA_TOKEN"   # the N+1 question
#
# Rows two and three answer identically on purpose: "not yours" and "does not exist" must not be
# distinguishable, or the endpoint enumerates other people's invoices.

require "kemal"
require "../../src/kemal_identity/kemal"
require "../../src/kemal_identity/sqlite"

# ---------------------------------------------------------------------------------------
# What a resource is.
#
# `Authz::Authorizable` has exactly two methods and will never grow a third: it is frozen at
# v1.0, and every method added to it would have to be implemented by every application's domain
# objects. Anything a rule needs beyond a type and an id, it gets by downcasting to its own type
# — which is why the downcast below matters so much.
# ---------------------------------------------------------------------------------------
class Invoice
  include KemalIdentity::Authz::Authorizable

  getter id : String
  getter owner_id : String
  getter total : String

  def initialize(@id : String, @owner_id : String, @total : String)
  end

  def authz_type : String
    "invoice"
  end

  def authz_id : String
    @id
  end
end

INVOICES = {
  "1" => Invoice.new("1", "ada", "42.00"),
  "2" => Invoice.new("2", "grace", "17.50"),
}

# ---------------------------------------------------------------------------------------
# The rule.
#
# Order is the security property: the account's grant first, the object rule second. A resource
# rule can only ever *narrow*. Written the other way round, an ownership check would be able to
# grant a permission the account was never given.
# ---------------------------------------------------------------------------------------
class OwnershipAuthorizer < KemalIdentity::Authz::Authorizer
  def initialize(@inner : KemalIdentity::Authz::Authorizer)
  end

  def decide(
    principal : KemalIdentity::Principal,
    permission : String,
    context : KemalIdentity::Authz::Context,
  ) : KemalIdentity::Authz::Decision
    decision = @inner.decide(principal, permission, context)
    return decision unless decision.permitted?

    resource = context.resource
    # No resource in the context: this is the "may they at all" question, and the account's grant
    # has already answered it. A list endpoint asks exactly this before filtering rows.
    return decision if resource.nil?

    # Not an invoice: some other rule's business.
    return decision unless resource.authz_type == "invoice"

    invoice = resource.as?(Invoice)

    # ---------------------------------------------------------------------------------
    # THE LINE THAT MATTERS.
    #
    # `as?` yields nil for anything that is not an `Invoice` — including an `Authz::Resource`
    # carrying only a type and an id, which is what a route that did not load the row passes.
    #
    # Written the obvious way this rule **fails open**:
    #
    #     return decision if invoice.nil?     # WRONG: falls through to the permissive branch
    #
    # Measured in `blueprints/0025-maturity-validation-results.md` (AUT-01): a resource with no
    # owner attribute was permitted by a rule whose entire purpose was to require ownership.
    # "I could not check" is not "yes".
    # ---------------------------------------------------------------------------------
    if invoice.nil?
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: "no_invoice_in_context", tenant_id: context.tenant_id
      )
    end

    if invoice.owner_id != principal.subject
      # A code of the application's own. It reaches the audit line and never the response: what
      # crosses into HTTP is one uniform 403, because a denial that explains itself is a denial
      # that enumerates.
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: "not_the_owner", tenant_id: context.tenant_id
      )
    end

    # An environment rule, to show that attributes arrive too — and one that asks for step-up
    # under its own name rather than borrowing `InsufficientAssurance`. `step_up: true` is what
    # `env.auth.authorize!` branches on, so this raises `FreshAuthenticationRequiredError`
    # instead of the plain refusal.
    if context["device"] == "unrecognised"
      return KemalIdentity::Authz::Forbidden.policy(
        permission, code: "unrecognised_device", step_up: true, tenant_id: context.tenant_id
      )
    end

    decision
  end
end

DATABASE = DB.open("sqlite3://#{ENV["DB_PATH"]? || "./kemal_identity_ownership_example.db"}?journal_mode=wal&busy_timeout=5000")

Dir.glob(File.join(__DIR__, "..", "..", "migrations", "sqlite", "*.sql")).sort.each do |path|
  body = File.read(path).split("-- +micrate Down").first.split("-- +micrate Up").last
  body.lines.map(&.sub(/--.*$/, "")).join('\n').split(';').each do |statement|
    next if statement.strip.empty?
    DATABASE.exec(statement) rescue nil # already applied
  end
end

ACCOUNTS = KemalIdentity::SQLite::AccountRepository.new(DATABASE)
AUTHZ    = KemalIdentity::SQLite::AuthzRepository.new(DATABASE)

{"ada", "grace"}.each do |who|
  next unless ACCOUNTS.find_by_id(who).nil?
  now = Time.utc
  DATABASE.exec(<<-SQL, who, "#{who}@example.com", now, now)
    INSERT INTO auth_accounts (id, normalized_login, auth_version, created_at, updated_at)
    VALUES (?, ?, 1, ?, ?)
    SQL
end

{"ada", "grace"}.each do |who|
  next if AUTHZ.assignments_for(who).any? { |assignment| assignment.role == "finance" }
  AUTHZ.grant(KemalIdentity::Authz::Assignment.new(
    id: Random::Secure.hex(8), account_id: who, role: "finance", granted_at: Time.utc
  ))
end

RBAC = KemalIdentity::Authz::RBAC.new(
  catalog: KemalIdentity::Authz::RoleCatalog.new(
    KemalIdentity::Authz::PermissionRegistry.new([
      KemalIdentity::Authz::Permission.new(
        "invoices.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
      ),
    ]),
    [KemalIdentity::Authz::Role.new("finance", ["invoices.read"])]
  ),
  store: AUTHZ,
  clock: KemalIdentity::SystemClock.new,
  random: KemalIdentity::SecureRandomSource.new,

  # ---------------------------------------------------------------------------------------
  # The N+1 question, and it has a price tag.
  #
  # A list endpoint applying one policy per row queries the grant store per row. Measured over a
  # hundred invoices (`blueprints/0025`, AUT-01): **one** store read with this cache configured,
  # **a hundred** without. It is off by default.
  #
  # It is off by default because its TTL *is* the revocation delay: a role removed from the store
  # keeps deciding requests until the entry expires. Five seconds by default, one minute at
  # `MAX_TTL`, and the constructor refuses anything larger.
  #
  # So pick the TTL against how fast a removed grant must stop working — not against the page
  # size. And a page that authorises a hundred rows is worth a second look on its own terms: one
  # `authorize!` for reading the list, plus the filtering the application already does in SQL, is
  # often the same answer in one query.
  # ---------------------------------------------------------------------------------------
  cache: KemalIdentity::Authz::Cache.new(clock: KemalIdentity::SystemClock.new, ttl: 5.seconds),
)

KemalIdentity.configure(
  accounts: ACCOUNTS,
  sessions: KemalIdentity::SQLite::SessionRepository.new(DATABASE),
  api_tokens: KemalIdentity::SQLite::ApiTokenRepository.new(DATABASE),

  # Installed as *the* authorizer, so `env.auth.authorize!` reaches it. That is the point: before
  # `Authz::Context` carried a resource, a route needing an ownership rule had to bypass
  # `env.auth` and lose the audit line, the step-up mapping and the uniform 403 with it.
  authorizer: OwnershipAuthorizer.new(RBAC),

  hasher: KemalIdentity::Passwords::BcryptHasher.new(cost: 12),
)

ADA       = ACCOUNTS.find_by_id("ada") || raise "seeding the account failed"
ADA_TOKEN = KemalIdentity.app.api!.issue(ADA, "ada-cli", scopes: ["invoices.read"])

puts
puts "ADA_TOKEN=#{ADA_TOKEN.token.reveal}"
puts "invoice 1 is Ada's, invoice 2 is Grace's, invoice 9 does not exist"
puts

use KemalIdentity::Kemal::ErrorHandler.new(login_path: nil, realm: "invoices")
use KemalIdentity::Kemal::AuthenticationHandler.new

get "/invoices/:id" do |env|
  invoice = INVOICES[env.params.url["id"]]?

  # Load first, authorise second, and pass what you loaded. A missing row must take the *same*
  # path as a forbidden one: returning 404 here and 403 below would tell a caller which invoice
  # ids exist. So an unknown id is authorised against a resource that names only its type and id,
  # and the rule above refuses it — fail-closed, by the branch that would otherwise fail open.
  resource = invoice || KemalIdentity::Authz::Resource.new("invoice", env.params.url["id"])

  env.auth.authorize!(
    "invoices.read",
    resource: resource,
    # Attributes are the application's, and they are strings on purpose: this is data crossing
    # into a policy, not an object graph.
    attributes: {"device" => env.request.headers["X-Device"]? || "known"},
  )

  if invoice
    {id: invoice.id, total: invoice.total}.to_json
  else
    # Unreachable while the rule above holds: an id that did not load is authorised against a
    # resource with no owner, and refused. Written as a branch rather than `not_nil!` so that
    # weakening the rule surfaces as a loud 500 here instead of quietly answering 404 — which
    # would be the enumeration this endpoint is shaped to prevent.
    raise "unreachable: an unknown invoice id is refused by the ownership rule"
  end
end

# The list endpoint: one authorisation for the *act* of listing, then the application's own
# filter. No per-row `authorize!`, so no per-row query — the alternative the cache above exists
# to make survivable.
get "/invoices" do |env|
  principal = env.auth.authorize!("invoices.read")

  INVOICES.values.select { |invoice| invoice.owner_id == principal.subject }
    .map { |invoice| {id: invoice.id, total: invoice.total} }.to_json
end

Kemal.config.port = 3000
Kemal.run

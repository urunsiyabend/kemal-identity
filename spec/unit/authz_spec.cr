require "../spec_helper"

private def registry : KemalIdentity::Authz::PermissionRegistry
  KemalIdentity::Authz::PermissionRegistry.new([
    KemalIdentity::Authz::Permission.new("invoices.read"),
    KemalIdentity::Authz::Permission.new("invoices.refund",
      minimum_assurance: KemalIdentity::AssuranceLevel::MFA),
  ])
end

describe KemalIdentity::Authz::Permission do
  it "accepts lowercase dotted segments" do
    KemalIdentity::Authz::Permission.new("invoices.line_items.read").name
      .should eq("invoices.line_items.read")
  end

  it "defaults to requiring a password, not a remembered session" do
    KemalIdentity::Authz::Permission.new("invoices.read").minimum_assurance
      .should eq(KemalIdentity::AssuranceLevel::Password)
  end

  # A wildcard grant is a grant of permissions that do not exist yet: whoever holds it silently
  # acquires the next one somebody adds, and no reviewer sees a privilege change.
  it "refuses a wildcard" do
    expect_raises(KemalIdentity::ConfigurationError, /invoices/) do
      KemalIdentity::Authz::Permission.new("invoices.*")
    end
  end

  # Permission names reach audit trails and log queries. Two that differ only in case are two
  # permissions, and one of them reads as granted and is not.
  it "refuses anything but lowercase" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Authz::Permission.new("Invoices.Read")
    end
  end

  it "refuses an empty name, a leading dot and a trailing dot" do
    ["", ".read", "invoices."].each do |name|
      expect_raises(KemalIdentity::ConfigurationError) do
        KemalIdentity::Authz::Permission.new(name)
      end
    end
  end

  it "refuses a name longer than the cap" do
    expect_raises(KemalIdentity::ConfigurationError, /longer than/) do
      KemalIdentity::Authz::Permission.new("a" * 101)
    end
  end
end

describe KemalIdentity::Authz::PermissionRegistry do
  it "refuses the same permission twice" do
    expect_raises(KemalIdentity::ConfigurationError, /twice/) do
      KemalIdentity::Authz::PermissionRegistry.new([
        KemalIdentity::Authz::Permission.new("invoices.read"),
        KemalIdentity::Authz::Permission.new("invoices.read", description: "again"),
      ])
    end
  end

  it "reports what it declares" do
    registry.declared?("invoices.read").should be_true
    registry.declared?("invoices.write").should be_false
    registry.names.should eq(["invoices.read", "invoices.refund"])
  end
end

describe KemalIdentity::Authz::RoleCatalog do
  # The whole reason the registry exists: a rename that updates the role definitions and misses
  # one raises here, on the machine of whoever made the change.
  it "refuses at boot a role granting a permission nobody declared" do
    expect_raises(KemalIdentity::ConfigurationError, /invoices.refnud/) do
      KemalIdentity::Authz::RoleCatalog.new(registry, [
        KemalIdentity::Authz::Role.new("finance", ["invoices.refnud"]),
      ])
    end
  end

  it "refuses the same role twice" do
    expect_raises(KemalIdentity::ConfigurationError, /twice/) do
      KemalIdentity::Authz::RoleCatalog.new(registry, [
        KemalIdentity::Authz::Role.new("finance", ["invoices.read"]),
        KemalIdentity::Authz::Role.new("finance", ["invoices.refund"]),
      ])
    end
  end

  it "names the granting role rather than answering true" do
    catalog = KemalIdentity::Authz::RoleCatalog.new(registry, [
      KemalIdentity::Authz::Role.new("reader", ["invoices.read"]),
      KemalIdentity::Authz::Role.new("finance", ["invoices.read", "invoices.refund"]),
    ])

    catalog.grants?(["reader", "finance"], "invoices.refund").should eq("finance")
    catalog.grants?(["reader"], "invoices.refund").should be_nil
  end

  # Assignments outlive the code that defined the role: somebody deletes a role from the
  # catalog and the rows stay. The safe reading of a role nobody defines is that it grants
  # nothing.
  it "treats an assignment naming an undefined role as granting nothing" do
    catalog = KemalIdentity::Authz::RoleCatalog.new(registry, [
      KemalIdentity::Authz::Role.new("reader", ["invoices.read"]),
    ])

    catalog.grants?(["beta_tester"], "invoices.read").should be_nil
    catalog.undefined_roles(["reader", "beta_tester"]).should eq(["beta_tester"])
  end

  it "refuses a role name that is not a lowercase identifier" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::Authz::Role.new("Finance Admin", [] of String)
    end
  end
end

describe KemalIdentity::Authz::Cache do
  it "serves a cached answer inside the ttl and reloads after it" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    cache = KemalIdentity::Authz::Cache.new(clock, ttl: 5.seconds)
    loads = 0

    load = -> do
      loads += 1
      KemalIdentity::Authz::Grants.new(global_roles: ["reader"])
    end

    cache.fetch("a1", nil) { load.call }
    cache.fetch("a1", nil) { load.call }
    loads.should eq(1)

    clock.advance(5.seconds)
    cache.fetch("a1", nil) { load.call }
    loads.should eq(2)
  end

  it "keeps the tenants of one account apart" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    cache = KemalIdentity::Authz::Cache.new(clock)

    cache.fetch("a1", "acme") { KemalIdentity::Authz::Grants.new(tenant_roles: ["finance"]) }
    globex = cache.fetch("a1", "globex") { KemalIdentity::Authz::Grants.new }

    globex.tenant_roles.should be_empty
  end

  # Length-prefixed keys: an account id containing the separator must not reach another
  # account's entry.
  it "does not let one account's id collide with another's" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    cache = KemalIdentity::Authz::Cache.new(clock)

    cache.fetch("a", "1:b") { KemalIdentity::Authz::Grants.new(global_roles: ["admin"]) }
    other = cache.fetch("a:1", "b") { KemalIdentity::Authz::Grants.new }

    other.global_roles.should be_empty
  end

  it "drops one account's entries on invalidation and leaves the rest" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    cache = KemalIdentity::Authz::Cache.new(clock)

    cache.fetch("a1", "acme") { KemalIdentity::Authz::Grants.new(global_roles: ["reader"]) }
    cache.fetch("a2", "acme") { KemalIdentity::Authz::Grants.new(global_roles: ["reader"]) }
    cache.invalidate("a1")

    cache.size.should eq(1)
    cache.fetch("a2", "acme") { raise "should not reload a2" }.global_roles.should eq(["reader"])
  end

  # Anybody signed in can ask about a tenant that does not exist, so the key space is
  # attacker-influenced and the map has to be bounded.
  it "clears itself rather than growing past the limit" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    cache = KemalIdentity::Authz::Cache.new(clock, max_entries: 4)

    10.times { |i| cache.fetch("a1", "tenant-#{i}") { KemalIdentity::Authz::Grants.new } }

    cache.size.should be <= 4
  end

  # The ttl is how long a revoked grant keeps working. A ten-minute cache is a ten-minute
  # window in which a compromised account still works after somebody has revoked it.
  it "refuses a ttl longer than the ceiling" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

    expect_raises(KemalIdentity::ConfigurationError, /ttl/) do
      KemalIdentity::Authz::Cache.new(clock, ttl: 10.minutes)
    end
  end

  it "refuses a zero or negative ttl" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)

    expect_raises(KemalIdentity::ConfigurationError, /positive/) do
      KemalIdentity::Authz::Cache.new(clock, ttl: Time::Span.zero)
    end
  end
end

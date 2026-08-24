require "../spec_helper"

describe KemalIdentity::Testing::MemoryAccountRepository do
  it_behaves_like_an_account_repository do |accounts|
    KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
  end

  now = KemalIdentity::SpecHelper::FIXED_NOW

  build = ->(id : String, login : String, tenant : String?) do
    KemalIdentity::Accounts::Account.new(
      id: id, normalized_login: login, tenant_id: tenant, created_at: now, updated_at: now
    )
  end

  # The double must reject what the real schema rejects, or a spec passes here and the
  # PostgreSQL adapter fails on the same data.
  describe "the constraints it mirrors" do
    it "refuses a duplicate id" do
      repo = KemalIdentity::Testing::MemoryAccountRepository.new([build.call("a1", "ada@example.com", nil)])
      expect_raises(KemalIdentity::InfrastructureError) do
        repo.insert(build.call("a1", "bob@example.com", nil))
      end
    end

    it "refuses a duplicate login within a tenant" do
      repo = KemalIdentity::Testing::MemoryAccountRepository.new([build.call("a1", "ada@example.com", "t1")])
      expect_raises(KemalIdentity::InfrastructureError) do
        repo.insert(build.call("a2", "ada@example.com", "t1"))
      end
    end

    # This is the partial unique index from docs/03: without it, two null-tenant rows with
    # the same login do not collide under a plain UNIQUE (tenant_id, normalized_login).
    it "refuses a duplicate login when both tenants are null" do
      repo = KemalIdentity::Testing::MemoryAccountRepository.new([build.call("a1", "ada@example.com", nil)])
      expect_raises(KemalIdentity::InfrastructureError) do
        repo.insert(build.call("a2", "ada@example.com", nil))
      end
    end

    it "allows the same login in different tenants" do
      repo = KemalIdentity::Testing::MemoryAccountRepository.new([build.call("a1", "ada@example.com", "t1")])
      repo.insert(build.call("a2", "ada@example.com", "t2"))
      repo.size.should eq(2)
    end
  end
end

module KemalIdentity::Testing
  # In-memory `Accounts::Repository`.
  #
  # Passes the same contract spec as the PostgreSQL adapter, which is the only thing that
  # makes it trustworthy. It lives in `spec/support` and is unreachable from a production
  # build — `src/CLAUDE.md` bans in-memory repositories under `src/`.
  #
  # Guarded by a `Mutex` because the contract requires adapters to be safe for concurrent use
  # from multiple fibers on multiple threads, and since Crystal 1.21 that may genuinely mean
  # multiple threads.
  class MemoryAccountRepository < KemalIdentity::Accounts::Repository
    def initialize(accounts : Array(KemalIdentity::Accounts::Account) = [] of KemalIdentity::Accounts::Account)
      @mutex = Mutex.new
      @accounts = {} of String => KemalIdentity::Accounts::Account
      accounts.each { |account| insert(account) }
    end

    # Test-setup only, and deliberately *not* part of the repository contract: an adapter
    # over an application's existing `users` table has no business inserting rows into it.
    def insert(account : KemalIdentity::Accounts::Account) : Nil
      @mutex.synchronize do
        if @accounts.has_key?(account.id)
          raise KemalIdentity::InfrastructureError.new("duplicate account id")
        end

        # Mirrors `UNIQUE (tenant_id, normalized_login)` plus the partial unique index that
        # PostgreSQL needs for null tenants — without the partial index, two null-tenant rows
        # with the same login do not collide. Enforcing it here is what stops the double
        # accepting data the real schema rejects.
        collision = @accounts.each_value.find do |existing|
          existing.tenant_id == account.tenant_id &&
            existing.normalized_login == account.normalized_login
        end

        raise KemalIdentity::InfrastructureError.new("duplicate normalized_login") if collision

        @accounts[account.id] = account
      end
    end

    def find_by_id(id : String) : KemalIdentity::Accounts::Account?
      @mutex.synchronize { @accounts[id]? }
    end

    def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
      @mutex.synchronize do
        # Equality on both, including the null tenant: `nil` means the single-tenant row, not
        # "any tenant". Getting this wrong in SQL is the `= NULL` mistake.
        @accounts.each_value.find do |account|
          account.normalized_login == normalized_login && account.tenant_id == tenant_id
        end
      end
    end

    def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
      @mutex.synchronize do
        existing = @accounts[id]?
        return false if existing.nil?

        @accounts[id] = replace(existing, password_digest: digest, password_scheme: scheme, updated_at: at)
        true
      end
    end

    def bump_auth_version(id : String) : Int32?
      @mutex.synchronize do
        existing = @accounts[id]?
        return if existing.nil?

        bumped = existing.auth_version + 1
        @accounts[id] = replace(existing, auth_version: bumped)
        bumped
      end
    end

    # Test-setup only. Disabling an account is an application action, not something the
    # authentication path does.
    def disable(id : String, at : Time) : Bool
      @mutex.synchronize do
        existing = @accounts[id]?
        return false if existing.nil?

        @accounts[id] = replace(existing, disabled_at: at, updated_at: at)
        true
      end
    end

    def size : Int32
      @mutex.synchronize { @accounts.size }
    end

    # `Account` is an immutable struct, so an update is a rebuild. Verbose, and worth it:
    # nothing can mutate a stored account by holding a reference to it.
    private def replace(
      account : KemalIdentity::Accounts::Account,
      auth_version : Int32? = nil,
      password_digest : String? = nil,
      password_scheme : String? = nil,
      disabled_at : Time? = nil,
      updated_at : Time? = nil,
    ) : KemalIdentity::Accounts::Account
      KemalIdentity::Accounts::Account.new(
        id: account.id,
        normalized_login: account.normalized_login,
        tenant_id: account.tenant_id,
        auth_version: auth_version || account.auth_version,
        password_digest: password_digest || account.password_digest,
        password_scheme: password_scheme || account.password_scheme,
        email_verified_at: account.email_verified_at,
        disabled_at: disabled_at || account.disabled_at,
        created_at: account.created_at,
        updated_at: updated_at || account.updated_at,
      )
    end
  end
end

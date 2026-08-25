module KemalIdentity::Postgres
  # `Accounts::Repository` over the reference `auth_accounts` table.
  #
  # A **reference implementation, not a requirement**. An application that already has
  # `users.email` and `users.password_digest` implements the contract over that table and
  # never creates `auth_accounts` at all — that distinction is the difference between
  # "adoptable incrementally" and "rewrite your user model first"
  # (`docs/03-data-model.md`). This class exists so there is something to point at, and so the
  # contract has a second implementation keeping the in-memory double honest.
  class AccountRepository < Accounts::Repository
    # Every column the contract needs, named explicitly rather than `SELECT *`: a column added
    # to the table later must not silently change what this reads.
    COLUMNS = <<-SQL
      id, tenant_id, normalized_login, email_verified_at, disabled_at,
      auth_version, password_digest, password_scheme, created_at, updated_at
      SQL

    def initialize(@db : DB::Database)
    end

    def find_by_id(id : String) : Accounts::Account?
      @db.query_one?("SELECT #{COLUMNS} FROM auth_accounts WHERE id = $1", id) do |row|
        read(row)
      end
    end

    # The `tenant_id IS NULL` case is split out rather than folded into one clever predicate.
    #
    # `tenant_id = NULL` matches nothing in SQL — it is not false, it is unknown — so the
    # single-tenant lookup has to say `IS NULL` explicitly. Writing the obvious parameterised
    # query instead returns no rows for every single-tenant application, and the contract spec
    # has a named example for it.
    def find_by_login(normalized_login : String, tenant_id : String? = nil) : Accounts::Account?
      if tenant_id.nil?
        @db.query_one?(
          "SELECT #{COLUMNS} FROM auth_accounts WHERE normalized_login = $1 AND tenant_id IS NULL",
          normalized_login
        ) { |row| read(row) }
      else
        @db.query_one?(
          "SELECT #{COLUMNS} FROM auth_accounts WHERE normalized_login = $1 AND tenant_id = $2",
          normalized_login, tenant_id
        ) { |row| read(row) }
      end
    end

    def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
      # Deliberately does not touch auth_version: a rehash at a higher cost is not a credential
      # change, and bumping it would log every user out of the application that just raised its
      # bcrypt cost.
      result = @db.exec(<<-SQL, digest, scheme, at, id)
        UPDATE auth_accounts
           SET password_digest = $1, password_scheme = $2, updated_at = $3
         WHERE id = $4
        SQL

      result.rows_affected == 1
    end

    def mark_email_verified(id : String, at : Time) : Bool
      result = @db.exec(
        "UPDATE auth_accounts SET email_verified_at = $1, updated_at = $1 WHERE id = $2", at, id
      )

      result.rows_affected == 1
    end

    def bump_auth_version(id : String) : Int32?
      # One statement, `RETURNING` the new value: a read-then-write would let two concurrent
      # password changes both read the same version and both write the same increment, so one
      # of them would not invalidate the sessions it was meant to.
      @db.query_one?(
        "UPDATE auth_accounts SET auth_version = auth_version + 1 WHERE id = $1 RETURNING auth_version",
        id, as: Int32
      )
    end

    private def read(row : DB::ResultSet) : Accounts::Account
      Accounts::Account.new(
        id: row.read(String),
        tenant_id: row.read(String?),
        normalized_login: row.read(String),
        email_verified_at: row.read(Time?),
        disabled_at: row.read(Time?),
        auth_version: row.read(Int32),
        password_digest: row.read(String?),
        password_scheme: row.read(String?),
        created_at: row.read(Time),
        updated_at: row.read(Time),
      )
    end
  end
end

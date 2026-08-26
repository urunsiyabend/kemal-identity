module KemalIdentity::SQLite
  # `Accounts::Repository` over the reference `auth_accounts` table, SQLite dialect.
  #
  # Same contract, same reference-implementation caveat as the PostgreSQL adapter: an
  # application with its own `users` table implements the contract over that and never creates
  # `auth_accounts` at all.
  class AccountRepository < Accounts::Repository
    COLUMNS = <<-SQL
      id, tenant_id, normalized_login, email_verified_at, disabled_at,
      auth_version, password_digest, password_scheme, created_at, updated_at
      SQL

    def initialize(@db : DB::Database)
    end

    def find_by_id(id : String) : Accounts::Account?
      @db.query_one?("SELECT #{COLUMNS} FROM auth_accounts WHERE id = ?", id) { |row| read(row) }
    end

    # The null-tenant case is split out for the same reason as in PostgreSQL: `tenant_id = NULL`
    # is unknown rather than false in SQLite too, so the obvious parameterised query returns no
    # rows for every single-tenant application.
    def find_by_login(normalized_login : String, tenant_id : String? = nil) : Accounts::Account?
      if tenant_id.nil?
        @db.query_one?(
          "SELECT #{COLUMNS} FROM auth_accounts WHERE normalized_login = ? AND tenant_id IS NULL",
          normalized_login
        ) { |row| read(row) }
      else
        @db.query_one?(
          "SELECT #{COLUMNS} FROM auth_accounts WHERE normalized_login = ? AND tenant_id = ?",
          normalized_login, tenant_id
        ) { |row| read(row) }
      end
    end

    def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
      result = @db.exec(<<-SQL, digest, scheme, at, id)
        UPDATE auth_accounts
           SET password_digest = ?, password_scheme = ?, updated_at = ?
         WHERE id = ?
        SQL

      result.rows_affected == 1
    end

    def mark_email_verified(id : String, at : Time) : Bool
      result = @db.exec(
        "UPDATE auth_accounts SET email_verified_at = ?, updated_at = ? WHERE id = ?", at, at, id
      )

      result.rows_affected == 1
    end

    def bump_auth_version(id : String) : Int32?
      # One statement with `RETURNING`, as in PostgreSQL: a read-then-write would let two
      # concurrent password changes read the same version and write the same increment, so one
      # would not invalidate the sessions it was meant to. SQLite has supported `RETURNING`
      # since 3.35.
      @db.query_one?(
        "UPDATE auth_accounts SET auth_version = auth_version + 1 WHERE id = ? RETURNING auth_version",
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

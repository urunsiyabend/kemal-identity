module KemalIdentity::Postgres
  # `Federation::LinkRepository` over `auth_external_identities`.
  #
  # The unique index on `(issuer, subject)` is doing the security work here: without it one
  # provider account can be attached to two local ones, and whichever row is found first decides
  # who somebody logs in as. A duplicate is surfaced as an `InfrastructureError` rather than
  # absorbed.
  class LinkRepository < Federation::LinkRepository
    UNIQUE_VIOLATION = "23505"

    COLUMNS = "id, account_id, issuer, subject, created_at, last_authenticated_at"

    def initialize(@db : DB::Database)
    end

    def link(record : Federation::Link) : Nil
      @db.exec(<<-SQL,
        INSERT INTO auth_external_identities (#{COLUMNS})
        VALUES ($1, $2, $3, $4, $5, $6)
        SQL
        record.id, record.account_id, record.issuer, record.subject,
        record.created_at, record.last_authenticated_at)
    rescue error : PQ::PQError
      raise error unless error.field_message(:code) == UNIQUE_VIOLATION

      raise InfrastructureError.new("external identity is already linked")
    end

    def find(issuer : String, subject : String) : Federation::Link?
      @db.query_one?(<<-SQL, issuer, subject) { |row| read(row) }
        SELECT #{COLUMNS} FROM auth_external_identities
         WHERE issuer = $1 AND subject = $2
        SQL
    end

    def for_account(account_id : String) : Array(Federation::Link)
      @db.query_all(<<-SQL, account_id) { |row| read(row) }
        SELECT #{COLUMNS} FROM auth_external_identities
         WHERE account_id = $1
         ORDER BY created_at ASC, id ASC
        SQL
    end

    def unlink(issuer : String, subject : String) : Bool
      result = @db.exec(
        "DELETE FROM auth_external_identities WHERE issuer = $1 AND subject = $2", issuer, subject
      )

      result.rows_affected == 1
    end

    def touch(issuer : String, subject : String, at : Time) : Bool
      result = @db.exec(<<-SQL, at, issuer, subject)
        UPDATE auth_external_identities
           SET last_authenticated_at = $1
         WHERE issuer = $2 AND subject = $3
        SQL

      result.rows_affected == 1
    end

    private def read(row : DB::ResultSet) : Federation::Link
      Federation::Link.new(
        id: row.read(String),
        account_id: row.read(String),
        issuer: row.read(String),
        subject: row.read(String),
        created_at: row.read(Time),
        last_authenticated_at: row.read(Time?),
      )
    end
  end
end

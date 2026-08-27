module KemalIdentity::SQLite
  # `MFA::Repository` over `auth_mfa_factors` and `auth_mfa_recovery_codes`.
  #
  # The two single-use operations are each **one statement**, for the reason
  # `blueprints/0011-action-token-atomicity.md` gives: a read followed by a write passes every
  # spec written against one fiber and fails against two, and here failing means a replayed
  # TOTP code or a recovery code spent twice.
  class MfaRepository < MFA::Repository
    FACTOR_COLUMNS = <<-SQL
      id, account_id, kind, label, sealed_secret, digits, period_seconds, algorithm,
      created_at, confirmed_at, last_used_counter
      SQL

    def initialize(@db : DB::Database)
    end

    def create_factor(factor : MFA::Factor) : Nil
      # `ON CONFLICT DO NOTHING` plus a row count rather than catching the driver's exception:
      # crystal-sqlite3 surfaces a constraint failure when the statement is finalised, so a
      # `rescue` around the insert never sees it. See blueprints/0014-sqlite-adapter.md.
      result = @db.exec(<<-SQL,
        INSERT INTO auth_mfa_factors (#{FACTOR_COLUMNS})
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT DO NOTHING
        SQL
        factor.id, factor.account_id, factor.kind.value, factor.label, factor.sealed_secret,
        factor.digits, factor.period.total_seconds.to_i32, factor.algorithm.value,
        factor.created_at, factor.confirmed_at, factor.last_used_counter)

      raise InfrastructureError.new("mfa factor already exists") if result.rows_affected.zero?
    end

    def find_factor(id : String) : MFA::Factor?
      @db.query_one?("SELECT #{FACTOR_COLUMNS} FROM auth_mfa_factors WHERE id = ?", id) do |row|
        read_factor(row)
      end
    end

    def factors_for_account(account_id : String) : Array(MFA::Factor)
      @db.query_all(<<-SQL, account_id) { |row| read_factor(row) }
        SELECT #{FACTOR_COLUMNS} FROM auth_mfa_factors
         WHERE account_id = ?
         ORDER BY created_at ASC, id ASC
        SQL
    end

    # `AND confirmed_at IS NULL` reports whether anything changed and stops a second
    # confirmation overwriting the first timestamp, which is the one an audit trail wants.
    def confirm_factor(id : String, counter : Int64, at : Time) : Bool
      result = @db.exec(<<-SQL, at, counter, id)
        UPDATE auth_mfa_factors
           SET confirmed_at = ?, last_used_counter = ?
         WHERE id = ? AND confirmed_at IS NULL
        SQL

      result.rows_affected == 1
    end

    # The replay defence, as one statement. `last_used_counter IS NULL OR ... < ?` is what makes
    # "check that this counter is new" and "record that it is now used" the same operation, so
    # two requests carrying the same intercepted code cannot both succeed.
    def consume_counter(id : String, counter : Int64, at : Time) : Bool
      result = @db.exec(<<-SQL, counter, id, counter)
        UPDATE auth_mfa_factors
           SET last_used_counter = ?
         WHERE id = ?
           AND (last_used_counter IS NULL OR last_used_counter < ?)
        SQL

      result.rows_affected == 1
    end

    def delete_factor(id : String) : Bool
      @db.exec("DELETE FROM auth_mfa_factors WHERE id = ?", id).rows_affected == 1
    end

    def delete_factors_for_account(account_id : String) : Int32
      @db.exec("DELETE FROM auth_mfa_factors WHERE account_id = ?", account_id)
        .rows_affected.to_i32
    end

    # One transaction, because the two halves are a security hole apart: an account left
    # briefly with no codes cannot recover, and one left briefly with both sets has old codes
    # that were supposed to be void.
    def replace_recovery_codes(account_id : String, codes : Array(MFA::RecoveryCode)) : Nil
      inserted = 0

      @db.transaction do |tx|
        connection = tx.connection
        connection.exec("DELETE FROM auth_mfa_recovery_codes WHERE account_id = ?", account_id)

        codes.each do |code|
          result = connection.exec(<<-SQL,
            INSERT INTO auth_mfa_recovery_codes (id, account_id, code_digest, created_at, used_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT DO NOTHING
            SQL
            code.id, code.account_id, code.code_digest, code.created_at, code.used_at)

          inserted += result.rows_affected
        end
      end

      if inserted != codes.size
        raise InfrastructureError.new("recovery code already exists")
      end
    end

    # Single use, as one statement, for the same reason as `#consume_counter`.
    def consume_recovery_code(account_id : String, digest : Bytes, at : Time) : Bool
      return false if digest.empty?

      result = @db.exec(<<-SQL, at, account_id, digest)
        UPDATE auth_mfa_recovery_codes
           SET used_at = ?
         WHERE account_id = ? AND code_digest = ? AND used_at IS NULL
        SQL

      result.rows_affected == 1
    end

    def unused_recovery_codes(account_id : String) : Int32
      @db.scalar(<<-SQL, account_id).as(Int64).to_i32
        SELECT COUNT(*) FROM auth_mfa_recovery_codes
         WHERE account_id = ? AND used_at IS NULL
        SQL
    end

    private def read_factor(row : DB::ResultSet) : MFA::Factor
      MFA::Factor.new(
        id: row.read(String),
        account_id: row.read(String),
        kind: MFA::FactorKind.from_value(row.read(Int64).to_i16),
        label: row.read(String),
        sealed_secret: row.read(Bytes),
        digits: row.read(Int64).to_i32,
        period: row.read(Int64).to_i32.seconds,
        algorithm: MFA::TOTP::Algorithm.from_value(row.read(Int64).to_i32),
        created_at: row.read(Time),
        confirmed_at: row.read(Time?),
        last_used_counter: row.read(Int64?),
      )
    end
  end
end

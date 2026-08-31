module KemalIdentity::Testing
  # In-memory `MFA::Repository`, passing the same contract the database adapters must.
  #
  # The two single-use operations hold the mutex across their check *and* their write, which is
  # what "one statement" means with no statements available. A double that checked and then
  # wrote outside the lock would pass every single-fiber spec and quietly disagree with a real
  # adapter about the one property that matters.
  class MemoryMfaRepository < KemalIdentity::MFA::Repository
    def initialize
      @mutex = Mutex.new
      @factors = {} of String => KemalIdentity::MFA::Factor
      @codes = {} of String => KemalIdentity::MFA::RecoveryCode
    end

    def create_factor(factor : KemalIdentity::MFA::Factor) : Nil
      @mutex.synchronize do
        if @factors.has_key?(factor.id)
          raise KemalIdentity::InfrastructureError.new("mfa factor id already exists")
        end

        @factors[factor.id] = factor
      end
    end

    def find_factor(id : String) : KemalIdentity::MFA::Factor?
      @mutex.synchronize { @factors[id]? }
    end

    def factors_for_account(account_id : String) : Array(KemalIdentity::MFA::Factor)
      @mutex.synchronize do
        @factors.each_value
          .select { |factor| factor.account_id == account_id }
          .to_a
          .sort_by! { |factor| {factor.created_at, factor.id} }
      end
    end

    def confirm_factor(id : String, counter : Int64, at : Time) : Bool
      @mutex.synchronize do
        existing = @factors[id]?
        return false if existing.nil?
        return false if existing.confirmed?

        @factors[id] = replace(existing, confirmed_at: at, last_used_counter: counter)
        true
      end
    end

    def consume_counter(id : String, counter : Int64, at : Time) : Bool
      @mutex.synchronize do
        existing = @factors[id]?
        return false if existing.nil?

        last = existing.last_used_counter
        return false if last && counter <= last

        @factors[id] = replace(existing, last_used_counter: counter)
        true
      end
    end

    def delete_factor(id : String) : Bool
      @mutex.synchronize { !@factors.delete(id).nil? }
    end

    def delete_factors_for_account(account_id : String) : Int32
      @mutex.synchronize do
        doomed = @factors.each_value.select { |factor| factor.account_id == account_id }.to_a
        doomed.each { |factor| @factors.delete(factor.id) }
        doomed.size
      end
    end

    def replace_recovery_codes(
      account_id : String,
      codes : Array(KemalIdentity::MFA::RecoveryCode),
    ) : Nil
      @mutex.synchronize do
        @codes.each_value.select { |code| code.account_id == account_id }.to_a
          .each { |existing| @codes.delete(existing.id) }

        codes.each { |code| @codes[code.id] = code }
      end
    end

    def consume_recovery_code(account_id : String, digest : Bytes, at : Time) : Bool
      return false if digest.empty?

      @mutex.synchronize do
        match = @codes.each_value.find do |code|
          code.account_id == account_id && !code.used? && code.code_digest == digest
        end

        return false if match.nil?

        @codes[match.id] = KemalIdentity::MFA::RecoveryCode.new(
          id: match.id,
          account_id: match.account_id,
          code_digest: match.code_digest,
          created_at: match.created_at,
          used_at: at,
        )

        true
      end
    end

    def unused_recovery_codes(account_id : String) : Int32
      @mutex.synchronize do
        @codes.each_value.count { |code| code.account_id == account_id && !code.used? }
      end
    end

    private def replace(
      factor : KemalIdentity::MFA::Factor,
      confirmed_at : Time? = nil,
      last_used_counter : Int64? = nil,
    ) : KemalIdentity::MFA::Factor
      KemalIdentity::MFA::Factor.new(
        id: factor.id,
        account_id: factor.account_id,
        sealed_secret: factor.sealed_secret,
        created_at: factor.created_at,
        label: factor.label,
        kind: factor.kind,
        digits: factor.digits,
        period: factor.period,
        algorithm: factor.algorithm,
        confirmed_at: confirmed_at || factor.confirmed_at,
        last_used_counter: last_used_counter || factor.last_used_counter,
      )
    end
  end
end

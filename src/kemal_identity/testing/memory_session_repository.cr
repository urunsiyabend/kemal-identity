module KemalIdentity::Testing
  # In-memory `Sessions::Repository`.
  #
  # Passes the same contract spec as the PostgreSQL adapter. Wired to an account repository
  # because `find_by_digest` must return session state and account status together — the
  # reference SQL is one indexed lookup with a join, and a double that returned session state
  # alone would let a spec pass that the real adapter fails.
  class MemorySessionRepository < KemalIdentity::Sessions::Repository
    def initialize(@accounts : MemoryAccountRepository)
      @mutex = Mutex.new
      @sessions = {} of String => KemalIdentity::Sessions::Record
      # Digests are keyed by hex string rather than by `Bytes`: a byte slice's suitability as
      # a hash key is a detail worth not depending on, and this mirrors the unique index on
      # `auth_sessions.token_digest`.
      @by_digest = {} of String => String
    end

    def create(record : KemalIdentity::Sessions::Record) : Nil
      @mutex.synchronize do
        key = record.token_digest.hexstring

        # The unique index on token_digest, enforced. An upsert here would turn the error the
        # index exists to raise into two accounts sharing a session.
        if @by_digest.has_key?(key)
          raise KemalIdentity::InfrastructureError.new("duplicate session token digest")
        end

        if @sessions.has_key?(record.id)
          raise KemalIdentity::InfrastructureError.new("duplicate session id")
        end

        @sessions[record.id] = record
        @by_digest[key] = record.id
      end
    end

    def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
      record = @mutex.synchronize do
        id = @by_digest[digest.hexstring]?
        id.nil? ? nil : @sessions[id]?
      end

      return if record.nil?

      # An inner join: a session whose account has gone resolves to nothing, so the failure
      # mode is closed rather than open.
      account = @accounts.find_by_id(record.account_id)
      return if account.nil?

      KemalIdentity::Sessions::Lookup.new(
        session: record,
        account_auth_version: account.auth_version,
        account_disabled_at: account.disabled_at,
      )
    end

    def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
      @mutex.synchronize do
        existing = @sessions[id]?
        return false if existing.nil?

        @sessions[id] = replace(existing, last_seen_at: last_seen_at, idle_expires_at: idle_expires_at)
        true
      end
    end

    def revoke(id : String, at : Time) : Bool
      @mutex.synchronize do
        existing = @sessions[id]?
        return false if existing.nil?
        return false if existing.revoked? # revoking twice changes nothing, and says so

        @sessions[id] = replace(existing, revoked_at: at)
        true
      end
    end

    def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
      @mutex.synchronize do
        revoked = 0

        @sessions.each do |id, record|
          next if record.account_id != account_id
          next if id == except_id
          next if record.revoked? # not counted, not re-stamped

          @sessions[id] = replace(record, revoked_at: at)
          revoked += 1
        end

        revoked
      end
    end

    def delete_revoked_before(before : Time) : Int32
      @mutex.synchronize do
        stale = @sessions.each_value.select do |record|
          revoked_at = record.revoked_at
          !revoked_at.nil? && revoked_at <= before
        end.to_a

        stale.each do |record|
          @sessions.delete(record.id)
          @by_digest.delete(record.token_digest.hexstring)
        end

        stale.size
      end
    end

    def delete_expired(before : Time) : Int32
      @mutex.synchronize do
        expired = @sessions.each_value.select { |record| record.absolute_expires_at <= before }.to_a

        expired.each do |record|
          @sessions.delete(record.id)
          @by_digest.delete(record.token_digest.hexstring)
        end

        expired.size
      end
    end

    def size : Int32
      @mutex.synchronize { @sessions.size }
    end

    private def replace(
      record : KemalIdentity::Sessions::Record,
      last_seen_at : Time? = nil,
      idle_expires_at : Time? = nil,
      revoked_at : Time? = nil,
    ) : KemalIdentity::Sessions::Record
      KemalIdentity::Sessions::Record.new(
        id: record.id,
        account_id: record.account_id,
        token_digest: record.token_digest,
        auth_version: record.auth_version,
        assurance: record.assurance,
        created_at: record.created_at,
        authenticated_at: record.authenticated_at,
        last_seen_at: last_seen_at || record.last_seen_at,
        idle_expires_at: idle_expires_at || record.idle_expires_at,
        absolute_expires_at: record.absolute_expires_at,
        tenant_id: record.tenant_id,
        mfa_verified_at: record.mfa_verified_at,
        revoked_at: revoked_at || record.revoked_at,
      )
    end
  end
end

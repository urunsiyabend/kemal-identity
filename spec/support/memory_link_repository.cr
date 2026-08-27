module KemalIdentity::Testing
  # In-memory `OIDC::LinkRepository`, passing the same contract the database adapters must.
  class MemoryLinkRepository < KemalIdentity::OIDC::LinkRepository
    def initialize
      @mutex = Mutex.new
      @links = {} of String => KemalIdentity::OIDC::Link
      @by_pair = {} of String => String
    end

    def link(record : KemalIdentity::OIDC::Link) : Nil
      @mutex.synchronize do
        key = pair(record.issuer, record.subject)

        if @by_pair.has_key?(key)
          raise KemalIdentity::InfrastructureError.new("external identity is already linked")
        end

        if @links.has_key?(record.id)
          raise KemalIdentity::InfrastructureError.new("link id already exists")
        end

        @links[record.id] = record
        @by_pair[key] = record.id
      end
    end

    def find(issuer : String, subject : String) : KemalIdentity::OIDC::Link?
      @mutex.synchronize do
        id = @by_pair[pair(issuer, subject)]?
        id.nil? ? nil : @links[id]?
      end
    end

    def for_account(account_id : String) : Array(KemalIdentity::OIDC::Link)
      @mutex.synchronize do
        @links.each_value
          .select { |record| record.account_id == account_id }
          .to_a
          .sort_by! { |record| {record.created_at, record.id} }
      end
    end

    def unlink(issuer : String, subject : String) : Bool
      @mutex.synchronize do
        id = @by_pair.delete(pair(issuer, subject))
        return false if id.nil?

        !@links.delete(id).nil?
      end
    end

    def touch(issuer : String, subject : String, at : Time) : Bool
      @mutex.synchronize do
        id = @by_pair[pair(issuer, subject)]?
        return false if id.nil?

        existing = @links[id]?
        return false if existing.nil?

        @links[id] = KemalIdentity::OIDC::Link.new(
          id: existing.id,
          account_id: existing.account_id,
          issuer: existing.issuer,
          subject: existing.subject,
          created_at: existing.created_at,
          last_authenticated_at: at,
        )

        true
      end
    end

    # Both halves, unambiguously: an issuer containing the separator must not be able to
    # collide with another pair.
    private def pair(issuer : String, subject : String) : String
      "#{issuer.bytesize}:#{issuer}:#{subject}"
    end
  end
end

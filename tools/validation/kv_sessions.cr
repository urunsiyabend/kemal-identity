require "kemal_identity"

# `SessionRepository` over a key-value store, written to Redis-shaped rules: get, set, delete,
# and an atomic compare-and-set. No joins, no transactions across keys, no scans on the hot path.
#
# The store is a Hash behind a mutex rather than a real Redis, so the test needs no server —
# what is under test is whether the *contract* can be satisfied without SQL, not whether Redis
# works.
class KVStore
  def initialize
    @data = {} of String => String
    @mutex = Mutex.new
  end

  def get(key : String) : String?
    @mutex.synchronize { @data[key]? }
  end

  def set(key : String, value : String) : Nil
    @mutex.synchronize { @data[key] = value }
  end

  def set_if_absent(key : String, value : String) : Bool
    @mutex.synchronize do
      next false if @data.has_key?(key)
      @data[key] = value
      true
    end
  end

  # Read-modify-write under the store's own lock, which is what a Redis Lua script or a WATCH
  # loop gives you. The contract needs this for revoke and touch.
  def update(key : String, & : String -> String?) : Bool
    @mutex.synchronize do
      current = @data[key]?
      next false if current.nil?
      replacement = yield current
      next false if replacement.nil?
      @data[key] = replacement
      true
    end
  end

  def delete(key : String) : Bool
    @mutex.synchronize { !@data.delete(key).nil? }
  end

  def keys_with_prefix(prefix : String) : Array(String)
    @mutex.synchronize { @data.keys.select(&.starts_with?(prefix)) }
  end
end

class KVSessionRepository < KemalIdentity::Sessions::Repository
  # The friction OPS-04 is really about: `#find_by_digest` must return session state *and*
  # account status together. SQL does it with a join; a key-value store cannot, so the accounts
  # have to be reachable from here. Passing the account repository in is the honest answer, and
  # it means the hot path is two reads rather than one -- stated rather than hidden.
  def initialize(@store : KVStore, @accounts : KemalIdentity::Accounts::Repository)
  end

  private def key(digest : Bytes) : String
    "session:digest:#{digest.hexstring}"
  end

  private def id_key(id : String) : String
    "session:id:#{id}"
  end

  def create(record : KemalIdentity::Sessions::Record) : Nil
    unless @store.set_if_absent(key(record.token_digest), encode(record))
      # The unique index, as a key-value store expresses it. The contract requires a loud error
      # rather than an overwrite, because an overwrite is two accounts sharing a session.
      raise KemalIdentity::InfrastructureError.new("session already exists")
    end
    @store.set(id_key(record.id), record.token_digest.hexstring)
  end

  def find_by_digest(digest : Bytes) : KemalIdentity::Sessions::Lookup?
    raw = @store.get(key(digest))
    return nil if raw.nil?

    record = decode(raw)

    # Second read. Over SQL this is the join; here it is a separate get, and it is what keeps
    # "account disabled state remains promptly available" true rather than caching it into the
    # session row where it would go stale.
    account = @accounts.find_by_id(record.account_id)
    return nil if account.nil?

    KemalIdentity::Sessions::Lookup.new(
      session: record,
      account_auth_version: account.auth_version,
      account_disabled_at: account.disabled_at,
    )
  end

  def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool
    with_record(id) do |record|
      rebuild(record, last_seen_at: last_seen_at, idle_expires_at: idle_expires_at)
    end
  end

  def revoke(id : String, at : Time) : Bool
    with_record(id) do |record|
      next nil unless record.revoked_at.nil?   # already revoked reports false, never re-stamps
      rebuild(record, revoked_at: at)
    end
  end

  def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32
    revoked = 0
    @store.keys_with_prefix("session:digest:").each do |k|
      raw = @store.get(k)
      next if raw.nil?
      record = decode(raw)
      next unless record.account_id == account_id
      next unless record.revoked_at.nil?
      next if except_id && record.id == except_id
      revoked += 1 if revoke(record.id, at)
    end
    revoked
  end

  def delete_revoked_before(before : Time) : Int32
    deleted = 0
    @store.keys_with_prefix("session:digest:").each do |k|
      raw = @store.get(k)
      next if raw.nil?
      record = decode(raw)
      revoked_at = record.revoked_at
      next if revoked_at.nil? || revoked_at > before
      deleted += 1 if @store.delete(k)
      @store.delete(id_key(record.id))
    end
    deleted
  end

  def delete_expired(before : Time) : Int32
    deleted = 0
    @store.keys_with_prefix("session:digest:").each do |k|
      raw = @store.get(k)
      next if raw.nil?
      record = decode(raw)
      next if record.absolute_expires_at > before
      deleted += 1 if @store.delete(k)
      @store.delete(id_key(record.id))
    end
    deleted
  end

  private def with_record(id : String, & : KemalIdentity::Sessions::Record -> KemalIdentity::Sessions::Record?) : Bool
    hex = @store.get(id_key(id))
    return false if hex.nil?

    @store.update("session:digest:#{hex}") do |raw|
      replacement = yield decode(raw)
      replacement.nil? ? nil : encode(replacement)
    end
  end

  private def rebuild(
    r : KemalIdentity::Sessions::Record,
    last_seen_at : Time? = nil,
    idle_expires_at : Time? = nil,
    revoked_at : Time? = nil,
  ) : KemalIdentity::Sessions::Record
    KemalIdentity::Sessions::Record.new(
      id: r.id, account_id: r.account_id, token_digest: r.token_digest,
      auth_version: r.auth_version, assurance: r.assurance, created_at: r.created_at,
      authenticated_at: r.authenticated_at,
      last_seen_at: last_seen_at || r.last_seen_at,
      idle_expires_at: idle_expires_at || r.idle_expires_at,
      absolute_expires_at: r.absolute_expires_at, tenant_id: r.tenant_id,
      mfa_verified_at: r.mfa_verified_at, revoked_at: revoked_at || r.revoked_at,
    )
  end

  private def encode(r : KemalIdentity::Sessions::Record) : String
    {
      id: r.id, account_id: r.account_id, digest: r.token_digest.hexstring,
      auth_version: r.auth_version, assurance: r.assurance.value,
      created_at: r.created_at, authenticated_at: r.authenticated_at,
      last_seen_at: r.last_seen_at, idle_expires_at: r.idle_expires_at,
      absolute_expires_at: r.absolute_expires_at, tenant_id: r.tenant_id,
      mfa_verified_at: r.mfa_verified_at, revoked_at: r.revoked_at,
    }.to_json
  end

  private def decode(raw : String) : KemalIdentity::Sessions::Record
    j = JSON.parse(raw)
    KemalIdentity::Sessions::Record.new(
      id: j["id"].as_s,
      account_id: j["account_id"].as_s,
      token_digest: j["digest"].as_s.hexbytes,
      auth_version: j["auth_version"].as_i,
      assurance: KemalIdentity::AssuranceLevel.from_value(j["assurance"].as_i),
      created_at: Time.parse_rfc3339(j["created_at"].as_s),
      authenticated_at: Time.parse_rfc3339(j["authenticated_at"].as_s),
      last_seen_at: Time.parse_rfc3339(j["last_seen_at"].as_s),
      idle_expires_at: Time.parse_rfc3339(j["idle_expires_at"].as_s),
      absolute_expires_at: Time.parse_rfc3339(j["absolute_expires_at"].as_s),
      tenant_id: j["tenant_id"].as_s?,
      mfa_verified_at: j["mfa_verified_at"].as_s?.try { |v| Time.parse_rfc3339(v) },
      revoked_at: j["revoked_at"].as_s?.try { |v| Time.parse_rfc3339(v) },
    )
  end
end

require "kemal_identity"
require "db"
require "digest/sha256"

# An application that already has users, written the way one that exists would be: UUID primary
# keys, soft deletion, and a password column full of SHA-256 digests from whatever came before.
#
# `auth_accounts` is never created. This is IDP-03's whole claim — "a repository adapter is
# sufficient" — attempted rather than assumed.
class LegacyUserRepository < KemalIdentity::Accounts::Repository
  def self.migrate!(db : DB::Database) : Nil
    db.exec <<-SQL
      CREATE TABLE users (
        id              TEXT PRIMARY KEY,   -- a UUID, as the application already had
        email           TEXT NOT NULL,
        email_lower     TEXT NOT NULL,      -- what the shard compares against
        password_hash   TEXT,
        password_scheme TEXT NOT NULL DEFAULT 'sha256',
        auth_epoch      INTEGER NOT NULL DEFAULT 1,   -- the application's own name for it
        confirmed_at    TEXT,
        deleted_at      TEXT,               -- soft deletion
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
      )
      SQL
    db.exec "CREATE UNIQUE INDEX users_email_lower ON users (email_lower) WHERE deleted_at IS NULL"
  end

  def initialize(@db : DB::Database)
  end

  # The one documented boundary IDP-03 asks for: `Principal#subject` is a String, and here it is
  # the application's UUID, unconverted. Nothing casts it anywhere else.
  private SELECT = <<-SQL
    SELECT id, email_lower, auth_epoch, password_hash, password_scheme,
           confirmed_at, deleted_at, created_at, updated_at
      FROM users
    SQL

  def find_by_id(id : String) : KemalIdentity::Accounts::Account?
    @db.query_one?("#{SELECT} WHERE id = ?", id) { |row| read(row) }
  end

  def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
    # Single-tenant application: a tenant-scoped question has no answer here, and answering it
    # from the untenanted rows would be worse than not answering.
    return nil unless tenant_id.nil?

    @db.query_one?("#{SELECT} WHERE email_lower = ?", normalized_login) { |row| read(row) }
  end

  def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
    @db.exec(
      "UPDATE users SET password_hash = ?, password_scheme = ?, updated_at = ? WHERE id = ?",
      digest, scheme, at, id
    ).rows_affected == 1
  end

  def mark_email_verified(id : String, at : Time) : Bool
    @db.exec("UPDATE users SET confirmed_at = ?, updated_at = ? WHERE id = ?", at, at, id)
      .rows_affected == 1
  end

  def bump_auth_version(id : String) : Int32?
    @db.exec("UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?", id)
    @db.query_one?("SELECT auth_epoch FROM users WHERE id = ?", id, as: Int32)
  end

  private def read(row : DB::ResultSet) : KemalIdentity::Accounts::Account
    KemalIdentity::Accounts::Account.new(
      id: row.read(String),
      normalized_login: row.read(String),
      auth_version: row.read(Int32),
      password_digest: row.read(String?),
      password_scheme: row.read(String?),
      email_verified_at: row.read(Time?),
      # Soft deletion mapped onto the shard's own idea of disabled. A deleted row therefore
      # fails closed on the credential path without the application writing a single check.
      disabled_at: row.read(Time?),
      created_at: row.read(Time),
      updated_at: row.read(Time),
    )
  end
end

# The old scheme, verify-only. The shard ships no implementations on purpose: a published
# Sha256Verifier is a published working SHA-256 password check.
class Sha256Verifier < KemalIdentity::Passwords::LegacyVerifier
  def name : String
    "sha256"
  end

  def handles?(digest : String) : Bool
    digest.starts_with?("sha256$")
  end

  def verify(secret : KemalIdentity::Secret, digest : String) : Bool
    expected = digest.lchop("sha256$")
    actual = ::Digest::SHA256.hexdigest(secret.reveal)
    Crypto::Subtle.constant_time_compare(expected, actual)
  end

  def self.digest_for(password : String) : String
    "sha256$#{::Digest::SHA256.hexdigest(password)}"
  end
end

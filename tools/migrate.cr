# Migration runner for this repository's own development and CI databases.
#
# Deliberately not a feature of the shard. `docs/03-data-model.md` publishes migrations as
# files the application copies into its own tooling: an auth library that mutates the schema
# on boot is one that will mutate it at the wrong moment. This runner exists so that the
# integration and concurrency specs have a schema to run against, and for nothing else.
#
# It reads the same `-- +micrate Up` / `-- +micrate Down` directives the published files
# carry, so an application already using micrate or Amber applies those files unchanged.
# See blueprints/0002-no-micrate-dependency.md for why micrate is not a dependency here.
#
#   bin/migrate up       apply every pending migration
#   bin/migrate down     revert the most recently applied migration
#   bin/migrate status   list every migration and whether it is applied

require "db"
require "pg"

module Migrate
  VERSION_TABLE = "kemal_identity_schema_migrations"

  # Only the dialect this repository tests against. A second dialect gets its own directory
  # (docs/03-data-model.md), not a lowest-common-denominator schema.
  MIGRATIONS_DIR = File.expand_path("../migrations/postgres", __DIR__)

  record Migration, version : String, name : String, up : String, down : String

  class Error < Exception; end

  def self.migrations : Array(Migration)
    unless Dir.exists?(MIGRATIONS_DIR)
      raise Error.new("no migrations directory at #{MIGRATIONS_DIR}")
    end

    files = Dir.children(MIGRATIONS_DIR)
      .select(&.ends_with?(".sql"))
      .select { |name| File.file?(File.join(MIGRATIONS_DIR, name)) }
      .select(&.matches?(/\A\d+_/))
      .sort!

    files.map do |file|
      version = file.split('_', 2).first
      parse(version, file, File.read(File.join(MIGRATIONS_DIR, file)))
    end
  end

  # Splits a file on the `+micrate` section directives. A file missing either directive is
  # an error rather than a silently empty migration — a migration that applies nothing is
  # worse than one that fails loudly.
  def self.parse(version : String, file : String, body : String) : Migration
    up = [] of String
    down = [] of String
    target = nil.as(Array(String)?)

    body.each_line do |line|
      case line.strip
      when /\A--\s*\+micrate\s+Up\b/i   then target = up
      when /\A--\s*\+micrate\s+Down\b/i then target = down
      else                                   target.try(&.<<(line))
      end
    end

    raise Error.new("#{file}: no `-- +micrate Up` section") if up.empty?
    raise Error.new("#{file}: no `-- +micrate Down` section") if down.empty?

    Migration.new(version: version, name: file, up: up.join('\n'), down: down.join('\n'))
  end

  def self.connect(&)
    url = ENV["DATABASE_URL"]?

    if url.nil? || url.empty?
      abort "DATABASE_URL is not set. Example:\n" \
            "  postgres://kemal_identity:<password>@localhost/kemal_identity_test"
    end

    DB.open(url) do |db|
      db.exec <<-SQL
        CREATE TABLE IF NOT EXISTS #{VERSION_TABLE} (
          version    TEXT PRIMARY KEY,
          name       TEXT        NOT NULL,
          applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        SQL
      yield db
    end
  end

  def self.applied(db) : Set(String)
    versions = Set(String).new
    db.query_each("SELECT version FROM #{VERSION_TABLE}") do |row|
      versions << row.read(String)
    end
    versions
  end

  def self.up
    connect do |db|
      done = applied(db)
      pending = migrations.reject { |migration| done.includes?(migration.version) }

      if pending.empty?
        puts "nothing to apply"
        next
      end

      pending.each do |migration|
        # One transaction per migration: a failure half way through a set leaves the
        # earlier ones applied and recorded, which is recoverable, rather than leaving one
        # migration half applied, which is not.
        db.transaction do |tx|
          # `exec_all`, not `exec`: PostgreSQL's extended (prepared) protocol accepts
          # exactly one command per statement, so a migration body with several DDL
          # statements fails with "cannot insert multiple commands into a prepared
          # statement". crystal-pg's `unprepared` is an alias for the prepared builder and
          # does not help; `exec_all` is the simple-protocol path and takes the section as
          # written. Splitting on `;` instead would break the first time a migration
          # carries a dollar-quoted function body.
          tx.connection.as(PG::Connection).exec_all(migration.up)
          tx.connection.exec(
            "INSERT INTO #{VERSION_TABLE} (version, name) VALUES ($1, $2)",
            migration.version, migration.name
          )
        end
        puts "applied  #{migration.name}"
      end
    end
  end

  def self.down
    connect do |db|
      done = applied(db)
      last = migrations.reverse_each.find { |migration| done.includes?(migration.version) }

      if last.nil?
        puts "nothing to revert"
        next
      end

      db.transaction do |tx|
        tx.connection.as(PG::Connection).exec_all(last.down)
        tx.connection.exec("DELETE FROM #{VERSION_TABLE} WHERE version = $1", last.version)
      end
      puts "reverted #{last.name}"
    end
  end

  def self.status
    connect do |db|
      done = applied(db)
      migrations.each do |migration|
        state = done.includes?(migration.version) ? "applied" : "pending"
        puts "#{state.ljust(8)}#{migration.name}"
      end
    end
  end
end

case ARGV.first?
when "up"     then Migrate.up
when "down"   then Migrate.down
when "status" then Migrate.status
else
  puts "usage: bin/migrate [up|down|status]"
  exit 1
end

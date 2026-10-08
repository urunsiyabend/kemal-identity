require "../spec_helper"
require "file_utils"
require "../../src/kemal_identity/postgres"
require "../../src/kemal_identity/sqlite"

# Separate operating-system processes sharing one limiter, which no fiber-level spec can
# stand in for: `blueprints/0025` (OPS-01) found a limiter that passed every contract example
# while allowing 2.2× its limit across processes, because the contract ran in one process.
#
# Six workers make twenty attempts each against one key with a limit of ten, all released at
# once. Over shared storage the sum of what they were allowed must be **exactly** ten. The
# in-memory limiter runs the same way as a control and must allow more — if it did not, this
# spec could not tell a shared limiter from a broken probe.
#
# The worker is compiled once per run, which is most of this file's cost.
private WORKERS  =  6
private ATTEMPTS = 20
private LIMIT    = 10

private MP_DATABASE_URL  = ENV["DATABASE_URL"]?.presence
private REQUIRE_DATABASE = ENV["KEMAL_IDENTITY_REQUIRE_DATABASE"]? == "1"

private WORK_DIR = File.join(Dir.tempdir, "kemal_identity_multiprocess_#{Process.pid}")

Spec.after_suite { FileUtils.rm_rf(WORK_DIR) }

private def worker_binary : String
  path = File.join(WORK_DIR, "rate_limit_worker")
  return path if File.exists?(path)

  Dir.mkdir_p(WORK_DIR)
  source = File.join(__DIR__, "..", "support", "rate_limit_worker.cr")
  crystal = ENV["CRYSTAL"]? || Process.find_executable("crystal") || "crystal"
  output = IO::Memory.new

  status = Process.run(crystal, ["build", source, "-o", path], output: output, error: output)
  raise "building the worker failed:\n#{output}" unless status.success?

  path
end

# Starts every worker, releases them together, and returns {allowed, unavailable} summed.
private def run_workers(adapter : String, url : String, key : String) : Tuple(Int32, Int32)
  binary = worker_binary
  start_file = File.join(WORK_DIR, "start-#{adapter}-#{Random.new.hex(4)}")

  processes = Array.new(WORKERS) do
    output = IO::Memory.new
    process = Process.new(
      binary, [adapter, url, LIMIT.to_s, ATTEMPTS.to_s, key, start_file],
      output: output, error: Process::Redirect::Inherit
    )
    {process, output}
  end

  File.touch(start_file)

  # Every worker is waited for before anything is asserted, so a failing one leaves no others
  # running behind it.
  statuses = processes.map { |process, _| process.wait }
  statuses.all?(&.success?).should be_true

  processes.reduce({0, 0}) do |(allowed, unavailable), (_, output)|
    counts = output.to_s.split.map(&.to_i)
    {allowed + counts[0], unavailable + counts[1]}
  end
end

# The Up section of a migration file, as statements. Enough for the one file this needs.
private def up_statements(path : String) : Array(String)
  up = File.read(path).split("-- +micrate Up").last.split("-- +micrate Down").first
  up.lines.reject(&.strip.starts_with?("--")).join("\n").split(";").map(&.strip).reject(&.empty?)
end

describe "rate limiting across processes" do
  it "allows each process the whole limit with the in-memory limiter, which is the control" do
    allowed, _ = run_workers("memory", "", "login:control")
    allowed.should eq(WORKERS * LIMIT)
  end

  it "holds the limit exactly across processes sharing one SQLite file" do
    path = File.join(WORK_DIR, "limits.db")
    Dir.mkdir_p(WORK_DIR)
    url = "sqlite3://#{path}?journal_mode=wal&busy_timeout=5000"

    DB.open(url) do |db|
      migration = File.join(__DIR__, "..", "..", "migrations", "sqlite", "20261008090000_create_auth_rate_limits.sql")
      up_statements(migration).each { |statement| db.exec(statement) }
    end

    allowed, unavailable = run_workers("sqlite", url, "login:ada")

    unavailable.should eq(0)
    allowed.should eq(LIMIT)
  end

  if url = MP_DATABASE_URL
    it "holds the limit exactly across processes sharing one PostgreSQL database" do
      key = "login:ada:#{Random.new.hex(8)}"
      DB.open(url) { |db| db.exec("DELETE FROM auth_rate_limits WHERE key = $1", key) }

      allowed, unavailable = run_workers("postgres", url, key)

      unavailable.should eq(0)
      allowed.should eq(LIMIT)
    end
  elsif REQUIRE_DATABASE
    it "runs against PostgreSQL" do
      fail "KEMAL_IDENTITY_REQUIRE_DATABASE=1 and DATABASE_URL is not set"
    end
  else
    pending "rate limiting across processes on PostgreSQL (set DATABASE_URL to run it)"
  end
end

require "../spec_helper"

# Mechanical enforcement of the "Banned in this directory" list in `src/CLAUDE.md`.
#
# These rules are the reason the suite is deterministic and the reason secrets stay out of
# logs. A convention that is only written down drifts; this spec makes each violation a red
# build. It is a unit spec on purpose — it needs no database, so it runs on every save.
#
# Comments are stripped before scanning so that a rule can be *discussed* in a doc comment
# without tripping its own check. The stripping is deliberately naive: it cuts at the first
# `#` preceded by whitespace, which can also truncate a line at a `"#{...}"` interpolation.
# That direction of error hides a violation rather than inventing one, and the cost is a
# false negative on a line that both interpolates and violates a rule.
private SRC_ROOT = File.expand_path("../../src", __DIR__)

# `src/kemal_identity/testing` is excluded, and the exclusion is the narrow kind: it is where the
# banned constructs are the *product*. `Testing::TestClock` exists to be the only thing that reads
# a wall clock, `Testing::DeterministicRandom` exists to be seeded rather than secure, and the
# shared contracts use `or_fail` because that is what a spec helper does. Scanning them would
# demand they lie about what they are.
#
# It is scoped to that one directory rather than to a pattern, so a violation anywhere else in
# `src/` — including a production file that happens to have "testing" in its name — is still
# caught. The tree is not required by `kemal_identity` itself, so none of it reaches an
# application that does not ask for it.
private TESTING_ROOT = File.join(SRC_ROOT, "kemal_identity", "testing")

private def source_files : Array(String)
  Dir.glob(File.join(SRC_ROOT, "**", "*.cr"))
    .reject(&.starts_with?(TESTING_ROOT + File::SEPARATOR))
    .sort!
end

# The excluded tree, so a typo in the path above cannot silently disable the scan.
private def testing_files : Array(String)
  Dir.glob(File.join(TESTING_ROOT, "**", "*.cr")).sort
end

private def relative(path : String) : String
  path.lchop(File.dirname(SRC_ROOT) + "/")
end

private def code_lines(path : String) : Array({Int32, String})
  lines = [] of {Int32, String}
  File.read_lines(path).each_with_index do |line, index|
    stripped = line.gsub(/(\A|\s)#.*\z/, "")
    next if stripped.blank?
    lines << {index + 1, stripped}
  end
  lines
end

# Every offending `file:line`, so a failure names the location rather than just the count.
private def offences(pattern : Regex, allow : Array(String) = [] of String) : Array(String)
  found = [] of String
  source_files.each do |path|
    rel = relative(path)
    next if allow.any? { |allowed| rel.ends_with?(allowed) }
    code_lines(path).each do |(number, line)|
      found << "#{rel}:#{number}" if line.matches?(pattern)
    end
  end
  found
end

describe "src/ source hygiene" do
  it "excludes the testing tree, and finds it" do
    # If this path ever stops matching, the exclusion becomes a no-op and the three rules below
    # start failing on the doubles -- loudly, which is the right direction. This asserts the
    # other one: that the exclusion is not silently swallowing all of `src/`.
    testing_files.should_not be_empty
    source_files.none?(&.includes?("/testing/")).should be_true
  end

  # The testing tree carries `require "spec"` and the in-memory doubles. If `kemal_identity.cr`
  # ever reaches it, every production consumer starts compiling both -- and the exclusion above
  # would hide the wall-clock and RNG reads that came with them. Measured from the consumer side
  # in blueprints/0025 (OPS-07): a production binary has zero `Spec::` symbols, and this keeps it
  # that way without needing a linked binary to check.
  it "never requires the testing tree from the production entry points" do
    %w[kemal_identity.cr kemal_identity/kemal.cr kemal_identity/postgres.cr
      kemal_identity/sqlite.cr].each do |entry|
      path = File.join(SRC_ROOT, entry)
      next unless File.exists?(path)

      File.read(path).should_not match(/require\s+"[^"]*testing/)
    end
  end

  it "finds source files to scan" do
    # Guards against the whole spec silently passing because the glob broke.
    source_files.should_not be_empty
  end

  it "never calls not_nil!" do
    offences(/\.or_fail/).should eq([] of String)
  end

  it "reads the clock only through the injected Clock" do
    offences(/\bTime\.(utc|local)\b/, allow: ["core/clock.cr"]).should eq([] of String)
  end

  it "reads randomness only through the injected RandomSource" do
    offences(/\bRandom(::Secure|\.new)\b/, allow: ["core/random_source.cr"]).should eq([] of String)
  end

  it "logs through Log rather than puts, p or pp" do
    offences(/^\s*(puts|pp?)\s/).should eq([] of String)
  end

  it "never rescues without an exception class" do
    offences(/^\s*rescue\s*$/).should eq([] of String)
  end

  it "compares secrets in constant time" do
    # `Crypto::Subtle.constant_time_compare` is the only permitted comparison for secret
    # material; `Secret#==` is the single wrapper over it.
    offences(/\.reveal\s*==/).should eq([] of String)
  end
end

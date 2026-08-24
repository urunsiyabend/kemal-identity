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

private def source_files : Array(String)
  Dir.glob(File.join(SRC_ROOT, "**", "*.cr")).sort
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

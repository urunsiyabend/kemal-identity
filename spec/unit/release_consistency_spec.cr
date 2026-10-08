require "../spec_helper"

# The places a version is written down for a reader, held to the one the shard declares.
#
# The README went on telling people to install `~> 0.9.0` for three minor releases, and the
# roadmap went on calling a released milestone "in progress": nothing failed when they drifted,
# so nothing noticed. `tools/release/verify.sh` checks the same thing at the gate; this makes it
# a failure on every run rather than only when a release is being cut.
private ROOT = File.expand_path("../..", __DIR__)

private def read(path : String) : String
  File.read(File.join(ROOT, path))
end

private def minor_line : String
  KemalIdentity::VERSION.split('.')[0, 2].join('.')
end

describe "release consistency" do
  it "declares the same version in shard.yml and VERSION" do
    read("shard.yml").should match(/^version: #{Regex.escape(KemalIdentity::VERSION)}$/m)
  end

  it "has a changelog section for this version" do
    read("CHANGELOG.md").should match(/^## v#{Regex.escape(KemalIdentity::VERSION)} /m)
  end

  it "pins this minor line in every README install snippet" do
    pins = read("README.md").scan(/version: (~> [0-9.]+)/).map(&.[1])

    pins.should_not be_empty
    pins.uniq.should eq(["~> #{minor_line}.0"])
  end

  it "has a roadmap section for this minor line" do
    read("docs/06-roadmap.md").should match(/^## v#{Regex.escape(minor_line)}\b/m)
  end

  it "calls nothing at or below this version in progress" do
    roadmap = read("docs/06-roadmap.md")

    roadmap.scan(/^## v(\d+)\.(\d+)[^\n]*\n+\*\*In progress/m).each do |match|
      section = {match[1].to_i, match[2].to_i}
      current = {KemalIdentity::VERSION.split('.')[0].to_i, KemalIdentity::VERSION.split('.')[1].to_i}
      (section <=> current).should eq(1)
    end
  end
end

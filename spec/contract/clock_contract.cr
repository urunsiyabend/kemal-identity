# Shared spec for `KemalIdentity::Clock`. Every implementation runs it, the test double
# included — a double that behaves differently from the real thing turns a green suite into
# false confidence.
def it_behaves_like_a_clock(&build : -> KemalIdentity::Clock)
  it "returns a UTC instant" do
    build.call.now.location.should eq(Time::Location::UTC)
  end

  it "never runs backwards" do
    clock = build.call
    first = clock.now
    second = clock.now
    (second >= first).should be_true
  end
end

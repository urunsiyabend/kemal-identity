require "../spec_helper"

describe KemalIdentity::SystemClock do
  it_behaves_like_a_clock { KemalIdentity::SystemClock.new }
end

describe KemalIdentity::Testing::TestClock do
  it_behaves_like_a_clock { KemalIdentity::Testing::TestClock.new }

  it "stands still until advanced" do
    clock = KemalIdentity::Testing::TestClock.new
    clock.now.should eq(clock.now)
  end

  it "advances by the given span" do
    clock = KemalIdentity::Testing::TestClock.new(Time.utc(2026, 8, 24))
    clock.advance(13.hours)
    clock.now.should eq(Time.utc(2026, 8, 24, 13, 0, 0))
  end

  it "refuses to rewind" do
    clock = KemalIdentity::Testing::TestClock.new
    expect_raises(ArgumentError) { clock.advance(-1.hour) }
  end
end

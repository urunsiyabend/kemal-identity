# Shared spec for `KemalIdentity::RandomSource`. Every implementation runs it, the test
# double included.
def it_behaves_like_a_random_source(&build : -> KemalIdentity::RandomSource)
  it "returns exactly the requested number of bytes" do
    build.call.bytes(32).size.should eq(32)
  end

  it "rejects a non-positive count" do
    source = build.call
    expect_raises(ArgumentError) { source.bytes(0) }
    expect_raises(ArgumentError) { source.bytes(-1) }
  end

  it "does not repeat itself across calls" do
    source = build.call
    source.bytes(32).should_not eq(source.bytes(32))
  end

  it "produces a url-safe token with no padding" do
    token = build.call.token
    token.should match(/\A[A-Za-z0-9_-]+\z/)
  end

  it "produces a token of the length the shape check expects" do
    build.call.token.size.should eq(KemalIdentity::RandomSource.token_length)
  end

  it "refuses to mint a token below the minimum entropy" do
    source = build.call
    expect_raises(ArgumentError) { source.token(16) }
  end
end

require "../spec_helper"
# The contract comes in via spec_helper, which now requires the published testing entry points.

describe KemalIdentity::Testing::MemoryRevocationStore do
  it_behaves_like_a_revocation_store { KemalIdentity::Testing::MemoryRevocationStore.new }
end

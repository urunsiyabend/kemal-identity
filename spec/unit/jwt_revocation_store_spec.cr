require "../spec_helper"
require "../contract/jwt_revocation_store_contract"

describe KemalIdentity::Testing::MemoryRevocationStore do
  it_behaves_like_a_revocation_store { KemalIdentity::Testing::MemoryRevocationStore.new }
end

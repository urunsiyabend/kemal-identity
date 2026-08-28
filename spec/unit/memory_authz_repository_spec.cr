require "../spec_helper"

describe KemalIdentity::Testing::MemoryAuthzRepository do
  it_behaves_like_an_authz_repository { KemalIdentity::Testing::MemoryAuthzRepository.new }
end

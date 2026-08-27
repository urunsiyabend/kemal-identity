require "../spec_helper"

describe KemalIdentity::Testing::MemoryMfaRepository do
  it_behaves_like_an_mfa_repository { KemalIdentity::Testing::MemoryMfaRepository.new }
end

require "../spec_helper"

describe KemalIdentity::Testing::MemoryRememberRepository do
  it_behaves_like_a_remember_repository do |tokens|
    KemalIdentity::Testing::MemoryRememberRepository.new(tokens)
  end
end

require "../spec_helper"

describe KemalIdentity::Testing::MemoryLinkRepository do
  it_behaves_like_a_link_repository { KemalIdentity::Testing::MemoryLinkRepository.new }
end

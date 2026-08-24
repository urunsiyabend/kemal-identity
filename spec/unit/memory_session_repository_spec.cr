require "../spec_helper"

describe KemalIdentity::Testing::MemorySessionRepository do
  it_behaves_like_a_session_repository do |accounts|
    KemalIdentity::Testing::MemorySessionRepository.new(
      KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
    )
  end
end

require "../spec_helper"

describe KemalIdentity::Testing::MemoryActionTokenRepository do
  it_behaves_like_an_action_token_repository do |tokens|
    KemalIdentity::Testing::MemoryActionTokenRepository.new(tokens)
  end
end

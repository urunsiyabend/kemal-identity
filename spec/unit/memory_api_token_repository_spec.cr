require "../spec_helper"

describe KemalIdentity::Testing::MemoryApiTokenRepository do
  it_behaves_like_an_api_token_repository do |accounts|
    KemalIdentity::Testing::MemoryApiTokenRepository.new(
      KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
    )
  end
  it_behaves_like_an_api_token_repository_with_family_revocation do |accounts|
    KemalIdentity::Testing::MemoryApiTokenRepository.new(
      KemalIdentity::Testing::MemoryAccountRepository.new(accounts)
    )
  end
end

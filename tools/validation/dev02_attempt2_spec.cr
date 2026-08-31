require "spec"
require "kemal_identity"
require "kemal_identity/sqlite"
require "sqlite3"

# DEV-02, attempt 2: the contract that actually matters to an adapter author.
require "../lib/kemal_identity/spec/contract/api_token_repository_contract"

it_behaves_like_an_api_token_repository do |accounts|
  KemalIdentity::SQLite::ApiTokenRepository.new(DB.open("sqlite3://:memory:"))
end

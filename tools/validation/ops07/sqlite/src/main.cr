require "kemal_identity"
require "kemal_identity/sqlite"
require "sqlite3"
puts "sqlite adapter=#{KemalIdentity::SQLite::AccountRepository.name}"

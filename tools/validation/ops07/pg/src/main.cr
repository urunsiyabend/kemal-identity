require "kemal_identity"
require "kemal_identity/postgres"
require "pg"
puts "postgres adapter=#{KemalIdentity::Postgres::AccountRepository.name}"

require "kemal_identity"
# Core only: a password hasher and a principal. No database, no driver, no Kemal.
hasher = KemalIdentity::Passwords::BcryptHasher.new(cost: 4)
digest = hasher.hash_secret(KemalIdentity::Secret.new("correct horse battery"))
puts "verify=#{hasher.verify(KemalIdentity::Secret.new("correct horse battery"), digest)}"
puts "principal=#{KemalIdentity::Principal.new(
  subject: "u-1", assurance: KemalIdentity::AssuranceLevel::Password, authenticated_at: Time.utc
).subject}"

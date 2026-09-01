require "spec"
require "kemal_identity"
require "kemal_identity/testing"
require "kemal_identity/testing/contracts"

# Does `tenanted: false` catch the unsafe single-tenant behaviour, or does it just skip?
#
# This adapter ignores the tenant argument and hands back the untenanted row -- which passes every
# other example in the contract and is a cross-tenant leak the day the application grows a second
# tenant. If the flag only skipped the tenancy group, this would pass.
class LeakyAdapter < KemalIdentity::Accounts::Repository
  def initialize(@accounts : Array(KemalIdentity::Accounts::Account))
  end

  def find_by_id(id : String) : KemalIdentity::Accounts::Account?
    @accounts.find { |a| a.id == id }
  end

  def find_by_login(normalized_login : String, tenant_id : String? = nil) : KemalIdentity::Accounts::Account?
    # The bug: `tenant_id` is never consulted.
    @accounts.find { |a| a.normalized_login == normalized_login }
  end

  def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool
    false
  end

  def mark_email_verified(id : String, at : Time) : Bool
    false
  end

  def bump_auth_version(id : String) : Int32?
    nil
  end
end

it_behaves_like_an_account_repository(tenanted: false) do |accounts|
  LeakyAdapter.new(accounts)
end

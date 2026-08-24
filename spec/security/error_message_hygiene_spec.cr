require "../spec_helper"

# docs/02-security-model.md: an error message must never contain a login, a token, or a
# digest. The error classes exist so that the authentication path raises only for the two
# deliberate guard cases; everything else is a `Failed` value.
describe "error taxonomy" do
  it "roots every error at KemalIdentity::Error" do
    [
      KemalIdentity::ConfigurationError.new("bad cookie configuration"),
      KemalIdentity::InfrastructureError.new("session store unavailable"),
      KemalIdentity::NotAuthenticatedError.new("not authenticated"),
      KemalIdentity::FreshAuthenticationRequiredError.new("fresh authentication required"),
    ].each do |error|
      error.should be_a(KemalIdentity::Error)
      error.should be_a(Exception)
    end
  end

  it "keeps the guard errors distinguishable so they can map to 401 and 403" do
    KemalIdentity::NotAuthenticatedError.new("x").should_not be_a(KemalIdentity::FreshAuthenticationRequiredError)
    KemalIdentity::FreshAuthenticationRequiredError.new("x").should_not be_a(KemalIdentity::NotAuthenticatedError)
  end
end

require "../spec_helper"

# Records what it was asked, so the specs can assert that a chain stopped rather than merely
# that it returned the right answer. "Did not fall through" and "fell through and the next one
# happened to agree" are the same outcome and very different behaviour.
private class StubAuthenticator < KemalIdentity::RequestAuthenticator
  getter calls = 0

  def initialize(@outcome : KemalIdentity::Outcome)
  end

  def authenticate(credential : String?) : KemalIdentity::Outcome
    @calls += 1
    @outcome
  end
end

private def anonymous
  StubAuthenticator.new(KemalIdentity::Anonymous.new)
end

private def malformed
  StubAuthenticator.new(KemalIdentity::Failed.new(KemalIdentity::FailureReason::MalformedCredential))
end

private def authenticated(subject : String = "a1")
  StubAuthenticator.new(
    KemalIdentity::Authenticated.new(
      KemalIdentity::Principal.new(
        subject: subject,
        assurance: KemalIdentity::AssuranceLevel::ApiToken,
        authenticated_at: KemalIdentity::SpecHelper::FIXED_NOW,
      )
    )
  )
end

private def failing(reason : KemalIdentity::FailureReason)
  StubAuthenticator.new(KemalIdentity::Failed.new(reason))
end

# The whole of the contract, implemented. `blueprints/0020` decision 7 rests on this staying
# true: request attributes can reach an authenticator after 1.0 through a *defaulted* overload,
# which breaks nobody — but only while `authenticate(credential)` is the single abstract method.
#
# A second `abstract def` added here would freeze at 1.0 and force every consumer's
# authenticator to implement it. That would not fail an example; it would stop this file
# compiling, which is the point of the fixture.
private class MinimalAuthenticator < KemalIdentity::RequestAuthenticator
  def authenticate(credential : String?) : KemalIdentity::Outcome
    KemalIdentity::Anonymous.new
  end
end

private def chain(*authenticators : KemalIdentity::RequestAuthenticator)
  KemalIdentity::AuthenticatorChain.new(authenticators.to_a.map(&.as(KemalIdentity::RequestAuthenticator)))
end

describe KemalIdentity::RequestAuthenticator do
  it "is satisfied by implementing one method" do
    MinimalAuthenticator.new.authenticate("anything").should be_a(KemalIdentity::Anonymous)
  end

  # A consumer's own authenticator goes in the chain beside the built-in ones, which is what
  # keeps a future request-aware subclass registrable without the element type moving.
  it "composes into a chain alongside the shipped authenticators" do
    KemalIdentity::AuthenticatorChain
      .new([MinimalAuthenticator.new] of KemalIdentity::RequestAuthenticator)
      .authenticate("anything")
      .should be_a(KemalIdentity::Anonymous)
  end
end

describe KemalIdentity::AuthenticatorChain do
  it "returns the first authenticator that recognises the credential" do
    first = authenticated("first")
    second = authenticated("second")

    outcome = chain(first, second).authenticate("anything")

    KemalIdentity::SpecHelper.should_authenticate(outcome).subject.should eq("first")
    second.calls.should eq(0)
  end

  # Shape is the only thing that routes: "not a credential of mine" is an invitation to try
  # the next one.
  it "falls through when an authenticator does not recognise the shape" do
    first = malformed
    second = authenticated

    chain(first, second).authenticate("x").should be_a(KemalIdentity::Authenticated)
    second.calls.should eq(1)
  end

  it "falls through an authenticator that saw nothing to authenticate" do
    second = authenticated

    chain(anonymous, second).authenticate("x").should be_a(KemalIdentity::Authenticated)
    second.calls.should eq(1)
  end

  # The property the whole class exists for. A credential that was recognised and then failed
  # on its merits must not get a second opinion from an authenticator that never issued it —
  # that is how a revoked credential ends up authenticating a request.
  it "stops at a recognised credential that failed on its merits" do
    [
      KemalIdentity::FailureReason::Revoked,
      KemalIdentity::FailureReason::Expired,
      KemalIdentity::FailureReason::InvalidCredential,
      KemalIdentity::FailureReason::InvalidClaim,
      KemalIdentity::FailureReason::DisabledAccount,
      KemalIdentity::FailureReason::StaleAuthVersion,
      KemalIdentity::FailureReason::RateLimited,
      KemalIdentity::FailureReason::ReplayedToken,
    ].each do |reason|
      never_reached = authenticated

      KemalIdentity::SpecHelper.should_fail_with(
        chain(failing(reason), never_reached).authenticate("x"), reason
      )

      never_reached.calls.should eq(0)
    end
  end

  it "reports the last refusal when nobody recognised the credential" do
    KemalIdentity::SpecHelper.should_fail_with(
      chain(malformed, malformed).authenticate("x"),
      KemalIdentity::FailureReason::MalformedCredential
    )
  end

  it "is anonymous when nobody saw a credential at all" do
    chain(anonymous, anonymous).authenticate(nil).should be_a(KemalIdentity::Anonymous)
  end

  it "asks every authenticator in order" do
    first = malformed
    second = malformed
    third = malformed

    chain(first, second, third).authenticate("x")

    {first, second, third}.each(&.calls.should(eq(1)))
  end

  it "refuses an empty chain, which would silently authenticate nothing" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::AuthenticatorChain.new([] of KemalIdentity::RequestAuthenticator)
    end
  end
end

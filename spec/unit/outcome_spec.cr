require "../spec_helper"

describe "KemalIdentity::Outcome" do
  # The whole point of the union: the principal is reachable only in the branch where it
  # exists, so no call site needs `not_nil!`, and adding a variant is a compile error at
  # every consumer.
  it "is exhaustively matchable over all three variants" do
    outcomes = [
      KemalIdentity::Anonymous.new,
      KemalIdentity::Authenticated.new(KemalIdentity::SpecHelper.principal),
      KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential),
    ] of KemalIdentity::Outcome

    labels = outcomes.map do |outcome|
      case outcome
      in KemalIdentity::Anonymous     then "anonymous"
      in KemalIdentity::Authenticated then outcome.principal.subject
      in KemalIdentity::Failed        then outcome.reason.to_s
      end
    end

    labels.should eq(["anonymous", "account-1", "InvalidCredential"])
  end

  it "carries a retry_after only where one was given" do
    KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidCredential).retry_after.should be_nil

    denied = KemalIdentity::Failed.new(KemalIdentity::FailureReason::RateLimited, retry_after: 30.seconds)
    denied.retry_after.should eq(30.seconds)
  end
end

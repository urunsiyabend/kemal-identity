# Assertions for `KemalIdentity::Outcome`.
#
# Written because `outcome.as(KemalIdentity::Failed).reason.should eq(...)` reports a
# regression as a `TypeCastError` stack trace rather than as a failure that says what went
# wrong. A security spec is only as useful as its failure message: "expected
# Failed(StaleAuthVersion), got Authenticated(a1)" names the vulnerability, while a cast
# error makes the reader go and find it.
#
# The exhaustive `case ... in` is the other half — adding an `Outcome` variant becomes a
# compile error here rather than a silently unhandled branch.
module KemalIdentity::SpecHelper
  def self.should_fail_with(
    outcome : KemalIdentity::Outcome,
    reason : KemalIdentity::FailureReason,
    file : String = __FILE__,
    line : Int32 = __LINE__,
  ) : KemalIdentity::Failed
    case outcome
    in KemalIdentity::Failed
      unless outcome.reason == reason
        raise Spec::AssertionFailed.new(
          "expected Failed(#{reason}), got Failed(#{outcome.reason})", file, line
        )
      end
      outcome
    in KemalIdentity::Anonymous
      raise Spec::AssertionFailed.new("expected Failed(#{reason}), got Anonymous", file, line)
    in KemalIdentity::Authenticated
      raise Spec::AssertionFailed.new(
        "expected Failed(#{reason}), got Authenticated(#{outcome.principal.subject})", file, line
      )
    end
  end

  def self.should_authenticate(
    outcome : KemalIdentity::Outcome,
    file : String = __FILE__,
    line : Int32 = __LINE__,
  ) : KemalIdentity::Principal
    case outcome
    in KemalIdentity::Authenticated
      outcome.principal
    in KemalIdentity::Anonymous
      raise Spec::AssertionFailed.new("expected Authenticated, got Anonymous", file, line)
    in KemalIdentity::Failed
      raise Spec::AssertionFailed.new(
        "expected Authenticated, got Failed(#{outcome.reason})", file, line
      )
    end
  end
end

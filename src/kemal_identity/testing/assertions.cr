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
module KemalIdentity::Testing
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

  # The same, for a second-factor check.
  #
  # `MFA::VerificationResult` is `Verified | Failed` rather than an `Outcome`, so the overload
  # above does not accept it and a consumer's spec falls back to the cast this module exists to
  # replace. Found writing MFA-01 in `blueprints/0025`: a packaged assertion that covers three
  # of the four result unions is a packaged assertion somebody stops using.
  def self.should_fail_with(
    result : KemalIdentity::MFA::VerificationResult,
    reason : KemalIdentity::FailureReason,
    file : String = __FILE__,
    line : Int32 = __LINE__,
  ) : KemalIdentity::Failed
    case result
    in KemalIdentity::Failed
      unless result.reason == reason
        raise Spec::AssertionFailed.new(
          "expected Failed(#{reason}), got Failed(#{result.reason})", file, line
        )
      end
      result
    in KemalIdentity::MFA::Verified
      raise Spec::AssertionFailed.new(
        "expected Failed(#{reason}), got Verified(#{result.by_recovery_code? ? "recovery code" : result.factor.try(&.id)})",
        file, line
      )
    end
  end

  def self.should_verify(
    result : KemalIdentity::MFA::VerificationResult,
    file : String = __FILE__,
    line : Int32 = __LINE__,
  ) : KemalIdentity::MFA::Verified
    case result
    in KemalIdentity::MFA::Verified
      result
    in KemalIdentity::Failed
      raise Spec::AssertionFailed.new(
        "expected Verified, got Failed(#{result.reason})", file, line
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

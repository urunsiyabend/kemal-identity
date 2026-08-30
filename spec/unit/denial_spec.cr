require "../spec_helper"

# `blueprints/0022` decisions 5 to 8: a denial names its own reason for the audit trail, and
# says separately whether authenticating again could change the answer.
describe KemalIdentity::Authz::Forbidden do
  describe "step_up, which decides the control flow" do
    # The one built-in reason a stronger credential fixes.
    it "asks for step-up when assurance was insufficient" do
      denial = KemalIdentity::Authz::Forbidden.insufficient_assurance("payouts:edit")

      denial.step_up?.should be_true
      denial.reason.should eq(KemalIdentity::Authz::DenialReason::InsufficientAssurance)
    end

    # Re-authenticating grants nobody a role, joins nobody to a tenant and declares no
    # permission. Prompting for a second factor in these cases asks for something that cannot
    # help.
    it "does not ask for step-up when re-authenticating could not help" do
      {
        KemalIdentity::Authz::Forbidden.not_permitted("invoices:edit"),
        KemalIdentity::Authz::Forbidden.not_a_member("invoices:edit", "t1"),
        KemalIdentity::Authz::Forbidden.tenant_mismatch("invoices:edit", "t2"),
        KemalIdentity::Authz::Forbidden.unknown_permission("invoices:edti"),
        KemalIdentity::Authz::Forbidden.out_of_scope("releases:write"),
      }.each do |denial|
        denial.step_up?.should be_false
      end
    end

    # A token's attenuation was fixed when it was issued. No amount of proving who you are
    # widens it — that needs a new token, which is a remediation and not a step-up.
    it "does not ask for step-up when the credential is out of scope" do
      denial = KemalIdentity::Authz::Forbidden.out_of_scope("releases:write")

      denial.reason.should eq(KemalIdentity::Authz::DenialReason::OutOfScope)
      denial.step_up?.should be_false
    end
  end

  # Decision 7: the flag is not a parameter of the general constructor, so `RBAC` cannot build
  # an assurance denial and forget it. `initialize` is private; these are the only ways in.
  describe "named constructors" do
    it "fixes the flag for every built-in reason" do
      KemalIdentity::Authz::Forbidden.responds_to?(:not_permitted).should be_true
      KemalIdentity::Authz::Forbidden.responds_to?(:insufficient_assurance).should be_true
      KemalIdentity::Authz::Forbidden.responds_to?(:out_of_scope).should be_true
      KemalIdentity::Authz::Forbidden.responds_to?(:policy).should be_true
    end

    it "carries the tenant it was asked about" do
      KemalIdentity::Authz::Forbidden.not_a_member("invoices:edit", "t1").tenant_id.should eq("t1")
    end

    it "leaves code nil for the built-in reasons, which #reason already names" do
      KemalIdentity::Authz::Forbidden.not_permitted("invoices:edit").code.should be_nil
    end
  end

  # Decision 5: an application authorizer names its own reason. Audit only — the response is
  # identical, because a denial that explains itself confirms which tenants exist.
  describe "an application authorizer's own denial" do
    it "carries a code and chooses its own step-up answer" do
      denial = KemalIdentity::Authz::Forbidden.policy(
        "reports:export", code: "change_window_closed", step_up: false
      )

      denial.reason.should eq(KemalIdentity::Authz::DenialReason::Custom)
      denial.code.should eq("change_window_closed")
      denial.step_up?.should be_false
    end

    it "can ask for step-up under its own reason, without borrowing InsufficientAssurance" do
      denial = KemalIdentity::Authz::Forbidden.policy(
        "payouts:edit", code: "sensitive_operation", step_up: true
      )

      denial.reason.should eq(KemalIdentity::Authz::DenialReason::Custom)
      denial.code.should eq("sensitive_operation")
      denial.step_up?.should be_true
    end

    # A Custom denial with no code is a denial that says nothing at all: the enum member means
    # "see the code" and there is none.
    it "refuses a policy denial with no code" do
      expect_raises(ArgumentError) do
        KemalIdentity::Authz::Forbidden.policy("reports:export", code: "")
      end
    end
  end

  it "is never permitted" do
    KemalIdentity::Authz::Forbidden.not_permitted("a").permitted?.should be_false
  end
end

describe KemalIdentity::Authz::DenialReason do
  # Consumers write `case decision.reason` over these. Appended to, never renumbered.
  it "has the members consumers switch on" do
    KemalIdentity::Authz::DenialReason.names.should eq(
      %w[NotPermitted NotAMember TenantMismatch InsufficientAssurance UnknownPermission OutOfScope Custom]
    )
  end
end

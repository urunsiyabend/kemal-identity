module KemalIdentity::Authz
  # Why an authorization check said no.
  #
  # **For the audit log, not for the response.** The same discipline as `FailureReason`, and
  # for a sharper reason here: `NotAMember` and `NotPermitted` tell an attacker whether the
  # tenant they just guessed at exists and whether they are inside it. Every denial renders one
  # identical 403 — `ErrorHandler` does not read this, and neither should a route.
  enum DenialReason
    # Nobody granted it. The ordinary case, and the one that should be boring.
    NotPermitted

    # The check named a tenant this principal does not belong to. Distinct from `NotPermitted`
    # because it means something different to whoever reads the trail: a member without a role
    # is a provisioning gap, and a non-member reaching for a tenant's data is an incident.
    NotAMember

    # The principal is bound to one tenant and the check named another. This is the horizontal
    # privilege-escalation attempt — the id in the URL swapped for somebody else's — and it is
    # refused before membership is even consulted.
    TenantMismatch

    # A role grants this permission and the caller holds that role, but they have not proved
    # who they are strongly enough for this particular action. The application should prompt
    # for a second factor rather than show a dead end.
    InsufficientAssurance

    # The permission was never declared. Fails closed, and is named separately because it is
    # almost always a typo or a half-finished rename rather than an access-control event.
    UnknownPermission
  end

  # The check said yes.
  struct Permitted
    getter permission : String

    # Which role granted it. For the audit trail: "allowed" is not a useful line in a log, and
    # "allowed via finance_admin" is what somebody reviewing an access review needs.
    getter via : String

    getter tenant_id : String?

    def initialize(@permission : String, @via : String, @tenant_id : String? = nil)
    end

    def permitted? : Bool
      true
    end
  end

  # The check said no.
  struct Forbidden
    getter permission : String
    getter reason : DenialReason
    getter tenant_id : String?

    def initialize(@permission : String, @reason : DenialReason, @tenant_id : String? = nil)
    end

    def permitted? : Bool
      false
    end
  end

  # The result of an authorization check.
  #
  # A union rather than a `Bool`, for the same reason `Outcome` is a union rather than a
  # nilable principal: the granting role is reachable only in the branch where there is one,
  # and adding a variant is a compile error at every exhaustive `case ... in` rather than a
  # silently unhandled case. `#permitted?` is on both variants for the call sites that only
  # want the yes or no.
  alias Decision = Permitted | Forbidden
end

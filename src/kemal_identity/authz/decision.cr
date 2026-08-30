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

    # The account holds the permission, but the credential presenting the request does not.
    #
    # A personal access token scoped to `reports:read` used against `releases:write`. The
    # account's grant is not in question; the token's attenuation is
    # (`blueprints/0021-credential-reference.md`).
    OutOfScope

    # An application authorizer's own reason, named by `Forbidden#code`.
    #
    # Five members cannot describe every policy — a closed change window, an unmanaged device,
    # an incident lockdown — and an authorizer forced to report `NotPermitted` for those loses
    # the only thing the audit trail wanted.
    Custom
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
  #
  # ### Built with a named constructor, never with `new`
  #
  # `#step_up?` decides control flow — `env.auth.authorize!` raises
  # `FreshAuthenticationRequiredError` when it is true — and if it were an ordinary constructor
  # argument then `RBAC` could build an `InsufficientAssurance` denial and forget to pass it.
  # Step-up would stop working, silently, and no type would catch it. Before this struct carried
  # the flag the enum member *was* the signal, so that mistake was unrepresentable; splitting
  # the two axes must not buy extensibility with that guarantee.
  #
  # So `initialize` is private and each built-in reason has a constructor that fixes the flag.
  # The one place a caller chooses is `.policy`, which is the one place the answer is not
  # already known here. Same shape as `Verdict.allow` and `Verdict.deny`.
  struct Forbidden
    getter permission : String
    getter reason : DenialReason

    # An application authorizer's own reason, for the audit trail. `nil` for the built-in ones,
    # which `#reason` already names.
    #
    # **Never rendered to a client.** Laravel propagates a gate's message into the HTTP response
    # and Django REST Framework renders one; this shard does not, for the reason `DenialReason`
    # gives above — a denial that explains itself confirms which tenants exist and who is in
    # them. Every denial still renders one identical 403.
    getter code : String?

    # Whether stronger or fresher authentication may allow this request to succeed.
    #
    # Not "the caller is missing something" — *"authenticating again, or harder, may change this
    # answer"*. Joining a tenant, enrolling a managed device or being issued a wider token do
    # not qualify: those are remediations, and no amount of re-authentication performs them.
    # Prompting for a second factor in those cases asks somebody for something that cannot help.
    getter? step_up : Bool

    getter tenant_id : String?

    private def initialize(
      @permission : String,
      @reason : DenialReason,
      @step_up : Bool,
      @code : String? = nil,
      @tenant_id : String? = nil,
    )
    end

    # Nobody granted it.
    def self.not_permitted(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::NotPermitted, step_up: false, tenant_id: tenant_id)
    end

    # The check named a tenant this principal does not belong to.
    def self.not_a_member(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::NotAMember, step_up: false, tenant_id: tenant_id)
    end

    # The principal is bound to one tenant and the check named another.
    def self.tenant_mismatch(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::TenantMismatch, step_up: false, tenant_id: tenant_id)
    end

    # The permission was never declared.
    def self.unknown_permission(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::UnknownPermission, step_up: false, tenant_id: tenant_id)
    end

    # A role grants this and the caller holds it, but has not proved who they are strongly
    # enough. The one built-in reason that step-up can fix.
    def self.insufficient_assurance(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::InsufficientAssurance, step_up: true, tenant_id: tenant_id)
    end

    # The account holds the permission; the credential presenting the request does not.
    #
    # `step_up: false`, and worth stating rather than assuming: re-authenticating does not widen
    # a token's scope. The attenuation was fixed when the token was issued, and no amount of
    # proving who you are changes what the credential may carry. Issuing a new token can help,
    # and that is a remediation rather than a step-up.
    def self.out_of_scope(permission : String, tenant_id : String? = nil) : self
      new(permission, DenialReason::OutOfScope, step_up: false, tenant_id: tenant_id)
    end

    # An application authorizer's own denial.
    #
    # `code` names the reason for the audit trail. `step_up` is chosen here because this is the
    # only case where this shard cannot know the answer — but choose it honestly: true only when
    # authenticating again, or harder, could actually change the outcome.
    def self.policy(
      permission : String,
      code : String,
      step_up : Bool = false,
      tenant_id : String? = nil,
    ) : self
      raise ArgumentError.new("a policy denial must carry a code") if code.empty?

      new(permission, DenialReason::Custom, step_up: step_up, code: code, tenant_id: tenant_id)
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

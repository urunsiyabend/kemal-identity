module KemalIdentity
  # Who is making this request, since when, and at what assurance.
  #
  # The minimum security context and nothing more. It carries no roles, no permissions, no
  # email, no profile — those are authorization or application concerns, they go stale the
  # moment they are copied, and loading them would put a join on the hot path
  # (`docs/03-data-model.md`). The application loads its own user object when it actually
  # needs one.
  struct Principal
    # The canonical account identifier, as a string.
    #
    # A `String` rather than a generic parameter on purpose: `RequestAuthenticator(T)`
    # would propagate `T` through every handler, service and repository in the type graph,
    # and an application wanting a UUID in one place and an `Int64` in another would have
    # no way out. The cost is one `subject.to_i64` at the application boundary — see
    # `docs/01-architecture.md`.
    getter subject : String

    # How strongly this principal was authenticated.
    getter assurance : AssuranceLevel

    # When the credential behind `assurance` was last verified.
    #
    # Not a stored `fresh_until`: the freshness window belongs to the caller
    # (`require_fresh!(within: 5.minutes)`), so storing a precomputed deadline would bake
    # one caller's policy into every row.
    getter authenticated_at : Time

    # The session this principal was resolved from, when there is one. Present so that
    # "log out everywhere else" can spare the current session.
    getter session_id : String?

    # When a second factor was last verified, if ever.
    getter mfa_verified_at : Time?

    # Unused in v0.1. Present on the principal and in the schema so that adding tenancy is
    # not a breaking migration.
    getter tenant_id : String?

    def initialize(
      @subject : String,
      @assurance : AssuranceLevel,
      @authenticated_at : Time,
      @session_id : String? = nil,
      @mfa_verified_at : Time? = nil,
      @tenant_id : String? = nil,
    )
      raise ArgumentError.new("subject must not be empty") if @subject.empty?
    end

    # Whether the credential behind this principal was verified within `within` of `now`.
    #
    # A principal below `AssuranceLevel::Password` is never fresh, however recent it is: a
    # session restored from a remember-me cookie proves possession of a stored token, not
    # the presence of the account holder. Step-up therefore always forces a real
    # re-authentication out of `Remembered`.
    def fresh?(within : Time::Span, now : Time) : Bool
      return false if @assurance < AssuranceLevel::Password
      now - @authenticated_at <= within
    end

    # Whether this principal reached at least `level`.
    def at_least?(level : AssuranceLevel) : Bool
      @assurance >= level
    end
  end
end

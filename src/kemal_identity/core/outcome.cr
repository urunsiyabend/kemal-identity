module KemalIdentity
  # No credential was presented. The request is simply not signed in.
  #
  # Distinct from `Failed` on purpose: a request with no cookie needs no response action,
  # whereas a request with a cookie that did not resolve needs that cookie cleared. A
  # public page renders for `Anonymous`; only a guard turns it into a 401.
  struct Anonymous
  end

  # A credential resolved to a principal.
  struct Authenticated
    getter principal : Principal

    def initialize(@principal : Principal)
    end
  end

  # A credential was presented and rejected.
  #
  # `reason` exists for the audit log. It must not reach the response body: identical
  # status, body and headers for every reason, or the shard becomes an enumeration oracle
  # (`docs/02-security-model.md`).
  struct Failed
    getter reason : FailureReason

    # Set only for `FailureReason::RateLimited`, where telling an honest client when to
    # come back is worth more than the timing it reveals.
    getter retry_after : Time::Span?

    def initialize(@reason : FailureReason, @retry_after : Time::Span? = nil)
    end
  end

  # The result of any authentication attempt.
  #
  # A union rather than a struct with a nilable `principal` and a nilable `failure`: the
  # union makes the principal reachable *only* in the branch where it exists, so there is
  # no `not_nil!` at any call site, and an exhaustive `case ... in` means adding a variant
  # is a compile error at every consumer rather than a silently unhandled case.
  #
  # `docs/01-architecture.md` names the credential-side result `AuthenticationResult` and
  # lists two variants; `src/CLAUDE.md` and the login example in
  # `docs/04-kemal-integration.md` use three. One three-variant union is used everywhere —
  # see `blueprints/0001-single-outcome-union.md` for why.
  alias Outcome = Anonymous | Authenticated | Failed

  # The name `docs/01-architecture.md` uses at the credential and request boundaries.
  alias AuthenticationResult = Outcome
end

module KemalIdentity::ApiTokens
  # Why an issuance was refused by the deployment's token lifetime policy.
  #
  # Like `Passwords::PolicyViolation` and unlike `FailureReason`, these **are** safe to show the
  # person who asked: they arise when somebody is creating a credential, not when somebody is
  # proving they hold one, so there is no account to enumerate and a specific message is what
  # makes the requirement followable.
  enum PolicyViolation
    # The deployment forbids a token with no expiry, and none was given.
    ExpiryRequired

    # The requested expiry is further away than the deployment permits.
    TooLong
  end

  # Raised by `Service#issue` when the deployment's lifetime policy refuses the issuance.
  #
  # Carries the violation and the limit so an application can render the requirement — "tokens
  # must expire within 30 days" — rather than a generic failure. Both are safe to show.
  class PolicyError < KemalIdentity::Error
    getter violation : PolicyViolation
    getter maximum : Time::Span

    def initialize(@violation : PolicyViolation, @maximum : Time::Span)
      super(
        case @violation
        in PolicyViolation::ExpiryRequired
          "a token must expire: this deployment does not permit an unbounded token"
        in PolicyViolation::TooLong
          "a token must expire within #{@maximum.total_days.round(2)} days"
        end
      )
    end
  end

  # How long a personal access token may live in this deployment.
  #
  # An enterprise requires every token to expire within thirty days and forbids unbounded ones;
  # the deployment next door permits a non-expiring deploy key. Both are correct, so this is
  # **absent by default** — `Service.new` with no policy accepts what its caller asks for,
  # including no expiry at all, which is the shipped behaviour and stays it.
  #
  # ### Checked at issuance, and only there
  #
  # A policy describes what may be *created*. It is not consulted on the authentication path:
  # every request already reads the token's own `expires_at`, and re-deriving a limit per request
  # would put a policy lookup on the hot path to answer a question the row already answers.
  #
  # The consequence, which `docs/02-security-model.md` states rather than leaves to be
  # discovered: **tightening the policy does not shorten the tokens that already exist.** A
  # ninety-day token issued under the old rule keeps its ninety days. That is the honest
  # behaviour for a rule about creation, and it is why `Service#expire` exists — an organisation
  # that must apply a new limit retroactively walks its tokens and brings each deadline forward,
  # which is one call per token and cannot lengthen anything by mistake.
  #
  # ```
  # policy = KemalIdentity::ApiTokens::LifetimePolicy.new(maximum: 30.days, default: 7.days)
  # ```
  struct LifetimePolicy
    # The furthest away an expiry may be, measured from the moment of issuance.
    getter maximum : Time::Span

    # What to use when the caller names no expiry. `nil` means an issuance with no expiry is
    # refused rather than defaulted — the stricter reading, and the one an enterprise asking
    # for this feature usually wants: a client that forgot to ask for a deadline should be told,
    # not quietly given one.
    getter default : Time::Span?

    def initialize(@maximum : Time::Span, @default : Time::Span? = nil)
      unless @maximum > Time::Span::ZERO
        raise ConfigurationError.new("maximum must be positive")
      end

      default = @default

      if default
        unless default > Time::Span::ZERO
          raise ConfigurationError.new("default must be positive")
        end

        if default > @maximum
          raise ConfigurationError.new(
            "default lifetime of #{default} exceeds the maximum of #{@maximum}"
          )
        end
      end
    end

    # The expiry to store, filling in `default` when the caller named none. Returns `nil` when
    # there is nothing to fill in, which `#violation` then refuses.
    def resolve(expires_at : Time?, now : Time) : Time?
      return expires_at if expires_at

      default = @default
      default.nil? ? nil : now + default
    end

    # Why this expiry is unacceptable, or `nil` if it is fine.
    #
    # Takes `now` rather than reading a clock: a policy is a value, and the one thing worse
    # than a policy that cannot be tested is one that reads the system clock while being
    # tested.
    def violation(expires_at : Time?, now : Time) : PolicyViolation?
      return PolicyViolation::ExpiryRequired if expires_at.nil?
      return PolicyViolation::TooLong if expires_at > now + @maximum

      nil
    end
  end
end

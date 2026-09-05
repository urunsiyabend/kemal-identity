module KemalIdentity
  # What would satisfy a refusal that step-up can fix.
  #
  # A refusal that says only "insufficient" leaves the one party who has to *do* something —
  # the application rendering the prompt, or the client retrying the call — guessing between
  # "type your password again", "produce a second factor" and "you cannot get there from a
  # token at all". Before this struct existed the only signal was whether
  # `FreshAuthenticationRequiredError#max_age` was present, so an application inferred:
  #
  # ```
  # error.max_age ? "fresh" : "mfa"
  # ```
  #
  # That inference was already wrong when `AssuranceLevel::Recovery` was added — the absent
  # window now covers three different levels — and `require_recent_password!` made it worse,
  # because a password refusal and an ordinary freshness refusal both carry a window and mean
  # different prompts.
  #
  # Carrying the requirement with the refusal, rather than reconstructing it in the response
  # layer, is what every comparable framework does: ASP.NET Core puts the failed requirement
  # objects in `AuthorizationFailure.FailedRequirements`, and Spring Security 7's
  # `FactorAuthorizationDecision` carries the list of factors that were missing.
  # `blueprints/0032` measures both.
  #
  # ### It is not the response
  #
  # This is what the *application* reads. What crosses onto the wire is still one RFC 9470
  # challenge with `max_age` and nothing else — `blueprints/0028` decided that, and publishing
  # an assurance level as an `acr_values` string would still be inventing a vocabulary for a
  # deployment that has its own. An application that renders `#minimum_assurance` into a page is
  # telling its own user which proof to produce, which is the point; putting it in an API
  # response for an anonymous caller would be telling everybody what guards what.
  struct StepUpRequirement
    # The level the principal must reach, when *strength* is what failed.
    #
    # `nil` when the refusal was about recency rather than strength.
    getter minimum_assurance : AssuranceLevel?

    # The allowable elapsed time since the proof, when *recency* is what failed.
    #
    # `nil` when the refusal was about strength. RFC 9470 defines exactly this as `max_age`,
    # which is what `ErrorHandler` emits from it.
    getter max_age : Time::Span?

    # The method that specifically has to have been used, when the guard named one.
    #
    # `nil` means any proof of the required strength and recency will do — which is every guard
    # but `require_recent_password!`, where a second factor proved a minute ago is *fresher*
    # than the password and still does not satisfy the route.
    getter method : AuthenticationMethod?

    def initialize(
      @minimum_assurance : AssuranceLevel? = nil,
      @max_age : Time::Span? = nil,
      @method : AuthenticationMethod? = nil,
    )
    end

    # Whether this requirement says anything at all.
    #
    # An empty one is the honest answer for a refusal that knows only that the credential was
    # not good enough — an application authorizer's own `step_up: true` denial, which named no
    # level.
    def empty? : Bool
      @minimum_assurance.nil? && @max_age.nil? && @method.nil?
    end
  end
end

module KemalIdentity
  # Tries several `RequestAuthenticator`s in turn against one credential.
  #
  # An `Authorization: Bearer` header carries no indication of *which kind* of token it holds,
  # so an application accepting both an opaque personal access token and a JWT has to decide
  # which one is being presented. This decides it by asking, in order, and taking the first
  # answer that means something.
  #
  # ### Falling through, and when not to
  #
  # An authenticator gets to say one of three things, and only two of them are an invitation
  # to try the next:
  #
  # * `Anonymous` — "nothing was presented". Try the next.
  # * `Failed(MalformedCredential)` — "this is not a credential of mine". A `ki_`-prefixed
  #   token is not a JWT and a three-segment JWT is not an opaque token, and each rejects the
  #   other's shape before doing any work. Try the next.
  # * anything else — the credential *was* recognised and then failed on its merits: expired,
  #   revoked, a bad signature. **Stop.** Falling through here would let a rejected token get
  #   a second opinion from an authenticator that never issued it, which is how a revoked
  #   credential ends up authenticating a request.
  #
  # Shape is the only thing that routes, which is why every authenticator in this shard checks
  # shape before any I/O: the fall-through costs a length comparison rather than a lookup.
  class AuthenticatorChain < RequestAuthenticator
    getter authenticators : Array(RequestAuthenticator)

    def initialize(@authenticators : Array(RequestAuthenticator))
      if @authenticators.empty?
        raise ConfigurationError.new("an authenticator chain must hold at least one authenticator")
      end
    end

    def authenticate(credential : String?) : Outcome
      last = Anonymous.new.as(Outcome)

      @authenticators.each do |authenticator|
        last = authenticator.authenticate(credential)

        case last
        in Anonymous
          next
        in Failed
          next if last.reason.malformed_credential?
          return last
        in Authenticated
          return last
        end
      end

      last
    end
  end
end

module KemalIdentity
  # Answers "who is making *this* request?" from a credential the client presented.
  #
  # One of the three concepts `docs/01-architecture.md` deliberately keeps apart. Passport.js is
  # the cautionary example: "log in with a password", "read a session cookie" and "log in with
  # Google" are all called authentication, so they were given one interface — but they have
  # different inputs, different outputs and different lifecycles.
  #
  # | | Question | Runs |
  # |---|---|---|
  # | `RequestAuthenticator` | who is making this request? | every request |
  # | `CredentialAuthenticator` | does this secret prove this identity? | at login only |
  # | `IdentityProvider` | what does an external issuer assert? | redirect and callback |
  #
  # A session cookie reads an already-established session; a password *establishes* one. They
  # converge at `Principal` and nowhere else.
  #
  # ### The contract
  #
  # Every implementation takes the raw credential — a cookie value, the part of an
  # `Authorization` header after the scheme — and returns an `Outcome`:
  #
  # * `Anonymous` when no credential was presented. The request is simply not signed in, and
  #   needs no response action.
  # * `Failed` when one was presented and did not hold. The caller now knows to clear a cookie
  #   or answer 401, which it could not tell from a nilable principal.
  # * `Authenticated` otherwise.
  #
  # Implementations **must not raise** for anything a client controls. A two-megabyte header is
  # a `Failed`, not a 500. Shape is checked before hashing and before any I/O, so a hostile
  # value costs a length comparison rather than a database round trip.
  # ### One abstract method, and why that is load-bearing
  #
  # A credential is all this sees. That is deliberate — it is what keeps the contract
  # framework-independent — but some credentials cannot be judged from their own value alone: a
  # DPoP proof covers the request's method and URI, and a trusted-proxy or mTLS identity means
  # nothing without the peer address behind it.
  #
  # Those need more input, and the road to giving it to them stays open after v1.0 freezes this
  # class, because a **defaulted concrete overload** breaks no implementor:
  #
  # ```
  # def authenticate(credential : String?, request : RequestAttributes?) : Outcome
  #   authenticate(credential)
  # end
  # ```
  #
  # Measured rather than assumed (`blueprints/0020` decision 7): an authenticator written
  # against today's shape keeps compiling and routes through its own one-argument method, and
  # one-argument call sites still resolve. `AuthenticatorChain`, `AuthenticationHandler` and
  # `Application` are all outside the freeze list, so the plumbing can follow.
  #
  # What must not happen is a **second abstract method** here. That would freeze at v1.0 and
  # force every consumer's authenticator to implement it, and it would also remove the useful
  # part of the arrangement above: a request-aware authenticator has to implement the
  # one-argument form too, so it cannot leave *"what if no request attributes were supplied"*
  # implicit. For DPoP that answer is a rejection.
  #
  # `spec/unit/authenticator_chain_spec.cr` holds a fixture implementing exactly this one
  # method, so a second one does not fail an example — it stops the suite compiling.
  abstract class RequestAuthenticator
    # Resolves `credential` to an outcome. `nil` or empty means nothing was presented.
    abstract def authenticate(credential : String?) : Outcome
  end
end

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
  abstract class RequestAuthenticator
    # Resolves `credential` to an outcome. `nil` or empty means nothing was presented.
    abstract def authenticate(credential : String?) : Outcome
  end
end

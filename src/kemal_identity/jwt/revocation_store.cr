module KemalIdentity::JWT
  # Remembers which `jti` values must no longer be accepted.
  #
  # ### This is the part that makes a JWT stateful
  #
  # `docs/06-roadmap.md` asks for the trade-off to be documented rather than hidden, so:
  # **a stateless JWT cannot be revoked before its `exp`.** The signature is the entire
  # proof, the server keeps nothing, and there is therefore nothing to change when someone
  # clicks "sign out everywhere" or an employee leaves. There are exactly two honest
  # answers, and neither is free:
  #
  # 1. **A very short lifetime.** Keep `exp` minutes away and accept that a stolen token
  #    works until then. Nothing is stored, and the property you get is bounded exposure,
  #    not revocation. `Validator#max_lifetime` is what enforces this.
  # 2. **This store.** Record the `jti` of every token that must stop working and check it
  #    on every request. That is a read from shared storage on the hot path — which is
  #    precisely the thing a JWT was chosen to avoid. It buys real revocation and it costs
  #    the statelessness. Say so out loud rather than describing the result as stateless.
  #
  # If you are reaching for option 2, compare it honestly against `ApiTokens::Service`
  # first: that already reads from storage on every request, and in exchange gives
  # revocation, an expiry you can extend, and a `last_used_at` — for one lookup, the same
  # lookup this store costs. A JWT plus a revocation store is usually the worse half of
  # both designs.
  #
  # ### Storage
  #
  # An entry only has to outlive the token that carries it, which is what `expires_at` is
  # for: past that instant the signature no longer verifies, so the row proves nothing and
  # `#delete_expired` may drop it. The store is therefore bounded by the number of tokens
  # revoked within one `max_lifetime`, not by the number ever issued.
  abstract class RevocationStore
    # Whether this `jti` has been revoked. Called on every request that carries a token, so
    # it must be cheap; an implementation backed by a database wants an index on the id.
    abstract def revoked?(jti : String) : Bool

    # Refuses this `jti` from now on.
    #
    # `expires_at` is the token's own `exp`. Recording it is what lets the entry be swept:
    # after that instant the token fails on expiry anyway.
    #
    # Revoking twice is not an error — the caller may be replaying a "sign out everywhere"
    # that was already applied.
    abstract def revoke(jti : String, expires_at : Time) : Nil

    # Drops entries whose tokens have expired, returning how many. Called by `Sweeper`.
    abstract def delete_expired(before : Time) : Int32
  end
end

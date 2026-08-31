module KemalIdentity::Federation
  # What an external issuer asserted about somebody, once their assertion verified.
  #
  # ### Why this is not `OIDC::Identity`
  #
  # Nothing here is specific to OpenID Connect. An issuer, a subject, some claims, and an
  # address nobody has proved — a SAML assertion carries the same shape under different names,
  # and so would anything else that federates. `OIDC::Pending` is genuinely OIDC-specific,
  # because a nonce and a PKCE verifier are; this is not.
  #
  # It lives here so that a second protocol added after v1.0 can return it rather than defining
  # a near-duplicate, and so that `Federation::LinkRepository` — which every protocol has to
  # share — is not reaching into a protocol's namespace for its own currency.
  # `blueprints/0024-federation-namespace.md`.
  #
  # ### `(issuer, subject)` is the identity. The email is not.
  #
  # `docs/06-roadmap.md`: "The persistent key for an external identity is `(issuer, subject)` —
  # never email." Two reasons, and both bite in production:
  #
  # 1. **Emails change.** People marry, change surname, leave a company and come back. A row
  #    keyed on an address becomes a different person's row, or a stranded orphan.
  # 2. **Emails are claimed, not proved.** A provider that lets somebody set an unverified
  #    address and hands it to you in a token has just let them claim to be whoever owns that
  #    address at *your* service. Matching on it is account takeover with extra steps.
  #
  # `subject` is stable within an issuer and meaningless outside it, which is why both halves
  # are the key. Use `email` to *display*, and to pre-fill a form somebody then confirms —
  # never to look an account up.
  #
  # ### What is deliberately *not* settled here
  #
  # Whether `(issuer, subject)` is one namespace across protocols. OIDC's `(iss, sub)` and
  # SAML's `(EntityID, NameID)` are independent identifier spaces that can coincide as strings —
  # at least one mainstream identity provider serves both protocols from the same realm URL — and
  # this shard does not claim to know what a coincidence means. It might be the same person, in
  # which case sharing the key is correct; it might be two, in which case the key needs a
  # discriminator. Adding one blindly would be its own bug: it would split an identity that two
  # protocols legitimately agree on into two accounts.
  #
  # So the question is left open rather than answered by omission, and it is answered by whoever
  # implements the second protocol. See `blueprints/0024-federation-namespace.md`.
  struct Identity
    getter issuer : String
    getter subject : String
    getter email : String?

    # Whether the issuer claims to have verified the address, when it said anything at all.
    #
    # Three states, and the middle one is why this is nilable:
    #
    # | Value | Meaning |
    # |---|---|
    # | `nil` | the issuer asserted nothing — normal for a protocol with no such concept |
    # | `false` | the issuer said the address is *not* verified |
    # | `true` | the issuer says it verified it, and that is all it means |
    #
    # OIDC standardises `email_verified`; other federation protocols need not have an equivalent,
    # and collapsing "said no" into "said nothing" would make a policy of *"only accept issuers
    # that verify addresses"* unwritable. Use `#email_verified?` for the security decision — it
    # treats both of the first two as false, which is the only safe reading.
    getter email_verified : Bool?

    getter name : String?

    # Every claim the assertion carried, verified but uninterpreted.
    getter claims : Hash(String, ::JSON::Any)

    def initialize(
      @issuer : String,
      @subject : String,
      @claims : Hash(String, ::JSON::Any),
      @email : String? = nil,
      @email_verified : Bool? = nil,
      @name : String? = nil,
    )
      raise ArgumentError.new("issuer must not be empty") if @issuer.empty?
      raise ArgumentError.new("subject must not be empty") if @subject.empty?
    end

    # Whether this address may be treated as proved. **`nil` reads as false.**
    #
    # Written out rather than left to `getter?`, which over a `Bool?` would generate a method
    # returning `Bool?` — falsy in a conditional, but not a `Bool`, and one refactor away from
    # somebody reading `nil` as something other than "no". The security answer is a `Bool` and
    # only ever a `Bool`.
    #
    # "May be treated as proved" is still doing the issuer a favour: `true` means that party
    # says so, and how much that is worth is a property of the issuer you chose to trust.
    def email_verified? : Bool
      @email_verified == true
    end
  end
end

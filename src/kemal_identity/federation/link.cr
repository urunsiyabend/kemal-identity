module KemalIdentity::Federation
  # A stored association between an external identity and a local account.
  #
  # `Identity` is what a provider asserted during one flow. This is what the application decided
  # to remember about it: that `(issuer, subject)` is *this* account here.
  #
  # ### Keyed on `(issuer, subject)`, and nothing else
  #
  # No email column, and deliberately so — `docs/06-roadmap.md` requires it. An address is
  # neither stable nor proved: people change them, and a provider that hands you an unverified
  # one has let somebody claim to be whoever owns that address at your service. Keying on it is
  # account takeover with extra steps.
  #
  # Both halves are the key because `subject` is stable *within* an issuer and meaningless
  # outside it. Two providers can hand out the same `sub` and mean two different people.
  struct Link
    getter id : String
    getter account_id : String
    getter issuer : String
    getter subject : String
    getter created_at : Time

    # When this link last carried somebody into a session. For a management screen — "last used
    # to sign in on…" — and for noticing a link nobody has touched in two years.
    getter last_authenticated_at : Time?

    def initialize(
      @id : String,
      @account_id : String,
      @issuer : String,
      @subject : String,
      @created_at : Time,
      @last_authenticated_at : Time? = nil,
    )
      raise ArgumentError.new("id must not be empty") if @id.empty?
      raise ArgumentError.new("account_id must not be empty") if @account_id.empty?
      raise ArgumentError.new("issuer must not be empty") if @issuer.empty?
      raise ArgumentError.new("subject must not be empty") if @subject.empty?
    end
  end

  # Storage for `Link`s, shared by every federation protocol.
  #
  # Small and boring on purpose. The security in federated login is in the flow — `state`,
  # `nonce`, PKCE, the assertion's `iss` and `aud` — and by the time anything reaches here the
  # provider's assertion has already been verified. What this layer has to get right is the
  # uniqueness constraint, which is doing more work than it looks like.
  #
  # ### One repository for all protocols, and the reason is `#for_account`
  #
  # A second protocol added later must write here rather than to a table of its own. Not because
  # of the uniqueness constraint — that holds inside any one table, and two protocols naturally
  # produce different issuers, so splitting them would not violate it. The reason is the two
  # methods that ask a question *about an account* rather than about a link:
  #
  # * `#for_account` is "which providers is this account linked to". Answered from half the rows,
  #   it is a management screen that lies.
  # * `#unlink` is guarded by the application against removing somebody's last way in. That check
  #   reads `#for_account`, so against a split store it can strand an account with no login
  #   method left — which is the one outcome unlinking must never produce.
  #
  # Both break silently and both break in the direction of losing access, which is why this is a
  # `Federation` type and not an `OIDC` one (`blueprints/0024-federation-namespace.md`).
  abstract class LinkRepository
    # Records that `(issuer, subject)` is this account.
    #
    # Raises `InfrastructureError` when that pair is already linked — **including to the same
    # account**. Silently accepting a second link is how one provider account ends up attached
    # to two local ones, and then whichever row is found first decides who somebody logs in as.
    # The application checks with `#find` and decides; this refuses to guess.
    abstract def link(record : Link) : Nil

    # The account `(issuer, subject)` belongs to, or `nil`.
    #
    # The hot path of a federated login, and the only lookup that may decide who somebody is.
    abstract def find(issuer : String, subject : String) : Link?

    # Every external identity attached to an account, for a management screen. Oldest first.
    abstract def for_account(account_id : String) : Array(Link)

    # Removes one link. Returns `false` if it was not there.
    #
    # An application that offers this must make sure the account keeps *some* way in — removing
    # the only link from an account with no password is how somebody is locked out permanently.
    # That check belongs in the application, which is the only thing that knows what else the
    # account has.
    abstract def unlink(issuer : String, subject : String) : Bool

    # Records that this link was just used to authenticate. Returns `false` for an unknown pair.
    abstract def touch(issuer : String, subject : String, at : Time) : Bool
  end
end

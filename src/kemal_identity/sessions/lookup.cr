module KemalIdentity::Sessions
  # The result of resolving a session cookie: session state **and** account status, together.
  #
  # This type exists to make decision D7 unavoidable. Fetching the session and then fetching
  # the account is two round trips on every authenticated request, which roughly doubles the
  # fixed cost of every page view for no benefit. The reference SQL is one indexed lookup
  # with a join:
  #
  # ```sql
  # SELECT s.*, a.disabled_at AS account_disabled_at, a.auth_version AS account_auth_version
  #   FROM auth_sessions s
  #   JOIN auth_accounts a ON a.id = s.account_id
  #  WHERE s.token_digest = $1
  # ```
  #
  # An application whose `Repository` reads its own `users` table is responsible for
  # producing this same shape. The contract spec asserts the shape, never the SQL.
  #
  # Note what is *not* here: the account's login, its email, its roles, its linked
  # identities. `Principal` carries the minimum security context, and widening this struct
  # is how a hot path quietly becomes a join across half the schema.
  struct Lookup
    getter session : Record

    # The account's `disabled_at`. A disabled account's live sessions must fail on their very
    # next request, which is only possible if this arrives with the session.
    getter account_disabled_at : Time?

    # The account's *current* `auth_version`, to compare against `session.auth_version`.
    getter account_auth_version : Int32

    def initialize(
      @session : Record,
      @account_auth_version : Int32,
      @account_disabled_at : Time? = nil,
    )
    end

    def account_disabled? : Bool
      !@account_disabled_at.nil?
    end

    # Whether this session was minted before the account's `auth_version` was bumped.
    def stale_auth_version? : Bool
      @session.auth_version != @account_auth_version
    end
  end
end

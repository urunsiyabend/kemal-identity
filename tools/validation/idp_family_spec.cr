require "spec"
require "kemal_identity"
require "../lib/kemal_identity/spec/spec_helper"

# IDP-01, IDP-02, IDP-04 from the consumer side: an application supporting Google, Okta and a
# customer's private provider, linking those identities to local accounts, across tenants.

private alias TestKey = KemalIdentity::Testing::RSATestKey

private GOOGLE = "https://accounts.google.example"
private OKTA   = "https://acme.okta.example"

private def keys : KemalIdentity::JWT::KeySource
  KemalIdentity::JWT::StaticKeySource.new(
    KemalIdentity::JWT::Keyring.new([
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::RS256, TestKey.public_key, "rsa"),
    ])
  )
end

private class FakeEndpoint
  getter calls = 0
  property body : String = "{}"

  def to_proc : Proc(URI, String, HTTP::Headers, Time::Span, String)
    ->(_u : URI, _f : String, _h : HTTP::Headers, _t : Time::Span) do
      @calls += 1
      @body
    end
  end
end

private def client_for(issuer : String, client_id : String, endpoint : FakeEndpoint, clock,
                       seed : Int32 = 1)
  KemalIdentity::OIDC::Client.new(
    provider: KemalIdentity::OIDC::Provider.new(
      issuer: issuer,
      client_id: client_id,
      authorization_endpoint: "#{issuer}/authorize",
      token_endpoint: "#{issuer}/token",
      redirect_uri: "https://app.example.com/auth/callback/#{client_id}",
      keys: keys,
    ),
    clock: clock,
    random: KemalIdentity::Testing::DeterministicRandom.new(seed: seed),
    exchanger: endpoint.to_proc,
  )
end

private def id_token_for(issuer : String, audience : String, nonce : String, now : Time,
                         subject : String = "provider-sub-1", email : String? = "ada@example.com",
                         email_verified : Bool? = true)
  claims = {} of String => ::JSON::Any
  claims["sub"] = ::JSON::Any.new(subject)
  claims["iss"] = ::JSON::Any.new(issuer)
  claims["aud"] = ::JSON::Any.new(audience)
  claims["nonce"] = ::JSON::Any.new(nonce)
  claims["exp"] = ::JSON::Any.new((now + 1.hour).to_unix)
  claims["iat"] = ::JSON::Any.new(now.to_unix)
  claims["email"] = ::JSON::Any.new(email) if email
  claims["email_verified"] = ::JSON::Any.new(email_verified) unless email_verified.nil?
  KemalIdentity::Testing::JWTForge.encode_rsa(claims, kid: "rsa")
end

private def response_for(token : String)
  %({"access_token":"a","token_type":"Bearer","expires_in":3600,"id_token":"#{token}"})
end

describe "IDP-01: several providers with provider-specific options" do
  clock = -> { KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW) }

  it "registers several providers, each with its own issuer, client id and redirect" do
    c = clock.call
    google = client_for(GOOGLE, "google-client", FakeEndpoint.new, c)
    okta = client_for(OKTA, "okta-client", FakeEndpoint.new, c, seed: 2)

    google.provider.issuer.should eq(GOOGLE)
    okta.provider.issuer.should eq(OKTA)
    google.provider.redirect_uri.should_not eq(okta.provider.redirect_uri)
  end

  # Two flows in the air at once, completed in the reverse order they were started.
  it "keeps two concurrent flows apart and completes them out of order" do
    c = clock.call
    g_endpoint = FakeEndpoint.new
    o_endpoint = FakeEndpoint.new
    google = client_for(GOOGLE, "google-client", g_endpoint, c)
    okta = client_for(OKTA, "okta-client", o_endpoint, c, seed: 2)

    g_flow = google.authorize
    o_flow = okta.authorize

    g_flow.pending.state.should_not eq(o_flow.pending.state)
    g_flow.pending.nonce.should_not eq(o_flow.pending.nonce)

    # Okta's callback lands first.
    o_endpoint.body = response_for(
      id_token_for(OKTA, "okta-client", o_flow.pending.nonce, c.now, subject: "okta-sub")
    )
    okta.complete(o_flow.pending, state: o_flow.pending.state, code: "okta-code")
      .as(KemalIdentity::Federation::Identity).issuer.should eq(OKTA)

    # Then Google's.
    g_endpoint.body = response_for(
      id_token_for(GOOGLE, "google-client", g_flow.pending.nonce, c.now, subject: "google-sub")
    )
    google.complete(g_flow.pending, state: g_flow.pending.state, code: "google-code")
      .as(KemalIdentity::Federation::Identity).issuer.should eq(GOOGLE)
  end

  # Pass condition: "pending state binds provider, redirect URI, nonce and PKCE verifier" and
  # "callback cannot switch providers". This is the one that does not hold.
  it "accepts a pending flow completed by the wrong provider's client" do
    c = clock.call
    g_endpoint = FakeEndpoint.new
    o_endpoint = FakeEndpoint.new
    google = client_for(GOOGLE, "google-client", g_endpoint, c)
    okta = client_for(OKTA, "okta-client", o_endpoint, c, seed: 2)

    g_flow = google.authorize

    # Okta's client is handed Google's pending state, and a token minted by Okta.
    o_endpoint.body = response_for(
      id_token_for(OKTA, "okta-client", g_flow.pending.nonce, c.now)
    )
    identity = okta.complete(g_flow.pending, state: g_flow.pending.state, code: "stolen")

    # It succeeds. `Pending` carries state, nonce, the PKCE verifier and `return_to` -- and
    # **not the provider**, so every check passes from Okta's client's point of view: the state
    # matches the pending it was given, the nonce matches the token, and `iss`/`aud` are compared
    # against Okta's own provider, which minted it.
    identity.should be_a(KemalIdentity::Federation::Identity)
    identity.as(KemalIdentity::Federation::Identity).issuer.should eq(OKTA)

    # So "the callback cannot switch providers" is the application's job: whatever decodes the
    # pending state must hand it to the client that started the flow. Nothing in the type stops
    # a route from handing it to the wrong one.
    KemalIdentity::OIDC::Pending.new(
      state: "s", nonce: "n", code_verifier: KemalIdentity::Secret.new("v" * 43),
      created_at: c.now,
    ).responds_to?(:issuer).should be_false
  end

  # Pass condition: "custom authorisation parameters are allowlisted."
  it "cannot send a provider-specific authorisation parameter" do
    c = clock.call
    google = client_for(GOOGLE, "google-client", FakeEndpoint.new, c)

    # `prompt` is the one the shard accepts.
    ::URI.parse(google.authorize(prompt: "login").url).query_params["prompt"]
      .should eq("login")

    # Google's `hd`, Okta's `login_hint`, Azure's `domain_hint`: nowhere to put them. The
    # constructor is fixed and `authorize` takes only `return_to` and `prompt`.
    params = ::URI.parse(google.authorize.url).query_params
    params.has_key?("hd").should be_false
    params.has_key?("domain_hint").should be_false
    params.has_key?("login_hint").should be_false

    KemalIdentity::OIDC::Provider.new(
      issuer: GOOGLE, client_id: "g",
      authorization_endpoint: "#{GOOGLE}/authorize", token_endpoint: "#{GOOGLE}/token",
      redirect_uri: "https://app.example.com/cb", keys: keys,
    ).responds_to?(:extra_authorization_params).should be_false
  end

  # And whether the consumer can get around it: `authorize` hands back the `Pending`, and every
  # value the authorization URL needs is readable from it, so the URL can be rebuilt with the
  # provider's own parameters added.
  it "lets a consumer build the authorisation URL themselves, with any parameter" do
    c = clock.call
    google = client_for(GOOGLE, "google-client", FakeEndpoint.new, c)

    flow = google.authorize(return_to: "/dashboard")
    pending = flow.pending
    provider = google.provider

    params = ::URI::Params.build do |form|
      form.add("response_type", "code")
      form.add("client_id", provider.client_id)
      form.add("redirect_uri", provider.redirect_uri)
      form.add("scope", provider.scopes.join(' '))
      form.add("state", pending.state)
      form.add("nonce", pending.nonce)
      form.add("code_challenge", pending.code_challenge)
      form.add("code_challenge_method", "S256")
      form.add("hd", "example.com")             # Google's domain restriction
      form.add("login_hint", "ada@example.com") # and a hint the shard cannot send
    end

    uri = provider.authorization_endpoint.dup
    uri.query = params
    rebuilt = ::URI.parse(uri.to_s).query_params

    rebuilt["hd"].should eq("example.com")
    rebuilt["login_hint"].should eq("ada@example.com")
    rebuilt["state"].should eq(pending.state)
    rebuilt["code_challenge"].should eq(pending.code_challenge)

    # And the pending still completes through the shard, so nothing was duplicated except the
    # query-string assembly.
    pending.return_to.should eq("/dashboard")
  end

  # Pass condition: "provider discovery and JWKS caches are isolated."
  it "gives each provider its own key source" do
    c = clock.call
    google = client_for(GOOGLE, "google-client", FakeEndpoint.new, c)
    okta = client_for(OKTA, "okta-client", FakeEndpoint.new, c, seed: 2)

    google.provider.keys.should_not be(okta.provider.keys)
  end
end

describe "IDP-02: safe account linking and conflict resolution" do
  # Pass condition: "Email never auto-links identities." Structurally: there is nowhere to put
  # one. The stored link is (issuer, subject) and an account, and that is all.
  it "cannot store an email on a link even by accident" do
    link = KemalIdentity::Federation::Link.new(
      id: "l-1", account_id: "acct-1", issuer: GOOGLE, subject: "google-sub",
      created_at: KemalIdentity::SpecHelper::FIXED_NOW,
    )

    link.responds_to?(:email).should be_false
    KemalIdentity::Federation::Link.new(
      id: "l-2", account_id: "acct-1", issuer: GOOGLE, subject: "s",
      created_at: KemalIdentity::SpecHelper::FIXED_NOW,
    ).issuer.should eq(GOOGLE)
  end

  # Two providers asserting the same email for two different people. The application looks up by
  # (issuer, subject), so they are simply two identities -- no collision, no merge.
  it "keeps two providers' claims about one email apart" do
    repo = KemalIdentity::Testing::MemoryLinkRepository.new
    now = KemalIdentity::SpecHelper::FIXED_NOW

    repo.link(KemalIdentity::Federation::Link.new(
      id: "l-1", account_id: "ada", issuer: GOOGLE, subject: "sub-1", created_at: now))
    repo.link(KemalIdentity::Federation::Link.new(
      id: "l-2", account_id: "grace", issuer: OKTA, subject: "sub-1", created_at: now))

    repo.find(GOOGLE, "sub-1").not_nil!.account_id.should eq("ada")
    repo.find(OKTA, "sub-1").not_nil!.account_id.should eq("grace")
  end

  # Pass condition: "conflicts are typed outcomes." Linking a pair that is already linked --
  # including to the same account -- must not silently succeed, or one provider identity ends up
  # on two local accounts and whichever row is found first decides who signs in.
  it "refuses to relink a pair that is already linked, including to the same account" do
    repo = KemalIdentity::Testing::MemoryLinkRepository.new
    now = KemalIdentity::SpecHelper::FIXED_NOW
    repo.link(KemalIdentity::Federation::Link.new(
      id: "l-1", account_id: "ada", issuer: GOOGLE, subject: "sub-1", created_at: now))

    expect_raises(KemalIdentity::InfrastructureError) do
      repo.link(KemalIdentity::Federation::Link.new(
        id: "l-2", account_id: "grace", issuer: GOOGLE, subject: "sub-1", created_at: now))
    end

    expect_raises(KemalIdentity::InfrastructureError) do
      repo.link(KemalIdentity::Federation::Link.new(
        id: "l-3", account_id: "ada", issuer: GOOGLE, subject: "sub-1", created_at: now))
    end
  end

  # Pass condition: "unlink cannot strand an account without a recovery path." The repository
  # gives the application what it needs to check -- and leaves the check to it.
  it "reports what an account is linked to, so unlinking the last one can be refused" do
    repo = KemalIdentity::Testing::MemoryLinkRepository.new
    now = KemalIdentity::SpecHelper::FIXED_NOW
    repo.link(KemalIdentity::Federation::Link.new(
      id: "l-1", account_id: "ada", issuer: GOOGLE, subject: "sub-1", created_at: now))

    repo.for_account("ada").size.should eq(1)

    # Nothing in the repository refuses this: it is the application's guard, and the data to
    # write it is `for_account`. Recorded rather than asserted away.
    repo.unlink(GOOGLE, "sub-1").should be_true
    repo.for_account("ada").should be_empty
  end
end

describe "IDP-04: multi-tenant login discovery" do
  it "resolves the same address to different accounts in different tenants" do
    ada_acme = KemalIdentity::SpecHelper.account(
      id: "ada-acme", login: "ada@example.com", tenant_id: "acme")
    ada_globex = KemalIdentity::SpecHelper.account(
      id: "ada-globex", login: "ada@example.com", tenant_id: "globex")
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([ada_acme, ada_globex])

    accounts.find_by_login("ada@example.com", "acme").not_nil!.id.should eq("ada-acme")
    accounts.find_by_login("ada@example.com", "globex").not_nil!.id.should eq("ada-globex")
  end

  # Pass condition: "authorization always receives the target tenant." A check that names no
  # tenant is not a wildcard, and this is where a route that forgot the tenant fails closed.
  it "does not treat a missing tenant as any tenant" do
    ada_acme = KemalIdentity::SpecHelper.account(
      id: "ada-acme", login: "ada@example.com", tenant_id: "acme")
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([ada_acme])

    accounts.find_by_login("ada@example.com", nil).should be_nil
  end

  it "refuses a principal bound to one tenant asking about another" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
    rbac = KemalIdentity::Authz::RBAC.new(
      catalog: KemalIdentity::Authz::RoleCatalog.new(
        KemalIdentity::Authz::PermissionRegistry.new(
          [KemalIdentity::Authz::Permission.new("invoices.read")]),
        [KemalIdentity::Authz::Role.new("reader", ["invoices.read"])]
      ),
      store: KemalIdentity::Testing::MemoryAuthzRepository.new,
      clock: clock, random: KemalIdentity::Testing::DeterministicRandom.new,
    )
    rbac.add_member("ada", "globex")
    rbac.grant("ada", "reader", tenant_id: "globex")

    bound_to_acme = KemalIdentity::SpecHelper.principal(subject: "ada", tenant_id: "acme")

    denial = rbac.decide(bound_to_acme, "invoices.read", "globex")
    denial.permitted?.should be_false
    denial.as(KemalIdentity::Authz::Forbidden).reason
      .should eq(KemalIdentity::Authz::DenialReason::TenantMismatch)
  end

  # Pass condition: "tenant discovery does not enumerate accounts to an attacker." There is no
  # discovery API to abuse -- `find_by_login` answers one tenant at a time, and there is no
  # "which tenants has this address got accounts in" method.
  it "offers no way to ask which tenants an address exists in" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new(
      [] of KemalIdentity::Accounts::Account)

    accounts.responds_to?(:tenants_for_login).should be_false
    accounts.responds_to?(:find_all_by_login).should be_false
  end
end

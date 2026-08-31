require "../spec_helper"

# Federated login, named for what goes wrong. Every one of these is a documented OAuth attack
# and `docs/06-roadmap.md` names the defence: Authorization Code + PKCE only, `state` on every
# flow, `nonce` for OIDC, exact redirect matching, issuer and audience validation, and an
# open-redirect check.

private alias TestKey = KemalIdentity::Testing::RSATestKey

private CODEC_KEY = KemalIdentity::Secret.new("oidc-pending-signing-key-32bytes")
private ISSUER    = "https://issuer.example.com"
private CLIENT_ID = "kemal-identity-spec"

private def provider_keys : KemalIdentity::JWT::KeySource
  KemalIdentity::JWT::StaticKeySource.new(
    KemalIdentity::JWT::Keyring.new([
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::RS256, TestKey.public_key, "rsa"),
    ])
  )
end

# Stands in for the provider's token endpoint, so nothing here touches a network.
private class FakeTokenEndpoint
  getter calls = 0
  getter last_form : String = ""
  getter last_headers : HTTP::Headers = HTTP::Headers.new
  property body : String = "{}"
  property failure : Exception?

  def to_proc : Proc(URI, String, HTTP::Headers, Time::Span, String)
    ->(_uri : URI, form : String, headers : HTTP::Headers, _timeout : Time::Span) do
      @calls += 1
      @last_form = form
      @last_headers = headers
      failure = @failure
      raise failure if failure
      @body
    end
  end
end

private def oidc_provider(client_secret : KemalIdentity::Secret? = nil)
  KemalIdentity::OIDC::Provider.new(
    issuer: ISSUER,
    client_id: CLIENT_ID,
    authorization_endpoint: "#{ISSUER}/authorize",
    token_endpoint: "#{ISSUER}/token",
    redirect_uri: "https://app.example.com/auth/callback",
    keys: provider_keys,
    client_secret: client_secret,
  )
end

private def oidc_harness(client_secret : KemalIdentity::Secret? = nil)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::SpecHelper::FIXED_NOW)
  endpoint = FakeTokenEndpoint.new

  client = KemalIdentity::OIDC::Client.new(
    provider: oidc_provider(client_secret),
    clock: clock,
    random: KemalIdentity::Testing::DeterministicRandom.new,
    exchanger: endpoint.to_proc,
  )

  {client, endpoint, clock}
end

# An ID token as the provider would mint it.
private def id_token(
  nonce : String,
  now : Time,
  subject : String = "provider-subject-1",
  audience : ::JSON::Any? = nil,
  issuer : String? = ISSUER,
  email : String? = "ada@example.com",
  email_verified : Bool? = true,
  extra : Hash(String, ::JSON::Any) = {} of String => ::JSON::Any,
  kid : String? = "rsa",
) : String
  claims = {} of String => ::JSON::Any

  claims["sub"] = ::JSON::Any.new(subject)
  claims["iss"] = ::JSON::Any.new(issuer) if issuer
  claims["aud"] = audience || ::JSON::Any.new(CLIENT_ID)
  claims["nonce"] = ::JSON::Any.new(nonce)
  claims["exp"] = ::JSON::Any.new((now + 1.hour).to_unix)
  claims["iat"] = ::JSON::Any.new(now.to_unix)
  claims["email"] = ::JSON::Any.new(email) if email
  claims["email_verified"] = ::JSON::Any.new(email_verified) unless email_verified.nil?
  claims.merge!(extra)

  KemalIdentity::Testing::JWTForge.encode_rsa(claims, kid: kid)
end

private def token_response(id_token : String) : String
  %({"access_token":"provider-access-token","refresh_token":"provider-refresh-token",) +
    %("token_type":"Bearer","expires_in":3600,"id_token":"#{id_token}"})
end

# The happy path, as the application would drive it.
private def complete_with(client, endpoint, clock, **options)
  request = client.authorize
  endpoint.body = token_response(id_token(request.pending.nonce, clock.now, **options))

  client.complete(request.pending, state: request.pending.state, code: "provider-code")
end

describe "starting a flow" do
  it "sends the browser to the provider with everything the flow needs" do
    client, _, _ = oidc_harness
    request = client.authorize

    uri = URI.parse(request.url)
    params = uri.query_params

    uri.host.should eq("issuer.example.com")
    params["response_type"].should eq("code")
    params["client_id"].should eq(CLIENT_ID)
    params["redirect_uri"].should eq("https://app.example.com/auth/callback")
    params["scope"].should contain("openid")
    params["state"].should eq(request.pending.state)
    params["nonce"].should eq(request.pending.nonce)
  end

  # A `plain` challenge *is* the verifier, so it protects against nothing an interceptor of the
  # authorization request could not already do.
  it "uses S256 and never sends the verifier itself" do
    client, _, _ = oidc_harness
    request = client.authorize
    params = URI.parse(request.url).query_params

    params["code_challenge_method"].should eq("S256")
    params["code_challenge"].should eq(request.pending.code_challenge)
    params["code_challenge"].should_not eq(request.pending.code_verifier.reveal)
    request.url.should_not contain(request.pending.code_verifier.reveal)
  end

  it "gives every flow a distinct state, nonce and verifier" do
    client, _, _ = oidc_harness
    flows = Array.new(5) { client.authorize.pending }

    flows.map(&.state).uniq!.size.should eq(5)
    flows.map(&.nonce).uniq!.size.should eq(5)
    flows.map(&.code_verifier.reveal).uniq!.size.should eq(5)
  end

  it "redacts the pending state, which holds the PKCE secret" do
    client, _, _ = oidc_harness
    request = client.authorize

    "#{request}".should_not contain(request.pending.code_verifier.reveal)
    request.pending.inspect.should contain("[REDACTED]")
  end
end

# `return_to` is checked on the way *in*, before it has been round-tripped through the provider
# and back through the browser.
describe "the open redirect" do
  it "keeps a same-site path" do
    client, _, _ = oidc_harness

    client.authorize(return_to: "/dashboard").pending.return_to.should eq("/dashboard")
    client.authorize(return_to: "/a/b?c=d").pending.return_to.should eq("/a/b?c=d")
  end

  it "drops anything that could send a browser off-site" do
    client, _, _ = oidc_harness

    [
      "https://evil.example.com",
      "http://evil.example.com",
      # A browser reads a leading `//` as protocol-relative: an absolute URL wearing a path's
      # clothes, and the classic open redirect.
      "//evil.example.com",
      "/\\evil.example.com",
      "/path\\to",
      "javascript:alert(1)",
      "dashboard",
      "",
      "/" + "a" * 4000,
    ].each do |candidate|
      client.authorize(return_to: candidate).pending.return_to.should be_nil
    end
  end

  # If the value ever reaches a `Location` header unescaped, a newline is a second header.
  it "drops a value carrying a control character" do
    client, _, _ = oidc_harness

    ["/a\nSet-Cookie: x=1", "/a\rb", "/a\u0000b", "/a\tb"].each do |candidate|
      client.authorize(return_to: candidate).pending.return_to.should be_nil
    end
  end
end

describe "completing a flow" do
  it "returns the identity the provider asserted" do
    client, endpoint, clock = oidc_harness

    identity = complete_with(client, endpoint, clock)

    identity.should be_a(KemalIdentity::Federation::Identity)

    asserted = identity.as(KemalIdentity::Federation::Identity)
    asserted.issuer.should eq(ISSUER)
    asserted.subject.should eq("provider-subject-1")
    asserted.email.should eq("ada@example.com")
    asserted.email_verified?.should be_true
  end

  # `blueprints/0024`. Three states, because "the issuer said no" and "the issuer said nothing"
  # are different assertions — and a protocol with no such concept says nothing. Collapsing them
  # makes a policy of *"only accept issuers that verify addresses"* unwritable.
  describe "what the issuer said about the address" do
    it "keeps an absent claim apart from a claim of false" do
      client, endpoint, clock = oidc_harness
      complete_with(client, endpoint, clock, email_verified: nil)
        .as(KemalIdentity::Federation::Identity)
        .email_verified.should be_nil

      client, endpoint, clock = oidc_harness
      complete_with(client, endpoint, clock, email_verified: false)
        .as(KemalIdentity::Federation::Identity)
        .email_verified.should be_false
    end

    # The security answer is one Bool, and both of the first two states are "no". Written out
    # rather than left to `getter?`, which over a `Bool?` returns `Bool?`.
    it "reads both as unverified for the security decision" do
      KemalIdentity::Federation::Identity
        .new(issuer: "https://i", subject: "s", claims: {} of String => ::JSON::Any)
        .email_verified?.should be_false

      KemalIdentity::Federation::Identity
        .new(
          issuer: "https://i", subject: "s", claims: {} of String => ::JSON::Any,
          email_verified: false
        ).email_verified?.should be_false

      KemalIdentity::Federation::Identity
        .new(
          issuer: "https://i", subject: "s", claims: {} of String => ::JSON::Any,
          email_verified: true
        ).email_verified?.should be_true
    end

    # A boolean claim that is not a boolean — some issuers send the string "true". Nothing said,
    # which reads as unverified rather than as trusted.
    it "treats a non-boolean claim as nothing said" do
      identity = KemalIdentity::Federation::Identity.new(
        issuer: "https://i", subject: "s", claims: {} of String => ::JSON::Any,
        email_verified: ::JSON::Any.new("true").as_bool?
      )

      identity.email_verified.should be_nil
      identity.email_verified?.should be_false
    end
  end

  it "sends the PKCE verifier and the redirect URI at the exchange" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now))

    client.complete(request.pending, state: request.pending.state, code: "provider-code")

    endpoint.last_form.should contain("grant_type=authorization_code")
    endpoint.last_form.should contain("code=provider-code")
    endpoint.last_form.should contain(URI.encode_www_form(request.pending.code_verifier.reveal))
    endpoint.last_form.should contain(URI.encode_www_form("https://app.example.com/auth/callback"))
  end

  it "authenticates a confidential client in the Authorization header, not the body" do
    secret = KemalIdentity::Secret.new("client-secret")
    client, endpoint, clock = oidc_harness(client_secret: secret)

    complete_with(client, endpoint, clock)

    endpoint.last_headers["Authorization"].should start_with("Basic ")
    endpoint.last_form.should_not contain("client-secret")
  end

  # `docs/06-roadmap.md`: provider tokens are not stored unless the application actually calls
  # the provider's API. Storing one it never uses turns a breach here into a breach of every
  # user's account *there*.
  it "keeps nothing but the identity, discarding the provider's access and refresh tokens" do
    client, endpoint, clock = oidc_harness

    identity = complete_with(client, endpoint, clock).as(KemalIdentity::Federation::Identity)

    identity.claims.has_key?("access_token").should be_false
    identity.claims.has_key?("refresh_token").should be_false
    identity.to_s.should_not contain("provider-refresh-token")
  end
end

# Login CSRF. An attacker hands a victim a callback URL carrying the *attacker's* code, and the
# victim's browser silently links the attacker's provider account to the victim's session.
describe "a callback that did not come from a flow we started" do
  it "is refused when the state does not match" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now))

    result = client.complete(request.pending, state: "attacker-state", code: "attacker-code")

    result.should be_a(KemalIdentity::Failed)
  end

  # Before any I/O: exchanging the code would be doing the attacker's work for them.
  it "does not exchange the code when the state does not match" do
    client, endpoint, _ = oidc_harness
    request = client.authorize

    client.complete(request.pending, state: "attacker-state", code: "attacker-code")

    endpoint.calls.should eq(0)
  end

  it "is refused when the callback carries no state or no code" do
    client, endpoint, _ = oidc_harness
    request = client.authorize

    client.complete(request.pending, state: nil, code: "c").should be_a(KemalIdentity::Failed)
    client.complete(request.pending, state: "", code: "c").should be_a(KemalIdentity::Failed)
    client.complete(request.pending, state: request.pending.state, code: nil)
      .should be_a(KemalIdentity::Failed)
    client.complete(request.pending, state: request.pending.state, code: "")
      .should be_a(KemalIdentity::Failed)

    endpoint.calls.should eq(0)
  end

  # A login that has been open in a tab since yesterday is not a login in progress.
  it "is refused once the flow has expired" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now))

    clock.advance(16.minutes)

    result = client.complete(request.pending, state: request.pending.state, code: "c")

    result.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::Expired)
    endpoint.calls.should eq(0)
  end

  # A provider that says no is final, whatever else the callback carries. A callback holding
  # both an error *and* a code is not a thing an honest provider sends, and exchanging the code
  # anyway would be taking the attacker's half of a hand-crafted URL at face value.
  it "reports a provider that declined, without exchanging anything" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now))

    client.complete(request.pending, state: request.pending.state, code: nil, error: "access_denied")
      .should be_a(KemalIdentity::Failed)

    client.complete(
      request.pending, state: request.pending.state, code: "a-real-code", error: "access_denied"
    ).should be_a(KemalIdentity::Failed)

    endpoint.calls.should eq(0)
  end
end

# The ID token is the assertion. Everything the JWT validator refuses, this refuses — and two
# more things that only matter in a federated flow.
describe "an ID token that should not be believed" do
  it "is refused when the nonce does not match the flow" do
    client, endpoint, clock = oidc_harness
    request = client.authorize

    # A perfectly valid token, minted for somebody else's authorization request.
    endpoint.body = token_response(id_token("some-other-flows-nonce", clock.now))

    result = client.complete(request.pending, state: request.pending.state, code: "c")

    result.as(KemalIdentity::Failed).reason.should eq(KemalIdentity::FailureReason::InvalidClaim)
  end

  it "is refused when it carries no nonce at all" do
    client, endpoint, clock = oidc_harness
    request = client.authorize

    claims = {} of String => ::JSON::Any
    claims["sub"] = ::JSON::Any.new("s")
    claims["iss"] = ::JSON::Any.new(ISSUER)
    claims["aud"] = ::JSON::Any.new(CLIENT_ID)
    claims["exp"] = ::JSON::Any.new((clock.now + 1.hour).to_unix)
    endpoint.body = token_response(
      KemalIdentity::Testing::JWTForge.encode_rsa(claims, kid: "rsa")
    )

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  # A token minted for a *different application at the same provider*. Believing it is a
  # complete cross-application account takeover.
  it "is refused when it was issued to another client" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(
      id_token(request.pending.nonce, clock.now, audience: ::JSON::Any.new("some-other-app"))
    )

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  # `azp` names the party a multi-audience token was issued to.
  it "is refused when azp names another client" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(
      id_token(
        request.pending.nonce, clock.now,
        extra: {"azp" => ::JSON::Any.new("some-other-app")}
      )
    )

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  it "is refused when the issuer is not the one configured" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(
      id_token(request.pending.nonce, clock.now, issuer: "https://evil.example.com")
    )

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  it "is refused when it is signed by a key the provider does not publish" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now, kid: "attacker"))

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  it "is refused when it has expired" do
    client, endpoint, clock = oidc_harness
    request = client.authorize
    endpoint.body = token_response(id_token(request.pending.nonce, clock.now - 2.hours))

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end

  # One mutation of `#extract_id_token` survives and is genuinely equivalent: returning `""`
  # instead of `nil` for a missing `id_token` produces the same `MalformedCredential`, because
  # the validator refuses an empty credential on the next line. It differs only in a log message.
  it "is refused when the token endpoint answers with anything else" do
    client, endpoint, _ = oidc_harness
    request = client.authorize

    [
      "", "null", "[]", "not json", "{}",
      %({"error":"invalid_grant","error_description":"code already used"}),
      %({"access_token":"a"}),
      %({"id_token":""}),
      %({"id_token":123}),
      %({"id_token":"not.a.jwt"}),
    ].each do |body|
      endpoint.body = body

      client.complete(request.pending, state: request.pending.state, code: "c")
        .should be_a(KemalIdentity::Failed)
    end
  end

  # The callback is a public endpoint reachable by anybody with a URL.
  it "never raises when the provider cannot be reached" do
    client, endpoint, _ = oidc_harness
    request = client.authorize
    endpoint.failure = IO::Error.new("connection refused")

    client.complete(request.pending, state: request.pending.state, code: "c")
      .should be_a(KemalIdentity::Failed)
  end
end

describe "configuring a provider" do
  # A provider compares the redirect URI character for character. Anything ambiguous here is
  # either rejected later or, worse, matched more loosely than you meant.
  it "refuses a redirect URI that is not exact and absolute" do
    {
      "/callback"                       => /absolute/,
      "app.example.com/cb"              => /absolute/,
      "https://app.example.com/cb#frag" => /fragment/,
      "https://app.*.com/cb"            => /exact/,
    }.each do |redirect, message|
      expect_raises(KemalIdentity::ConfigurationError, message) do
        KemalIdentity::OIDC::Provider.new(
          issuer: ISSUER, client_id: CLIENT_ID,
          authorization_endpoint: "#{ISSUER}/authorize", token_endpoint: "#{ISSUER}/token",
          redirect_uri: redirect, keys: provider_keys
        )
      end
    end
  end

  # A code delivered over plain http is a code anybody on the path can take.
  it "refuses a plain-http redirect URI, except on loopback" do
    expect_raises(KemalIdentity::ConfigurationError, /https/) do
      KemalIdentity::OIDC::Provider.new(
        issuer: ISSUER, client_id: CLIENT_ID,
        authorization_endpoint: "#{ISSUER}/authorize", token_endpoint: "#{ISSUER}/token",
        redirect_uri: "http://app.example.com/cb", keys: provider_keys
      )
    end

    KemalIdentity::OIDC::Provider.new(
      issuer: ISSUER, client_id: CLIENT_ID,
      authorization_endpoint: "#{ISSUER}/authorize", token_endpoint: "#{ISSUER}/token",
      redirect_uri: "http://localhost:3000/cb", keys: provider_keys
    ).redirect_uri.should eq("http://localhost:3000/cb")
  end

  it "refuses plain-http endpoints" do
    ["authorization_endpoint", "token_endpoint"].each do |which|
      expect_raises(KemalIdentity::ConfigurationError, /https/) do
        KemalIdentity::OIDC::Provider.new(
          issuer: ISSUER, client_id: CLIENT_ID,
          authorization_endpoint: which == "authorization_endpoint" ? "http://a.example.com/a" : "#{ISSUER}/a",
          token_endpoint: which == "token_endpoint" ? "http://a.example.com/t" : "#{ISSUER}/t",
          redirect_uri: "https://app.example.com/cb", keys: provider_keys
        )
      end
    end
  end

  # Without `openid` the provider returns no ID token, and there is nothing to verify.
  it "refuses a scope list without openid" do
    expect_raises(KemalIdentity::ConfigurationError, /openid/) do
      KemalIdentity::OIDC::Provider.new(
        issuer: ISSUER, client_id: CLIENT_ID,
        authorization_endpoint: "#{ISSUER}/authorize", token_endpoint: "#{ISSUER}/token",
        redirect_uri: "https://app.example.com/cb", keys: provider_keys,
        scopes: ["email", "profile"]
      )
    end
  end

  it "redacts the client secret" do
    provider = oidc_provider(client_secret: KemalIdentity::Secret.new("client-secret"))

    provider.inspect.should contain("[REDACTED]")
    provider.inspect.should_not contain("client-secret")
    provider.to_s.should_not contain("client-secret")
  end
end

# The flow's state has to survive a round trip through the provider, and it holds the PKCE
# verifier. Signed, so nobody can swap in their own `state` or `nonce` — which is the attack.
describe "carrying the pending flow in a cookie" do
  it "round trips a flow" do
    client, _, _ = oidc_harness
    codec = KemalIdentity::OIDC::PendingCodec.new(CODEC_KEY)
    pending = client.authorize(return_to: "/dashboard").pending

    restored = codec.open?(codec.seal(pending)).or_fail

    restored.state.should eq(pending.state)
    restored.nonce.should eq(pending.nonce)
    restored.code_verifier.reveal.should eq(pending.code_verifier.reveal)
    restored.created_at.to_unix.should eq(pending.created_at.to_unix)
    restored.return_to.should eq("/dashboard")
  end

  # Swapping in an attacker's `state` is the whole point of signing this.
  it "refuses a payload that was edited" do
    client, _, _ = oidc_harness
    codec = KemalIdentity::OIDC::PendingCodec.new(CODEC_KEY)
    sealed = codec.seal(client.authorize.pending)

    payload, _, signature = sealed.partition('.')
    tampered = KemalIdentity::Testing::JWTForge.segment(
      %({"s":"attacker","n":"attacker","v":"attacker","c":0})
    )

    codec.open?("#{tampered}.#{signature}").should be_nil
    codec.open?("#{payload}.#{signature}x").should be_nil
  end

  it "refuses a payload signed with another key" do
    client, _, _ = oidc_harness
    other = KemalIdentity::OIDC::PendingCodec.new(
      KemalIdentity::Secret.new("a-completely-different-key-32byte")
    )
    sealed = other.seal(client.authorize.pending)

    KemalIdentity::OIDC::PendingCodec.new(CODEC_KEY).open?(sealed).should be_nil
  end

  it "never raises for anything a browser could send" do
    codec = KemalIdentity::OIDC::PendingCodec.new(CODEC_KEY)

    [nil, "", ".", "a.b", "....", "a" * 10_000, "not-a-cookie",
     "#{KemalIdentity::Testing::JWTForge.segment("{}")}.AAAA"].each do |candidate|
      codec.open?(candidate).should be_nil
    end
  end

  # A signature proves who wrote a value, not that the value was ever any good.
  it "re-validates return_to on the way back in" do
    codec = KemalIdentity::OIDC::PendingCodec.new(CODEC_KEY)
    payload = KemalIdentity::Testing::JWTForge.segment(
      %({"s":"a","n":"b","v":"c","c":1,"r":"//evil.example.com"})
    )
    signature = codec.seal(
      KemalIdentity::OIDC::Pending.new(
        state: "a", nonce: "b", code_verifier: KemalIdentity::Secret.new("c"),
        created_at: Time.unix(1)
      )
    ).partition('.').last

    restored = codec.open?("#{payload}.#{signature}")

    restored.try(&.return_to).should be_nil
  end

  it "refuses a signing key too short to be worth signing with" do
    expect_raises(KemalIdentity::ConfigurationError, /32 bytes/) do
      KemalIdentity::OIDC::PendingCodec.new(KemalIdentity::Secret.new("short"))
    end
  end
end

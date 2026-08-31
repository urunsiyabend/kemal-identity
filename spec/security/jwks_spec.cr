require "../spec_helper"

# A JWKS is where a verifier gets the keys it trusts, which makes it the most valuable thing an
# attacker on the path could rewrite. These examples are named for what goes wrong.

private alias Forge = KemalIdentity::Testing::JWTForge
private alias TestKey = KemalIdentity::Testing::RSATestKey

# One RSA entry describing the suite's fixed key.
private def jwks_body(kid : String = "rsa", extra : Array(String) = [] of String) : String
  entry = <<-JSON
    {"kty":"RSA","use":"sig","alg":"RS256","kid":"#{kid}",
     "n":"#{TestKey::MODULUS_BASE64URL}","e":"#{TestKey::EXPONENT_BASE64URL}"}
    JSON

  %({"keys":[#{([entry] + extra).join(",")}]})
end

# Counts calls, so a spec can assert that a fetch did *not* happen.
private class RecordingFetcher
  getter calls = 0
  property body : String
  property failure : Exception?

  def initialize(@body : String)
  end

  def to_proc : Proc(URI, Time::Span, String)
    ->(_uri : URI, _timeout : Time::Span) do
      @calls += 1
      failure = @failure
      raise failure if failure
      @body
    end
  end
end

private def jwks_harness(body : String = jwks_body, ttl : Time::Span = 10.minutes)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
  fetcher = RecordingFetcher.new(body)

  jwks = KemalIdentity::JWT::JWKS.new(
    uri: "https://issuer.example.com/jwks",
    clock: clock,
    ttl: ttl,
    fetcher: fetcher.to_proc,
  )

  {jwks, fetcher, clock}
end

describe "parsing a JWKS" do
  it "builds a keyring from an RSA entry" do
    ring = KemalIdentity::JWT::JWKS.parse(jwks_body, ["RS256"])

    ring.size.should eq(1)
    ring.find("rsa").should_not be_nil
  end

  # A provider publishing one EC key beside three RSA ones is normal. Refusing the whole
  # document over a key that was never going to be selected would take the application down.
  it "skips entries it cannot use rather than refusing the document" do
    ec = %({"kty":"EC","crv":"P-256","kid":"ec","x":"aa","y":"bb"})
    octet = %({"kty":"oct","kid":"oct","k":"aaaa"})

    ring = KemalIdentity::JWT::JWKS.parse(jwks_body(extra: [ec, octet]), ["RS256"])

    ring.size.should eq(1)
    ring.find("ec").should be_nil
  end

  it "skips an encryption key, which is not a signing key" do
    enc = jwks_body("enc").sub(%("use":"sig"), %("use":"enc"))

    expect_raises(KemalIdentity::InfrastructureError, /no usable/) do
      KemalIdentity::JWT::JWKS.parse(enc, ["RS256"])
    end
  end

  it "skips an entry whose alg the allow-list forbids" do
    expect_raises(KemalIdentity::InfrastructureError, /no usable/) do
      KemalIdentity::JWT::JWKS.parse(jwks_body, ["RS512"])
    end
  end

  # The weakest key in a rotating set would otherwise set the security of the whole thing.
  it "skips a key too short to be worth verifying with" do
    short = %({"kty":"RSA","alg":"RS256","kid":"weak","n":"#{"a" * 100}","e":"AQAB"})

    ring = KemalIdentity::JWT::JWKS.parse(jwks_body(extra: [short]), ["RS256"])

    ring.size.should eq(1)
    ring.find("weak").should be_nil
  end

  # Indistinguishable from a document meant for another service, so it is fatal rather than an
  # empty ring that silently verifies nothing.
  it "refuses a document with nothing usable in it" do
    expect_raises(KemalIdentity::InfrastructureError, /no usable/) do
      KemalIdentity::JWT::JWKS.parse(%({"keys":[]}), ["RS256"])
    end
  end

  it "refuses a document that is not a key set" do
    ["", "null", "{}", "[]", %({"keys":{}}), "not json", %({"keys":[1,2]})].each do |body|
      expect_raises(KemalIdentity::InfrastructureError) do
        KemalIdentity::JWT::JWKS.parse(body, ["RS256"])
      end
    end
  end
end

describe "caching a JWKS" do
  it "fetches once and serves the cached ring" do
    jwks, fetcher, _ = jwks_harness

    5.times { jwks.keyring }

    fetcher.calls.should eq(1)
  end

  # A cache with no expiry is a key set that cannot rotate, and the provider will rotate whether
  # or not you noticed.
  it "refetches once the TTL has passed" do
    jwks, fetcher, clock = jwks_harness(ttl: 10.minutes)
    jwks.keyring

    clock.advance(9.minutes)
    jwks.keyring
    fetcher.calls.should eq(1)

    clock.advance(2.minutes)
    jwks.keyring
    fetcher.calls.should eq(2)
  end

  # An unknown `kid` is what a rotation looks like from here.
  it "refetches when a token names a kid the ring does not hold" do
    jwks, fetcher, _ = jwks_harness
    jwks.keyring

    fetcher.body = jwks_body("rotated")
    jwks.refresh_for("rotated").find("rotated").should_not be_nil

    fetcher.calls.should eq(2)
  end

  # Otherwise a stream of tokens carrying invented `kid`s is a way to make this process hammer
  # somebody else's identity provider.
  it "rate limits refetches provoked by an unknown kid" do
    jwks, fetcher, clock = jwks_harness
    jwks.keyring

    20.times { jwks.refresh_for("invented") }
    fetcher.calls.should eq(2)

    clock.advance(2.minutes)
    jwks.refresh_for("invented")
    fetcher.calls.should eq(3)
  end

  it "does not refetch for a kid the ring already holds" do
    jwks, fetcher, _ = jwks_harness
    jwks.keyring

    jwks.refresh_for("rsa")

    fetcher.calls.should eq(1)
  end

  # A provider outage must not sign everybody out: a key that verified a minute ago has not
  # become dangerous because a fetch failed.
  it "keeps serving the last good ring when a refetch fails" do
    jwks, fetcher, clock = jwks_harness(ttl: 1.minute)
    jwks.keyring

    fetcher.failure = IO::Error.new("connection refused")
    clock.advance(2.minutes)

    jwks.keyring.find("rsa").should_not be_nil
  end

  # With nothing cached there is nothing to fall back to, and pretending otherwise would mean
  # an empty ring that verifies nothing while looking healthy.
  it "raises when the very first fetch fails" do
    jwks, fetcher, _ = jwks_harness
    fetcher.failure = IO::Error.new("connection refused")

    expect_raises(KemalIdentity::InfrastructureError, /could not fetch/) { jwks.keyring }
  end
end

describe "configuring a JWKS" do
  # Anybody who can rewrite the key set can mint tokens that verify. That is the whole game.
  it "refuses a plain-http endpoint" do
    expect_raises(KemalIdentity::ConfigurationError, /https/) do
      KemalIdentity::JWT::JWKS.new(
        uri: "http://issuer.example.com/jwks",
        clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
      )
    end
  end

  it "refuses a non-positive ttl or timeout" do
    clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

    expect_raises(KemalIdentity::ConfigurationError, /ttl/) do
      KemalIdentity::JWT::JWKS.new(uri: "https://a.example.com/jwks", clock: clock, ttl: 0.seconds)
    end

    expect_raises(KemalIdentity::ConfigurationError, /timeout/) do
      KemalIdentity::JWT::JWKS.new(
        uri: "https://a.example.com/jwks", clock: clock, timeout: 0.seconds
      )
    end
  end
end

# The point of all of the above: a validator pointed at a JWKS verifies real tokens, and picks
# up a rotation without being restarted.
describe "a validator backed by a JWKS" do
  it "verifies a token signed by a key it fetched" do
    jwks, _, clock = jwks_harness

    validator = KemalIdentity::JWT::Validator.new(
      keyring: jwks,
      issuer: Forge::ISSUER,
      audience: Forge::AUDIENCE,
      algorithms: ["RS256"],
      clock: clock,
    )

    KemalIdentity::Testing.should_authenticate(
      validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "rsa"))
    ).subject.should eq("a1")
  end

  it "picks up a rotated key without a restart" do
    jwks, fetcher, clock = jwks_harness

    validator = KemalIdentity::JWT::Validator.new(
      keyring: jwks,
      issuer: Forge::ISSUER,
      audience: Forge::AUDIENCE,
      algorithms: ["RS256"],
      clock: clock,
    )

    validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "rsa"))
      .should be_a(KemalIdentity::Authenticated)

    # The provider starts signing under a new name.
    fetcher.body = jwks_body("2026-09")

    validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "2026-09"))
      .should be_a(KemalIdentity::Authenticated)
  end

  # A retired key must stay retired, and the refetch must not become a way to keep asking.
  it "rejects a token naming a kid no fetch produces" do
    jwks, fetcher, clock = jwks_harness

    validator = KemalIdentity::JWT::Validator.new(
      keyring: jwks,
      issuer: Forge::ISSUER,
      audience: Forge::AUDIENCE,
      algorithms: ["RS256"],
      clock: clock,
    )

    validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "rsa"))
      .should be_a(KemalIdentity::Authenticated)

    10.times do
      validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "retired"))
        .should be_a(KemalIdentity::Failed)
    end

    # One refetch for the first miss, not ten.
    fetcher.calls.should eq(2)
  end
end

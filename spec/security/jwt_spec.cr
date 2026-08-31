require "../spec_helper"

# Every example here is named for an attack, not a method. JWT's failure modes are unusually
# well catalogued — `alg: none`, algorithm confusion, a retired key that still verifies, a
# token replayed at the wrong service — and `docs/06-roadmap.md` asks for a strict validator,
# so each of those catalogued attacks gets an example that would pass if the defence were
# removed.

private alias Forge = KemalIdentity::Testing::JWTForge

# Stands in for an asymmetric algorithm this shard does not ship. It verifies anything, which
# is the whole point: with HMAC only, "the key decides which algorithm applies" has no visible
# consequence, because an HMAC key recomputes its own digest and a mismatched one fails on the
# signature anyway. The confusion attack needs a key that *would* have said yes.
private class AlwaysVerifies < KemalIdentity::JWT::HMAC
  def initialize(name : String)
    super(name, ::OpenSSL::Algorithm::SHA256, 32)
  end

  def verify(signing_input : String, signature : Bytes, key : KemalIdentity::Secret) : Bool
    true
  end
end

private def keyring(*keys : KemalIdentity::JWT::Key) : KemalIdentity::JWT::Keyring
  KemalIdentity::JWT::Keyring.new(keys.to_a)
end

private def hs256_key(id : String? = nil, secret : KemalIdentity::Secret = Forge::SECRET)
  KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, secret, id)
end

private def jwt_harness(
  keyring : KemalIdentity::JWT::Keyring = KemalIdentity::JWT::Keyring.new([hs256_key]),
  algorithms : Array(String) = ["HS256"],
  leeway : Time::Span = KemalIdentity::JWT::Validator::DEFAULT_LEEWAY,
  max_lifetime : Time::Span? = KemalIdentity::JWT::Validator::DEFAULT_MAX_LIFETIME,
  purpose : String? = "access",
  revocations : KemalIdentity::JWT::RevocationStore? = nil,
  accounts : KemalIdentity::Accounts::Repository? = nil,
)
  clock = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)

  validator = KemalIdentity::JWT::Validator.new(
    keyring: keyring,
    issuer: Forge::ISSUER,
    audience: Forge::AUDIENCE,
    algorithms: algorithms,
    clock: clock,
    leeway: leeway,
    max_lifetime: max_lifetime,
    purpose: purpose,
    revocations: revocations,
    accounts: accounts,
  )

  {validator, clock}
end

# Separate from `jwt_harness` because these two are not otherwise varied.
private def jwt_harness_with(issuer : String = Forge::ISSUER, audience : String = Forge::AUDIENCE)
  KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new([hs256_key]),
    issuer: issuer,
    audience: audience,
    algorithms: ["HS256"],
    clock: KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW),
  )
end

describe "a well-formed JWT" do
  it "authenticates the subject it names" do
    validator, _ = jwt_harness
    outcome = validator.authenticate(Forge.encode(Forge.claims))

    KemalIdentity::Testing.should_authenticate(outcome).subject.should eq("a1")
  end

  it "names the token by its jti when the issuer states one" do
    validator, _ = jwt_harness
    outcome = validator.authenticate(Forge.encode(Forge.claims(jti: "jti-1")))

    credential = KemalIdentity::Testing.should_authenticate(outcome).credential.should_not be_nil
    credential.kind.should eq(KemalIdentity::CredentialKind::Jwt)
    credential.id.should eq("jti-1")
  end

  # `jti` is required only when a revocation store is configured, so an unnamed token is a
  # legitimate configuration rather than an error. What it costs is worth stating: a
  # credential with no id cannot be attributed in an audit line or revoked on its own.
  it "leaves the credential unnamed when the issuer omits jti" do
    validator, _ = jwt_harness
    outcome = validator.authenticate(Forge.encode(Forge.claims))

    credential = KemalIdentity::Testing.should_authenticate(outcome).credential.should_not be_nil
    credential.kind.should eq(KemalIdentity::CredentialKind::Jwt)
    credential.id.should be_nil
  end

  # Same level an opaque token gets, and for the same reason: possession of a secret, not
  # the presence of a person.
  it "authenticates at ApiToken assurance, which is never fresh" do
    validator, clock = jwt_harness
    principal = KemalIdentity::Testing.should_authenticate(
      validator.authenticate(Forge.encode(Forge.claims))
    )

    principal.assurance.should eq(KemalIdentity::AssuranceLevel::ApiToken)
    principal.fresh?(within: 5.minutes, now: clock.now).should be_false
    principal.session_id.should be_nil
  end

  it "dates the principal from iat, which is when the credential was actually verified" do
    validator, _ = jwt_harness
    issued_at = KemalIdentity::Testing::FIXED_NOW - 3.minutes

    principal = KemalIdentity::Testing.should_authenticate(
      validator.authenticate(Forge.encode(Forge.claims(issued_at: issued_at)))
    )

    principal.authenticated_at.to_unix.should eq(issued_at.to_unix)
  end

  it "accepts a token carrying no iat at all" do
    claims = Forge.claims
    claims.delete("iat")

    validator, _ = jwt_harness
    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Authenticated)
  end

  it "accepts every HMAC variant it ships" do
    {"HS256" => KemalIdentity::JWT::HS256,
     "HS384" => KemalIdentity::JWT::HS384,
     "HS512" => KemalIdentity::JWT::HS512}.each do |name, algorithm|
      validator, _ = jwt_harness(
        keyring: keyring(KemalIdentity::JWT::Key.new(algorithm, Forge::SECRET)),
        algorithms: [name],
      )

      validator.authenticate(Forge.encode(Forge.claims, algorithm: name))
        .should be_a(KemalIdentity::Authenticated)
    end
  end
end

# The single most reliably exploited JWT flaw: a token that declares itself unsigned, which a
# credulous library treats as valid. Three independent defences, so all three get an example.
describe "the alg: none attack" do
  it "rejects a token declaring itself unsigned with an empty signature" do
    validator, _ = jwt_harness
    validator.authenticate(Forge.unsigned(Forge.claims)).should be_a(KemalIdentity::Failed)
  end

  # Some validators only check that a signature segment is *present*.
  it "rejects an unsigned token carrying a junk signature" do
    validator, _ = jwt_harness
    validator.authenticate(Forge.unsigned(Forge.claims, signature: "AAAA"))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects every casing of none" do
    validator, _ = jwt_harness

    ["None", "NONE", "nOnE"].each do |spelling|
      validator.authenticate(Forge.unsigned(Forge.claims, signature: "AAAA", algorithm: spelling))
        .should be_a(KemalIdentity::Failed)
    end
  end

  it "refuses at boot to be configured with none in the allow-list, however spelled" do
    ["none", "None", "NONE"].each do |spelling|
      expect_raises(KemalIdentity::ConfigurationError, /none/i) do
        jwt_harness(algorithms: ["HS256", spelling])
      end
    end
  end
end

# The second classic: the token picks how it will be verified, so a public key gets used as an
# HMAC secret. Here the *key* names its algorithm and the header only ever gets compared to it.
describe "algorithm confusion" do
  it "rejects a token whose alg header disagrees with the key's algorithm" do
    validator, _ = jwt_harness(
      keyring: keyring(KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, Forge::SECRET)),
      algorithms: ["HS256", "HS512"],
    )

    # Correctly signed with HS512, and the ring holds an HS256 key. The signature is real;
    # the mismatch is what must reject it.
    validator.authenticate(Forge.encode(Forge.claims, algorithm: "HS512"))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a header that lies about which algorithm signed it" do
    validator, _ = jwt_harness(algorithms: ["HS256", "HS512"])

    validator.authenticate(Forge.encode_lying(Forge.claims, claimed: "HS256", signed_with: "HS512"))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects an algorithm the allow-list does not name, even with a valid signature" do
    validator, _ = jwt_harness(
      keyring: keyring(KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS512, Forge::SECRET)),
      algorithms: ["HS512"],
    )

    # Signed with the ring's own secret under HS256, which the allow-list does not permit.
    validator.authenticate(Forge.encode(Forge.claims, algorithm: "HS256"))
      .should be_a(KemalIdentity::Failed)
  end

  # The attack in its real shape: an RS256 public key used as an HMAC secret. A library that
  # reads `alg` from the token and then asks "what key do I have?" verifies it happily.
  it "never lets the token choose which key checks it" do
    ring = keyring(
      KemalIdentity::JWT::Key.new(AlwaysVerifies.new("RS256"), Forge::SECRET, "asymmetric"),
      hs256_key("symmetric"),
    )
    validator, _ = jwt_harness(keyring: ring, algorithms: ["RS256", "HS256"])

    # A control: that key really does verify, so the rejection below is the mismatch and not
    # a failed signature.
    validator.authenticate(Forge.encode(Forge.claims, algorithm: "RS256", kid: "asymmetric"))
      .should be_a(KemalIdentity::Authenticated)

    # Same key, and a header asking for it to be used as an HMAC key instead.
    validator.authenticate(
      Forge.encode(
        Forge.claims,
        algorithm: "HS256",
        kid: "asymmetric",
        secret: KemalIdentity::Secret.new("attacker" * 8),
      )
    ).should be_a(KemalIdentity::Failed)
  end

  # Two of this shard's three defences against a lying `alg` are unreachable one at a time, by
  # construction: the boot check forces the keyring's algorithms to be a subset of the
  # allow-list, so an `alg` the allow-list refuses can never match the selected key either.
  # They are kept as independent gates — one misconfigured keyring should not be enough — and
  # the reachable half of each is asserted at boot below.
  it "refuses at boot a keyring holding an algorithm the allow-list forbids" do
    expect_raises(KemalIdentity::ConfigurationError, /allow-list/) do
      jwt_harness(
        keyring: keyring(KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS512, Forge::SECRET)),
        algorithms: ["HS256"],
      )
    end
  end
end

# The asymmetric half, which is what an OpenID Connect provider actually signs ID tokens with.
# Unlike HMAC, the key this shard holds verifies and cannot forge — and that difference is
# exactly what the classic confusion attack tries to erase.
private def rsa_harness(algorithms : Array(String) = ["RS256"], kid : String? = "rsa")
  ring = keyring(
    KemalIdentity::JWT::Key.new(
      KemalIdentity::JWT::RS256, KemalIdentity::Testing::RSATestKey.public_key, kid
    )
  )

  jwt_harness(keyring: ring, algorithms: algorithms)
end

describe "RSA-signed tokens" do
  it "verifies a token signed by the issuer's private key" do
    validator, _ = rsa_harness

    KemalIdentity::Testing.should_authenticate(
      validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "rsa"))
    ).subject.should eq("a1")
  end

  it "verifies every RSA variant it ships" do
    {"RS256" => KemalIdentity::JWT::RS256,
     "RS384" => KemalIdentity::JWT::RS384,
     "RS512" => KemalIdentity::JWT::RS512}.each do |name, algorithm|
      ring = keyring(
        KemalIdentity::JWT::Key.new(
          algorithm, KemalIdentity::Testing::RSATestKey.public_key, "rsa"
        )
      )
      validator, _ = jwt_harness(keyring: ring, algorithms: [name])

      validator.authenticate(Forge.encode_rsa(Forge.claims, algorithm: name, kid: "rsa"))
        .should be_a(KemalIdentity::Authenticated)
    end
  end

  it "rejects claims swapped underneath a valid RSA signature" do
    validator, _ = rsa_harness
    genuine = Forge.encode_rsa(Forge.claims(subject: "a1"), kid: "rsa")

    validator.authenticate(Forge.swap_claims(genuine, Forge.claims(subject: "admin")))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a signature that was not made by the matching private key" do
    validator, _ = rsa_harness
    parts = Forge.encode_rsa(Forge.claims, kid: "rsa").split('.')
    signature = Forge.encode_bytes(
      KemalIdentity::Testing::RSATestKey.sign("#{parts[0]}.#{parts[1]}x")
    )

    validator.authenticate("#{parts[0]}.#{parts[1]}.#{signature}")
      .should be_a(KemalIdentity::Failed)
  end

  # **The real algorithm-confusion attack.** An attacker who has the issuer's *public* key —
  # which is public, it is served from a JWKS — re-signs the payload as HS256 using those very
  # bytes as an HMAC secret. A validator that reads `alg` from the token and then asks "what key
  # do I have?" verifies it and hands over the account.
  it "rejects the issuer's public key used as an HMAC secret" do
    validator, _ = rsa_harness(algorithms: ["RS256", "HS256"])

    # The public key as an attacker would have it: the raw modulus, long enough to satisfy
    # HS256's key-length floor.
    public_bytes = KemalIdentity::Testing::RSATestKey.modulus
    forged = Forge.encode(
      Forge.claims(subject: "admin"),
      secret: KemalIdentity::Secret.new(String.new(public_bytes)),
      algorithm: "HS256",
      kid: "rsa",
    )

    validator.authenticate(forged).should be_a(KemalIdentity::Failed)
  end

  it "rejects an RSA token whose kid names no key in the ring" do
    validator, _ = rsa_harness

    validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "retired"))
      .should be_a(KemalIdentity::Failed)
  end

  it "never raises for a malformed RSA signature" do
    validator, _ = rsa_harness
    parts = Forge.encode_rsa(Forge.claims, kid: "rsa").split('.')

    ["", "AAAA", parts[2][0..40], "A" * 400].each do |signature|
      validator.authenticate("#{parts[0]}.#{parts[1]}.#{signature}")
        .should be_a(KemalIdentity::Outcome)
    end
  end
end

describe "an RSA key" do
  # The weakest key in a rotating JWKS would otherwise set the security of the whole thing.
  it "refuses a modulus below 2048 bits" do
    expect_raises(KemalIdentity::ConfigurationError, /2048 bits/) do
      KemalIdentity::JWT::RSAPublicKey.new(Bytes.new(128, 0xff_u8), Bytes[0x01, 0x00, 0x01])
    end
  end

  it "refuses an empty exponent" do
    expect_raises(KemalIdentity::ConfigurationError, /exponent/) do
      KemalIdentity::JWT::RSAPublicKey.new(
        KemalIdentity::Testing::RSATestKey.modulus, Bytes.new(0)
      )
    end
  end

  # The DER this shard writes is parsed by OpenSSL rather than trusted, so a key built from the
  # wrong numbers is a key that verifies nothing — not one that verifies everything.
  it "verifies nothing when built from a modulus that is not the issuer's" do
    wrong = KemalIdentity::Testing::RSATestKey.modulus.dup
    wrong[100] ^= 0x01

    ring = keyring(
      KemalIdentity::JWT::Key.new(
        KemalIdentity::JWT::RS256,
        KemalIdentity::JWT::RSAPublicKey.new(wrong, KemalIdentity::Testing::RSATestKey.exponent),
        "rsa"
      )
    )
    validator, _ = jwt_harness(keyring: ring, algorithms: ["RS256"])

    validator.authenticate(Forge.encode_rsa(Forge.claims, kid: "rsa"))
      .should be_a(KemalIdentity::Failed)
  end

  # Pairing an RSA algorithm with a shared secret, or an HMAC algorithm with a public key, is
  # the confusion attack written into the configuration instead of into a token.
  it "refuses to pair an RSA algorithm with a shared secret" do
    expect_raises(KemalIdentity::ConfigurationError, /public key/) do
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::RS256, KemalIdentity::Secret.new("k" * 64))
    end
  end

  it "refuses to pair an HMAC algorithm with a public key" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::JWT::Key.new(
        KemalIdentity::JWT::HS256, KemalIdentity::Testing::RSATestKey.public_key
      )
    end
  end

  it "redacts itself" do
    key = KemalIdentity::JWT::Key.new(
      KemalIdentity::JWT::RS256, KemalIdentity::Testing::RSATestKey.public_key, "rsa"
    )

    key.inspect.should contain("[REDACTED]")
    key.inspect.should contain("RS256")
  end
end

describe "forging a signature" do
  it "rejects claims swapped underneath a valid signature" do
    validator, _ = jwt_harness
    genuine = Forge.encode(Forge.claims(subject: "a1"))
    tampered = Forge.swap_claims(genuine, Forge.claims(subject: "admin"))

    validator.authenticate(tampered).should be_a(KemalIdentity::Failed)
  end

  it "rejects a token signed with the wrong secret" do
    validator, _ = jwt_harness
    other = KemalIdentity::Secret.new("z" * 64)

    validator.authenticate(Forge.encode(Forge.claims, secret: other))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a truncated signature" do
    validator, _ = jwt_harness
    parts = Forge.encode(Forge.claims).split('.')

    validator.authenticate("#{parts[0]}.#{parts[1]}.#{parts[2][0..10]}")
      .should be_a(KemalIdentity::Failed)
  end
end

# Rotation is the reason `kid` exists: two keys verify at once while old tokens drain, then the
# retired one is dropped and must stay dropped.
describe "key rotation" do
  it "verifies tokens from either key while both are in the ring" do
    validator, _ = jwt_harness(keyring: keyring(hs256_key("old"), hs256_key("new")))

    validator.authenticate(Forge.encode(Forge.claims, kid: "old"))
      .should be_a(KemalIdentity::Authenticated)
    validator.authenticate(Forge.encode(Forge.claims, kid: "new"))
      .should be_a(KemalIdentity::Authenticated)
  end

  # The point of withdrawing a key. A validator that falls back to trying every key cannot
  # retire one at all.
  it "rejects a token naming a retired kid rather than trying the other keys" do
    validator, _ = jwt_harness(keyring: keyring(hs256_key("new")))

    validator.authenticate(Forge.encode(Forge.claims, kid: "old"))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects an unknown kid even when the signature verifies under a key in the ring" do
    validator, _ = jwt_harness(keyring: keyring(hs256_key("new")))

    # Same secret the ring holds, so only the name is wrong.
    validator.authenticate(Forge.encode(Forge.claims, secret: Forge::SECRET, kid: "attacker"))
      .should be_a(KemalIdentity::Failed)
  end

  it "resolves a token carrying no kid when the ring is unambiguous" do
    validator, _ = jwt_harness(keyring: keyring(hs256_key("only")))

    validator.authenticate(Forge.encode(Forge.claims)).should be_a(KemalIdentity::Authenticated)
  end

  # Guessing is how a retired key gets used again.
  it "refuses to guess when the ring holds more than one key and the token names none" do
    validator, _ = jwt_harness(keyring: keyring(hs256_key("old"), hs256_key("new")))

    validator.authenticate(Forge.encode(Forge.claims)).should be_a(KemalIdentity::Failed)
  end

  it "rejects a kid that is not a string" do
    validator, _ = jwt_harness
    header = {"kid" => ::JSON::Any.new([::JSON::Any.new("a")])}

    validator.authenticate(Forge.encode(Forge.claims, header: header))
      .should be_a(KemalIdentity::Failed)
  end
end

# A token minted for one service and presented to another. `iss` and `aud` are what make a
# signature mean "for you" rather than merely "from someone we trust".
describe "replaying a token across a trust boundary" do
  it "rejects a token from an issuer it does not trust" do
    validator, _ = jwt_harness

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(Forge.claims(issuer: "https://evil.example.com"))),
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  it "rejects a token carrying no issuer at all" do
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(Forge.claims(issuer: nil)))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a token addressed to another audience" do
    validator, _ = jwt_harness
    elsewhere = ::JSON::Any.new("https://other.example.com")

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(Forge.claims(audience: elsewhere))),
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  it "rejects a token carrying no audience at all" do
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(Forge.claims(audience: nil)))
      .should be_a(KemalIdentity::Failed)
  end

  # RFC 7519 allows an array when a token is meant for several recipients.
  it "accepts an audience array that names us" do
    validator, _ = jwt_harness
    many = ::JSON::Any.new(
      [::JSON::Any.new("https://other.example.com"), ::JSON::Any.new(Forge::AUDIENCE)]
    )

    validator.authenticate(Forge.encode(Forge.claims(audience: many)))
      .should be_a(KemalIdentity::Authenticated)
  end

  it "rejects an audience array that does not name us" do
    validator, _ = jwt_harness
    many = ::JSON::Any.new(
      [::JSON::Any.new("https://a.example.com"), ::JSON::Any.new("https://b.example.com")]
    )

    validator.authenticate(Forge.encode(Forge.claims(audience: many)))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects an empty audience array" do
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(Forge.claims(audience: ::JSON::Any.new([] of ::JSON::Any))))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects an audience that is neither a string nor an array of them" do
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(Forge.claims(audience: ::JSON::Any.new(42_i64))))
      .should be_a(KemalIdentity::Failed)
  end
end

# A JWT cannot be withdrawn, so its expiry is the only bound on a stolen one. Every part of
# that bound is enforced rather than trusted.
describe "expiry" do
  it "rejects a token with no exp, which would be a grant that never ends" do
    claims = Forge.claims(expires_in: nil)
    validator, _ = jwt_harness

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(claims)), KemalIdentity::FailureReason::InvalidClaim
    )
  end

  it "rejects a token past its exp" do
    validator, clock = jwt_harness
    token = Forge.encode(Forge.claims(expires_in: 15.minutes))

    clock.advance(16.minutes)

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(token), KemalIdentity::FailureReason::Expired
    )
  end

  it "tolerates skew up to the configured leeway and no further" do
    validator, clock = jwt_harness(leeway: 30.seconds)
    token = Forge.encode(Forge.claims(expires_in: 1.minute))

    clock.advance(1.minute + 20.seconds)
    validator.authenticate(token).should be_a(KemalIdentity::Authenticated)

    clock.advance(20.seconds)
    validator.authenticate(token).should be_a(KemalIdentity::Failed)
  end

  # Leeway extends the life of every expired token by its own width, so it is an expiry
  # bypass with a limit on it.
  it "refuses at boot a leeway wide enough to be an expiry bypass" do
    expect_raises(KemalIdentity::ConfigurationError, /leeway/) do
      jwt_harness(leeway: KemalIdentity::JWT::Validator::MAX_LEEWAY + 1.second)
    end
  end

  it "rejects a token that is not valid yet" do
    claims = Forge.claims
    claims["nbf"] = ::JSON::Any.new((KemalIdentity::Testing::FIXED_NOW + 10.minutes).to_unix)
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
  end

  it "accepts a token whose nbf has passed" do
    claims = Forge.claims
    claims["nbf"] = ::JSON::Any.new((KemalIdentity::Testing::FIXED_NOW - 10.minutes).to_unix)
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Authenticated)
  end

  it "rejects a token issued in the future" do
    validator, _ = jwt_harness
    future = KemalIdentity::Testing::FIXED_NOW + 10.minutes

    validator.authenticate(Forge.encode(Forge.claims(issued_at: future)))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a NumericDate that is not a number" do
    claims = Forge.claims
    claims["exp"] = ::JSON::Any.new("soon")
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
  end

  # RFC 7519 permits a non-integer NumericDate.
  it "accepts a fractional exp" do
    claims = Forge.claims
    seconds = (KemalIdentity::Testing::FIXED_NOW + 15.minutes).to_unix.to_f + 0.5
    claims["exp"] = ::JSON::Any.new(seconds)
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Authenticated)
  end

  it "rejects an absurd exp instead of overflowing on it" do
    validator, _ = jwt_harness

    [::JSON::Any.new(Int64::MAX), ::JSON::Any.new(1e30), ::JSON::Any.new(-1_i64)].each do |value|
      claims = Forge.claims
      claims["exp"] = value

      validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
    end
  end
end

# The "very short TTL" half of the revocation trade-off: a token is a standing grant, so its
# lifetime is the exposure window for a stolen one.
describe "the lifetime ceiling" do
  it "rejects a token claiming a lifetime longer than the ceiling" do
    validator, _ = jwt_harness(max_lifetime: 1.hour)

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(Forge.claims(expires_in: 30.days))),
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  it "accepts one inside the ceiling" do
    validator, _ = jwt_harness(max_lifetime: 1.hour)

    validator.authenticate(Forge.encode(Forge.claims(expires_in: 59.minutes)))
      .should be_a(KemalIdentity::Authenticated)
  end

  # Otherwise omitting `iat` would be the way around it.
  it "measures from now when the token states no iat" do
    claims = Forge.claims(expires_in: 30.days)
    claims.delete("iat")
    validator, _ = jwt_harness(max_lifetime: 1.hour)

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
  end

  it "can be turned off for an issuer that is trusted to bound its own tokens" do
    validator, _ = jwt_harness(max_lifetime: nil)

    validator.authenticate(Forge.encode(Forge.claims(expires_in: 30.days)))
      .should be_a(KemalIdentity::Authenticated)
  end
end

# Without this, any validly signed token from the issuer authenticates a request — including
# one minted to authorise a password reset.
describe "token-purpose separation" do
  it "rejects a token minted for another flow" do
    validator, _ = jwt_harness(purpose: "access")

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(Forge.claims(purpose: "password-reset"))),
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  it "rejects a token carrying no purpose at all" do
    validator, _ = jwt_harness(purpose: "access")

    validator.authenticate(Forge.encode(Forge.claims(purpose: nil)))
      .should be_a(KemalIdentity::Failed)
  end

  it "can be turned off explicitly, for an issuer that emits no such claim" do
    validator, _ = jwt_harness(purpose: nil)

    validator.authenticate(Forge.encode(Forge.claims(purpose: nil)))
      .should be_a(KemalIdentity::Authenticated)
  end

  it "refuses at boot a blank purpose, which would silently check nothing" do
    expect_raises(KemalIdentity::ConfigurationError, /purpose/) { jwt_harness(purpose: "   ") }
  end
end

describe "the subject" do
  it "rejects a token naming no subject" do
    claims = Forge.claims
    claims.delete("sub")
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
  end

  it "rejects an empty subject" do
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(Forge.claims(subject: "")))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a subject that is not a string" do
    claims = Forge.claims
    claims["sub"] = ::JSON::Any.new(1_i64)
    validator, _ = jwt_harness

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)
  end
end

# The stateful half of the trade-off, and the only way a JWT is revoked before its exp.
describe "revocation through a jti store" do
  it "refuses a token whose jti has been revoked" do
    store = KemalIdentity::Testing::MemoryRevocationStore.new
    validator, _ = jwt_harness(revocations: store)
    token = Forge.encode(Forge.claims(jti: "j1"))

    validator.authenticate(token).should be_a(KemalIdentity::Authenticated)

    store.revoke("j1", KemalIdentity::Testing::FIXED_NOW + 15.minutes)

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(token), KemalIdentity::FailureReason::Revoked
    )
  end

  it "leaves other tokens working" do
    store = KemalIdentity::Testing::MemoryRevocationStore.new
    validator, _ = jwt_harness(revocations: store)
    store.revoke("j1", KemalIdentity::Testing::FIXED_NOW + 15.minutes)

    validator.authenticate(Forge.encode(Forge.claims(jti: "j2")))
      .should be_a(KemalIdentity::Authenticated)
  end

  # A store you cannot key is a control that silently does nothing.
  it "rejects a token with no jti once a store is configured" do
    validator, _ = jwt_harness(revocations: KemalIdentity::Testing::MemoryRevocationStore.new)

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(Forge.encode(Forge.claims)),
      KemalIdentity::FailureReason::InvalidClaim
    )
  end

  # Which is exactly what "cannot be revoked" means, and why the store exists.
  it "accepts a revoked jti when no store is configured, because nothing is looking" do
    validator, _ = jwt_harness(revocations: nil)

    validator.authenticate(Forge.encode(Forge.claims(jti: "j1")))
      .should be_a(KemalIdentity::Authenticated)
  end
end

describe "an account that should no longer be admitted" do
  it "stops authenticating immediately when accounts are wired in" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    validator, clock = jwt_harness(accounts: accounts)
    token = Forge.encode(Forge.claims(subject: "a1"))

    validator.authenticate(token).should be_a(KemalIdentity::Authenticated)

    accounts.disable("a1", clock.now)

    KemalIdentity::Testing.should_fail_with(
      validator.authenticate(token), KemalIdentity::FailureReason::DisabledAccount
    )
  end

  it "rejects a subject that names no account" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    validator, _ = jwt_harness(accounts: accounts)

    validator.authenticate(Forge.encode(Forge.claims(subject: "ghost")))
      .should be_a(KemalIdentity::Failed)
  end

  # Deliberate, and the same choice `ApiTokens::Service` makes: a password change must not
  # silently break a machine client that has no way to notice.
  it "survives an auth_version bump, as an API token does" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    validator, _ = jwt_harness(accounts: accounts)
    accounts.bump_auth_version("a1")

    validator.authenticate(Forge.encode(Forge.claims)).should be_a(KemalIdentity::Authenticated)
  end

  # Left stateless by default, which is the property being bought and the one being paid for.
  it "keeps working without an account lookup when none is configured" do
    validator, _ = jwt_harness(accounts: nil)

    validator.authenticate(Forge.encode(Forge.claims(subject: "ghost")))
      .should be_a(KemalIdentity::Authenticated)
  end
end

describe "a malformed token" do
  it "is anonymous when nothing was presented" do
    validator, _ = jwt_harness

    validator.authenticate(nil).should be_a(KemalIdentity::Anonymous)
    validator.authenticate("").should be_a(KemalIdentity::Anonymous)
  end

  it "rejects anything that is not exactly three segments" do
    validator, _ = jwt_harness
    genuine = Forge.encode(Forge.claims)
    parts = genuine.split('.')

    [parts[0], "#{parts[0]}.#{parts[1]}", "#{genuine}.extra", "#{genuine}.d.e", ".."].each do |candidate|
      validator.authenticate(candidate).should be_a(KemalIdentity::Failed)
    end
  end

  # Five segments is a JWE, which this shard does not decrypt and must not mistake for a
  # signed token.
  it "rejects a five-segment JWE rather than treating it as signed" do
    validator, _ = jwt_harness

    validator.authenticate("a.b.c.d.e").should be_a(KemalIdentity::Failed)
  end

  # A decoder that accepts several encodings of one token is a decoder two systems can
  # disagree about.
  it "rejects standard base64 and padding, accepting only base64url" do
    validator, _ = jwt_harness
    parts = Forge.encode(Forge.claims).split('.')

    validator.authenticate("#{parts[0]}=.#{parts[1]}.#{parts[2]}").should be_a(KemalIdentity::Failed)
    validator.authenticate("#{parts[0]}.#{parts[1]}+.#{parts[2]}").should be_a(KemalIdentity::Failed)
    validator.authenticate("#{parts[0]}.#{parts[1]}/.#{parts[2]}").should be_a(KemalIdentity::Failed)
  end

  # The signature segment is not part of the signing input, so a lenient decoder would accept
  # the same bytes spelled in standard base64 and verify the token. Only base64url is a
  # signature here.
  it "rejects a signature re-spelled in standard base64" do
    validator, _ = jwt_harness
    header = {"alg" => ::JSON::Any.new("HS256"), "typ" => ::JSON::Any.new("JWT")}
    signing_input = "#{Forge.segment(header.to_json)}.#{Forge.segment(Forge.claims.to_json)}"
    signature = OpenSSL::HMAC.digest(
      ::OpenSSL::Algorithm::SHA256, Forge::SECRET.reveal, signing_input
    )

    # The same bytes, padded and in the standard alphabet.
    validator.authenticate("#{signing_input}.#{Base64.strict_encode(signature)}")
      .should be_a(KemalIdentity::Failed)

    # And the base64url spelling of those same bytes still works, so the rejection above is
    # the encoding and not the signature.
    validator.authenticate("#{signing_input}.#{Forge.encode_bytes(signature)}")
      .should be_a(KemalIdentity::Authenticated)
  end

  it "rejects a header that is not JSON, and one that is JSON but not an object" do
    validator, _ = jwt_harness
    parts = Forge.encode(Forge.claims).split('.')

    validator.authenticate("#{Forge.segment("not json")}.#{parts[1]}.#{parts[2]}")
      .should be_a(KemalIdentity::Failed)
    validator.authenticate("#{Forge.segment("[1,2]")}.#{parts[1]}.#{parts[2]}")
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a payload that is JSON but not an object" do
    validator, _ = jwt_harness
    header = {"alg" => ::JSON::Any.new("HS256")}
    signing_input = "#{Forge.segment(header.to_json)}.#{Forge.segment("[1,2]")}"
    signature = OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, Forge::SECRET.reveal, signing_input)

    validator.authenticate("#{signing_input}.#{Forge.encode_bytes(signature)}")
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a token with no alg header" do
    validator, _ = jwt_harness
    signing_input = "#{Forge.segment("{}")}.#{Forge.segment(Forge.claims.to_json)}"
    signature = OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, Forge::SECRET.reveal, signing_input)

    validator.authenticate("#{signing_input}.#{Forge.encode_bytes(signature)}")
      .should be_a(KemalIdentity::Failed)
  end

  # RFC 7515 §4.1.11: an extension the verifier does not understand must be rejected. This
  # shard understands none, so any `crit` at all is a refusal.
  it "rejects a crit header, since it understands no extensions" do
    validator, _ = jwt_harness
    header = {"crit" => ::JSON::Any.new([::JSON::Any.new("exp")])}

    validator.authenticate(Forge.encode(Forge.claims, header: header))
      .should be_a(KemalIdentity::Failed)
  end

  it "rejects a typ header claiming to be something other than a JWT" do
    validator, _ = jwt_harness
    header = {"typ" => ::JSON::Any.new("JWE")}

    validator.authenticate(Forge.encode(Forge.claims, header: header))
      .should be_a(KemalIdentity::Failed)
  end

  it "accepts the typ values a JWT may carry" do
    validator, _ = jwt_harness

    ["JWT", "jwt", "at+jwt", "application/at+JWT"].each do |typ|
      header = {"typ" => ::JSON::Any.new(typ)}

      validator.authenticate(Forge.encode(Forge.claims, header: header))
        .should be_a(KemalIdentity::Authenticated)
    end
  end

  it "accepts a token with no typ header, which is optional" do
    validator, _ = jwt_harness
    header = {"alg" => ::JSON::Any.new("HS256")}
    signing_input = "#{Forge.segment(header.to_json)}.#{Forge.segment(Forge.claims.to_json)}"
    signature = OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, Forge::SECRET.reveal, signing_input)

    validator.authenticate("#{signing_input}.#{Forge.encode_bytes(signature)}")
      .should be_a(KemalIdentity::Authenticated)
  end

  # Shape before parsing: a hostile header must cost an integer comparison, not a base64 decode
  # and a JSON parse. Asserted with a token that is otherwise perfectly valid, so that only the
  # size can be what rejects it.
  it "turns away an oversized token on its length alone" do
    validator, _ = jwt_harness

    claims = Forge.claims
    claims["padding"] = ::JSON::Any.new("x" * 10_000)

    validator.authenticate(Forge.encode(claims)).should be_a(KemalIdentity::Failed)

    validator.authenticate("#{"a" * 20_000}.#{"b" * 20_000}.#{"c" * 20_000}")
      .should be_a(KemalIdentity::Failed)
  end

  it "never raises for anything a client controls" do
    validator, _ = jwt_harness

    [
      "...", "a.b.c", "ki_garbage", "....", "a" * 2_000_000,
      "#{Forge.segment("{}")}.#{Forge.segment("{}")}.", " . . ",
      "#{Forge.segment(%q({"alg":"HS256"}))}.#{Forge.segment(%q({"exp":{}}))}.AAAA",
      "#{Forge.segment("{")}.AAAA.AAAA",
    ].each do |candidate|
      validator.authenticate(candidate).should be_a(KemalIdentity::Outcome)
    end
  end
end

describe "configuring a validator" do
  it "refuses an empty issuer, audience or allow-list" do
    expect_raises(KemalIdentity::ConfigurationError, /issuer/) { jwt_harness_with(issuer: "  ") }
    expect_raises(KemalIdentity::ConfigurationError, /audience/) { jwt_harness_with(audience: "") }
    expect_raises(KemalIdentity::ConfigurationError, /algorithms/) do
      jwt_harness(algorithms: [] of String)
    end
  end

  it "refuses a negative leeway" do
    expect_raises(KemalIdentity::ConfigurationError, /leeway/) { jwt_harness(leeway: -1.second) }
  end

  it "refuses a max_lifetime that is not positive" do
    expect_raises(KemalIdentity::ConfigurationError, /max_lifetime/) do
      jwt_harness(max_lifetime: Time::Span::ZERO)
    end
  end
end

describe "a keyring" do
  # RFC 7518 §3.2: an HMAC key must be at least as long as the hash output, or a single
  # captured token is enough to brute-force it offline.
  it "refuses an HMAC key shorter than the hash it is used with" do
    expect_raises(KemalIdentity::ConfigurationError, /at least 32 bytes/) do
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, KemalIdentity::Secret.new("short"))
    end

    expect_raises(KemalIdentity::ConfigurationError, /at least 64 bytes/) do
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS512, KemalIdentity::Secret.new("k" * 63))
    end
  end

  it "refuses an empty secret" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, KemalIdentity::Secret.new(""))
    end
  end

  it "refuses an empty ring" do
    expect_raises(KemalIdentity::ConfigurationError) do
      KemalIdentity::JWT::Keyring.new([] of KemalIdentity::JWT::Key)
    end
  end

  it "refuses two keys with the same id" do
    expect_raises(KemalIdentity::ConfigurationError, /same id/) do
      keyring(hs256_key("one"), hs256_key("one"))
    end
  end

  # Otherwise `kid` cannot select between them and rotation is guesswork.
  it "refuses a ring of several keys where one has no id" do
    expect_raises(KemalIdentity::ConfigurationError, /must have an id/) do
      keyring(hs256_key("one"), hs256_key)
    end
  end

  # A verification key for HMAC is also a signing key, so a config dump that printed it
  # would be handing out the ability to forge.
  it "redacts its keys, so a crash report is not a set of forging keys" do
    key = hs256_key("main")

    key.inspect.should contain("[REDACTED]")
    key.inspect.should_not contain(Forge::SECRET.reveal)
    key.to_s.should contain("main")

    ring = keyring(key)
    ring.inspect.should contain("[REDACTED]")
    ring.inspect.should_not contain(Forge::SECRET.reveal)
  end
end

require "spec"
require "kemal_identity"
require "kemal_identity/testing"
require "../src/tok04_gateway"

# Does the consumer's authenticator have to sit *between* the two built-ins, or is "after both"
# enough? Every position, every credential family, same table.
CLOCK2  = KemalIdentity::Testing::TestClock.new(KemalIdentity::Testing::FIXED_NOW)
SECRET2 = "gateway-shared-secret"

describe "TOK-04 — does the position among the built-ins matter" do
  it "produces the same answer for every credential family at every position" do
    accounts = KemalIdentity::Testing::MemoryAccountRepository.new([KemalIdentity::Testing.account])
    api = KemalIdentity::ApiTokens::Service.new(
      tokens: KemalIdentity::Testing::MemoryApiTokenRepository.new(accounts),
      clock: CLOCK2,
      random: KemalIdentity::Testing::DeterministicRandom.new(seed: 5),
    )
    jwt = KemalIdentity::JWT::Validator.new(
      keyring: KemalIdentity::JWT::Keyring.new(
        KemalIdentity::JWT::HS256, KemalIdentity::Testing::JWTForge::SECRET
      ),
      issuer: KemalIdentity::Testing::JWTForge::ISSUER,
      audience: KemalIdentity::Testing::JWTForge::AUDIENCE,
      algorithms: ["HS256"],
      clock: CLOCK2,
    )
    gw = GatewayAuthenticator.new(SECRET2, CLOCK2)

    issued = api.issue(account: KemalIdentity::Testing.account, name: "ci")
    credentials = {
      "shard token" => issued.token.reveal,
      "gateway"     => GatewayAuthenticator.mint(SECRET2, "ada"),
      "jwt"         => KemalIdentity::Testing::JWTForge.encode(KemalIdentity::Testing::JWTForge.claims),
      "garbage"     => "not-any-of-these",
      "nothing"     => "",
    }

    builtins = [api.as(KemalIdentity::RequestAuthenticator), jwt.as(KemalIdentity::RequestAuthenticator)]

    answers = [0, 1, 2].map do |position|
      list = builtins.dup
      list.insert(position, gw.as(KemalIdentity::RequestAuthenticator))
      chain = KemalIdentity::AuthenticatorChain.new(list)

      credentials.transform_values do |raw|
        outcome = chain.authenticate(raw)
        case outcome
        in KemalIdentity::Authenticated then "authenticated:#{outcome.principal.subject}"
        in KemalIdentity::Failed        then "failed:#{outcome.reason}"
        in KemalIdentity::Anonymous     then "anonymous"
        end
      end
    end

    puts ""
    answers.each_with_index { |a, i| puts "position #{i}: #{a}" }

    answers[1].should eq(answers[0])
    answers[2].should eq(answers[0])
  end
end

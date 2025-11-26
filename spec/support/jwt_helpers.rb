# frozen_string_literal: true

module JwtHelpers
  def generate_ec_keypair(curve = 'prime256v1')
    OpenSSL::PKey::EC.generate(curve)
  end

  def ec_jwk_from_keypair(keypair, kid = 'test-key-1')
    jwk = JWT::JWK.new(keypair)
    jwk_hash = jwk.export
    jwk_hash[:kid] = kid
    jwk_hash
  end

  def generate_jwks(*keypairs)
    keys = keypairs.map.with_index do |keypair, index|
      ec_jwk_from_keypair(keypair, "test-key-#{index + 1}")
    end
    { keys: keys }
  end

  def generate_client_assertion(client_id:, audience:, keypair:, algorithm: 'ES256', extra_claims: {})
    now = Time.now.to_i
    payload = {
      iss: client_id,
      sub: client_id,
      aud: audience,
      jti: SecureRandom.uuid,
      iat: now,
      exp: now + 300
    }.merge(extra_claims)

    JWT.encode(payload, keypair, algorithm, kid: 'test-key-1')
  end

  def curve_for_algorithm(algorithm)
    case algorithm
    when 'ES256' then 'prime256v1'
    when 'ES384' then 'secp384r1'
    when 'ES512' then 'secp521r1'
    else raise "Unsupported algorithm: #{algorithm}"
    end
  end
end

RSpec.configure do |config|
  config.include JwtHelpers
end

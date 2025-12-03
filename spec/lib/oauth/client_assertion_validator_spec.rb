# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::OpenidConnect::OAuth::ClientAssertionValidator do
  let(:keypair) { generate_ec_keypair }
  let(:jwks) { generate_jwks(keypair) }
  let(:application) do
    create(:application,
           token_endpoint_auth_method: 'private_key_jwt',
           jwks: jwks.to_json)
  end
  let(:token_endpoint_url) { 'https://example.com/oauth/token' }
  let(:valid_assertion) do
    generate_client_assertion(
      client_id: application.uid,
      audience: token_endpoint_url,
      keypair: keypair
    )
  end

  subject(:validator) do
    described_class.new(
      assertion: valid_assertion,
      application: application,
      token_endpoint_url: token_endpoint_url
    )
  end

  describe '#valid?' do
    context 'with valid assertion' do
      it 'returns true' do
        expect(validator.valid?).to be true
      end
    end

    context 'with invalid signature' do
      let(:wrong_keypair) { generate_ec_keypair }
      let(:invalid_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: wrong_keypair
        )
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: invalid_assertion,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with missing iss claim' do
      let(:assertion_without_iss) do
        now = Time.now.to_i
        payload = {
          sub: application.uid,
          aud: token_endpoint_url,
          jti: SecureRandom.uuid,
          iat: now,
          exp: now + 300
        }
        JWT.encode(payload, keypair, 'ES256', kid: 'test-key-1')
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: assertion_without_iss,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with wrong iss claim' do
      let(:wrong_iss_assertion) do
        generate_client_assertion(
          client_id: 'wrong_client_id',
          audience: token_endpoint_url,
          keypair: keypair
        )
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: wrong_iss_assertion,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with expired assertion' do
      let(:expired_assertion) do
        now = Time.now.to_i
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair,
          extra_claims: { exp: now - 600 } # 10 minutes ago
        )
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: expired_assertion,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with future iat claim' do
      let(:future_iat_assertion) do
        now = Time.now.to_i
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair,
          extra_claims: { iat: now + 600 } # 10 minutes in future
        )
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: future_iat_assertion,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with wrong audience' do
      let(:wrong_aud_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: 'https://wrong.example.com/oauth/token',
          keypair: keypair
        )
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: wrong_aud_assertion,
          application: application,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with multiple public keys' do
      let(:keypair1) { generate_ec_keypair }
      let(:keypair2) { generate_ec_keypair }
      let(:jwks_multi) { generate_jwks(keypair1, keypair2) }
      let(:application_multi_keys) do
        create(:application,
               token_endpoint_auth_method: 'private_key_jwt',
               jwks: jwks_multi.to_json)
      end
      let(:assertion_with_key2) do
        generate_client_assertion(
          client_id: application_multi_keys.uid,
          audience: token_endpoint_url,
          keypair: keypair2
        )
      end

      it 'returns true' do
        multi_key_validator = described_class.new(
          assertion: assertion_with_key2,
          application: application_multi_keys,
          token_endpoint_url: token_endpoint_url
        )
        expect(multi_key_validator.valid?).to be true
      end
    end

    context 'with no public keys' do
      before do
        allow(application).to receive(:public_keys).and_return([])
      end

      it 'returns false' do
        expect(validator.valid?).to be false
      end
    end

    context 'with invalid JWKS' do
      let(:application_invalid_jwks) do
        # Create with valid JWKS first, then corrupt it
        app = create(:application,
                     token_endpoint_auth_method: 'private_key_jwt',
                     jwks: jwks.to_json)
        # Use update_column to bypass validation and set invalid JWKS
        app.update_column(:jwks, 'invalid json')
        app
      end

      it 'returns false' do
        invalid_validator = described_class.new(
          assertion: valid_assertion,
          application: application_invalid_jwks,
          token_endpoint_url: token_endpoint_url
        )
        expect(invalid_validator.valid?).to be false
      end
    end

    context 'with different ECDSA algorithms' do
      %w[ES256 ES384 ES512].each do |algorithm|
        context "when using #{algorithm}" do
          let(:keypair) { generate_ec_keypair(curve_for_algorithm(algorithm)) }
          let(:assertion) do
            generate_client_assertion(
              client_id: application.uid,
              audience: token_endpoint_url,
              keypair: keypair,
              algorithm: algorithm
            )
          end

          before do
            allow(Doorkeeper::OpenidConnect.configuration)
              .to receive(:client_assertion_algorithms)
              .and_return(%w[RS256 ES256 ES384 ES512])
          end

          it 'returns true' do
            algo_validator = described_class.new(
              assertion: assertion,
              application: application,
              token_endpoint_url: token_endpoint_url
            )
            expect(algo_validator.valid?).to be true
          end
        end
      end
    end
  end
end

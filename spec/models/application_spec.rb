# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::OpenidConnect::Application do
  let(:application) { Doorkeeper::Application.new }

  describe '#public_keys' do
    context 'when jwks is blank' do
      it 'returns an empty array' do
        application.jwks = nil
        expect(application.public_keys).to eq([])
      end
    end

    context 'when jwks is valid JSON with keys' do
      it 'returns an array of JWT::JWK objects' do
        keypair = generate_ec_keypair
        jwks = generate_jwks(keypair)
        application.jwks = jwks.to_json

        keys = application.public_keys
        expect(keys).to be_an(Array)
        expect(keys.length).to eq(1)
        expect(keys.first.class.name).to match(/JWT::JWK/)
      end
    end

    context 'when jwks contains multiple keys' do
      it 'returns all keys' do
        keypair1 = generate_ec_keypair
        keypair2 = generate_ec_keypair
        jwks = generate_jwks(keypair1, keypair2)
        application.jwks = jwks.to_json

        keys = application.public_keys
        expect(keys.length).to eq(2)
      end
    end

    context 'when jwks is invalid JSON' do
      it 'raises InvalidJwks error' do
        application.jwks = 'invalid json'
        expect { application.public_keys }.to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidJwks, /Invalid JWKS JSON/)
      end
    end

    context 'when jwks JSON does not contain keys array' do
      it 'raises InvalidJwks error' do
        application.jwks = '{"foo": "bar"}'
        expect { application.public_keys }.to raise_error(Doorkeeper::OpenidConnect::Errors::InvalidJwks, /must contain a keys array/)
      end
    end
  end

  describe '#uses_private_key_jwt?' do
    it 'returns true when token_endpoint_auth_method is private_key_jwt' do
      application.token_endpoint_auth_method = 'private_key_jwt'
      expect(application.uses_private_key_jwt?).to be true
    end

    it 'returns false when token_endpoint_auth_method is client_secret_basic' do
      application.token_endpoint_auth_method = 'client_secret_basic'
      expect(application.uses_private_key_jwt?).to be false
    end

    it 'returns false when token_endpoint_auth_method is nil' do
      application.token_endpoint_auth_method = nil
      expect(application.uses_private_key_jwt?).to be false
    end
  end

  describe 'validations' do
    context 'when using private_key_jwt' do
      before do
        application.name = 'Test App'
        application.redirect_uri = 'https://example.com/callback'
        application.token_endpoint_auth_method = 'private_key_jwt'
      end

      it 'requires jwks to be present' do
        application.jwks = nil
        expect(application).not_to be_valid
        expect(application.errors[:jwks]).to include('must be present when using private_key_jwt')
      end

      it 'requires jwks to be valid JSON' do
        application.jwks = 'invalid json'
        expect(application).not_to be_valid
        expect(application.errors[:jwks]).to include('must be valid JSON')
      end

      it 'requires jwks to have a keys array' do
        application.jwks = '{"foo": "bar"}'
        expect(application).not_to be_valid
        expect(application.errors[:jwks]).to include('must have a keys array')
      end

      it 'is valid with proper jwks' do
        keypair = generate_ec_keypair
        jwks = generate_jwks(keypair)
        application.jwks = jwks.to_json

        expect(application).to be_valid
      end
    end

    context 'when not using private_key_jwt' do
      before do
        application.name = 'Test App'
        application.redirect_uri = 'https://example.com/callback'
        application.token_endpoint_auth_method = 'client_secret_basic'
      end

      it 'does not require jwks' do
        application.jwks = nil
        expect(application).to be_valid
      end

      it 'allows blank jwks' do
        application.jwks = ''
        expect(application).to be_valid
      end
    end
  end

  it 'extends the base doorkeeper Application' do
    expect(application).to respond_to(:public_keys)
    expect(application).to respond_to(:uses_private_key_jwt?)
  end
end

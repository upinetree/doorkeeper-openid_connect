# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::OpenidConnect::OAuth::ServerExtension do
  let(:keypair) { generate_ec_keypair }
  let(:jwks) { generate_jwks(keypair) }
  let(:application) do
    create(:application,
           token_endpoint_auth_method: 'private_key_jwt',
           jwks: jwks.to_json)
  end

  let(:token_endpoint_url) { 'https://example.com/oauth/token' }
  let(:client_assertion) do
    generate_client_assertion(
      client_id: application.uid,
      audience: token_endpoint_url,
      keypair: keypair
    )
  end

  let(:request) do
    double('Request',
           parameters: parameters,
           scheme: 'https',
           host_with_port: 'example.com',
           path: '/oauth/token',
           url: 'https://example.com/oauth/token',
           authorization: nil)
  end

  let(:context) { double('Context', request: request) }
  let(:server) { Doorkeeper::Server.new(context) }

  before do
    allow(Doorkeeper.config).to receive(:client_credentials_methods).and_return([:from_basic, :from_params])
  end

  describe '#client with private_key_jwt' do
    context 'when valid client_assertion is provided' do
      let(:parameters) do
        {
          'client_id' => application.uid,
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => client_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns authenticated client' do
        client = server.client
        expect(client).to be_present
        expect(client.uid).to eq(application.uid)
      end
    end

    context 'when client_assertion_type is missing' do
      let(:parameters) do
        {
          'client_id' => application.uid,
          'client_assertion' => client_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'falls back to standard authentication' do
        # In this case, standard authentication should return nil
        # because no client_secret is provided
        expect(server.client).to be_nil
      end
    end

    context 'when client_assertion is missing' do
      let(:parameters) do
        {
          'client_id' => application.uid,
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'grant_type' => 'authorization_code'
        }
      end

      it 'falls back to standard authentication' do
        # In this case, standard authentication should return nil
        # because no client_secret is provided
        expect(server.client).to be_nil
      end
    end

    context 'when client_id is missing' do
      let(:parameters) do
        {
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => client_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns nil' do
        expect(server.client).to be_nil
      end
    end

    context 'when application does not exist' do
      let(:parameters) do
        {
          'client_id' => 'non-existent-client',
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => client_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns nil' do
        expect(server.client).to be_nil
      end
    end

    context 'when application is not configured for private_key_jwt' do
      let(:application_secret_basic) do
        create(:application,
               token_endpoint_auth_method: 'client_secret_basic')
      end

      let(:parameters) do
        {
          'client_id' => application_secret_basic.uid,
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => client_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns nil' do
        expect(server.client).to be_nil
      end
    end

    context 'when client_assertion is invalid' do
      let(:wrong_keypair) { generate_ec_keypair }
      let(:invalid_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: wrong_keypair
        )
      end

      let(:parameters) do
        {
          'client_id' => application.uid,
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => invalid_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns nil' do
        expect(server.client).to be_nil
      end
    end

    context 'when audience does not match token endpoint' do
      let(:wrong_audience_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: 'https://wrong.example.com/oauth/token',
          keypair: keypair
        )
      end

      let(:parameters) do
        {
          'client_id' => application.uid,
          'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          'client_assertion' => wrong_audience_assertion,
          'grant_type' => 'authorization_code'
        }
      end

      it 'returns nil' do
        expect(server.client).to be_nil
      end
    end
  end

  describe '#client with standard authentication' do
    let(:standard_application) do
      create(:application, token_endpoint_auth_method: 'client_secret_basic')
    end

    let(:parameters) do
      {
        'client_id' => standard_application.uid,
        'client_secret' => standard_application.secret,
        'grant_type' => 'authorization_code'
      }
    end

    before do
      # Mock the OAuth::Client.authenticate to test that super is called correctly
      allow(Doorkeeper::OAuth::Client).to receive(:authenticate)
        .and_call_original
    end

    it 'uses standard authentication' do
      # Since we don't have the plaintext secret, we'll verify that
      # OAuth::Client.authenticate is called (which means super was invoked)
      server.client
      expect(Doorkeeper::OAuth::Client).to have_received(:authenticate)
    end
  end
end

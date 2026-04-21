# frozen_string_literal: true

require 'rails_helper'

describe 'Token endpoint with private_key_jwt authentication', type: :request do
  let(:keypair) { generate_ec_keypair }
  let(:jwks) { generate_jwks(keypair) }
  let(:application) do
    create(:application,
           token_endpoint_auth_method: 'private_key_jwt',
           jwks: jwks.to_json)
  end
  let(:resource_owner) { create(:user) }
  let(:token_endpoint_url) { 'http://www.example.com/oauth/token' }

  describe 'authorization_code grant with private_key_jwt' do
    let(:access_grant) do
      create(:access_grant,
             application: application,
             resource_owner_id: resource_owner.id,
             scopes: 'openid profile')
    end

    context 'with valid client_assertion' do
      let(:client_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair
        )
      end

      it 'returns access_token and id_token' do
        post '/oauth/token', params: {
          grant_type: 'authorization_code',
          code: access_grant.token,
          redirect_uri: application.redirect_uri,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: client_assertion
        }

        expect(response).to have_http_status(:ok)

        json = JSON.parse(response.body)
        expect(json).to have_key('access_token')
        expect(json).to have_key('id_token')
        expect(json['token_type']).to eq('Bearer')

        decoded = JWT.decode(json['id_token'], nil, false).first
        expect(decoded['sub']).to eq(resource_owner.id.to_s)
        expect(decoded['iss']).to eq('dummy')
      end
    end

    context 'with invalid client_assertion signature' do
      let(:wrong_keypair) { generate_ec_keypair }
      let(:invalid_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: wrong_keypair
        )
      end

      it 'returns 401 unauthorized' do
        post '/oauth/token', params: {
          grant_type: 'authorization_code',
          code: access_grant.token,
          redirect_uri: application.redirect_uri,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: invalid_assertion
        }

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with wrong audience in client_assertion' do
      let(:wrong_audience_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: 'https://wrong.example.com/oauth/token',
          keypair: keypair
        )
      end

      it 'returns 401 unauthorized' do
        post '/oauth/token', params: {
          grant_type: 'authorization_code',
          code: access_grant.token,
          redirect_uri: application.redirect_uri,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: wrong_audience_assertion
        }

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'without client_assertion (standard secret auth)' do
      let(:secret_application) do
        create(:application, token_endpoint_auth_method: 'client_secret_basic')
      end
      let(:secret_access_grant) do
        create(:access_grant,
               application: secret_application,
               resource_owner_id: resource_owner.id,
               scopes: 'openid profile')
      end

      it 'falls back to standard authentication' do
        post '/oauth/token', params: {
          grant_type: 'authorization_code',
          code: secret_access_grant.token,
          redirect_uri: secret_application.redirect_uri,
          client_id: secret_application.uid,
          client_secret: secret_application.secret
        }

        expect(response).to have_http_status(:ok)
        json = JSON.parse(response.body)
        expect(json).to have_key('access_token')
        expect(json).to have_key('id_token')
      end
    end
  end

  describe 'client_credentials grant with private_key_jwt' do
    context 'with valid client_assertion' do
      let(:client_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair
        )
      end

      it 'returns access_token' do
        post '/oauth/token', params: {
          grant_type: 'client_credentials',
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: client_assertion
        }

        expect(response).to have_http_status(:ok)
        json = JSON.parse(response.body)
        expect(json).to have_key('access_token')
        expect(json['token_type']).to eq('Bearer')
      end
    end

    context 'with expired client_assertion' do
      let(:expired_assertion) do
        now = Time.now.to_i
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair,
          extra_claims: { exp: now - 600 }
        )
      end

      it 'returns 401 unauthorized' do
        post '/oauth/token', params: {
          grant_type: 'client_credentials',
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: expired_assertion
        }

        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'refresh_token grant with private_key_jwt' do
    let(:access_token) do
      create(:access_token,
             application: application,
             resource_owner_id: resource_owner.id,
             use_refresh_token: true,
             scopes: 'openid')
    end

    context 'with valid client_assertion' do
      let(:client_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair
        )
      end

      it 'returns new access_token' do
        post '/oauth/token', params: {
          grant_type: 'refresh_token',
          refresh_token: access_token.refresh_token,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: client_assertion
        }

        expect(response).to have_http_status(:ok)
        json = JSON.parse(response.body)
        expect(json).to have_key('access_token')
        expect(json['token_type']).to eq('Bearer')
      end
    end

    context 'with invalid client_assertion signature' do
      let(:wrong_keypair) { generate_ec_keypair }
      let(:invalid_assertion) do
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: wrong_keypair
        )
      end

      it 'returns 401 unauthorized' do
        post '/oauth/token', params: {
          grant_type: 'refresh_token',
          refresh_token: access_token.refresh_token,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: invalid_assertion
        }

        expect(response).to have_http_status(:unauthorized)
      end
    end

    context 'with expired client_assertion' do
      let(:expired_assertion) do
        now = Time.now.to_i
        generate_client_assertion(
          client_id: application.uid,
          audience: token_endpoint_url,
          keypair: keypair,
          extra_claims: { exp: now - 600 }
        )
      end

      it 'returns 401 unauthorized' do
        post '/oauth/token', params: {
          grant_type: 'refresh_token',
          refresh_token: access_token.refresh_token,
          client_id: application.uid,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: expired_assertion
        }

        expect(response).to have_http_status(:unauthorized)
      end
    end
  end

  describe 'missing client_assertion_type' do
    let(:client_assertion) do
      generate_client_assertion(
        client_id: application.uid,
        audience: token_endpoint_url,
        keypair: keypair
      )
    end

    it 'falls back to standard authentication and fails' do
      post '/oauth/token', params: {
        grant_type: 'client_credentials',
        client_id: application.uid,
        client_assertion: client_assertion
      }

      expect(response).to have_http_status(:unauthorized)
    end
  end
end

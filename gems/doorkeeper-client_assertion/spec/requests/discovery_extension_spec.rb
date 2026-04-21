# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::ClientAssertion::DiscoveryExtension, type: :request do
  describe 'GET /.well-known/openid-configuration' do
    it 'includes private_key_jwt in token_endpoint_auth_methods_supported' do
      get '/.well-known/openid-configuration'
      data = JSON.parse(response.body)

      expect(data['token_endpoint_auth_methods_supported']).to include('private_key_jwt')
    end

    context 'when client_credentials is configured with only from_basic' do
      before { Doorkeeper.configure { client_credentials :from_basic } }

      it 'appends private_key_jwt to client_secret_basic' do
        get '/.well-known/openid-configuration'
        data = JSON.parse(response.body)

        expect(data['token_endpoint_auth_methods_supported']).to eq %w[client_secret_basic private_key_jwt]
      end
    end

    context 'when client_credentials is configured with only from_params' do
      before { Doorkeeper.configure { client_credentials :from_params } }

      it 'appends private_key_jwt to client_secret_post' do
        get '/.well-known/openid-configuration'
        data = JSON.parse(response.body)

        expect(data['token_endpoint_auth_methods_supported']).to eq %w[client_secret_post private_key_jwt]
      end
    end

    context 'when client_credentials is configured with both from_basic and from_params' do
      before { Doorkeeper.configure { client_credentials :from_basic, :from_params } }

      it 'appends private_key_jwt after both secret methods' do
        get '/.well-known/openid-configuration'
        data = JSON.parse(response.body)

        expect(data['token_endpoint_auth_methods_supported']).to eq %w[client_secret_basic client_secret_post private_key_jwt]
      end
    end
  end
end

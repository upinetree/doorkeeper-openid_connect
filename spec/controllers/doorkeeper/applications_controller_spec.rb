# frozen_string_literal: true

require 'rails_helper'

describe Doorkeeper::ApplicationsController, type: :controller do
  describe 'extension' do
    it 'has ApplicationsControllerExtension prepended' do
      expect(controller.class.ancestors).to include(Doorkeeper::ClientAssertion::ApplicationsControllerExtension)
    end
  end

  describe '#application_params' do
    let(:keypair) { generate_ec_keypair }
    let(:jwks) { generate_jwks(keypair) }

    before do
      allow(controller).to receive(:authenticate_admin!).and_return(true)

      params = ActionController::Parameters.new(
        doorkeeper_application: {
          name: 'Test App',
          redirect_uri: 'https://example.com/callback',
          token_endpoint_auth_method: 'private_key_jwt',
          jwks: jwks.to_json,
          scopes: 'openid',
          confidential: true
        }
      )
      allow(controller).to receive(:params).and_return(params)
    end

    it 'permits token_endpoint_auth_method parameter' do
      permitted = controller.send(:application_params)
      expect(permitted.permitted?).to be true
      expect(permitted[:token_endpoint_auth_method]).to eq('private_key_jwt')
    end

    it 'permits jwks parameter' do
      permitted = controller.send(:application_params)
      expect(permitted.permitted?).to be true
      expect(permitted[:jwks]).to eq(jwks.to_json)
    end

    it 'still permits existing parameters' do
      permitted = controller.send(:application_params)
      expect(permitted.permitted?).to be true
      expect(permitted[:name]).to eq('Test App')
      expect(permitted[:redirect_uri]).to eq('https://example.com/callback')
      expect(permitted[:scopes]).to eq('openid')
      expect(permitted[:confidential]).to eq(true)
    end
  end
end

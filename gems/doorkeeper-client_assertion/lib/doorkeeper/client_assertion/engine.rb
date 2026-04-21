# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    class Engine < ::Rails::Engine
      config.to_prepare do
        Doorkeeper::Server.prepend                     Doorkeeper::ClientAssertion::ServerExtension
        Doorkeeper::OAuth::RefreshTokenRequest.prepend Doorkeeper::ClientAssertion::OAuth::RefreshTokenRequestExtension
        Doorkeeper::Request::RefreshToken.prepend      Doorkeeper::ClientAssertion::RequestStrategy::RefreshTokenExtension
        Doorkeeper::ApplicationsController.prepend     Doorkeeper::ClientAssertion::ApplicationsControllerExtension

        if Gem.loaded_specs.key?('doorkeeper-openid_connect')
          Doorkeeper::OpenidConnect::DiscoveryController.prepend Doorkeeper::ClientAssertion::DiscoveryExtension
          if defined?(Doorkeeper::OpenidConnect::DynamicClientRegistrationController)
            Doorkeeper::OpenidConnect::DynamicClientRegistrationController.prepend Doorkeeper::ClientAssertion::DynamicClientRegistrationExtension
          end
        end
      end

      initializer 'doorkeeper_client_assertion.models' do
        ActiveSupport.on_load(:active_record) do
          Doorkeeper.config.application_model.prepend Doorkeeper::ClientAssertion::ApplicationExtension
        end
      end
    end
  end
end

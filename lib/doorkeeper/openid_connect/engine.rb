# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class Engine < ::Rails::Engine
      initializer 'doorkeeper.openid_connect.routes' do
        Doorkeeper::OpenidConnect::Rails::Routes.install!
      end

      config.to_prepare do
        Doorkeeper::AuthorizationsController.prepend Doorkeeper::OpenidConnect::AuthorizationsExtension
        Doorkeeper::ApplicationsController.prepend Doorkeeper::OpenidConnect::ApplicationsExtension
        Doorkeeper::Server.prepend Doorkeeper::OpenidConnect::OAuth::ServerExtension
        Doorkeeper::OAuth::RefreshTokenRequest.prepend Doorkeeper::OpenidConnect::OAuth::RefreshTokenRequestExtension
        Doorkeeper::Request::RefreshToken.prepend Doorkeeper::OpenidConnect::RequestStrategy::RefreshTokenExtension
      end
    end
  end
end

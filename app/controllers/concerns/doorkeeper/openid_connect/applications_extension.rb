# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module ApplicationsExtension
      private

      def application_params
        params.require(:doorkeeper_application)
          .permit(:name, :redirect_uri, :scopes, :confidential, :token_endpoint_auth_method, :jwks)
      end
    end
  end
end

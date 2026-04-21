# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module DynamicClientRegistrationExtension
      private

      def registration_response(doorkeeper_application)
        response = super(doorkeeper_application)
        response[:token_endpoint_auth_methods_supported] += ['private_key_jwt']
        response
      end
    end
  end
end

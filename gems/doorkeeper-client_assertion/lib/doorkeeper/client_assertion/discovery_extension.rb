# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module DiscoveryExtension
      private

      def token_endpoint_auth_methods_supported(doorkeeper)
        super(doorkeeper) + ['private_key_jwt']
      end
    end
  end
end

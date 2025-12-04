# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      module ServerExtension
        include Doorkeeper::OpenidConnect::Errors

        def client
          @client ||= authenticate_client_with_private_key_jwt || super
        end

        private

        def authenticate_client_with_private_key_jwt
          return nil unless uses_private_key_jwt?

          client_id = extract_client_id_from_assertion
          return nil if client_id.blank?

          application = Doorkeeper.config.application_model.by_uid(client_id)
          return nil unless application&.uses_private_key_jwt?

          validator = ClientAssertionValidator.new(
            assertion: parameters['client_assertion'],
            application: application,
            token_endpoint_url: token_endpoint_url
          )

          return nil unless validator.valid?

          Doorkeeper::OAuth::Client.new(application)
        end

        def uses_private_key_jwt?
          parameters['client_assertion_type'] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
            parameters['client_assertion'].present?
        end

        def extract_client_id_from_assertion
          # Decode JWT without verification to extract iss claim
          # Verification will happen in ClientAssertionValidator
          decoded = JWT.decode(parameters['client_assertion'], nil, false).first
          decoded['iss']
        rescue JWT::DecodeError
          nil
        end

        def token_endpoint_url
          # Use the request URL without query parameters for JWT audience validation
          # This matches the standard practice in RFC 7523
          request = context.request
          request.url.split('?').first
        end
      end
    end
  end
end

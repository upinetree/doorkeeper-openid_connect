# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module ServerExtension
      include Errors

      def client
        @client ||= authenticate_client_with_private_key_jwt || super
      end

      private

      def authenticate_client_with_private_key_jwt
        return nil unless uses_private_key_jwt?

        client_id = credentials&.uid || client_id_from_assertion
        return nil if client_id.blank?

        application = Doorkeeper.config.application_model.by_uid(client_id)
        return nil unless application&.uses_private_key_jwt?

        validator = Doorkeeper::ClientAssertion::ClientAssertionValidator.new(
          assertion: parameters[:client_assertion],
          application: application,
          token_endpoint_url: token_endpoint_url
        )

        validator.validate!

        Doorkeeper::OAuth::Client.new(application)
      rescue JWT::DecodeError, JwtVerificationError, InvalidJwks => e
        Doorkeeper::ClientAssertion.configuration.on_jwt_verification_failure.call(
          e,
          {
            application_id: application&.id,
            assertion: parameters[:client_assertion]
          }
        )
        nil
      end

      def client_id_from_assertion
        # Decode without verification to extract iss (client_id) before we have
        # the application record needed to look up the public key.
        # Signature is verified later in ClientAssertionValidator#validate!
        JWT.decode(parameters[:client_assertion], nil, false).first['iss']
      rescue JWT::DecodeError
        nil
      end

      def uses_private_key_jwt?
        # The assertion type URN is defined in RFC 7521 Section 4.2 and
        # registered for JWT client assertions by RFC 7523 Section 2.2
        parameters[:client_assertion_type] == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' &&
          parameters[:client_assertion].present?
      end

      def token_endpoint_url
        # Strip query parameters from the URL for JWT audience validation.
        # RFC 7523 Section 3 requires aud to match the token endpoint URL exactly.
        request = context.request
        request.url.split('?').first
      end
    end
  end
end

# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      class ClientAssertionValidator
        include Doorkeeper::OpenidConnect::Errors

        attr_reader :assertion, :application, :token_endpoint_url

        def initialize(assertion:, application:, token_endpoint_url:)
          @assertion = assertion
          @application = application
          @token_endpoint_url = token_endpoint_url
        end

        def valid?
          decoded_token = decode_and_verify_signature
          return false unless decoded_token

          verify_claims(decoded_token)
        rescue InvalidJwks
          false
        end

        private

        def decode_and_verify_signature
          public_keys = application.public_keys
          return nil if public_keys.empty?

          public_keys.each do |jwk|
            return decode_with_key(jwk)
          rescue JWT::DecodeError, JWT::VerificationError
            next
          end

          nil
        end

        def decode_with_key(jwk)
          JWT.decode(
            assertion,
            jwk.keypair,
            true,
            {
              algorithms: allowed_algorithms,
              aud: token_endpoint_url,
              verify_aud: true, # JWT gem handles both string and array aud
              leeway: exp_tolerance # Clock skew tolerance for exp/nbf
            }
          ).first
        end

        def verify_claims(decoded)
          return false unless verify_required_claims(decoded)
          return false unless verify_issuer_and_subject(decoded)
          return false unless verify_issued_at(decoded)

          true
        end

        def verify_required_claims(decoded)
          required_claims = %w[iss sub aud exp iat]
          missing_claims = required_claims - decoded.keys
          missing_claims.empty?
        end

        def verify_issuer_and_subject(decoded)
          client_id = application.uid

          return false unless decoded['iss'] == client_id
          return false unless decoded['sub'] == client_id
          return false unless decoded['iss'] == decoded['sub']

          true
        end

        def verify_issued_at(decoded)
          # RFC 7523: "The JWT MAY contain an 'iat' (issued at) claim"
          # While not required by RFC, we reject JWTs with future iat values
          # as a security best practice (with clock skew tolerance)
          iat_time = Time.at(decoded['iat'])
          now = Time.now

          iat_time <= now + exp_tolerance
        end

        def allowed_algorithms
          Doorkeeper::OpenidConnect.configuration.client_assertion_algorithms
        end

        def exp_tolerance
          Doorkeeper::OpenidConnect.configuration.jwt_assertion_exp_tolerance
        end
      end
    end
  end
end

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
          validate!
          true
        rescue JwtVerificationError, InvalidJwks
          false
        end

        def validate!
          decoded_token = decode_and_verify_signature
          verify_claims(decoded_token)
        end

        private

        def decode_and_verify_signature
          public_keys = application.public_keys

          raise JwtVerificationError, 'Empty JWKS' if public_keys.empty?

          errors = []
          public_keys.each_with_index do |jwk, index|
            return decode_with_key(jwk)
          rescue JWT::DecodeError, JWT::VerificationError => e
            # エラーと鍵の対応を記録
            key_id = jwk['kid'] || "key#{index + 1}"
            errors << "#{key_id}: #{e.class.name} - #{e.message}"
            next
          end

          # すべてのエラー情報を含めて raise
          raise JwtVerificationError, "JWT signature verification failed with all keys (#{errors.join('; ')})"
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
          unless verify_required_claims(decoded)
            raise JwtVerificationError, 'Missing required claims'
          end

          unless verify_issuer_and_subject(decoded)
            raise JwtVerificationError, 'Issuer or subject mismatch'
          end

          unless verify_issued_at(decoded)
            raise JwtVerificationError, 'Invalid issued_at time'
          end
        end

        def verify_required_claims(decoded)
          required_claims = %w[iss sub aud exp iat]
          missing_claims = required_claims - decoded.keys
          missing_claims.empty?
        end

        def verify_issuer_and_subject(decoded)
          client_id = application.uid

          # RFC 7523 Section 3: iss and sub MUST be equal to client_id
          return false unless decoded['iss'] == client_id
          return false unless decoded['sub'] == client_id

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

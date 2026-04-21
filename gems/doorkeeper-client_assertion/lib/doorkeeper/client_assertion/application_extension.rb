# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module ApplicationExtension
      include Errors

      def public_keys
        return [] unless respond_to?(:jwks)
        return [] if jwks.blank?

        jwks_hash = JSON.parse(jwks)
        raise InvalidJwks, 'JWKS must contain a keys array' unless jwks_hash&.key?('keys')

        jwks_hash['keys'].map { |key_data| JWT::JWK.import(key_data) }
      rescue JSON::ParserError => e
        raise InvalidJwks, "Invalid JWKS JSON: #{e.message}"
      end

      def uses_private_key_jwt?
        respond_to?(:token_endpoint_auth_method) && token_endpoint_auth_method == 'private_key_jwt'
      end

      private

      def secret_required?
        !uses_private_key_jwt? && super
      end

      def self.prepended(base)
        base.class_eval do
          validate :jwks_format, if: -> { uses_private_key_jwt? }

          private

          def jwks_format
            if jwks.blank?
              errors.add(:jwks, 'must be present when using private_key_jwt')
              return
            end

            parsed = JSON.parse(jwks)
            errors.add(:jwks, 'must have a keys array') unless parsed.key?('keys')
          rescue JSON::ParserError
            errors.add(:jwks, 'must be valid JSON')
          end
        end
      end
    end
  end
end

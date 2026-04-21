# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module Errors
      class ClientAssertionError < StandardError; end
      class InvalidJwks < ClientAssertionError; end
      class JwtVerificationError < ClientAssertionError; end
    end
  end
end

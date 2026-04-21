# frozen_string_literal: true

Doorkeeper::ClientAssertion.configure do
  client_assertion_algorithms %w[RS256 ES256]
  jwt_assertion_exp_tolerance 300
  on_jwt_verification_failure ->(error, context) { nil }
end

# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    module OAuth
      module RefreshTokenRequestExtension
        def initialize(server, refresh_token, credentials, parameters = {}, client: nil)
          super(server, refresh_token, credentials, parameters)
          # super calls load_client(credentials) which only supports uid+secret auth.
          # If the Strategy passed an already-authenticated client (e.g. via private_key_jwt),
          # use it; otherwise keep whatever load_client returned.
          @client = client || @client
        end
      end
    end
  end
end

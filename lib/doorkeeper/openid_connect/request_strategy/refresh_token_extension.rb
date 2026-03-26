# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module RequestStrategy
      module RefreshTokenExtension
        def request
          # server.client leverages ServerExtension which handles private_key_jwt authentication
          # as well as standard uid+secret authentication. Pass the result so that
          # RefreshTokenRequest does not need to repeat the authentication logic.
          @request ||= Doorkeeper::OAuth::RefreshTokenRequest.new(
            Doorkeeper.config,
            refresh_token,
            credentials,
            parameters,
            client: server.client,
          )
        end
      end
    end
  end
end

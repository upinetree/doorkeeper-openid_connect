# frozen_string_literal: true

require 'jwt'

require 'doorkeeper/client_assertion/version'
require 'doorkeeper/client_assertion/errors'
require 'doorkeeper/client_assertion/config'
require 'doorkeeper/client_assertion/client_assertion_validator'
require 'doorkeeper/client_assertion/server_extension'
require 'doorkeeper/client_assertion/application_extension'
require 'doorkeeper/client_assertion/applications_controller_extension'
require 'doorkeeper/client_assertion/discovery_extension'
require 'doorkeeper/client_assertion/dynamic_client_registration_extension'
require 'doorkeeper/client_assertion/oauth/refresh_token_request_extension'
require 'doorkeeper/client_assertion/request_strategy/refresh_token_extension'
require 'doorkeeper/client_assertion/engine'

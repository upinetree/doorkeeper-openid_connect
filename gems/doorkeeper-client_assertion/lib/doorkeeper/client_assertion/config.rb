# frozen_string_literal: true

module Doorkeeper
  module ClientAssertion
    class Config
      DEFAULTS = {
        client_assertion_algorithms: %w[RS256 ES256],
        jwt_assertion_exp_tolerance: 300,
        on_jwt_verification_failure: ->(_error, _context) { nil }
      }.freeze

      DEFAULTS.each_key do |option|
        define_method(option) do |value = :__unset__|
          if value == :__unset__
            instance_variable_defined?("@#{option}") ? instance_variable_get("@#{option}") : DEFAULTS[option]
          else
            instance_variable_set("@#{option}", value)
          end
        end
      end
    end

    def self.configure(&block)
      @config = Config.new
      @config.instance_eval(&block) if block
      @config
    end

    def self.configuration
      @config || configure
    end
  end
end

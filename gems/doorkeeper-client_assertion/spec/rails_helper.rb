# frozen_string_literal: true

ENV['RAILS_ENV'] ||= 'test'
require 'dummy/config/environment'
abort('The Rails environment is running in production mode!') if Rails.env.production?
require 'spec_helper'
require 'rspec/rails'

Dir.chdir('spec/dummy') do
  unless ActiveRecord::Base.connection.table_exists?('oauth_applications')
    load "#{Rails.root}/db/schema.rb"
  end
end

require_relative 'support/jwt_helpers'
require 'factory_bot'
FactoryBot.find_definitions

RSpec.configure do |config|
  config.use_transactional_fixtures = true
  config.filter_rails_from_backtrace!
  config.include FactoryBot::Syntax::Methods

  config.after do
    load Rails.root.join('config/initializers/doorkeeper.rb')
    load Rails.root.join('config/initializers/doorkeeper_client_assertion.rb')
    if defined?(Doorkeeper::OpenidConnect)
      load Rails.root.join('config/initializers/doorkeeper_openid_connect.rb')
    end
  end
end

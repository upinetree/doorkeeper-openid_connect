# frozen_string_literal: true

source 'https://rubygems.org'

$LOAD_PATH.unshift File.join(__dir__, 'gems/doorkeeper-client_assertion/lib')

# use Rails version specified by environment
ENV['rails'] ||= '8.0.0'
gem 'rails', "~> #{ENV['rails']}"
gem 'rails-controller-testing'

gem 'rubocop', '~> 1.6'
gem 'rubocop-performance', require: false
gem 'rubocop-rails', require: false
gem 'rubocop-rspec', require: false

gemspec

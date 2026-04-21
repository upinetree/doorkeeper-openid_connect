# frozen_string_literal: true

source 'https://rubygems.org'

gem 'doorkeeper-client_assertion', path: 'gems/doorkeeper-client_assertion'

# use Rails version specified by environment
ENV['rails'] ||= '8.0.0'
gem 'rails', "~> #{ENV['rails']}"
gem 'rails-controller-testing'

gem 'rubocop', '~> 1.6'
gem 'rubocop-performance', require: false
gem 'rubocop-rails', require: false
gem 'rubocop-rspec', require: false

gemspec

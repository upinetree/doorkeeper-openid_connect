# frozen_string_literal: true

ENV['RAILS_ENV'] ||= 'test'

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new

task default: :spec
task test: :spec

desc 'Generate and run migrations in the test application'
task :migrate do
  Dir.chdir('spec/dummy') do
    # Migration files are already included in the db/schema.rb file, so we can skip generating them. Otherwise, it will conflict with the existing migration files.
    # system('bin/rails generate doorkeeper:openid_connect:migration')
    # system('bin/rails generate doorkeeper:openid_connect:client_assertion_migration')
    system('bin/rake db:migrate')
  end
end

desc 'Run server in the test application'
task :server do
  Dir.chdir('spec/dummy') do
    system('bin/rails server')
  end
end

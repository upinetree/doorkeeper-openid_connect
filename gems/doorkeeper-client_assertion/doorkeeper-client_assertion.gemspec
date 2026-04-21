# frozen_string_literal: true

require_relative 'lib/doorkeeper/client_assertion/version'

Gem::Specification.new do |spec|
  spec.name    = 'doorkeeper-client_assertion'
  spec.version = Doorkeeper::ClientAssertion::VERSION
  spec.authors = ['upinetree']
  spec.email   = ['upinetree@gmail.com']

  spec.summary     = 'private_key_jwt client authentication for Doorkeeper'
  spec.description = 'Adds RFC 7523 / OpenID Connect private_key_jwt client authentication to Doorkeeper.'
  spec.homepage    = 'https://github.com/doorkeeper-gem/doorkeeper-client_assertion'
  spec.license     = 'MIT'

  spec.metadata = {
    'homepage_uri'    => spec.homepage,
    'source_code_uri' => spec.homepage,
    'bug_tracker_uri' => "#{spec.homepage}/issues",
    'changelog_uri'   => "#{spec.homepage}/blob/main/CHANGELOG.md",
  }

  spec.files         = Dir['{lib,generators}/**/*', 'README.md', 'CHANGELOG.md', 'LICENSE.txt']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.1'

  spec.add_dependency 'doorkeeper', '>= 5.5', '< 6.0'
  spec.add_dependency 'jwt', '>= 2.5'
end

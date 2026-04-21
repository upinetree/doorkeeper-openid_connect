# frozen_string_literal: true

Rails.application.configure do
  config.cache_classes = true
  config.eager_load = false
  config.active_support.to_time_preserves_timezone = :zone
  config.consider_all_requests_local = true
  config.action_controller.perform_caching = false

  config.action_dispatch.show_exceptions =
    Rails.gem_version >= Gem::Version.new('7.1.0') ? :none : false

  config.action_controller.allow_forgery_protection = false
  config.active_support.deprecation = :stderr
end

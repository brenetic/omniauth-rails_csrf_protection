require "active_support/configurable"
require "action_controller"

module OmniAuth
  module RailsCsrfProtection
    # Provides a callable method that verifies Cross-Site Request Forgery
    # protection token. This class includes
    # `ActionController::RequestForgeryProtection` directly and utilizes
    # `verified_request?` method to match the way Rails performs token
    # verification in Rails controllers.
    #
    # If you like to learn more about how Rails generate and verify
    # authenticity token, you can find the source code at
    # https://github.com/rails/rails/blob/v5.2.2/actionpack/lib/action_controller/metal/request_forgery_protection.rb#L217-L240.
    class TokenVerifier
      include ActiveSupport::Configurable
      include ActionController::RequestForgeryProtection

      # `ActionController::RequestForgeryProtection` contains a few
      # configurable options. As we want to make sure that our configuration is
      # the same as what being set in `ActionController::Base`, we should make
      # all out configuration methods to delegate to `ActionController::Base`.
      config.each_key do |configuration_name|
        undef_method configuration_name
        define_method configuration_name do
          ActionController::Base.config[configuration_name]
        end
      end

      def call(env)
        @request = ActionDispatch::Request.new(env.dup)

        Rails.logger.info('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')
        Rails.logger.info("forgery -> #{!protect_against_forgery?}")
        Rails.logger.info("get -> #{request.get?}")
        Rails.logger.info("head -> #{request.head?}")
        Rails.logger.info("valid origin -> #{valid_request_origin?}")
        Rails.logger.info("valid token -> #{any_authenticity_token_valid?}")
        Rails.logger.info("params -> #{params}")
        Rails.logger.info("Authenticity param -> #{params[request_forgery_protection_token]}")
        Rails.logger.info("Request x csrf token ->#{request.x_csrf_token}")
        Rails.logger.info('&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&')

        unless verified_request?
          raise ActionController::InvalidAuthenticityToken
        end
      end

      private

        attr_reader :request
        delegate :params, :session, to: :request
    end
  end
end

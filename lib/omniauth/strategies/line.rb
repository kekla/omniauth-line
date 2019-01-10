require 'omniauth-oauth2'
require 'json'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid email'

      option :token_params, {
        grant_type: 'authorization_code'
      }

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      def build_access_token
        verifier = request.params["code"]
        get_token_params = {:redirect_uri => callback_url, :client_id => client.id, :client_secret => client.secret}.merge(token_params.to_hash(:symbolize_keys => true))
        result = client.auth_code.get_token(verifier, get_token_params, deep_symbolize(options.auth_token_params))
        # extract email from jwt token
        iss = "https://access.line.me"
        aud = client.id
        begin
          decoded_token = JWT.decode result.params["id_token"], client.secret, "HS256", {iss: iss, verify_iss: true, aud: aud.to_s, verify_aud: aud}
          email = decoded_token[0]["email"]
          raw_email(email)
        rescue Exception => e
          Rails.logger.info "JWT error: #{e.inspect}"
          Rails.logger.info "error id_token: #{result.params["id_token"].inspect}"
          Rails.logger.info "error secret: #{client.secret.inspect}"
          Rails.logger.info "error iss: #{iss.inspect}"
          Rails.logger.info "error aud: #{aud.inspect}"
        end
        # Rails.logger.info "=========== result.params: #{result.params.inspect}"
        # Rails.logger.info "raw_email: #{raw_email.inspect}"
        return result
      end

      def callback_url
        full_host + script_name + callback_path
      end

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email: raw_email,
        }
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get('v2/profile').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def raw_email(email_string = nil)
        @raw_email ||= email_string
      end

    end
  end
end

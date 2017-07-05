# name: elcinema-sso
# about: Support for remote sso in Discourse
# version: 0.1
# authors: 'Mustafa Zain Eddin'
# url: https://github.com/MZainDamlag/elcinema-sso

enabled_site_setting :remote_sso_enabled

after_initialize do

  Discourse::Application.routes.append do
    get "session/elcinema_sso" => "session#elcinema_sso"
    get "session/elcinema_sso_login" => "session#elcinema_sso_login"
  end

  ::SessionController.skip_before_filter :check_xhr, only: ['sso', 'elcinema_sso', 'sso_login', 'elcinema_sso_login', 'become', 'sso_provider']

  add_to_class(:session_controller, :elcinema_sso) do
    if SiteSetting.enable_sso
      @url = DiscourseSingleSignOn.generate_url(params[:return_path])
      render :json => data = { url: @url }, :status => '200'
    else
      render nothing: true, status: 404
    end
  end

  add_to_class(:session_controller, :elcinema_sso_login) do
    unless SiteSetting.enable_sso
      render nothing: true, status: 404
      return
    end

    sso = DiscourseSingleSignOn.parse(request.query_string)
    if !sso.nonce_valid?
      render text: I18n.t("sso.timeout_expired"), status: 500
      return
    end

    return_path = sso.return_path
    sso.expire_nonce!

    begin
      if user = sso.lookup_or_create_user
        if SiteSetting.must_approve_users? && !user.approved?
          render text: I18n.t("sso.account_not_approved"), status: 403
        else
          log_on_user user
        end

        render :json => user , :status => '200'
      else
        render text: I18n.t("sso.not_found"), status: 500
      end
    rescue => e
      details = {}
      SingleSignOn::ACCESSORS.each do |a|
        details[a] = sso.send(a)
      end
      Discourse.handle_exception(e, details)

      render text: I18n.t("sso.unknown_error"), status: 500
    end
  end

  add_to_class(:session_controller, :destroy) do
    reset_session
    log_off_user
    cookies.delete("_t")
    cookies.delete("_t", domain: :all)
    if request.xhr?
      render nothing: true
    else
      redirect_to (params[:return_url] || path("/"))
    end
  end

  add_to_class('Auth::DefaultCurrentUserProvider', :lookup_api_user) do |api_key_value, request|
    if api_key = ApiKey.where(key: api_key_value).includes(:user).first
      api_username = request["api_username"]

      if api_key.allowed_ips.present? && !api_key.allowed_ips.any? { |ip| ip.include?(request.ip) }
        Rails.logger.warn("[Unauthorized API Access] username: #{api_username}, IP address: #{request.ip}")
        return nil
      end

      if api_key.user
        api_key.user if !api_username || (api_key.user.username_lower == api_username.downcase)
      elsif api_username
        SingleSignOnRecord.find_by(external_username: api_username).user
      end
    end
  end
end

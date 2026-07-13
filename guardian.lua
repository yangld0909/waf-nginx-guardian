-- guardian.lua - Main WAF pipeline orchestrator
-- Defines run_guardian() called by access_by_lua_file

-- Note: This file is required by init.lua but defines the entry point function.
-- All global helper functions are already loaded by init.lua and its dependencies.

function run_guardian()
    -- ============================================================
    -- 1. Resolve server identity
    -- ============================================================
    server_name = string.gsub(resolve_server_name(), "_", ".")

    -- ============================================================
    -- 2. Admin routes & API (always available, even when WAF is off)
    -- ============================================================
    handle_admin_routes()
    if handle_admin_api() then return true end

    -- Global on/off switch (after admin routes so admin always works)
    if not config.config["open"] or not get_site_config("open") then return false end

    -- ============================================================
    -- 3. Initialize per-request globals
    -- ============================================================
    error_rule = nil
    rule_type = nil
    request_uri = ngx.var.request_uri
    uri = ngx.unescape_uri(ngx.var.uri)
    request_header = ngx.req.get_headers()
    method = ngx.req.get_method()
    ip = get_client_ip()
    ipn = arrip(ip)
    uri_request_args = ngx.req.get_uri_args(10000000)

    -- Cooldown after captcha verification
    verify_captcha_response()

    -- ============================================================
    -- 4. IP whitelist check (fast path: bypass all checks)
    -- ============================================================
    if check_ip_whitelist() then
        increment_normal_score()
        return true
    end

    -- ============================================================
    -- 5. IP blacklist check
    -- ============================================================
    check_ip_blacklist()

    -- ============================================================
    -- 6. UA whitelist check (bypass UA rules)
    -- ============================================================
    if check_ua_whitelist() then
        increment_normal_score()
        -- Still do light checks: args + scan + POST
        check_get_args()
        check_scan_tools()
        check_post_body()
        return true
    end

    -- ============================================================
    -- 7. UA blacklist
    -- ============================================================
    check_ua_blacklist()

    -- ============================================================
    -- 8. URI character blacklist
    -- ============================================================
    check_uri_blacklist_chars()

    -- ============================================================
    -- 9. Static resource accounting (for CC)
    -- ============================================================
    account_static_resources()

    -- ============================================================
    -- 10. Check if IP is already blocked
    -- ============================================================
    check_ip_dropped()

    -- ============================================================
    -- 11. HEAD request handling
    -- ============================================================
    check_head_requests()

    -- ============================================================
    -- 12. Method validation
    -- ============================================================
    if not validate_method() then
        deny_request(405, "Method Not Allowed")
        return true
    end

    -- ============================================================
    -- 13. Header length validation
    -- ============================================================
    validate_header_lengths()

    -- ============================================================
    -- 14. Transfer-Encoding check
    -- ============================================================
    check_transfer_encoding()

    -- ============================================================
    -- 15. URL whitelist check (light pipeline)
    -- ============================================================
    if check_url_whitelist() then
        check_get_args()
        check_post_body()
        check_multipart_upload()
        increment_normal_score()
        return true
    end

    -- ============================================================
    -- 16. URL blacklist
    -- ============================================================
    check_url_blacklist()

    -- ============================================================
    -- 17. Geo-blocking
    -- ============================================================
    check_geo_block()

    -- ============================================================
    -- 18. WebShell file scanning
    -- ============================================================
    check_webshell_files()

    -- ============================================================
    -- 19. Spider verification
    -- ============================================================
    local spider_result = verify_spider(ip)

    if spider_result == 2 then
        -- Verified spider: light checks only
        check_get_args()
        check_scan_tools()
        check_thinkphp_rce()
        check_thinkphp_info_leak()
        check_post_body()
        check_multipart_upload()

        -- Per-site rules
        if config.site_config[server_name] then
            check_maccms_rce()
            check_x_forwarded_for()
            check_site_php_paths()
            check_site_url_paths()
            check_site_url_extensions()
            check_site_custom_url_rules()
            check_site_url_validation()
        end

        increment_normal_score()
        return false
    end

    -- ============================================================
    -- 20. Not a verified spider: full pipeline
    -- ============================================================
    -- UA rule check
    check_ua_rules()

    -- CC protection (standard + enhanced + automatic)
    check_cc()
    automatic_cc()
    enhanced_cc_captcha()

    -- URL rules
    check_url_rules()

    -- Application layer checks
    check_referer()
    check_cookie()
    check_get_args()
    check_scan_tools()

    -- Application-specific protection
    check_thinkphp_rce()
    check_thinkphp_info_leak()

    -- POST body checks
    check_post_body()
    check_multipart_upload()

    -- Per-site rules
    if config.site_config[server_name] then
        check_maccms_rce()
        check_x_forwarded_for()
        check_site_php_paths()
        check_site_url_paths()
        check_site_url_extensions()
        check_site_custom_url_rules()
        check_site_url_validation()
    end

    -- Normal request tracking (for false positive mitigation)
    increment_normal_score()

    return false
end

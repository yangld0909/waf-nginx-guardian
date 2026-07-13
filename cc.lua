-- cc.lua - CC (Challenge Collapsar) / Rate Limiting protection

-- ============================================================
-- Static resource exclusions
-- ============================================================
local static_extensions = {
    "css", "js", "png", "gif", "ico", "jpg", "jpeg", "bmp",
    "svg", "webp", "swf", "pdf", "rar", "zip", "doc", "docx",
    "xlsx", "xls", "ppt", "pptx", "mp4", "avi", "mov", "wmv",
    "flv", "mp3", "wav", "ogg", "woff", "woff2", "ttf", "eot"
}

-- Download-type static resources (not counted in CC)
local download_extensions = {"pdf", "zip", "rar", "gz", "7z", "mp4", "avi", "mkv"}

function is_static_resource()
    for _, ext in ipairs(static_extensions) do
        if ngx.re.find(uri, "/?.*%." .. ext .. "$", "isjo") then
            return true
        end
    end
    return false
end

function is_download_resource()
    for _, ext in ipairs(download_extensions) do
        if ngx.re.find(uri, "/?.*%." .. ext .. "$", "isjo") then
            return true
        end
    end
    return false
end

-- ============================================================
-- CC URI whitelist check
-- ============================================================
function is_cc_uri_whitelisted()
    if is_static_resource() then return true end
    if match_rules(cc_uri_white_rules, uri, nil) then return true end

    local site = config.site_config[server_name]
    if site and site["cc_uri_white"] then
        return match_rules(site["cc_uri_white"], uri, nil)
    end
    return false
end

-- ============================================================
-- Static resource accounting (cc_html_dan equivalent)
-- Tracks requests by resource type per-IP
-- ============================================================
function account_static_resources()
    if uri == nil then return false end

    local resource_type = nil
    for _, ext in ipairs(static_extensions) do
        if string.find(uri, "%." .. ext .. "$") then
            resource_type = ext
            break
        end
    end

    if not resource_type then
        -- Dynamic resource (PHP, ASP, etc.)
        resource_type = "dynamic"
    end

    if is_download_resource() then return false end

    local token = ip .. ":" .. server_name .. ":" .. resource_type
    local count, _ = ngx.shared.waf_cache:get(token)
    if count then
        ngx.shared.waf_cache:incr(token, 1)
    else
        ngx.shared.waf_cache:set(token, 1, 60)
    end
end

-- ============================================================
-- Standard CC protection
-- Uses IP+URI token with configurable cycle/limit
-- ============================================================
function check_cc()
    local cfg = config.config["cc"]
    if not cfg["open"] then return false end

    local site_cc = get_site_config("cc")
    if not site_cc then return false end

    -- Skip avatar.php (common heavy endpoint for Discuz/UCenter)
    if ngx.re.find(uri, "/uc_server/avatar.php") then return false end

    -- Use per-site CC thresholds if available
    local cycle = cfg["cycle"]
    local limit = cfg["limit"]
    local endtime = cfg["endtime"]

    local site = config.site_config[server_name]
    if site and site["cc"] then
        if site["cc"]["cycle"] then cycle = site["cc"]["cycle"] end
        if site["cc"]["limit"] then limit = site["cc"]["limit"] end
        if site["cc"]["endtime"] then endtime = site["cc"]["endtime"] end
    end

    if is_cc_uri_whitelisted() then return false end

    local token = ngx.md5(ip .. "_" .. request_uri)
    local count, _ = ngx.shared.waf_cache:get(token)

    if count then
        if count > limit then
            write_log("cc", cycle .. "秒内累计超过" .. limit .. "次请求")
            escalate_block("cc", cycle .. "秒内累计超过" .. limit .. "次请求")
            deny_request(cfg["status"], "block by firewall")
            return true
        else
            ngx.shared.waf_cache:incr(token, 1)
        end
    else
        ngx.shared.waf_cache:set(token, 1, cycle)
    end
    return false
end

-- ============================================================
-- Enhanced CC (captcha verification)
-- When enabled per-site, triggers JS captcha for suspicious IPs
-- ============================================================
function enhanced_cc_js()
    local cfg = config.config["cc"]
    if not cfg["open"] then return false end
    local site_cc = get_site_config("cc")
    if not site_cc then return false end

    local site = config.site_config[server_name]
    if not site then return false end
    if not site["cc"]["increase"] then return false end
    if site["cc"]["cc_increase_type"] == "code" then return false end
    if is_static_resource() then return false end

    -- Check if already verified
    local verified, _ = ngx.shared.waf_cache:get(ip .. ":verified")
    if verified == 666 then return false end

    if is_cc_uri_whitelisted() then
        ngx.shared.waf_cache:delete(ip .. ":cc_key")
        ngx.shared.waf_cache:set(ip .. ":verified_cooldown", 1, 180)
        return false
    end

    trigger_captcha()
    return true
end

-- ============================================================
-- Enhanced CC (captcha) with code verification
-- ============================================================
function enhanced_cc_captcha()
    local cfg = config.config["cc"]
    if not cfg["open"] then return false end
    local site_cc = get_site_config("cc")
    if not site_cc then return false end
    if ngx.re.find(uri, "/uc_server/avatar.php") then return false end

    local site = config.site_config[server_name]
    if not site then return false end
    if not site["cc"]["increase"] then return false end
    if site["cc"]["cc_increase_type"] ~= "code" then
        enhanced_cc_js()
        return true
    end

    -- Already verified
    local verified, _ = ngx.shared.waf_cache:get(ip .. ":verified")
    if verified == 666 then return false end
    if is_static_resource() then return false end
    if is_cc_uri_whitelisted() then return false end

    trigger_captcha()
    return true
end

-- ============================================================
-- Captcha verification system
-- ============================================================
function trigger_captcha()
    local cache_token = ngx.md5(ip .. "_" .. server_name)
    if ngx.shared.waf_cache:get(cache_token .. ":cooldown") then return end

    local check_key = tostring(math.random(10000000, 99999999))
    ngx.shared.waf_cache:set(cache_token .. ":key", check_key, 60)

    -- Build redirect URL with captcha token
    local vargs = "&btwaf="
    local sargs = string.gsub(request_uri, "?btwaf=.*", "")
    if not string.find(sargs, "?", 1, true) then
        vargs = "?btwaf="
    end

    -- Track verification attempts
    escalate_block("cc", "触发验证码")

    local html = [[
        <html><meta charset="utf-8" /><title>验证检查</title>
        <div>跳转中...</div></html>
        <script>window.location.href = "]] .. sargs .. vargs .. check_key .. [[";</script>
    ]]
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.say(html)
    ngx.exit(403)
end

-- ============================================================
-- Captcha response verification
-- ============================================================
function verify_captcha_response()
    local token = uri_request_args["btwaf"]
    if not token then return false end

    local cache_token = ngx.md5(ip .. "_" .. server_name)
    local expected = ngx.shared.waf_cache:get(cache_token .. ":key")

    if expected and token == expected then
        ngx.shared.waf_cache:delete(cache_token .. ":key")
        ngx.shared.waf_cache:set(cache_token .. ":cooldown", 1, 180)
        ngx.shared.waf_cache:set(ip .. ":verified", 666, 18000)
        return true
    end
    return false
end

-- ============================================================
-- Automatic CC mode (adaptive rate limiting)
-- ============================================================
function automatic_cc()
    local cfg = config.config
    if not cfg["cc_automatic"] then return false end
    if not cfg["cc_time"] then return false end

    local cc_time = cfg["cc_time"] * 10
    local cc_retry_cycle = cfg["cc_retry_cycle"]

    local auto_key = "cc_auto:" .. server_name
    local count, _ = ngx.shared.waf_cache:get(auto_key)

    if not count then
        ngx.shared.waf_cache:set(auto_key, 1, cc_time)
    else
        ngx.shared.waf_cache:incr(auto_key, 1)
        if count > (cc_retry_cycle or 600) * 2 then
            -- Enable enhanced mode automatically
            local site = config.site_config[server_name]
            if site and site["cc"] then
                site["cc"]["increase"] = true
                site["cc"]["cc_increase_type"] = "js"
            end
            enhanced_cc_js()
        else
            -- Check if site config has it disabled
            local site_file = config.load_json("site.json")
            if site_file[server_name] and not site_file[server_name]["cc"]["increase"] then
                local site = config.site_config[server_name]
                if site and site["cc"] then
                    site["cc"]["increase"] = false
                end
            end
        end
    end
end

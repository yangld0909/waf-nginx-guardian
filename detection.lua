-- detection.lua - Core detection engine
-- Regex-based pattern matching for attack signatures

local ngx_match = ngx.re.find

-- Rule name categorization for display
local rule_categories = {
    ["目录保护1"] = "目录保护",
    ["目录保护2"] = "目录保护",
    ["目录保护3"] = "目录保护",
    ["PHP流协议过滤1"] = "PHP流协议",
    ["一句话木马过滤1"] = "PHP函数",
    ["一句话木马过滤3"] = "PHP函数",
    ["一句话木马过滤4"] = "PHP脚本过滤",
    ["一句话木马过滤5"] = "PHP脚本过滤",
    ["菜刀流量过滤"] = "PHP函数",
    ["SQL注入过滤1"] = "SQL注入",
    ["SQL注入过滤2"] = "SQL注入",
    ["SQL注入过滤3"] = "SQL注入",
    ["SQL注入过滤4"] = "SQL注入",
    ["SQL注入过滤5"] = "SQL注入",
    ["SQL注入过滤6"] = "SQL注入",
    ["SQL注入过滤7"] = "SQL注入",
    ["SQL注入过滤8"] = "SQL注入",
    ["SQL注入过滤9"] = "SQL注入",
    ["SQL注入过滤10"] = "SQL注入",
    ["SQL报错注入过滤01"] = "SQL注入",
    ["SQL报错注入过滤02"] = "SQL注入",
    ["XSS过滤1"] = "XSS攻击",
    ["ThinkPHP payload封堵"] = "ThinkPHP攻击",
    ["PHP脚本执行过滤1"] = "PHP脚本过滤",
    ["PHP脚本执行过滤2"] = "PHP脚本过滤",
    ["文件目录过滤1"] = "目录保护",
    ["文件目录过滤2"] = "目录保护",
    ["文件目录过滤3"] = "目录保护"
}

-- Keys that are excluded from matching (common form fields)
local skip_keys = {
    "content", "contents", "body", "msg", "file", "files",
    "img", "newcontent", "message", "subject", "kw", "srchtxt", ""
}

function should_skip_key(key)
    key = tostring(key)
    if #key > 64 then return true end
    for _, k in ipairs(skip_keys) do
        if k == key then return true end
    end
    return false
end

function categorize_rule(rule_name)
    if rule_categories[rule_name] then
        return rule_categories[rule_name]
    end
    return rule_name
end

-- ============================================================
-- Per-rule disable check (site_config disable_rule)
-- ============================================================
function is_rule_disabled(rule_idx, dim)
    local site = config.site_config[server_name]
    if not site then return false end

    local disabled = site["disable_rule"] and site["disable_rule"][dim]
    if not disabled then return false end

    for _, idx in ipairs(disabled) do
        if rule_idx == idx then return true end
    end
    return false
end

-- ============================================================
-- Main matching function
-- Matches rules against request body (string or table of key-value pairs)
-- ============================================================
function match_rules(rules, subject, dimension)
    if not rules or not subject then return false end
    if type(rules) == "string" then rules = {rules} end
    if type(subject) == "string" then subject = {subject} end

    for key, value in pairs(subject) do
        if should_skip_key(key) then
            -- still check the key name itself
        end

        for idx, pattern in ipairs(rules) do
            -- Check if this rule is disabled for this site
            if dimension and is_rule_disabled(idx - 1, dimension) then
                pattern = ""
            end

            if pattern ~= "" and value then
                if type(value) == "string" then
                    local decoded = ngx.unescape_uri(value)
                    if ngx_match(decoded, pattern, "isjo") then
                        error_rule = pattern .. " >> " .. tostring(key) .. "=" .. value
                        rule_type = categorize_rule(
                            get_rule_name(dimension, pattern)
                        )
                        return true
                    end
                end

                -- Also match key names
                if type(key) == "string" then
                    local decoded_key = ngx.unescape_uri(key)
                    if ngx_match(decoded_key, pattern, "isjo") then
                        error_rule = pattern .. " >> " .. key
                        rule_type = categorize_rule(
                            get_rule_name(dimension, pattern)
                        )
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- Get human-readable rule name from pattern
-- ============================================================
function get_rule_name(dim, pattern)
    local rules
    if dim == "args" then rules = load_rules("args")
    elseif dim == "post" then rules = load_rules("post")
    elseif dim == "url" then rules = load_rules("url")
    elseif dim == "cookie" then rules = load_rules("cookie")
    elseif dim == "user_agent" then rules = load_rules("user_agent")
    else return pattern end

    for _, v in ipairs(rules) do
        if v[2] == pattern then
            return v[3] or pattern
        end
    end
    return pattern
end

-- ============================================================
-- URL-based checks
-- ============================================================
function check_url_rules()
    if not config.config["uri"]["open"] or not get_site_config("uri") then
        return false
    end
    if match_rules(url_rules, uri, "url") then
        write_log("url", "URL规则匹配拦截")
        deny_request(config.config["uri"]["status"], resp_html["uri"])
        return true
    end
    return false
end

function check_url_blacklist()
    if match_rules(url_black_rules, request_uri, nil) then
        write_log("url_black", "URL黑名单拦截")
        deny_request(config.config["uri"]["status"], resp_html["uri"])
        return true
    end
    return false
end

function check_url_whitelist()
    -- phpMyAdmin is always whitelisted
    if ngx.var.document_root and string.find(ngx.var.document_root, "phpmyadmin") then
        return true
    end

    if match_rules(url_white_rules, request_uri, nil) then
        return true
    end

    local site = config.site_config[server_name]
    if site and site["url_white"] then
        if match_rules(site["url_white"], request_uri, nil) then
            return true
        end
    end
    return false
end

-- ============================================================
-- URI character filtering (config.json -> uri_find)
-- ============================================================
function check_uri_blacklist_chars()
    local uri_find = config.config["uri_find"]
    if not uri_find or #uri_find == 0 then return false end

    for _, pattern in ipairs(uri_find) do
        if string.find(ngx.unescape_uri(request_uri), pattern) then
            write_log("uri_find", "URI字符过滤拦截: " .. pattern)
            deny_request(403, "block by firewall")
            return true
        end
    end
    return false
end

-- ============================================================
-- Cookie check
-- ============================================================
function check_cookie()
    if not config.config["cookie"]["open"] or not get_site_config("cookie") then
        return false
    end

    local cookie = request_header["cookie"]
    if not cookie then return false end
    if type(cookie) ~= "string" then return false end

    if match_rules(cookie_rules, string.lower(cookie), "cookie") then
        write_log("cookie", "Cookie规则拦截")
        deny_request(config.config["cookie"]["status"], resp_html["cookie"])
        return true
    end
    return false
end

-- ============================================================
-- Referer check
-- ============================================================
function check_referer()
    local ref = request_header["Referer"]
    if not ref then return false end

    if method == "POST" then
        if match_rules(referer_rules, ref, "post") then
            write_log("post_referer", "Referer规则拦截")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    elseif method == "GET" then
        if match_rules(referer_rules, ref, "args") then
            write_log("get_referer", "Referer规则拦截")
            deny_request(config.config["args"]["status"], resp_html["get"])
            return true
        end
    end
    return false
end

-- ============================================================
-- HEAD request handling
-- ============================================================
function check_head_requests()
    if method ~= "HEAD" then return false end

    for _, pattern in ipairs(head_white_rules) do
        if ngx_match(uri, pattern[2], "isjo") then
            return false
        end
    end

    -- Allow spiders
    local ua = request_header["user-agent"]
    if ua then
        local ua_lower = string.lower(ua)
        if string.find(ua_lower, "spider") or string.find(ua_lower, "bot") then
            return false
        end
    end

    write_log("head", "禁止HEAD请求")
    ngx.shared.waf_cache:set(ip, config.config["retry"], config.config["cc"]["endtime"])
    deny_request(403, "block by firewall")
    return true
end

-- ============================================================
-- X-Forwarded-For check
-- ============================================================
function check_x_forwarded_for()
    local xff = request_header["X-forwarded-For"]
    if not xff then return false end

    if method == "POST" then
        if config.config["post"]["open"] and get_site_config("post") then
            if match_rules(post_rules, xff, "post") then
                write_log("post", "X-Forwarded-For POST拦截")
                deny_request(config.config["post"]["status"], resp_html["post"])
                return true
            end
        end
    else
        if config.config["args"]["open"] and get_site_config("args") then
            if match_rules(args_rules, xff, "args") then
                write_log("args", "X-Forwarded-For GET拦截")
                deny_request(config.config["args"]["status"], resp_html["get"])
                return true
            end
        end
    end
    return false
end

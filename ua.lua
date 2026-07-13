-- ua.lua - User-Agent filtering and spider verification

-- Spider UA definitions (from zhi.lua)
local spider_types = {
    {id = 1, name = "百度", ua_key = "Baiduspider", host_key = "baidu.com"},
    {id = 2, name = "Google", ua_key = "Googlebot", host_key = "google.com"},
    {id = 3, name = "360", ua_key = "360Spider", host_key = ""},
    {id = 4, name = "搜狗", ua_key = "Sogou", host_key = "sogou.com"},
    {id = 5, name = "雅虎", ua_key = "Yahoo", host_key = "yahoo.com"},
    {id = 6, name = "必应", ua_key = "bingbot", host_key = "msn.com"},
    {id = 7, name = "头条", ua_key = "bytespider", host_key = "bytedance.com"}
}

-- UAs that skip spider verification
local skip_spider_keywords = {"Android", "curl", "java", "python", "HttpClient", "okhttp"}

-- ============================================================
-- UA whitelist (config.json -> ua_white)
-- ============================================================
function check_ua_whitelist()
    local ua = request_header["user-agent"]
    if not ua then return false end

    local whitelist = config.config["ua_white"]
    if not whitelist or #whitelist == 0 then return false end

    for _, pattern in ipairs(whitelist) do
        if string.find(string.lower(ua), string.lower(pattern)) then
            return true
        end
    end
    return false
end

-- ============================================================
-- UA blacklist (config.json -> ua_black)
-- ============================================================
function check_ua_blacklist()
    local ua = request_header["user-agent"]
    if not ua then return false end

    local blacklist = config.config["ua_black"]
    if not blacklist or #blacklist == 0 then return false end

    for _, pattern in ipairs(blacklist) do
        if string.find(string.lower(ua), string.lower(pattern)) then
            write_log("user-agent", "UA黑名单拦截: " .. pattern)
            deny_request(403, "block by firewall")
            return true
        end
    end
    return false
end

-- ============================================================
-- UA regex rule check (rule/user_agent.json)
-- ============================================================
function check_ua_rules()
    if not config.config["user-agent"]["open"] or not get_site_config("user-agent") then
        return false
    end

    local ua = request_header["user-agent"]
    if not ua then return false end

    if match_rules(ua_rules, ua, "user_agent") then
        block_ip("user-agent", "UA 规则匹配拦截")
        return true
    end
    return false
end

-- ============================================================
-- Spider identification
-- ============================================================
function identify_spider(ua)
    if not ua then return nil end
    local ua_lower = string.lower(ua)

    for _, spider in ipairs(spider_types) do
        if string.find(ua_lower, string.lower(spider["ua_key"])) then
            return spider
        end
    end
    return nil
end

function should_skip_spider_check(ua)
    if not ua then return true end
    local ua_lower = string.lower(ua)

    for _, keyword in ipairs(skip_spider_keywords) do
        if string.find(ua_lower, string.lower(keyword)) then
            return true
        end
    end
    return false
end

-- ============================================================
-- DNS reverse-lookup spider verification
-- ============================================================
function verify_spider_by_dns(ip_addr, host_key)
    if not ip_addr or not host_key or host_key == "" then return false end

    -- Check cache
    local cache_key = ip_addr .. ":spider"
    local cached = ngx.shared.waf_cache:get(cache_key)
    if cached then
        return cached == "verified"
    end

    -- Perform DNS reverse lookup
    local s = require("socket")
    local hostname, err = s.dns.tohostname(ip_addr)
    if not hostname then
        ngx.shared.waf_cache:set(cache_key, "unverified", 3600)
        return false
    end

    if string.find(string.lower(hostname), string.lower(host_key)) then
        ngx.shared.waf_cache:set(cache_key, "verified", 86400)
        return true
    end

    ngx.shared.waf_cache:set(cache_key, "unverified", 3600)
    return false
end

-- ============================================================
-- Spider verification entry point
-- Returns: 2 = verified spider, 4 = not a spider, 33 = verification failed
-- ============================================================
function verify_spider(ip_addr)
    local ua = request_header["user-agent"]
    if not ua then return 4 end

    if should_skip_spider_check(ua) then return 4 end

    local spider = identify_spider(ua)
    if not spider then return 4 end

    -- 360 spider (id=3) uses shared IP list, not DNS
    if spider["id"] == 3 then
        -- Check against known 360 spider IP list
        -- (simplified: could maintain a list in rule/cn.json style)
        return 33
    end

    if verify_spider_by_dns(ip_addr, spider["host_key"]) then
        return 2
    end

    -- Track failed verification count
    local fail_key = ip_addr .. ":spider_fail"
    local count, _ = ngx.shared.waf_stats:get(fail_key)
    if not count then
        ngx.shared.waf_stats:set(fail_key, 1, 18000)
    elseif count > 50 then
        -- Excessive failures = likely a scanner pretending to be a spider
        return 188
    else
        ngx.shared.waf_stats:incr(fail_key, 1)
    end

    return 33
end

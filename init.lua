--[[
init.lua - Guardian WAF Initialization
Loads at Nginx startup via init_by_lua_file.
Defines the global WAF environment and all detection functions.
]]--

json = require "cjson"
config = require "config"

-- ============================================================
-- Global state (set per-request in run_guardian())
-- ============================================================
server_name = nil
request_uri = nil
uri = nil
request_header = nil
method = nil
ip = nil
ipn = nil
uri_request_args = {}
error_rule = nil
rule_type = nil

-- ============================================================
-- Utility functions
-- ============================================================

function arrlen(arr)
    if not arr then return 0 end
    local count = 0
    for _,_ in ipairs(arr) do count = count + 1 end
    return count
end

function split(str, delimiter)
    local result = {}
    if not str or not delimiter then return result end
    string.gsub(str, '[^' .. delimiter .. ']+', function(w)
        table.insert(result, w)
    end)
    return result
end

function table_count(t)
    if not t then return 0 end
    local n = 0
    for _,_ in pairs(t) do n = n + 1 end
    return n
end

function in_table(t, val)
    for _, v in ipairs(t) do
        if v == val then return true end
    end
    return false
end

-- ============================================================
-- Rule loading
-- ============================================================

function load_rules(name)
    local data = config.load_json("rule/" .. name .. ".json")
    if not data or type(data) ~= "table" then
        if json and json.empty_array_mt then
            return setmetatable({}, json.empty_array_mt)
        end
        return {}
    end
    -- cjson encodes empty tables as {} (object) by default, but rule files
    -- are always JSON arrays. Ensure empty results are marked as arrays
    -- so the frontend receives [] instead of {}.
    if #data == 0 then
        local has_keys = false
        for _,_ in pairs(data) do has_keys = true; break end
        if not has_keys and json and json.empty_array_mt then
            return setmetatable({}, json.empty_array_mt)
        end
    end
    return data
end

function load_active_rules(name)
    local rules = load_rules(name)
    local active = {}
    for _, v in ipairs(rules) do
        if v[1] == 1 then
            table.insert(active, v[2])
        end
    end
    return active
end

-- ============================================================
-- HTML response templates
-- ============================================================

local html_dir = config.config.reqfile_path .. "/"
resp_html = {}
local html_names = {"get", "post", "cookie", "user_agent", "other", "uri"}
for _, name in ipairs(html_names) do
    local body = config.read_file(html_dir .. name .. ".html")
    resp_html[name] = body or "Request blocked by Guardian WAF"
end

-- ============================================================
-- IP helpers
-- ============================================================

function arrip(ipstr)
    if ipstr == "unknown" then return {0, 0, 0, 0} end
    if string.find(ipstr, ":") then return ipstr end
    local parts = split(ipstr, ".")
    return {
        tonumber(parts[1]),
        tonumber(parts[2]),
        tonumber(parts[3]),
        tonumber(parts[4])
    }
end

function is_min(ip1, ip2)
    if not ip1 or not ip2 then return false end
    for _, i in ipairs({1, 2, 3, 4}) do
        if not ip1[i] or not ip2[i] then return false end
        if ip1[i] == ip2[i] then
            -- continue
        elseif ip1[i] > ip2[i] then
            break
        else
            return false
        end
    end
    return true
end

function is_max(ip1, ip2)
    if not ip1 or not ip2 then return false end
    for _, i in ipairs({1, 2, 3, 4}) do
        if not ip1[i] or not ip2[i] then return false end
        if ip1[i] == ip2[i] then
            -- continue
        elseif ip1[i] < ip2[i] then
            break
        else
            return false
        end
    end
    return true
end

function compare_ip(ip, range)
    if ip == "unknown" then return true end
    if type(range) == "string" then
        -- Check if it's an IP range "start-end"
        local dash = string.find(range, "-", 1, true)
        if dash then
            local start_str = string.sub(range, 1, dash - 1)
            local end_str = string.sub(range, dash + 1)
            local start_parts = arrip(start_str)
            local end_parts = arrip(end_str)
            local ip_parts = arrip(ip)
            if not ip_parts or not start_parts or not end_parts then return false end
            if not is_max(ip_parts, end_parts) then return false end
            if not is_min(ip_parts, start_parts) then return false end
            return true
        end
        return ip == range
    end
    -- range is {start, end} CIDR style
    if string.find(ip, ":") then return false end
    local ip_parts = arrip(ip)
    if not is_max(ip_parts, range[2]) then return false end
    if not is_min(ip_parts, range[1]) then return false end
    return true
end

function is_valid_ip(ip_str)
    local parts = split(ip_str, ".")
    if #parts < 4 then return false end
    for _, v in ipairs({1, 2, 3, 4}) do
        local n = tonumber(parts[v])
        if not n or n < 0 or n > 255 then return false end
    end
    return true
end

-- ============================================================
-- Domain resolution
-- ============================================================

function resolve_server_name()
    local cname = ngx.var.server_name
    -- check cache
    local cached = ngx.shared.waf_cache:get("sname:" .. cname)
    if cached then return cached end

    -- look up in domains.json
    local domains = config.domains
    for _, entry in ipairs(domains) do
        for _, d in ipairs(entry["domains"]) do
            if cname == d then
                ngx.shared.waf_cache:set("sname:" .. cname, entry["name"], 3600)
                return entry["name"]
            end
        end
    end
    return cname
end

function resolve_site_path()
    local cname = ngx.var.server_name
    local cached, _ = ngx.shared.waf_cache:get("spath:" .. cname)
    if cached then return cached end

    local domains = config.domains
    for _, entry in ipairs(domains) do
        for _, d in ipairs(entry["domains"]) do
            if cname == d then
                ngx.shared.waf_cache:set("spath:" .. cname, entry["path"], 3600)
                return entry["path"]
            end
        end
    end
    return false
end

-- ============================================================
-- Site-level config helper
-- ============================================================

function get_site_config(key)
    local site = config.site_config[server_name]
    if not site then return true end

    if key == "cc" then
        return site["cc"]["open"]
    end
    if key == "open" or key == "log" or key == "get" or key == "post" or
       key == "cookie" or key == "user-agent" or key == "scan" or key == "drop_abroad" or
       key == "uri" or key == "args" then
        -- For uri/args, also check the legacy "get" key
        if site[key] == false then return false end
        if (key == "uri" or key == "args") and site["get"] == false then return false end
    end
    return true
end

-- ============================================================
-- Response helpers
-- ============================================================

function deny_request(status, html_body)
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.status = status
    ngx.say(html_body)
    ngx.exit(status)
end

function deny_json(status, msg)
    ngx.header.content_type = "application/json"
    ngx.status = status
    ngx.say(json.encode(msg))
    ngx.exit(status)
end

-- ============================================================
-- Pre-load rules at startup
-- ============================================================

-- Rule tables
args_rules = load_active_rules("args")
post_rules = load_active_rules("post")
url_rules = load_active_rules("url")
cookie_rules = load_active_rules("cookie")
ua_rules = load_active_rules("user_agent")
referer_rules = load_active_rules("referer")
scan_black_rules = load_rules("scan_black")
ip_black_rules = load_rules("ip_black")
ip_white_rules = load_rules("ip_white")
url_white_rules = load_active_rules("url_white")
url_black_rules = load_active_rules("url_black")
cc_uri_white_rules = load_active_rules("cc_uri_white")
head_white_rules = load_rules("head_white")
cnlist = load_rules("cn")

-- ============================================================
-- Require sub-modules (they define functions in global scope)
-- ============================================================
require "ip"
require "ua"
require "cc"
require "detection"
require "log"
require "post"
require "scan"
require "semantics"
require "guardian"
require "admin"

-- ============================================================
-- Restore blocked IPs from stop_ip.json on startup
-- Nginx reload/restart clears shared dicts, so we need to
-- reload persisted IP blocks that haven't expired yet.
-- ============================================================
do
    local stop_ip_data = config.load_json("stop_ip.json")
    if stop_ip_data and type(stop_ip_data) == "table" then
        local now = os.time()
        local restored = 0
        local expired = 0
        local remaining = {}

        for _, entry in ipairs(stop_ip_data) do
            if entry["ip"] and entry["timeout"] then
                local ttl = entry["timeout"] - now
                if ttl > 0 then
                    -- IP block still valid, restore to shared dict
                    ngx.shared.waf_drop:set(entry["ip"], config.config["retry"] + 1, ttl)
                    -- Also restore violation count for graduated escalation
                    local sum_key = entry["ip"] .. ":sum"
                    local sum_count = math.ceil(entry["time"] / (config.config["retry_time"] or 60000))
                    if sum_count < 1 then sum_count = 1 end
                    ngx.shared.waf_stats:set(sum_key, sum_count, 86400)
                    restored = restored + 1
                    table.insert(remaining, entry)
                else
                    expired = expired + 1
                end
            end
        end

        -- Rewrite stop_ip.json with only non-expired entries
        if expired > 0 then
            config.write_file(config.root .. "stop_ip.json", json.encode(remaining))
        end

        if restored > 0 then
            print("Guardian WAF: restored " .. restored .. " blocked IPs, cleaned " .. expired .. " expired")
        end
    end
end

print("Guardian WAF initialized successfully")

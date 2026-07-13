-- admin.lua - Management API endpoints for Guardian WAF
-- Provides JSON APIs consumed by the admin web interface
-- Access control: IP whitelist (configurable)

local json = require "cjson"
local ngx_match = ngx.re.find
local ngx_time = ngx.time

-- ============================================================
-- Authentication
-- ============================================================
-- 安全提醒: 管理面板默认允许所有IP访问。
-- 如需限制，在 config.json 中添加 admin_ips 数组:
--   "admin_ips": ["127.0.0.1", "::1", "你的IP"]
-- 注意: 建议通过 Nginx auth_basic 或防火墙控制访问权限。
local function get_admin_ips()
    local ips = config.config["admin_ips"]
    if ips and type(ips) == "table" and #ips > 0 then return ips end
    -- 空数组或未设置 = 允许所有IP
    return nil
end

function is_admin_ip(ip_addr)
    local ips = get_admin_ips()
    if not ips then return true end  -- 无限制, 允许所有
    for _, allowed in ipairs(ips) do
        if ip_addr == allowed then return true end
    end
    return false
end

function require_admin_auth()
    local client_ip = ngx.var.remote_addr
    if not is_admin_ip(client_ip) then
        respond_error("管理面板访问被拒绝，你的IP: " .. (client_ip or "unknown") .. "，请在 config.json 的 admin_ips 中添加该IP", 403)
        return false
    end
    return true
end

-- ============================================================
-- JSON response helpers
-- ============================================================
function respond_json(data, status)
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.status = status or 200
    local ok, encoded = pcall(json.encode, data)
    if not ok then
        ngx.say(json.encode({success = false, message = "数据序列化失败: " .. tostring(encoded)}))
        ngx.exit(500)
    else
        ngx.say(encoded)
        ngx.exit(ngx.status)
    end
end

function respond_success(msg, extra)
    local resp = {success = true, message = msg}
    if extra then
        for k, v in pairs(extra) do resp[k] = v end
    end
    respond_json(resp)
end

function respond_error(msg, status)
    respond_json({success = false, message = msg}, status or 400)
end

-- ============================================================
-- Persist helpers
-- ============================================================
function save_site_config()
    local json_str = json.encode(config.site_config)
    config.write_file(config.root .. "site.json", json_str)
end

function save_domains()
    local json_str = json.encode(config.domains)
    config.write_file(config.root .. "domains.json", json_str)
end

-- ============================================================
-- 1. Dashboard stats
-- ============================================================
function api_dashboard()
    if not require_admin_auth() then return end

    local stats = config.load_json("total.json")
    if not stats or not stats.total then stats = {total = 0, sites = {}, rules = {}} end

    -- Compute per-site hit list from stats
    local site_hits = {}
    if stats.sites then
        for sname, rules_hit in pairs(stats.sites) do
            local total = 0
            for _, c in pairs(rules_hit) do total = total + c end
            table.insert(site_hits, {name = sname, total = total})
        end
        table.sort(site_hits, function(a, b) return a.total > b.total end)
    end

    -- Get blocked IPs
    local blocked_keys = ngx.shared.waf_drop:get_keys(0)
    local blocked_count = 0
    local blocked_ips = {}
    local blocked_by_site = {}
    for _, key in ipairs(blocked_keys) do
        local count = ngx.shared.waf_drop:get(key)
        if count and count > (config.config.retry or 3) then
            blocked_count = blocked_count + 1
            if #blocked_ips < 50 then
                table.insert(blocked_ips, {ip = key, count = count})
            end
        end
        -- Count blocked IPs per site (estimate from total stats)
        if count then
            local site = "unknown"
            for sname, _ in pairs(config.site_config) do
                if string.find(key, sname, 1, true) then
                    site = sname; break
                end
            end
            blocked_by_site[site] = (blocked_by_site[site] or 0) + 1
        end
    end

    respond_success("ok", {
        stats = stats,
        site_hits = site_hits,
        blocked_count = blocked_count,
        blocked_ips = blocked_ips,
        blocked_by_site = blocked_by_site,
        total_sites = table_count(config.site_config),
        total_domains = #config.domains,
        server_name = ngx.var.server_name or "unknown",
        today = ngx.today(),
        uptime = config.config.start_time > 0 and (os.time() - config.config.start_time) or 0
    })
end

-- ============================================================
-- 2. Get full config
-- ============================================================
function api_get_config()
    if not require_admin_auth() then return end
    local data = {success = true, message = "ok", config = config.config, site_config = config.site_config, domains = config.domains}
    local ok, encoded = pcall(json.encode, data)
    if not ok then
        respond_error("配置数据序列化失败: " .. tostring(encoded), 500)
        return
    end
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.say(encoded)
    ngx.exit(200)
end

-- ============================================================
-- 3. Update config (partial merge)
-- ============================================================
function api_update_config()
    if not require_admin_auth() then return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, updates = pcall(json.decode, body)
    if not ok then respond_error("Invalid JSON") return end

    local function merge(target, source)
        for k, v in pairs(source) do
            if type(v) == "table" then
                -- If source value is an empty table (no keys at all),
                -- replace target entirely (allows clearing arrays/objects)
                if next(v) == nil then
                    target[k] = v
                elseif type(target[k]) == "table" then
                    merge(target[k], v)
                else
                    target[k] = v
                end
            else
                target[k] = v
            end
        end
    end
    merge(config.config, updates)

    local json_str = json.encode(config.config)
    if not config.write_file(config.root .. "config.json", json_str) then
        respond_error("Failed to write config file") return
    end
    respond_success("配置已更新")
end

-- ============================================================
-- 4. List sites (with domains per site)
-- ============================================================
function api_list_sites()
    if not require_admin_auth() then return end

    -- Build domain -> site name lookup
    local domain_to_site = {}
    for _, entry in ipairs(config.domains) do
        local sname = entry["name"]
        for _, d in ipairs(entry["domains"]) do
            domain_to_site[d] = sname
        end
    end

    local sites = {}
    for name, cfg in pairs(config.site_config) do
        -- Find domains for this site
        local domains = {}
        for d, s in pairs(domain_to_site) do
            if s == name then table.insert(domains, d) end
        end
        table.sort(domains)

        -- Find site path
        local site_path = ""
        for _, entry in ipairs(config.domains) do
            if entry["name"] == name then
                site_path = entry["path"] or ""
                break
            end
        end

        table.insert(sites, {
            name = name,
            open = cfg.open,
            cc_enabled = cfg.cc and cfg.cc.open,
            post_enabled = cfg.post,
            get_enabled = cfg.get,
            domains = domains,
            path = site_path,
            scan = cfg.scan
        })
    end
    table.sort(sites, function(a, b) return a.name < b.name end)

    respond_success("ok", {sites = sites, total = #sites, domains = config.domains})
end

-- ============================================================
-- 5. Get single site detail
-- ============================================================
function api_get_site_detail(site_name)
    if not require_admin_auth() then return end

    local cfg = config.site_config[site_name]
    if not cfg then respond_error("Site not found: " .. site_name, 404) return end

    -- Find domains and path
    local domains = {}
    local site_path = ""
    for _, entry in ipairs(config.domains) do
        if entry["name"] == site_name then
            site_path = entry["path"] or ""
            for _, d in ipairs(entry["domains"] or {}) do
                table.insert(domains, d)
            end
        end
    end
    table.sort(domains)

    respond_success("ok", {
        site = {
            name = site_name,
            config = cfg,
            domains = domains,
            path = site_path
        }
    })
end

-- ============================================================
-- 6. Create new site
-- ============================================================
function api_create_site()
    if not require_admin_auth() then return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, data = pcall(json.decode, body)
    if not ok then respond_error("Invalid JSON") return end

    local name = data.name
    if not name or name == "" then respond_error("Site name is required") return end

    -- Validate site name (no special chars or path separators)
    if string.find(name, "[/\\:]") then
        respond_error("Site name cannot contain / \\ :") return
    end

    -- Check for duplicate
    if config.site_config[name] then
        respond_error("Site '" .. name .. "' already exists") return
    end

    -- Create default site config
    config.site_config[name] = {
        open = true,
        log = true,
        cdn = false,
        cdn_header = {"x-forwarded-for", "x-real-ip"},
        retry = config.config.retry or 3,
        retry_cycle = config.config.retry_cycle or 60,
        retry_time = config.config.retry_time or 600,
        disable_upload_ext = {"php", "jsp", "asp", "aspx"},
        url_white = {},
        url_rule = {},
        url_tell = {},
        disable_rule = {url = {}, post = {}, args = {}, cookie = {}, user_agent = {}},
        disable_path = {},
        disable_ext = {},
        disable_php_path = {},
        cc = {
            open = true,
            cycle = config.config.cc and config.config.cc.cycle or 60,
            limit = config.config.cc and config.config.cc.limit or 120,
            endtime = config.config.cc and config.config.cc.endtime or 3600,
            increase = false
        },
        get = true,
        post = true,
        cookie = true,
        ["user-agent"] = true,
        scan = true,
        drop_abroad = false,
        body_character_string = {},
        cc_uri_white = {},
        uri_find = {},
        log_size = 0
    }
    save_site_config()

    -- Create domain mapping entry
    local path = data.path or ("/www/wwwroot/" .. name)
    local first_domain = data.domain or name
    table.insert(config.domains, {
        name = name,
        path = path,
        cms = data.cms or 0,
        domains = {first_domain}
    })
    save_domains()

    respond_success("站点 '" .. name .. "' 创建成功", {site = name, domain = first_domain, path = path})
end

-- ============================================================
-- 7. Delete site
-- ============================================================
function api_delete_site(site_name)
    if not require_admin_auth() then return end

    if not config.site_config[site_name] then
        respond_error("Site not found: " .. site_name, 404) return
    end

    -- Remove from site_config
    config.site_config[site_name] = nil
    save_site_config()

    -- Remove from domains
    local new_domains = {}
    for _, entry in ipairs(config.domains) do
        if entry["name"] ~= site_name then
            table.insert(new_domains, entry)
        end
    end
    config.domains = new_domains
    save_domains()

    -- Clear cached server names
    -- (cannot enumerate all, but next request will re-resolve)

    respond_success("站点 '" .. site_name .. "' 已删除")
end

-- ============================================================
-- 8. Update single site config
-- ============================================================
function api_update_site(site_name)
    if not require_admin_auth() then return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, updates = pcall(json.decode, body)
    if not ok then respond_error("Invalid JSON") return end

    if not config.site_config[site_name] then
        config.site_config[site_name] = {}
    end

    local function merge(target, source)
        for k, v in pairs(source) do
            if type(v) == "table" then
                -- If source value is an empty table (no keys at all),
                -- replace target entirely (allows clearing arrays/objects)
                if next(v) == nil then
                    target[k] = v
                elseif type(target[k]) == "table" then
                    merge(target[k], v)
                else
                    target[k] = v
                end
            else
                target[k] = v
            end
        end
    end
    merge(config.site_config[site_name], updates)

    save_site_config()
    respond_success("站点配置已更新")
end

-- ============================================================
-- 9. Add domain to site
-- ============================================================
function api_add_domain()
    if not require_admin_auth() then return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, data = pcall(json.decode, body)
    if not ok then respond_error("Invalid JSON") return end

    local site_name = data.site
    local domain = data.domain
    if not site_name or not domain then
        respond_error("site and domain are required") return
    end

    -- Check site exists
    if not config.site_config[site_name] then
        respond_error("Site not found: " .. site_name, 404) return
    end

    -- Check domain not already mapped
    for _, entry in ipairs(config.domains) do
        for _, d in ipairs(entry["domains"]) do
            if d == domain then
                respond_error("Domain '" .. domain .. "' already mapped to site '" .. entry["name"] .. "'") return
            end
        end
    end

    -- Find or create domain entry
    local found = false
    for _, entry in ipairs(config.domains) do
        if entry["name"] == site_name then
            table.insert(entry["domains"], domain)
            found = true
            break
        end
    end

    if not found then
        table.insert(config.domains, {
            name = site_name,
            path = "/www/wwwroot/" .. site_name,
            cms = 0,
            domains = {domain}
        })
    end
    save_domains()

    respond_success("域名 " .. domain .. " 已添加到站点 " .. site_name)
end

-- ============================================================
-- 10. Remove domain from site
-- ============================================================
function api_remove_domain()
    if not require_admin_auth() then return end

    local domain = ngx.var.arg_domain or ngx.var.arg_d
    if not domain then respond_error("domain parameter required") return end

    for _, entry in ipairs(config.domains) do
        local new_domains = {}
        local removed = false
        for _, d in ipairs(entry["domains"]) do
            if d == domain then
                removed = true
            else
                table.insert(new_domains, d)
            end
        end
        if removed then
            entry["domains"] = new_domains
            save_domains()
            respond_success("域名 " .. domain .. " 已移除")
            return
        end
    end

    respond_error("Domain not found: " .. domain, 404)
end

-- ============================================================
-- 11. Site stats from total.json
-- ============================================================
function api_site_stats(site_name)
    if not require_admin_auth() then return end

    local stats = config.load_json("total.json")
    local site_stats = {}
    if stats and stats.sites and stats.sites[site_name] then
        site_stats = stats.sites[site_name]
    end

    -- Compute totals
    local total_hits = 0
    for _, c in pairs(site_stats) do total_hits = total_hits + c end

    respond_success("ok", {
        site = site_name,
        hits = site_stats,
        total = total_hits
    })
end

-- ============================================================
-- 12. Get rules by type (with cn format conversion)
-- ============================================================
function api_get_rules(rule_type)
    if not require_admin_auth() then return end

    local allowed = {"args", "post", "url", "cookie", "user_agent",
                     "ip_black", "ip_white", "url_black", "url_white",
                     "scan_black", "cc_uri_white", "head_white", "cn", "referer"}
    local valid = false
    for _, t in ipairs(allowed) do if t == rule_type then valid = true; break end end
    if not valid then respond_error("Invalid rule type: " .. rule_type) return end

    local rules = load_rules(rule_type)

    -- Convert cn format [[start_ip],[end_ip]] to standard [1, "start-end", "name", 0]
    if rule_type == "cn" and rules and #rules > 0 then
        local converted = {}
        for _, range in ipairs(rules) do
            if type(range) == "table" and range[1] and range[2] then
                local start_str = table.concat(range[1], ".")
                local end_str = table.concat(range[2], ".")
                table.insert(converted, {1, start_str .. "-" .. end_str, "中国IP段", 0})
            end
        end
        rules = converted
    end

    respond_success("ok", {type = rule_type, rules = rules, count = #rules})
end

-- ============================================================
-- 13. Update rules (with cn format conversion)
-- ============================================================
function api_update_rules(rule_type)
    if not require_admin_auth() then return end

    local allowed = {"args", "post", "url", "cookie", "user_agent",
                     "ip_black", "ip_white", "url_black", "url_white",
                     "scan_black", "cc_uri_white", "head_white", "cn", "referer"}
    local valid = false
    for _, t in ipairs(allowed) do if t == rule_type then valid = true; break end end
    if not valid then respond_error("Invalid rule type") return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, new_rules = pcall(json.decode, body)
    if not ok or type(new_rules) ~= "table" then
        respond_error("Invalid rules JSON format") return
    end

    -- Convert standard [1, "start-end", "name", 0] back to [[start_ip],[end_ip]] for cn
    if rule_type == "cn" then
        local cn_rules = {}
        for _, rule in ipairs(new_rules) do
            local range_str = rule[2] or ""
            local dash = string.find(range_str, "-", 1, true)
            if dash then
                local start_str = string.sub(range_str, 1, dash - 1)
                local end_str = string.sub(range_str, dash + 1)
                local start_parts = arrip(start_str)
                local end_parts = arrip(end_str)
                if start_parts and end_parts then
                    table.insert(cn_rules, {start_parts, end_parts})
                end
            end
        end
        new_rules = cn_rules
    end

    local json_str = json.encode(new_rules)
    config.write_file(config.root .. "rule/" .. rule_type .. ".json", json_str)
    respond_success("规则已更新", {type = rule_type, count = #new_rules})
end

-- ============================================================
-- 14. List blocked IPs
-- ============================================================
function api_list_blocked()
    if not require_admin_auth() then return end

    local keys = ngx.shared.waf_drop:get_keys(0)
    local blocked = {}
    for _, key in ipairs(keys) do
        local count = ngx.shared.waf_drop:get(key)
        if count then
            table.insert(blocked, {ip = key, violations = count})
        end
    end
    table.sort(blocked, function(a, b) return a.violations > b.violations end)

    respond_success("ok", {total = #blocked, ips = blocked})
end

-- ============================================================
-- 15. Unblock an IP
-- ============================================================
function api_unblock_ip()
    if not require_admin_auth() then return end

    local target_ip = ngx.var.arg_ip
    if not target_ip or not is_valid_ip(target_ip) then
        respond_error("Invalid IP address") return
    end
    ngx.shared.waf_drop:delete(target_ip)
    respond_success("IP " .. target_ip .. " 已解封")
end

-- ============================================================
-- 16. Clear all blocked IPs
-- ============================================================
function api_clear_blocked()
    if not require_admin_auth() then return end

    local keys = ngx.shared.waf_drop:get_keys(0)
    for _, key in ipairs(keys) do
        ngx.shared.waf_drop:delete(key)
    end

    local cache_key = config.root .. "stop_ip"
    ngx.shared.waf_cache:delete(cache_key)

    respond_success("所有封锁 IP 已解除", {cleared = #keys})
end

-- ============================================================
-- 17. Get logs
-- ============================================================
function api_get_logs()
    if not require_admin_auth() then return end

    local log_path = config.config.logs_path or (config.root .. "logs")
    local date = ngx.var.arg_date or ngx.today()
    local server = ngx.var.arg_server or server_name
    local max_lines = tonumber(ngx.var.arg_lines) or 200

    local filename = log_path .. "/" .. server .. "_" .. date .. ".log"
    local fp = io.open(filename, "r")
    if not fp then
        respond_success("ok", {logs = {}, server = server, date = date})
        return
    end

    local lines = {}
    for line in fp:lines() do
        table.insert(lines, line)
        if #lines > max_lines then table.remove(lines, 1) end
    end
    fp:close()

    respond_success("ok", {logs = lines, server = server, date = date, count = #lines})
end

-- ============================================================
-- 18. Get log file list (available dates per site)
-- ============================================================
function api_log_files()
    if not require_admin_auth() then return end

    local log_path = config.config.logs_path or (config.root .. "logs")
    local files = {}
    local fp = io.popen("ls \"" .. log_path .. "\" 2>/dev/null")
    if fp then
        for line in fp:lines() do
            table.insert(files, line)
        end
        fp:close()
    end
    table.sort(files)

    -- Parse into site/date structure
    local log_index = {}
    for _, fname in ipairs(files) do
        -- Format: sitename_YYYY-MM-DD.log
        local site, date = string.match(fname, "^(.+)_(%d%d%d%d%-%d%d%-%d%d)%.log$")
        if site and date then
            if not log_index[site] then log_index[site] = {} end
            table.insert(log_index[site], date)
        end
    end

    respond_success("ok", {files = log_index})
end

-- ============================================================
-- 19. Test a rule against a payload
-- ============================================================
function api_debug()
    if not require_admin_auth() then return end
    local info = {
        config_type = type(config),
        config_config_type = type(config.config),
        config_keys = {},
        sample = {}
    }
    if type(config.config) == "table" then
        for k, _ in pairs(config.config) do table.insert(info.config_keys, k) end
        table.sort(info.config_keys)
        info.sample.open = config.config.open
        info.sample.uri = config.config.uri
        info.sample.args = config.config.args
        info.sample.retry = config.config.retry
        info.sample.cc = config.config.cc
        info.sample.disable_path = config.config.disable_path
        info.sample.admin_ips = config.config.admin_ips
    end
    respond_success("debug", info)
end

function api_test_rule()
    if not require_admin_auth() then return end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then respond_error("No request body") return end

    local ok, data = pcall(json.decode, body)
    if not ok then respond_error("Invalid JSON") return end

    local pattern = data.pattern
    local payload = data.payload
    if not pattern or not payload then
        respond_error("pattern and payload are required") return
    end

    local matched = ngx_match(payload, pattern, "isjo")
    respond_success("ok", {matched = matched ~= nil, pattern = pattern, payload = payload})
end

-- ============================================================
-- 20. WAF status / health check
-- ============================================================
function api_status()
    respond_json({
        success = true,
        status = "running",
        shared_dicts = {
            waf_cache = {keys = #ngx.shared.waf_cache:get_keys(0)},
            waf_drop = {keys = #ngx.shared.waf_drop:get_keys(0)}
        },
        config = {
            open = config.config.open,
            cc = config.config.cc.open,
            scan = config.config.scan.open,
            webshell = config.config.webshell_open
        },
        sites = table_count(config.site_config),
        domains = #config.domains,
        server = ngx.var.server_name
    })
end

-- ============================================================
-- Router: dispatch /waf/admin/* requests
-- ============================================================
function handle_admin_api()
    local uri_path = ngx.var.uri

    -- Check if URI starts with /waf/admin
    local base = "/waf/admin"
    if string.sub(uri_path, 1, #base) ~= base then return false end

    -- Compute route: strip "/waf/admin" prefix and leading slash
    local route = string.sub(uri_path, #base + 1)
    local qmark = string.find(route, "?", 1, true)
    if qmark then route = string.sub(route, 1, qmark - 1) end
    -- Normalize: strip leading slash
    if string.sub(route, 1, 1) == "/" then route = string.sub(route, 2) end

    -- Health check (no auth)
    if route == "status" then api_status(); return true end

    -- Serve admin HTML
    if route == "" or route == "/" then
        if ngx.req.get_method() == "GET" then
            local admin_path = config.config.reqfile_path .. "/admin.html"
            local html = config.read_file(admin_path)
            if html then
                ngx.header.content_type = "text/html; charset=utf-8"
                ngx.say(html)
                ngx.exit(200)
            else
                respond_error("Admin page not found", 404)
            end
            return true
        end
    end

    if route == "dashboard" then api_dashboard(); return true end

    -- All other routes require auth
    if not require_admin_auth() then return true end

    -- Route patterns: longer/more specific first
    if route == "config" then
        if ngx.req.get_method() == "GET" then api_get_config()
        elseif ngx.req.get_method() == "PUT" then api_update_config()
        else respond_error("Method not allowed", 405) end

    elseif route == "sites" then
        if ngx.req.get_method() == "GET" then api_list_sites()
        elseif ngx.req.get_method() == "POST" then api_create_site()
        else respond_error("Method not allowed", 405) end

    elseif string.find(route, "^sites/") then
        local rest = string.sub(route, 7)
        -- Parse: sites/{name}/stats or sites/{name}
        local site_name, sub = string.match(rest, "^([^/]+)/(.+)$")
        if site_name and sub == "stats" then
            api_site_stats(site_name)
        elseif site_name and sub == "detail" then
            api_get_site_detail(site_name)
        else
            site_name = rest  -- just "sites/{name}"
            if ngx.req.get_method() == "GET" then api_get_site_detail(site_name)
            elseif ngx.req.get_method() == "PUT" then api_update_site(site_name)
            elseif ngx.req.get_method() == "DELETE" then api_delete_site(site_name)
            else respond_error("Method not allowed", 405) end
        end

    elseif route == "domains" then
        if ngx.req.get_method() == "POST" then api_add_domain()
        elseif ngx.req.get_method() == "DELETE" then api_remove_domain()
        else respond_error("Method not allowed", 405) end

    elseif string.find(route, "^rules/") then
        local rule_type = string.sub(route, 7)
        if ngx.req.get_method() == "GET" then api_get_rules(rule_type)
        elseif ngx.req.get_method() == "PUT" then api_update_rules(rule_type)
        else respond_error("Method not allowed", 405) end

    elseif route == "blocked" then
        if ngx.req.get_method() == "GET" then api_list_blocked()
        else respond_error("Method not allowed", 405) end

    elseif route == "unblock" then api_unblock_ip()
    elseif route == "clear-blocked" then api_clear_blocked()
    elseif route == "logs" then api_get_logs()
    elseif route == "log-files" then api_log_files()
    elseif route == "test-rule" then api_test_rule()
    elseif route == "debug" then api_debug()

    else
        respond_error("Unknown API endpoint: " .. route, 404)
    end

    return true
end

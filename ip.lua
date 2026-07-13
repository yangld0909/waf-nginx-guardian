-- ip.lua - IP management module
-- Whitelist, blacklist, geo-blocking, and graduated blocking escalation

-- ============================================================
-- IP Whitelist
-- ============================================================
function check_ip_whitelist()
    for _, rule in ipairs(ip_white_rules) do
        if compare_ip(ip, rule) then
            return true
        end
    end
    return false
end

-- ============================================================
-- IP Blacklist
-- ============================================================
function check_ip_blacklist()
    for _, rule in ipairs(ip_black_rules) do
        if compare_ip(ip, rule) then
            write_log("ip_black", "IP黑名单拦截")
            deny_request(config.config["cc"]["status"], "block by firewall")
            return true
        end
    end
    return false
end

-- ============================================================
-- Geo-blocking (drop non-China IPs)
-- cnlist contains Chinese IP ranges; IPs NOT in the list are blocked
-- ============================================================
function check_geo_block()
    if ip == "unknown" then return false end
    if string.find(ip, ":") then return false end

    local cfg = config.config["drop_abroad"]
    if not cfg["open"] or not get_site_config("drop_abroad") then return false end

    for _, v in ipairs(cnlist) do
        if compare_ip(ip, v) then return false end
    end
    write_log("drop_abroad", "境外IP拦截")
    deny_request(cfg["status"], "block by firewall")
    return true
end

-- ============================================================
-- Client IP extraction with CDN support
-- ============================================================
function get_client_ip()
    local client_ip = "unknown"
    local site = config.site_config[server_name]

    if site and site["cdn"] then
        for _, header_name in ipairs(site["cdn_header"]) do
            local header_val = request_header[header_name]
            if header_val and header_val ~= "" then
                if type(header_val) == "table" then
                    header_val = header_val[1]
                end
                client_ip = split(header_val, ",")[1]
                if client_ip and is_valid_ip(client_ip) then
                    break
                end
            end
        end
    end

    if not client_ip or not is_valid_ip(client_ip) then
        client_ip = ngx.var.remote_addr
    end
    if not client_ip then client_ip = "unknown" end

    return client_ip
end

-- ============================================================
-- IP drop/safety counter management
-- ============================================================
function init_ip_drop_counters()
    -- These are initialized per-request in run_guardian
end

function increment_danger_score()
    local key = ip .. ":danger"
    local count, _ = ngx.shared.waf_stats:get(key)
    if count then
        ngx.shared.waf_stats:incr(key, 1)
    else
        ngx.shared.waf_stats:set(key, 1, 86400)
    end
end

function increment_normal_score()
    local key = ip .. ":normal"
    local count, _ = ngx.shared.waf_stats:get(key)
    if count then
        ngx.shared.waf_stats:incr(key, 1)
    else
        ngx.shared.waf_stats:set(key, 1, 1800)
    end
end

-- ============================================================
-- Graduated blocking logic
-- ============================================================
function escalate_block(type_name, reason)
    local retry_cfg = config.config["retry"]
    local retry_cycle = config.config["retry_cycle"]
    local retry_time = config.config["retry_time"]
    local endtime = config.config["cc"]["endtime"]

    -- Override with site config if available
    local site = config.site_config[server_name]
    if site then
        if site["retry"] then retry_cfg = site["retry"] end
        if site["retry_cycle"] then retry_cycle = site["retry_cycle"] end
        if site["retry_time"] then retry_time = site["retry_time"] end
        if site["cc"] and site["cc"]["endtime"] then endtime = site["cc"]["endtime"] end
    end

    local drop_count, _ = ngx.shared.waf_drop:get(ip)
    if not drop_count then
        ngx.shared.waf_drop:set(ip, 1, retry_cycle)
        return
    end

    ngx.shared.waf_drop:incr(ip, 1)
    drop_count = drop_count + 1

    if drop_count >= retry_cfg then
        local sum_count, _ = ngx.shared.waf_stats:get(ip .. ":sum")
        if not sum_count then
            ngx.shared.waf_stats:set(ip .. ":sum", 1, 86400)
            sum_count = 1
        else
            ngx.shared.waf_stats:incr(ip .. ":sum", 1)
            sum_count = sum_count + 1
        end

        local lock_time = retry_time * sum_count
        if lock_time > 86400 then lock_time = 86400 end

        ngx.shared.waf_drop:set(ip, retry_cfg + 1, lock_time)
        increment_danger_score()

        -- Persist to stop_ip.json so block survives Nginx restart
        insert_stop_ip(ip, lock_time, server_name)

        write_log(type_name, reason, "封锁 " .. lock_time .. " 秒")
        record_drop_event(type_name, lock_time)
    end
end

-- ============================================================
-- IP drop check (is this IP already blocked?)
-- ============================================================
function check_ip_dropped()
    local count, _ = ngx.shared.waf_drop:get(ip)
    if not count then return false end
    if count > config.config["retry"] then
        write_log("drop", "IP已被封锁,再次访问")
        deny_request(config.config["cc"]["status"], "block by firewall")
        return true
    end
    return false
end

-- ============================================================
-- Persistent IP blocklist management
-- ============================================================
function insert_stop_ip(ip_addr, lock_time, site)
    if lock_time < 300 then return false end

    local cache_key = config.root .. "stop_ip"
    local cached, _ = ngx.shared.waf_cache:get(cache_key)
    local ip_data
    if cached then
        ip_data = json.decode(cached)
    else
        ip_data = config.load_json("stop_ip.json")
        if not ip_data then ip_data = {} end
    end

    -- Check/update existing entry
    local found = false
    for _, entry in ipairs(ip_data) do
        if entry["ip"] == ip_addr then
            entry["time"] = lock_time
            entry["timeout"] = os.time() + lock_time
            found = true
            break
        end
    end

    if not found then
        table.insert(ip_data, {
            ip = ip_addr,
            time = lock_time,
            timeout = os.time() + lock_time,
            site = site or server_name
        })
    end

    local encoded = json.encode(ip_data)
    ngx.shared.waf_cache:set(cache_key, encoded, 18000)
    -- Deferred write to disk
    if not ngx.shared.waf_cache:get(cache_key .. ":lock") then
        ngx.shared.waf_cache:set(cache_key .. ":lock", 1, 5)
        config.write_file(config.root .. "stop_ip.json", encoded)
    end
end

-- ============================================================
-- Administrative endpoints (127.0.0.1 only)
-- ============================================================
function handle_admin_routes()
    local uri_check = split(request_uri, "?")
    if not uri_check[1] then return false end

    if ngx.var.remote_addr ~= "127.0.0.1" then return false end

    if uri_check[1] == "/get_drop_ip" then
        local data = ngx.shared.waf_drop:get_keys(0)
        deny_json(200, data)
    elseif uri_check[1] == "/remove_drop_ip" then
        local target = uri_request_args["ip"]
        if not target or not is_valid_ip(target) then
            deny_json(200, {status = false, msg = "格式错误"})
        end
        ngx.shared.waf_drop:delete(target)
        deny_json(200, {status = true, msg = target .. " 已解封"})
    elseif uri_check[1] == "/clean_drop_ip" then
        local keys = ngx.shared.waf_drop:get_keys(0)
        for _, k in ipairs(keys) do
            ngx.shared.waf_drop:delete(k)
        end
        deny_json(200, {status = true, msg = "所有封锁 IP 已解除"})
    end
    return false
end

-- ============================================================
-- Method validation
-- ============================================================
function validate_method()
    local method_types = config.config["method_type"]
    if not method_types then return true end

    for _, entry in ipairs(method_types) do
        if method == entry[1] then
            if entry[2] then return true end
            return false
        end
    end
    return false
end

-- ============================================================
-- Header length validation
-- ============================================================
function validate_header_lengths()
    local conf = config.config
    if not conf["header_len"] then return true end

    for header_name, header_value in pairs(request_header) do
        if type(header_value) == "string" then
            local hdr = string.lower(header_name)
            for _, rule in ipairs(conf["header_len"]) do
                if hdr == string.lower(rule[1]) then
                    if #header_value > tonumber(rule[2]) then
                        deny_request(403, "Header " .. header_name .. " too long")
                        return false
                    end
                end
            end
            -- Default max 4096
            if #header_value > 4096 then
                deny_request(403, "Header " .. header_name .. " too long")
                return false
            end
        end
    end
    return true
end

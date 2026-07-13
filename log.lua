-- log.lua - Logging system
-- Records WAF events to daily log files and in-memory statistics
-- Supports detailed violation logging with full request context

local json = require "cjson"

-- ============================================================
-- Helper: capture request headers as a flat table
-- ============================================================
function capture_request_headers()
    local headers = ngx.req.get_headers()
    local result = {}
    if not headers then return result end

    for key, val in pairs(headers) do
        if type(val) == "string" then
            -- Skip Cookie value (privacy)
            if key == "cookie" or key == "Cookie" then
                result[key] = "(sensitive)"
            else
                result[key] = val
            end
        elseif type(val) == "table" then
            result[key] = table.concat(val, "; ")
        end
    end
    return result
end

-- ============================================================
-- Helper: capture request body (truncated)
-- ============================================================
function capture_request_body(max_size)
    if method == "GET" then return "" end

    ngx.req.read_body()
    local body_data = ngx.req.get_body_data()
    if not body_data then return "" end

    max_size = max_size or 4096
    if #body_data > max_size then
        return string.sub(body_data, 1, max_size) .. " ...(truncated " .. #body_data .. " bytes)"
    end
    return body_data
end

-- ============================================================
-- HTTP request logging (full request capture)
-- ============================================================
function capture_request_data()
    local data = method .. " " .. request_uri .. " HTTP/1.1\n"

    local headers = ngx.req.get_headers()
    if not headers then return data end

    for key, val in pairs(headers) do
        if type(val) == "string" then
            data = data .. key .. ": " .. val .. "\n"
        elseif type(val) == "table" then
            for _, v in ipairs(val) do
                data = data .. key .. ": " .. v .. "\n"
            end
        end
    end

    data = data .. "\n"

    if method ~= "GET" then
        ngx.req.read_body()
        local body_data = ngx.req.get_body_data()
        if body_data then
            data = data .. body_data
        end
    end

    return data
end

-- ============================================================
-- Resolve the HTTP status code for a given violation category
-- Used by write_log when ngx.status hasn't been set yet
-- ============================================================
function resolve_deny_status(category)
    local cfg = config.config
    local status_map = {
        args      = cfg["args"]       and cfg["args"]["status"],
        get       = cfg["args"]       and cfg["args"]["status"],
        uri       = cfg["uri"]        and cfg["uri"]["status"],
        url       = cfg["uri"]        and cfg["uri"]["status"],
        url_black = cfg["uri"]        and cfg["uri"]["status"],
        uri_find  = 444,
        post      = cfg["post"]       and cfg["post"]["status"],
        cookie    = cfg["cookie"]     and cfg["cookie"]["status"],
        user_agent = cfg["user-agent"] and cfg["user-agent"]["status"],
        scan      = cfg["scan"]       and cfg["scan"]["status"],
        cc        = cfg["cc"]         and cfg["cc"]["status"],
        drop      = cfg["cc"]         and cfg["cc"]["status"],
        drop_abroad = cfg["drop_abroad"] and cfg["drop_abroad"]["status"],
        ip_black  = cfg["cc"]         and cfg["cc"]["status"],
        other     = cfg["other"]      and cfg["other"]["status"],
        head      = 444,
    }
    return status_map[category] or 403
end

-- ============================================================
-- Write log entry (enhanced with detailed context)
-- ============================================================
function write_log(category, rule_name, detail)
    increment_danger_score()

    -- Track IP drop count for graduated blocking
    local count, _ = ngx.shared.waf_drop:get(ip)
    local cur_count
    if count then
        cur_count = ngx.shared.waf_drop:incr(ip, 1)
        -- incr() does NOT extend TTL, so reset it explicitly
        if cur_count then
            ngx.shared.waf_drop:set(ip, cur_count, config.config["retry_cycle"])
        end
    else
        ngx.shared.waf_drop:set(ip, 1, config.config["retry_cycle"])
        cur_count = 1
    end

    -- Check if logging is enabled
    if config.config["log"] ~= true or get_site_config("log") ~= true then
        return false
    end

    local log_rule = rule_name
    local match_pattern = ""
    local matched_param = ""
    local matched_value = ""
    if error_rule then
        log_rule = error_rule
        error_rule = nil
        -- Parse "pattern >> key=value" from match_rules
        local arrow_pos = string.find(log_rule, " >> ", 1, true)
        if arrow_pos then
            match_pattern = string.sub(log_rule, 1, arrow_pos - 1)
            local kv = string.sub(log_rule, arrow_pos + 4)
            local eq_pos = string.find(kv, "=", 1, true)
            if eq_pos then
                matched_param = string.sub(kv, 1, eq_pos - 1)
                matched_value = string.sub(kv, eq_pos + 1)
            else
                matched_param = kv
            end
        end
    end

    local log_type = rule_type or category
    rule_type = nil

    -- Build core log entry
    local log_entry = {
        time = ngx.localtime(),
        ip = ip,
        method = method,
        uri = request_uri,
        ua = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",
        xff = ngx.var.http_x_forwarded_for or "",
        server = server_name,
        status = (ngx.status and ngx.status ~= 200) and ngx.status or resolve_deny_status(category),
        category = category,
        rule = log_rule,
        detail = detail or "",
        type = log_type
    }

    -- Add structured match info (if available from rule matching)
    if match_pattern ~= "" then
        log_entry.match_pattern = match_pattern
        log_entry.match_param = matched_param
        log_entry.match_value = matched_value
    end

    -- Detail logging: full request context (opt-in via config)
    if config.config["detail_log"] then
        log_entry.headers = capture_request_headers()
        log_entry.request_body = capture_request_body(4096)
    end

    local log_line = json.encode(log_entry) .. "\n"

    -- Check for escalation to IP block
    if cur_count and cur_count > config.config["retry"] - 1 and category ~= "cc" then
        local sum_key = ip .. ":sum"
        local sum_count, _ = ngx.shared.waf_stats:get(sum_key)
        if not sum_count then
            ngx.shared.waf_stats:set(sum_key, 1, 86400)
            sum_count = 1
        else
            ngx.shared.waf_stats:incr(sum_key, 1)
            sum_count = sum_count + 1
        end

        local lock_time = config.config["retry_time"] * sum_count
        if lock_time > 86400 then lock_time = 86400 end

        ngx.shared.waf_drop:set(ip, config.config["retry"] + 1, lock_time)

        -- Persist to stop_ip.json so block survives Nginx restart
        insert_stop_ip(ip, lock_time, server_name)

        local escalate_entry = {
            time = ngx.localtime(),
            ip = ip,
            method = method,
            uri = request_uri,
            ua = ngx.var.http_user_agent or "",
            referer = ngx.var.http_referer or "",
            xff = ngx.var.http_x_forwarded_for or "",
            server = server_name,
            category = category,
            rule = config.config["retry_cycle"] .. "秒内累计超过" .. config.config["retry"] .. "次违规,封锁" .. lock_time .. "秒"
        }
        if config.config["detail_log"] then
            escalate_entry.headers = capture_request_headers()
            escalate_entry.request_body = capture_request_body(4096)
        end
        log_line = log_line .. json.encode(escalate_entry) .. "\n"
    end

    write_to_logfile(log_line)
    update_statistics(category, rule_name or "")
end

-- ============================================================
-- Write to daily log file
-- ============================================================
function write_to_logfile(log_line)
    local log_path = config.config["logs_path"]
    if not log_path then return false end

    local filename = log_path .. "/" .. server_name .. "_" .. ngx.today() .. ".log"
    local fp = io.open(filename, "ab")
    if not fp then
        -- Try to create the log directory and retry
        os.execute("mkdir \"" .. log_path .. "\" 2>nul")
        fp = io.open(filename, "ab")
        if not fp then return false end
    end

    fp:write(log_line)
    fp:flush()
    fp:close()
    return true
end

-- ============================================================
-- Record IP drop event (enhanced with detailed context)
-- ============================================================
function record_drop_event(is_drop, drop_time)
    local filename = config.root .. "drop_ip.log"
    local fp = io.open(filename, "ab")
    if not fp then return false end

    local entry = {
        timestamp = os.time(),
        time = ngx.localtime(),
        ip = ip,
        server = server_name,
        uri = request_uri,
        duration = drop_time,
        type = is_drop,
        method = method,
        ua = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",
        xff = ngx.var.http_x_forwarded_for or "",
        status = (ngx.status and ngx.status ~= 200) and ngx.status or resolve_deny_status(is_drop),
        rule = error_rule or "",
        request = capture_request_data()
    }
    error_rule = nil

    if config.config["detail_log"] then
        entry.headers = capture_request_headers()
        entry.request_body = capture_request_body(4096)
    end

    fp:write(json.encode(entry) .. "\n")
    fp:flush()
    fp:close()
    return true
end

-- ============================================================
-- In-memory statistics (total.json)
-- ============================================================
function update_statistics(category, rule)
    local total_path = config.root .. "total.json"
    local cached = ngx.shared.waf_cache:get(total_path)
    local totals

    if cached then
        totals = json.decode(cached) or {}
    else
        totals = config.load_json("total.json")
        if not totals then totals = {} end
    end

    if not totals["sites"] then totals["sites"] = {} end
    if not totals["sites"][server_name] then totals["sites"][server_name] = {} end
    if not totals["sites"][server_name][category] then
        totals["sites"][server_name][category] = 0
    end
    if not totals["rules"] then totals["rules"] = {} end
    if not totals["rules"][category] then totals["rules"][category] = 0 end
    if not totals["total"] then totals["total"] = 0 end

    totals["total"] = totals["total"] + 1
    totals["sites"][server_name][category] = totals["sites"][server_name][category] + 1
    totals["rules"][category] = totals["rules"][category] + 1

    local encoded = json.encode(totals)
    ngx.shared.waf_cache:set(total_path, encoded)

    -- Deferred disk write (every 5 seconds max)
    if not ngx.shared.waf_cache:get("total_write_lock") then
        ngx.shared.waf_cache:set("total_write_lock", 1, 5)
        config.write_file(total_path, encoded)
    end
end

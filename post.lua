-- post.lua - POST parameter filtering and upload validation

local ngx_match = ngx.re.find
local multipart = require("multipart")

-- ============================================================
-- Nested table flattener for JSON POST data
-- ============================================================
function flatten_json_args(json_args, target)
    if type(json_args) ~= "table" then return {} end
    local t = target or {}

    for k, v in pairs(json_args) do
        if type(v) == "table" then
            for _k, _v in pairs(v) do
                if type(_v) == "table" then
                    flatten_json_args(_v, t)
                elseif type(t[k]) == "table" then
                    table.insert(t[k], _v)
                elseif type(t[k]) == "string" then
                    local tmp = {t[k], _v}
                    t[k] = tmp
                else
                    t[k] = _v
                end
            end
        elseif type(t[k]) == "table" then
            table.insert(t[k], v)
        elseif type(t[k]) == "string" then
            local tmp = {t[k], v}
            t[k] = tmp
        else
            t[k] = v
        end
    end
    return t
end

-- ============================================================
-- POST argument count check
-- ============================================================
function count_params(t)
    local n = 0
    for _,_ in pairs(t) do n = n + 1 end
    return n
end

-- ============================================================
-- Main POST body check (application/x-www-form-urlencoded + JSON)
-- ============================================================
function check_post_body()
    if not config.config["post"]["open"] or not get_site_config("post") then
        return false
    end
    if method == "GET" then return false end

    local content_length = tonumber(request_header["content-length"])
    if not content_length then return false end

    local content_type = request_header["content-type"]
    if not content_type then return false end
    if type(content_type) ~= "string" then return false end

    -- Skip multipart (handled separately)
    if ngx_match(content_type, "multipart", "oij") then return false end

    ngx.req.read_body()
    local post_args = ngx.req.get_post_args(1000000)
    if not post_args then
        -- Buffer overflow protection
        if content_length > 10000 then
            deny_request(403, "POST body too large for buffer")
            return true
        end
        return true
    end

    -- Check individual parameter length
    for k, v in pairs(post_args) do
        if type(v) == "string" and #v >= 200000 then
            write_log("post", k .. " 参数值长度超过20万")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    end

    -- JSON content-type handling
    if ngx_match(content_type, "^application/json", "oij") and
       request_header["content-length"] and
       tonumber(request_header["content-length"]) ~= 0 then

        local ok, json_args = pcall(function()
            return json.decode(ngx.req.get_body_data())
        end)

        if not ok then
            deny_request(403, "JSON格式错误")
            return true
        end
        if type(json_args) ~= "table" then return false end

        json_args = flatten_json_args(json_args)
        if match_rules(post_rules, json_args, "post") then
            write_log("post", "JSON POST规则拦截")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
        -- Semantic analysis on JSON POST body
        if semantic_sql_scan_params(json_args) then
            write_log("post", "语义分析出SQL注入")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    else
        -- x-www-form-urlencoded
        if count_params(post_args) >= 800 then
            write_log("post", "POST参数超过800个")
            deny_request(403, "POST参数过多")
            return true
        end

        if match_rules(post_rules, post_args, "post") then
            if not check_false_positive() then
                write_log("post", "POST规则拦截")
                deny_request(config.config["post"]["status"], resp_html["post"])
                return true
            end
        end
        -- Semantic analysis on urlencoded POST body
        if semantic_sql_scan_params(post_args) then
            write_log("post", "语义分析出SQL注入")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    end

    return false
end

-- ============================================================
-- False positive mitigation
-- If an IP has many normal requests and few blocks, allow one pass
-- ============================================================
function check_false_positive()
    local normal = ngx.shared.waf_stats:get(ip .. ":normal")
    if not normal then return false end

    local danger = ngx.shared.waf_stats:get(ip .. ":danger")
    if not danger then return false end

    if normal > 30 and danger == 1 then
        local pass_key = ip .. ":fp_pass"
        if ngx.shared.waf_stats:get(pass_key) then
            return false
        end
        ngx.shared.waf_stats:set(pass_key, 1, 1800)
        return true
    end
    return false
end

-- ============================================================
-- Multipart/form-data validation & upload scanning
-- ============================================================
function check_multipart_upload()
    if not config.config["post"]["open"] or not get_site_config("post") then
        return false
    end
    if method ~= "POST" then return false end

    local content_length = tonumber(request_header["content-length"])
    if not content_length then return false end
    if content_length > 108246867 then return false end -- ~100MB

    local boundary = get_boundary_header()
    if not boundary then return false end

    ngx.req.read_body()
    local body_data = ngx.req.get_body_data()
    if not body_data then
        local file_path = ngx.req.get_body_file()
        if file_path then
            body_data = config.read_file(file_path)
        end
    end
    if not body_data then return false end

    -- Parse multipart
    local parser, err = multipart.new(body_data, request_header["content-type"])
    if not parser then return false end

    local fields = {}
    local file_count = 0

    while true do
        local part_body, name, mime, filename, raw_header = parser:parse_part()
        if not raw_header then break end

        -- Check filename in raw header
        if filename then
            file_count = file_count + 1
            local ext = string.lower(string.match(filename, "%.([^%.]+)$") or "")
            if check_disallowed_upload_ext(ext) then
                block_ip("disable_upload_ext", "上传非法文件: " .. ext)
                return true
            end

            -- Check file content for webshell signatures
            if part_body and #part_body > 0 then
                if check_webshell_content(part_body) then
                    block_ip("disable_upload_ext", "WebShell上传拦截")
                    return true
                end
            end
        end

        -- Store non-file fields
        if name and not filename then
            if #name > 300 then
                deny_request(403, "参数名过长")
                return true
            end
            fields[name] = part_body
        end

        -- Check parameter value length
        if part_body and type(part_body) == "string" and #part_body >= 200000 then
            write_log("post", "参数值超过20万")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    end

    -- Check for ThinkPHP RCE via multipart
    if check_thinkphp_multipart(fields) then return true end

    -- Run POST rules on collected fields
    if match_rules(post_rules, fields, "post") then
        if not check_false_positive() then
            write_log("post", "Multipart POST规则拦截")
            deny_request(config.config["post"]["status"], resp_html["post"])
            return true
        end
    end

    -- Semantic analysis on multipart fields
    if semantic_sql_scan_params(fields) then
        write_log("post", "语义分析出SQL注入")
        deny_request(config.config["post"]["status"], resp_html["post"])
        return true
    end

    return false
end

-- ============================================================
-- Extract boundary from Content-Type header
-- ============================================================
function get_boundary_header()
    local ct = request_header["content-type"]
    if not ct then return nil end
    if type(ct) == "table" then
        deny_request(200, "Content-Type格式错误")
        return nil
    end

    if ngx_match(ct, "multipart", "ijo") then
        if not ngx_match(ct, "^multipart/form-data; boundary=") then
            deny_request(200, "Content-Type格式错误")
            return nil
        end
        return ct
    end
    return nil
end

-- ============================================================
-- Disallowed upload extension check
-- ============================================================
function check_disallowed_upload_ext(ext)
    if not ext then return false end
    ext = string.lower(ext)

    local disallowed = {}
    -- 全局 (config.json)
    if config.config["disable_upload_ext"] then
        for _, e in ipairs(config.config["disable_upload_ext"]) do table.insert(disallowed, e) end
    end
    -- 站点叠加 (site.json)
    local site = config.site_config[server_name]
    if site and site["disable_upload_ext"] then
        for _, e in ipairs(site["disable_upload_ext"]) do table.insert(disallowed, e) end
    end
    if #disallowed == 0 then return false end

    for _, banned in ipairs(disallowed) do
        if ext == string.lower(banned) then
            return true
        end
    end
    return false
end

-- ============================================================
-- WebShell content scanning
-- ============================================================
function check_webshell_content(part_body)
    if type(part_body) ~= "string" then return false end

    local patterns = {
        "phpinfo\\(\\)", "\\$_SERVER", "<\\?php", "fputs",
        "file_put_contents", "file_get_contents", "eval\\(",
        "\\$_POST", "\\$_GET", "base64_decode\\(", "\\$_REQUEST",
        "assert\\(", "copy\\(", "create_function\\(",
        "preg_replace\\(.*e", "system\\(", "curl_init\\(",
        "curl_error\\(", "fopen\\(", "stream_context_create\\(",
        "fsockopen\\("
    }

    for _, pattern in ipairs(patterns) do
        if ngx_match(part_body, pattern, "ijo") then
            return true
        end
    end
    return false
end

-- ============================================================
-- ThinkPHP RCE detection in multipart fields
-- ============================================================
function check_thinkphp_multipart(fields)
    if fields["_method"] and fields["method"] and fields["server[REQUEST_METHOD]"] then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    if fields["_method"] and fields["method"] and fields["server[]"] and fields["get[]"] then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    if fields["_method"] and ngx_match(fields["_method"], "construct", "ijo") then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    return false
end

-- ============================================================
-- Standalone ThinkPHP detection for urlencoded POST
-- ============================================================
function check_thinkphp_rce()
    if method ~= "POST" then return false end

    ngx.req.read_body()
    local data = ngx.req.get_post_args()
    if not data then return false end

    if data["_method"] and data["method"] and data["server[REQUEST_METHOD]"] then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    if data["_method"] and data["method"] and data["server[]"] and data["get[]"] then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    if data["_method"] and ngx_match(data["_method"], "construct", "ijo") then
        block_ip("post", "拦截ThinkPHP 5.x RCE攻击")
        return true
    end
    return false
end

-- ============================================================
-- ThinkPHP 3.x log/sensitive info exposure
-- ============================================================
function check_thinkphp_info_leak()
    local patterns = {
        "^/Application/.+log$", "^/Application/.+php$",
        "^/application/.+log$", "^/application/.+php$",
        "^/Runtime/.+log$", "^/Runtime/.+php$",
        "^/runtime/.+php$", "^/runtime/.+log$"
    }
    for _, pattern in ipairs(patterns) do
        if string.find(uri, pattern) then
            block_ip("args", "拦截ThinkPHP 3.x敏感信息泄露")
            return true
        end
    end
    return false
end

-- ============================================================
-- General blocking with IP escalation
-- ============================================================
function block_ip(type_name, reason)
    rule_type = type_name
    increment_danger_score()
    write_log(type_name, reason)
    escalate_block(type_name, reason)

    local status = config.config["post"]["status"]
    if type_name == "args" then status = config.config["args"]["status"] end
    deny_request(status, "block by firewall")
end

-- ============================================================
-- Apple CMS (maccms) RCE protection
-- ============================================================
function check_maccms_rce()
    if method ~= "POST" then return false end
    if not uri_request_args["m"] then return false end
    if uri_request_args["m"] ~= "vod-search" then return false end

    ngx.req.read_body()
    local data = ngx.req.get_post_args()
    if not data or not data["wd"] then return false end

    if #data["wd"] > 2000 then
        write_log("post", "拦截苹果CMS RCE")
        deny_request(config.config["post"]["status"], resp_html["post"])
        return true
    end
    return false
end

-- ============================================================
-- Transfer-Encoding check (TE chunked attack)
-- ============================================================
function check_transfer_encoding()
    if request_header["transfer-encoding"] then
        block_ip("args", "拦截 Transfer-Encoding 分块请求")
        return true
    end
    return false
end

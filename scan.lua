-- scan.lua - Scanning/attack tool detection

local ngx_match = ngx.re.find

-- ============================================================
-- Scan tool detection
-- Checks for known scanner cookies, URI patterns, and headers
-- ============================================================
function check_scan_tools()
    if not config.config["scan"]["open"] or not get_site_config("scan") then
        return false
    end

    local scan_rules = scan_black_rules
    if not scan_rules then return false end

    -- Check cookie for scanner identifiers
    if scan_rules["cookie"] and request_header["cookie"] then
        if match_rules({scan_rules["cookie"]}, request_header["cookie"], nil) then
            write_log("scan", "扫描工具Cookie拦截")
            deny_request(config.config["scan"]["status"], "block by firewall")
            return true
        end
    end

    -- Check URI for scanner patterns
    if scan_rules["args"] and scan_rules["args"] ~= "" then
        if ngx_match(request_uri, scan_rules["args"], "isjo") then
            write_log("scan", "扫描工具URI拦截")
            deny_request(config.config["scan"]["status"], "block by firewall")
            return true
        end
    end

    -- Check headers for scanner identifiers
    if scan_rules["header"] and scan_rules["header"] ~= "" then
        for key, _ in pairs(request_header) do
            if ngx_match(key, scan_rules["header"], "isjo") then
                write_log("scan", "扫描工具Header拦截")
                deny_request(config.config["scan"]["status"], "block by firewall")
                return true
            end
        end
    end

    return false
end

-- ============================================================
-- GET parameter check
-- ============================================================
function check_get_args()
    if not config.config["args"]["open"] or not get_site_config("args") then
        return false
    end
    if method == "POST" then return false end

    -- Check parameter count
    if count_params(uri_request_args) >= 800 then
        write_log("args", "GET参数超过800个")
        deny_request(403, "参数过多")
        return true
    end

    -- Flatten nested args
    local flat_args = flatten_json_args(uri_request_args)

    -- Match against active rules
    if match_rules(args_rules, flat_args, "args") then
        write_log("args", "GET参数规则拦截")
        deny_request(config.config["args"]["status"], resp_html["get"])
        return true
    end

    -- Semantic analysis (replaces mycomplib2 + mycomplib_xss in original)
    if semantic_sql_scan_params(uri_request_args) then
        write_log("args", "语义分析出SQL注入")
        deny_request(config.config["args"]["status"], resp_html["get"])
        return true
    end
    if semantic_xss_scan_params(uri_request_args) then
        write_log("args", "语义分析出XSS攻击")
        deny_request(config.config["args"]["status"], resp_html["get"])
        return true
    end

    return false
end

-- ============================================================
-- Per-site URL path blocking (叠加上全局 disable_path)
-- ============================================================
function check_site_url_paths()
    local paths = {}
    -- 全局
    if config.config["disable_path"] then
        for _, p in ipairs(config.config["disable_path"]) do table.insert(paths, p) end
    end
    -- 站点叠加
    local site = config.site_config[server_name]
    if site and site["disable_path"] then
        for _, p in ipairs(site["disable_path"]) do table.insert(paths, p) end
    end
    if #paths == 0 then return false end

    for _, pattern in ipairs(paths) do
        if ngx_match(uri, pattern, "isjo") then
            write_log("path", "路径规则拦截")
            deny_request(config.config["other"]["status"], resp_html["other"])
            return true
        end
    end
    return false
end

-- ============================================================
-- Per-site URL extension blocking (叠加上全局 disable_ext)
-- ============================================================
function check_site_url_extensions()
    local exts = {}
    if config.config["disable_ext"] then
        for _, e in ipairs(config.config["disable_ext"]) do table.insert(exts, e) end
    end
    local site = config.site_config[server_name]
    if site and site["disable_ext"] then
        for _, e in ipairs(site["disable_ext"]) do table.insert(exts, e) end
    end
    if #exts == 0 then return false end

    for _, ext in ipairs(exts) do
        if ngx_match(uri, "\\." .. ext .. "$", "isjo") then
            write_log("url_ext", "后缀规则拦截")
            deny_request(config.config["other"]["status"], resp_html["other"])
            return true
        end
    end
    return false
end

-- ============================================================
-- Per-site PHP path blocking (叠加上全局 disable_php_path)
-- ============================================================
function check_site_php_paths()
    local paths = {}
    if config.config["disable_php_path"] then
        for _, p in ipairs(config.config["disable_php_path"]) do table.insert(paths, p) end
    end
    local site = config.site_config[server_name]
    if site and site["disable_php_path"] then
        for _, p in ipairs(site["disable_php_path"]) do table.insert(paths, p) end
    end
    if #paths == 0 then return false end

    local url_data = split(request_uri, "?")
    local clean_uri = url_data[1] or request_uri

    for _, path in ipairs(paths) do
        if ngx_match(clean_uri, path .. "/?.*%.php$", "isjo") then
            write_log("disable_php_path", "目录禁止执行PHP")
            deny_request(403, "当前目录禁止执行PHP文件")
            return true
        end
    end
    return false
end

-- ============================================================
-- Per-site custom URL rule
-- ============================================================
function check_site_custom_url_rules()
    local site = config.site_config[server_name]
    if not site then return false end

    local url_rules = site["url_rule"]
    if not url_rules then return false end

    for _, rule in ipairs(url_rules) do
        if ngx_match(uri, rule[1], "isjo") then
            -- Check GET args
            if match_rules({rule[2]}, uri_request_args, nil) then
                write_log("url_rule", "自定义URL规则拦截")
                deny_request(config.config["other"]["status"], resp_html["other"])
                return true
            end

            -- Check POST args
            if method == "POST" then
                ngx.req.read_body()
                local post_args = ngx.req.get_post_args()
                if post_args and match_rules({rule[2]}, post_args, "post") then
                    write_log("url_rule", "自定义URL规则拦截(POST)")
                    deny_request(config.config["other"]["status"], resp_html["other"])
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- Per-site URL parameter validation
-- ============================================================
function check_site_url_validation()
    local site = config.site_config[server_name]
    if not site then return false end

    local rules = site["url_tell"]
    if not rules then return false end

    for _, rule in ipairs(rules) do
        if ngx_match(uri, rule[1], "isjo") then
            if uri_request_args[rule[2]] ~= rule[3] then
                write_log("url_tell", "URL参数校验失败")
                deny_request(config.config["other"]["status"], resp_html["other"])
                return true
            end
        end
    end
    return false
end

-- ============================================================
-- WebShell file scanning
-- ============================================================
function check_webshell_files()
    if not config.config["webshell_open"] then return false end

    local url_data = split(request_uri, "?")
    if not url_data then return false end
    if url_data[1] == "index.php" or url_data[1] == "index.html" then return false end

    local site_path = resolve_site_path()
    if not site_path then return false end

    local file_path = site_path .. "/" .. url_data[1]
    if not ngx_match(file_path, "php$") then return false end

    -- Check against known webshell list
    local shell_list = config.load_json("../webshell.json")
    if shell_list then
        for _, path in ipairs(shell_list) do
            if tostring(path) == file_path then
                write_log("args", uri .. " 检测为WebShell")
                deny_request(config.config["args"]["status"], resp_html["get"])
                return true
            end
        end
    end

    -- Scan PHP file for dangerous functions
    local cache_key = "webshell:" .. file_path
    if ngx.shared.waf_stats:get(cache_key) then return false end

    local file_data = config.read_file(file_path)
    if not file_data then
        ngx.shared.waf_stats:set(cache_key, "1", 360)
        return false
    end

    local dangerous = {"assert", "eval", "$_GET", "$_POST", "$_REQUEST",
                       "base64_decode", "file_get_contents", "copy"}
    for _, func in ipairs(dangerous) do
        if ngx_match(file_data, func) then
            ngx.shared.waf_stats:set(cache_key, "1", 360)
            return false -- Alert only, don't block purely on static analysis
        end
    end

    ngx.shared.waf_stats:set(cache_key, "1", 360)
    return false
end

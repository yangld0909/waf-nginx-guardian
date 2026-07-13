--[[
body.lua - Response body filter
Intercepts response content and applies find/replace transformations.
Configured via config.json -> body_character_string and body_regular.
]]--

local ngx_match = ngx.re.find

function check_content_type()
    local ct = ngx.header["Content-Type"]
    if not ct then return false end
    if string.find(ct, "text/html") or string.find(ct, "application/json") then
        return true
    end
    return false
end

function is_static_resource()
    local uri = ngx.var.uri
    local exts = {"pdf", "zip", "rar", "gz", "7z", "png", "jpg", "jpeg",
                  "gif", "ico", "css", "js", "swf", "webp", "bmp", "svg"}
    for _, ext in ipairs(exts) do
        if ngx_match(uri, "/?.*%." .. ext .. "$", "isjo") then
            return true
        end
    end
    return false
end

function apply_body_replacements(whole, replacements)
    local changed = false
    for _, pair in ipairs(replacements) do
        for find_str, replace_str in pairs(pair) do
            if type(find_str) == "string" then
                local count
                whole, count = string.gsub(whole, find_str, replace_str)
                if count > 0 then changed = true end
            end
        end
    end
    if changed then ngx.header.content_length = nil end
    return whole
end

function run_body_filter()
    if not check_content_type() then return end
    if is_static_resource() then return end

    local conf = require("config")
    if not conf.config["open"] then return end

    server_name = string.gsub(resolve_server_name(), "_", ".")

    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffered = ngx.ctx.buffered
    if not buffered then
        buffered = {}
        ngx.ctx.buffered = buffered
    end

    if chunk ~= "" then
        buffered[#buffered + 1] = chunk
        ngx.arg[1] = nil
    end

    if eof then
        local whole = table.concat(buffered)
        ngx.ctx.buffered = nil

        -- Global replacements
        local global_replacements = conf.config["body_character_string"]
        if global_replacements and #global_replacements > 0 then
            whole = apply_body_replacements(whole, global_replacements)
        end

        -- Per-site replacements
        local site = conf.site_config[server_name]
        if site and site["body_character_string"] and #site["body_character_string"] > 0 then
            whole = apply_body_replacements(whole, site["body_character_string"])
        end

        ngx.arg[1] = whole
    end
end

-- Run body filter with error protection
local ok, err = pcall(run_body_filter)
if not ok then
    if type(err) == "userdata" then
        -- ngx.exit() abort — re-throw to let ngx_lua handle it
        error(err)
    end
    ngx.log(ngx.ERR, "[Guardian WAF] body_filter error: ", err)
end

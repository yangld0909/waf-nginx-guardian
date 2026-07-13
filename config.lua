-- config.lua - Configuration loading and caching
local json = require "cjson"

local _M = {}

-- project root path (部署时修改为实际路径)
_M.root = "D:/waf_nginx/"

function _M.read_file(filename)
    local fp = io.open(filename, "r")
    if not fp then return nil end
    local body = fp:read("*a")
    fp:close()
    if body == "" then return nil end
    return body
end

function _M.write_file(filename, body)
    local fp = io.open(filename, "w")
    if not fp then return nil end
    fp:write(body)
    fp:flush()
    fp:close()
    return true
end

function _M.load_json(name)
    local body = _M.read_file(_M.root .. name)
    if not body then return {} end
    local ok, data = pcall(json.decode, body)
    if not ok then return {} end
    return data
end

function _M.save_json(name, data)
    _M.write_file(_M.root .. name .. ".json", json.encode(data))
end

-- Global config from config.json
_M.config = _M.load_json("config.json")
-- Per-site config from site.json
_M.site_config = _M.load_json("site.json")
-- Domain mapping
_M.domains = _M.load_json("domains.json")

return _M

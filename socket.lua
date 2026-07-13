--[[
socket.lua - LuaSocket DNS helper module
Used for spider verification via reverse DNS lookup.
Wraps the socket.core C module.
]]

local base = _G
local string = require("string")
local math = require("math")
local socket_core = require("socket.core")

local _M = {}

function _M.dns.tohostname(ip_addr)
    local success, hostname = pcall(socket_core.dns.tohostname, ip_addr)
    if success then
        return hostname
    end
    return nil
end

return _M

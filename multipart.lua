--[[
multipart.lua - Multipart/form-data stream parser
Parses multipart upload body for file validation.

Usage:
    local parser = multipart.new(body_data, content_type_header)
    while true do
        local part_body, name, mime, filename, raw_header = parser:parse_part()
        if not raw_header then break end
        -- process each part
    end
]]

local find = string.find
local sub = string.sub
local re_match = ngx.re.match
local re_find = ngx.re.find

local _M = {}
local mt = { __index = _M }
local match_table = {}

local function get_boundary(header)
    if type(header) == "table" then
        header = header[1]
    end

    match_table[1] = nil
    match_table[2] = nil
    local m, err = re_match(header,
        [[;\s*boundary\s*=\s*(?:"([^"]+)"|([-|+*$&!.%'`~^\#\w]+))]],
        "joi", nil, match_table)
    if m then
        return m[1] or m[2]
    end
    return nil, err
end

function _M.new(body, content_type)
    if not content_type then
        return nil, "no Content-Type header specified"
    end

    local boundary, err = get_boundary(content_type)
    if not boundary then
        if err then return nil, err end
        return nil, "no boundary defined in Content-Type"
    end

    return setmetatable({
        start = 1,
        boundary = "--" .. boundary,
        boundary2 = "\r\n--" .. boundary,
        body = body
    }, mt)
end

function _M.parse_part(self)
    local start = self.start
    local body = self.body

    -- First call: skip past initial boundary
    if start == 1 then
        local fr, to = find(body, self.boundary, 1, true)
        if not fr then return nil end
        start = to + 1
    end

    -- Find header/body separator
    local fr, to = find(body, "\r\n\r\n", start, true)
    if not fr then
        self.start = start
        return nil, "missing header separator"
    end

    local header = sub(body, start, fr + 2)
    start = to + 1

    -- Extract "name" parameter
    match_table[1] = nil
    match_table[2] = nil
    local m = re_match(header,
        [[^Content-Disposition:.*?;\s*name\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
        "joim", nil, match_table)
    local name
    if m then
        name = m[1] or m[2]
    end

    -- Extract "filename" parameter
    m = re_match(header,
        [[^Content-Disposition:.*?;\s*filename\s*=\s*(?:"?([^"]+)"?|([-'\w]+))]],
        "joim", nil, match_table)
    local filename
    if m then
        filename = m[1] or m[2]
    end

    -- Capture raw header for validation
    local is_filename = header

    -- Extract MIME type
    local mime
    local fr2, to2 = re_find(header, [[^Content-Type:\s*([^;\s]+)]], "joim", nil, 1)
    if fr2 then
        mime = sub(header, fr2, to2)
    end

    -- Find closing boundary
    fr, to = find(body, self.boundary2, start, true)
    if not fr then
        self.start = start
        return nil
    end

    local part_body = sub(body, start, fr - 1)
    self.start = to + 3

    return part_body, name, mime, filename, is_filename
end

return _M

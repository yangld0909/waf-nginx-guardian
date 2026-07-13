-- semantics.lua - Semantic analysis engine for SQL injection and XSS
-- Pure Lua replacement for mycomplib.dll
-- Detects attack patterns that regex alone cannot reliably catch:
--   SQL: keyword proximity, quote balancing, comment obfuscation, stacked queries
--   XSS: event handler context, javascript: scheme, DOM sinks, script tag variations

local ngx_match = ngx.re.find
local ngx_find = string.find
local ngx_lower = string.lower
local ngx_gsub = string.gsub

-- ============================================================
-- SQL Injection Semantic Analysis
-- ============================================================

-- SQL keywords that signal injection when combined with user input context
local SQL_KEYWORD_PAIRS = {
    -- [keyword1] = {keyword2, max_distance_in_words, label}
    { "select",   "from",        nil,  "SELECT...FROM" },
    { "union",    "select",      nil,  "UNION...SELECT" },
    { "insert",   "into",        nil,  "INSERT...INTO" },
    { "update",   "set",         nil,  "UPDATE...SET" },
    { "delete",   "from",        nil,  "DELETE...FROM" },
    { "create",   "table",       nil,  "CREATE...TABLE" },
    { "alter",    "table",       nil,  "ALTER...TABLE" },
    { "drop",     "table",       nil,  "DROP...TABLE" },
    { "exec",     "xp_cmdshell", nil,  "EXEC...xp_cmdshell" },
    { "truncate", "table",       nil,  "TRUNCATE...TABLE" },
    { "rename",   "table",       nil,  "RENAME...TABLE" },
    { "load",     "data",        nil,  "LOAD...DATA" },
    { "into",     "outfile",     nil,  "INTO...OUTFILE" },
    { "into",     "dumpfile",    nil,  "INTO...DUMPFILE" },
    { "order",    "by",          nil,  "ORDER...BY" },
    { "group",    "by",          nil,  "GROUP...BY" },
    { "having",   "by",          nil,  "HAVING...BY" },
    { "limit",    "offset",      nil,  "LIMIT...OFFSET" },
    { "for",      "update",      nil,  "FOR...UPDATE" },
}

-- SQL comment markers
local SQL_COMMENTS = { "#", "--", "/*", "*/" }

-- Functions that are almost always malicious in user input
local SQL_DANGEROUS_FUNCTIONS = {
    "load_file",        "into outfile",   "into dumpfile",
    "xp_cmdshell",      "sp_configure",   "exec master",
    "having",            "group_concat",   "concat_ws",
    "extractvalue",     "updatexml",       "name_const",
    "geometrycollection", "multipoint",    "polygon",
    "multipolygon",     "linestring",      "multilinestring",
}

-- ============================================================
-- Normalize SQL input for analysis
-- Strips obfuscation like inline comments, excessive whitespace
-- ============================================================
local function normalize_sql(s)
    if type(s) ~= "string" then return "", 0 end

    -- Remove inline SQL comments (obfuscation): SEL/**/ECT → SELECT
    -- ngx.re.gsub returns (result_string, count_string) — count is a string!
    local removed = 0
    local n, count1_str = ngx_gsub(s, "/%*.-%*/", " ")
    local count1 = tonumber(count1_str) or 0
    if count1 > 0 then
        removed = 1
        -- Check for nested comments (SEL/**/**/ECT)
        local _, count2_str = ngx_gsub(n, "/%*.-%*/", " ")
        if tonumber(count2_str) > 0 then
            removed = 2
        end
    end

    -- Collapse whitespace
    n = ngx_gsub(n, "%s+", " ")

    -- Remove hex encoding variations: 0x... is suspicious
    -- But keep the string for analysis

    -- Lowercase for keyword matching
    return ngx_lower(n), removed
end

-- ============================================================
-- Extract SQL tokens (words and operators)
-- ============================================================
local function tokenize_sql(s)
    local tokens = {}
    for token in ngx_gsub(s, "([%w_]+)", function(w)
        table.insert(tokens, { type = "word", value = w })
        return ""
    end):gmatch("(.)") do
        -- non-word characters as individual tokens
        -- skip
    end
    -- Actually, let's do it properly:
    local i = 1
    while i <= #s do
        -- Skip whitespace
        if ngx_find(s, "^%s", i) then
            i = i + 1
        -- Word
        elseif ngx_find(s, "^[%w_]+", i) then
            local w = ngx_gsub(s:sub(i, i + 50), "^([%w_]+).*$", "%1")
            -- Actually use proper pattern matching
            local _, e, word = ngx_find(s, "([%w_]+)", i)
            if word then
                table.insert(tokens, { type = "word", value = ngx_lower(word) })
                i = e + 1
            else
                -- try extracting via pattern
                local match_start, match_end = ngx_find(s, "[%w_]+", i)
                if match_start then
                    table.insert(tokens, { type = "word", value = ngx_lower(s:sub(match_start, match_end)) })
                    i = match_end + 1
                else
                    i = i + 1
                end
            end
        -- Quote
        elseif ngx_find(s, "^'", i) or ngx_find(s, "^\"", i) then
            local q = s:sub(i, i)
            local _, e = ngx_find(s, q, i + 1)
            table.insert(tokens, { type = "quoted", value = s:sub(i, e or i), delimiter = q })
            i = (e or i) + 1
        -- Comment
        elseif s:sub(i, i + 1) == "--" then
            table.insert(tokens, { type = "comment", value = "--" })
            break
        elseif s:sub(i, i) == "#" then
            table.insert(tokens, { type = "comment", value = "#" })
            break
        elseif s:sub(i, i + 1) == "/*" then
            local _, e = ngx_find(s, "%*/", i + 2)
            table.insert(tokens, { type = "block_comment", value = s:sub(i, (e or i) + 1) })
            i = (e or i) + 2
        else
            -- Operator or punctuation
            table.insert(tokens, { type = "op", value = s:sub(i, i) })
            i = i + 1
        end
    end
    return tokens
end

-- ============================================================
-- Check for SQL keyword pair proximity
-- e.g., SELECT found within N words of FROM
-- ============================================================
local function has_keyword_pair(tokens, kw1, kw2, max_dist)
    local pos1 = nil
    for i, tok in ipairs(tokens) do
        if tok.type == "word" then
            if not pos1 and tok.value == kw1 then
                pos1 = i
            elseif pos1 and tok.value == kw2 then
                local dist = i - pos1
                if not max_dist or dist <= max_dist then
                    return true, dist
                end
            end
        end
    end
    return false, 0
end

-- ============================================================
-- Analyze quote balance and surrounding context
-- Unbalanced single quotes near SQL keywords = injection
-- ============================================================
local function check_quote_anomaly(s)
    -- Count single quotes
    local quotes = 0
    local pos = 1
    while true do
        local _, e = ngx_find(s, "'", pos)
        if not e then break end
        quotes = quotes + 1
        pos = e + 1
    end

    -- Odd number of quotes = unbalanced (injection signal)
    if quotes % 2 ~= 0 then return false end

    -- Check for common injection patterns around quotes
    -- ' OR '1'='1, ' AND 1=1, ' UNION SELECT, '; DROP, etc.
    local patterns = {
        ["'%s*or%s+"] = true, ["'%s*and%s+"] = true,
        ["'%s*union%s+"] = true, ["';"] = true,
        ["'%s*--"] = true, ["'%s*#"] = true,
        ["'%s*/%*"] = true, ["%%27%s+or"] = true,
        ["%%27%s+and"] = true, ["%%27%s+union"] = true,
    }
    local sl = ngx_lower(s)
    for pat in pairs(patterns) do
        if ngx_find(sl, pat) then
            return true
        end
    end

    -- check for escaped hex quotes used in injection
    if ngx_find(s, "\\x27") or ngx_find(s, "\\'") then
        -- check nearby SQL context
        if ngx_find(ngx_lower(s), "or[%s+]+") or
           ngx_find(ngx_lower(s), "and[%s+]+") then
            return true
        end
    end

    return false
end

-- ============================================================
-- Check for SQL comment injection
-- Comments (#, --, /* */) used to truncate queries
-- ============================================================
local function check_comment_injection(s)
    local sl = ngx_lower(s)

    -- Check for comment markers near SQL keywords or quotes
    for _, marker in ipairs({ "#", "--", "/*" }) do
        local mpos = ngx_find(sl, marker, 1, true)
        if mpos then
            -- Check if there's SQL context before the comment
            local before = sl:sub(1, mpos - 1)
            -- A quote or SQL keyword before the comment is suspicious
            if ngx_find(before, "'") or
               ngx_find(before, "=") or
               ngx_find(before, ">") or
               ngx_find(before, "<") or
               ngx_find(before, "%%27") then
                return true
            end
            -- ' OR 1=1 -- , ' AND sleep(5) #
            for _, kw in ipairs({ "or", "and", "union", "select", "where" }) do
                if ngx_find(before, kw) then
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- Check for timing-based injection
-- SLEEP(n), BENCHMARK(n, expr), WAITFOR DELAY 'n'
-- ============================================================
local function check_timing_attack(s)
    local sl = ngx_lower(s)
    -- sleep(n) with n > 1 is almost always intentional
    local _, _, sleep_arg = ngx_find(sl, "sleep%s*%((%d+)%)")
    if sleep_arg and tonumber(sleep_arg) and tonumber(sleep_arg) > 1 then
        return true
    end
    -- benchmark(n, expr)
    local _, _, bench_count = ngx_find(sl, "benchmark%s*%((%d+)%s*,")
    if bench_count and tonumber(bench_count) and tonumber(bench_count) > 100000 then
        return true
    end
    -- WAITFOR DELAY '0:0:N'
    if ngx_find(sl, "waitfor") and ngx_find(sl, "delay") then
        return true
    end
    -- pg_sleep(N)
    _, _, pg_arg = ngx_find(sl, "pg_sleep%s*%((%d+)%)")
    if pg_arg and tonumber(pg_arg) and tonumber(pg_arg) > 1 then
        return true
    end
    return false
end

-- ============================================================
-- Check for hex/char based encoding often used in injection
-- 0xHEX, CHAR(..., ...), N'...'
-- ============================================================
local function check_encoded_injection(s)
    local sl = ngx_lower(s)

    -- 0x followed by a long hex string (typically binary data in SQL)
    _, _, hex_body = ngx_find(sl, "0x([0-9a-f]{8,})")
    if hex_body then
        -- Check if nearby SQL keywords
        if ngx_find(sl, "select") or ngx_find(sl, "union") or
           ngx_find(sl, "where") or ngx_find(sl, "and") or
           ngx_find(sl, "or") then
            return true
        end
    end

    -- CHAR(65,66,67) pattern for character encoding
    if ngx_find(sl, "char%s*%(") then
        -- multiple numeric args to CHAR is suspicious
        local args = ngx_gsub(sl, ".*char%s*%((.-)%).*$", "%1")
        if args then
            local count = 0
            for _ in ngx_gsub(args, ",", function() count = count + 1; return "" end) do end
            if count >= 2 then return true end
        end
    end

    -- N'...' Unicode string prefix (can bypass some filters)
    if ngx_find(sl, "n'") or ngx_find(sl, "n\"") then
        if ngx_find(sl, "select") or ngx_find(sl, "or") or
           ngx_find(sl, "and") or ngx_find(sl, "union") then
            return true
        end
    end

    return false
end

-- ============================================================
-- Check for stacked queries (semicolon + new SQL statement)
-- ============================================================
local function check_stacked_queries(s)
    local sl = ngx_lower(s)

    -- Find semicolons not inside string literals
    local in_string = false
    local string_char = nil
    local semi_positions = {}

    for i = 1, #sl do
        local c = sl:sub(i, i)
        if in_string then
            if c == string_char then
                in_string = false
            end
        else
            if c == "'" or c == '"' then
                in_string = true
                string_char = c
            elseif c == ";" and i < #sl then
                table.insert(semi_positions, i)
            end
        end
    end

    if #semi_positions > 0 then
        for _, pos in ipairs(semi_positions) do
            local after = sl:sub(pos + 1)
            -- Semicolon followed by SQL keyword = suspicious
            if ngx_find(after, "^%s*select") or
               ngx_find(after, "^%s*drop") or
               ngx_find(after, "^%s*insert") or
               ngx_find(after, "^%s*delete") or
               ngx_find(after, "^%s*update") or
               ngx_find(after, "^%s*create") or
               ngx_find(after, "^%s*alter") or
               ngx_find(after, "^%s*truncate") or
               ngx_find(after, "^%s*exec") or
               ngx_find(after, "^%s*shutdown") then
                return true
            end
        end
    end

    return false
end

-- ============================================================
-- Check for information_schema access pattern
-- ============================================================
local function check_information_schema(s)
    local sl = ngx_lower(s)
    if ngx_find(sl, "information_schema") then
        -- information_schema by itself in user input is suspicious
        -- Check if combined with SELECT/UNION/etc.
        if ngx_find(sl, "select") or ngx_find(sl, "union") or
           ngx_find(sl, "from") then
            return true
        end
    end
    if ngx_find(sl, "mysql%.user") or ngx_find(sl, "mysql%.db") or
       ngx_find(sl, "mysql%.password") or ngx_find(sl, "sys%.schema") or
       ngx_find(sl, "pg_catalog") or ngx_find(sl, "sqlite_master") then
        return true
    end
    return false
end

-- ============================================================
-- Check for error-based injection patterns
-- extractvalue, updatexml, floor(rand()), group by with concat
-- ============================================================
local function check_error_based(s)
    local sl = ngx_lower(s)

    -- extractvalue(1, concat(0x7e, ...))
    if ngx_find(sl, "extractvalue") and ngx_find(sl, "concat") then
        return true
    end
    -- updatexml(1, concat(0x7e, ...))
    if ngx_find(sl, "updatexml") and ngx_find(sl, "concat") then
        return true
    end
    -- floor(rand()*2) group by pattern
    if ngx_find(sl, "floor") and ngx_find(sl, "rand") and ngx_find(sl, "group") then
        return true
    end
    -- NAME_CONST
    if ngx_find(sl, "name_const") then
        return true
    end
    -- Double query with concat for error extraction
    if ngx_find(sl, "count%(") and ngx_find(sl, "concat%(") and
       (ngx_find(sl, "floor") or ngx_find(sl, "rand")) then
        return true
    end

    return false
end

-- ============================================================
-- Check for DML/DDL statement presence in user input
-- DML = SELECT, INSERT, UPDATE, DELETE
-- DDL = CREATE, DROP, ALTER, TRUNCATE
-- ============================================================
local function check_malicious_keywords(s)
    local sl = ngx_lower(s)
    local dangerous = {
        "xp_cmdshell",     "sp_oacreate",     "sp_oamethod",
        "sp_makewebtask",  "sp_send_dbmail",  "sys_exec",
        "shell_exec",      "cmdshell",        "having",
        "into outfile",    "into dumpfile",    "load_file",
        "bulk_insert",     "bulkadmin",       "shutdown",
    }
    for _, kw in ipairs(dangerous) do
        if ngx_find(sl, kw, 1, true) then
            return true
        end
    end
    return false
end

-- ============================================================
-- Main SQL injection entry point
-- ============================================================
function semantic_sql_detect(value)
    if type(value) ~= "string" or #value < 4 then return false end
    if #value > 5000 then
        -- Very long values are suspicious (could be encoded payload)
        -- Only check for obvious patterns
        -- But skip: base64 images, long text content
        if ngx_find(value, "^data:") then return false end
    end

    local s, comments_removed = normalize_sql(value)

    -- Quick checks first
    if check_malicious_keywords(s) then return true end

    -- Timing attacks
    if check_timing_attack(s) then return true end

    -- Comment injection
    if check_comment_injection(s) then return true end

    -- Error-based
    if check_error_based(s) then return true end

    -- information_schema
    if check_information_schema(s) then return true end

    -- Stacked queries
    if check_stacked_queries(s) then return true end

    -- Encoded injection
    if check_encoded_injection(s) then return true end

    -- Tokenize and check keyword pairs
    local tokens = tokenize_sql(s)

    -- Check for SQL keyword pairs
    for _, pair in ipairs(SQL_KEYWORD_PAIRS) do
        local found, dist = has_keyword_pair(tokens, pair[1], pair[2], pair[3])
        if found then
            -- Keywords found in close proximity = strong injection signal
            return true
        end
    end

    -- Quote anomaly analysis
    if check_quote_anomaly(s) then return true end

    -- Comment obfuscation: if inline comments were removed AND SQL keywords exist
    if comments_removed > 0 then
        for _, tok in ipairs(tokens) do
            if tok.type == "word" and (
                tok.value == "select" or tok.value == "union" or
                tok.value == "where" or tok.value == "from" or
                tok.value == "or" or tok.value == "and"
            ) then
                return true
            end
        end
    end

    return false
end

-- ============================================================
-- XSS Semantic Analysis
-- ============================================================

-- HTML event handlers
local XSS_EVENT_HANDLERS = {
    "onload", "onerror", "onclick", "ondblclick", "onmousedown",
    "onmouseup", "onmouseover", "onmousemove", "onmouseout",
    "onkeydown", "onkeypress", "onkeyup", "onsubmit", "onreset",
    "onfocus", "onblur", "onchange", "onselect", "onscroll",
    "onabort", "onunload", "onresize", "onmove", "oninput",
    "onpointerdown", "onpointerup", "onpointermove",
    "ontouchstart", "ontouchend", "ontouchmove",
    "onanimationstart", "onanimationend", "onanimationiteration",
    "ontransitionend", "onloadstart", "onloadeddata",
    "onwaiting", "onplaying", "onplay", "onpause",
    "ondrag", "ondrop", "ondragstart", "ondragend",
    "oncontextmenu", "onwheel", "onauxclick",
}

-- DOM XSS sink functions
local XSS_DOM_SINKS = {
    "document%.write", "innerHTML%s*=", "outerHTML%s*=",
    "insertAdjacentHTML", "eval%s*%(", "setTimeout%s*%(",
    "setInterval%s*%(", "new%s+Function%s*%(", "execScript%s*%(",
    "location%s*=", "location%.href", "location%.replace",
    "location%.assign", "srcdoc%s*=",
}

-- ============================================================
-- Check for event handler injection
-- ============================================================
local function check_event_handlers(s)
    local sl = ngx_lower(s)
    for _, handler in ipairs(XSS_EVENT_HANDLERS) do
        -- Pattern: onXXX= with executable content after =
        -- Allow to exclude onXXX="0" or onXXX='' (empty/zero)
        local idx = ngx_find(sl, handler, 1, true)
        if idx then
            -- Check what follows the event handler name
            local after = sl:sub(idx + #handler)
            -- Must have = after the handler name
            if ngx_find(after, "^%s*=") then
                -- Get the value after =
                local val_start = ngx_find(after, "=")
                if val_start then
                    local val = after:sub(val_start + 1)
                    -- Not empty and not just "0", "false", "null"
                    val = ngx_gsub(val, "^%s*", "")
                    if #val > 0 and val ~= "0" and val ~= "''" and
                       val ~= '""' and val ~= "false" and val ~= "null" and
                       val ~= "undefined" and val ~= "none" then
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- ============================================================
-- Check for javascript: URI scheme
-- ============================================================
local function check_javascript_uri(s)
    local sl = ngx_lower(s)
    -- javascript: followed by code
    local _, _, js_code = ngx_find(sl, "javascript%s*:%s*(.+)")
    if js_code then
        -- Skip "javascript:void(0)" and "javascript:;" which are commonly benign
        js_code = ngx_gsub(js_code, "^%s*", "")
        if js_code ~= "void(0)" and js_code ~= ";" and
           js_code ~= "void 0" and js_code ~= "" then
            return true
        end
    end
    -- Also check: data:text/html;base64,...
    if ngx_find(sl, "^data%s*:%s*text/html") then
        return true
    end
    return false
end

-- ============================================================
-- Check for script tag injection
-- ============================================================
local function check_script_tags(s)
    local sl = ngx_lower(s)
    -- <script> with content
    if ngx_find(sl, "<%s*script[^>]*>") then
        -- Check if there's executable content or just <script></script>
        if ngx_find(sl, "<%s*/%s*script%s*>") then
            local _, ss, se = ngx_find(sl, "<%s*script[^>]*>")
            if ss then
                local content = sl:sub(se + 1)
                -- If there's real content between script tags
                if ngx_find(content, "[%w%(%)]") then
                    -- But skip if just empty or src="..." with no inline code
                    -- unless src points to javascript:
                    if ngx_find(content, "src%s*=") and not ngx_find(content, "javascript:") then
                        -- external script src is benign
                        -- but still check if it has inline code too
                        if ngx_find(content, "<%s*/%s*script%s*>") then
                            local end_tag_pos = ngx_find(content, "<%s*/%s*script%s*>")
                            local inline = content:sub(1, end_tag_pos - 1)
                            inline = ngx_gsub(inline, "src%s*=%s*['\"][^'\"]*['\"]", "")
                            inline = ngx_gsub(inline, "^%s*", "")
                            if #inline > 10 then return true end
                        end
                    else
                        return true
                    end
                end
            end
        else
            -- <script> without closing tag (also suspicious)
            return true
        end
    end
    return false
end

-- ============================================================
-- Check for DOM XSS sinks
-- ============================================================
local function check_dom_xss(s)
    local sl = ngx_lower(s)
    for _, sink in ipairs(XSS_DOM_SINKS) do
        if ngx_find(sl, sink) then
            return true
        end
    end
    return false
end

-- ============================================================
-- Check for CSS expression injection
-- ============================================================
local function check_css_injection(s)
    local sl = ngx_lower(s)
    -- CSS expression() in style context
    if ngx_find(sl, "expression%s*%(") then
        return true
    end
    -- -moz-binding (Firefox XSS)
    if ngx_find(sl, "%-moz%-binding") then
        return true
    end
    -- url(javascript:...)
    if ngx_find(sl, "url%s*%(%s*['\"]?%s*javascript:") then
        return true
    end
    -- @import url(malicious)
    if ngx_find(sl, "@import") and ngx_find(sl, "url") then
        -- Check what's being imported
        if ngx_find(sl, "javascript:") or ngx_find(sl, "data:") then
            return true
        end
    end
    return false
end

-- ============================================================
-- Check for template injection (${{...}}, ${...})
-- ============================================================
local function check_template_injection(s)
    -- Angular/Svelte template injection
    if ngx_find(s, "{{") and ngx_find(s, "}}") then
        local inner = ngx_gsub(s, ".-{{(.-)}}.*$", "%1")
        if ngx_find(inner, "constructor") or ngx_find(inner, "prototype") or
           ngx_find(inner, "__proto__") or ngx_find(inner, "eval") or
           ngx_find(inner, "alert") or ngx_find(inner, "fetch") then
            return true
        end
    end
    -- Server-side template injection
    if ngx_find(s, "${") and ngx_find(s, "}") then
        if ngx_find(s, "class%.") or ngx_find(s, "runtime") or
           ngx_find(s, "exec") or ngx_find(s, "eval") then
            return true
        end
    end
    return false
end

-- ============================================================
-- Check for SVG/iframe/object/embed/input with XSS potential
-- ============================================================
local function check_html_tag_xss(s)
    local sl = ngx_lower(s)
    -- <iframe src=javascript:...> or srcdoc=...
    if ngx_find(sl, "<%s*iframe") then
        if ngx_find(sl, "src%s*=%s*['\"]?%s*javascript:") then
            return true
        end
        if ngx_find(sl, "srcdoc") then
            local _, sr = ngx_find(sl, "srcdoc%s*=")
            if sr then
                local after = sl:sub(sr + 1)
                if ngx_find(after, "<script") or
                   ngx_find(after, "onload") or
                   ngx_find(after, "onerror") then
                    return true
                end
            end
        end
        -- iframe with no src but with name (can be targeted by parent)
    end

    -- <object> with data or codebase
    if ngx_find(sl, "<%s*object") then
        if ngx_find(sl, "data%s*=%s*['\"]?%s*javascript:") then
            return true
        end
    end

    -- <embed> with src
    if ngx_find(sl, "<%s*embed") and ngx_find(sl, "src%s*=") then
        if ngx_find(sl, "javascript:") then return true end
    end

    -- <input onfocus=... autofocus>
    if ngx_find(sl, "<%s*input") and ngx_find(sl, "autofocus") then
        if ngx_find(sl, "onfocus") then return true end
    end

    -- <details ontoggle=...>
    if ngx_find(sl, "<%s*details") and ngx_find(sl, "ontoggle") then
        return true
    end

    -- <svg onload/onerror=...>
    if ngx_find(sl, "<%s*svg") then
        if ngx_find(sl, "onload") or ngx_find(sl, "onerror") then
            return true
        end
    end

    -- <body onload=...>
    if ngx_find(sl, "<%s*body") and ngx_find(sl, "onload") then
        return true
    end

    return false
end

-- ============================================================
-- Check for obfuscated/encoded XSS
-- ============================================================
local function check_encoded_xss(s)
    -- Base64 encoded HTML in data URIs
    if ngx_find(s, "data:text/html;base64,") then
        return true
    end
    -- Hex/unicode encoded script markers
    if ngx_find(s, "\\x3cscript") or ngx_find(s, "\\x3Cscript") or
       ngx_find(s, "\\u003cscript") or ngx_find(s, "&#60;script") or
       ngx_find(s, "&#x3c;script") then
        return true
    end
    -- HTML entity encoded event handlers
    if ngx_find(s, "&#") and ngx_find(s, "onload") or
       ngx_find(s, "&#") and ngx_find(s, "onerror") then
        -- Check for pattern: &...; where ... is number/hex
        if ngx_find(s, "&#%d+;") or ngx_find(s, "&#x[0-9a-fA-F]+;") then
            return true
        end
    end
    return false
end

-- ============================================================
-- Main XSS entry point
-- ============================================================
function semantic_xss_detect(value)
    if type(value) ~= "string" or #value < 4 then return false end

    local sl = ngx_lower(value)

    -- Quick checks
    if check_javascript_uri(sl) then return true end
    if check_script_tags(sl) then return true end
    if check_event_handlers(sl) then return true end
    if check_dom_xss(sl) then return true end
    if check_css_injection(sl) then return true end
    if check_template_injection(value) then return true end
    if check_html_tag_xss(sl) then return true end
    if check_encoded_xss(value) then return true end

    return false
end

-- ============================================================
-- Convenience wrappers for scanning parameter tables
-- These match the original mycomplib2/mymcomplib3/mycomplib_xss pattern
-- ============================================================

function semantic_sql_scan_params(args, use_key_filter)
    if type(args) ~= "table" then return false end
    for k, v in pairs(args) do
        if type(v) == "string" then
            if not use_key_filter or should_skip_key(k) then
                -- skip
            end
            if semantic_sql_detect(v) then
                error_rule = "语义分析出SQL注入 >> " .. tostring(k) .. "=" .. v
                rule_type = "SQL注入"
                return true
            end
        end
    end
    return false
end

function semantic_xss_scan_params(args, use_key_filter)
    if type(args) ~= "table" then return false end
    for k, v in pairs(args) do
        if type(v) == "string" then
            if semantic_xss_detect(v) then
                error_rule = "语义分析出XSS攻击 >> " .. tostring(k) .. "=" .. v
                rule_type = "XSS攻击"
                return true
            end
        end
    end
    return false
end

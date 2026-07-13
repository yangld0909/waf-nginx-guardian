-- waf.lua - Access-phase entry point
-- Called by access_by_lua_file on every request
-- NOTE: Do NOT wrap run_guardian() in pcall! ngx.exit() throws an "abort"
-- error that MUST propagate to ngx_lua's internal handler to properly
-- terminate blocked requests (444, 403, 404, etc.).
-- Error logging is handled inside run_guardian() and individual detection
-- functions instead.

run_guardian()

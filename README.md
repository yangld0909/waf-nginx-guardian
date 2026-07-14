# Guardian WAF

A Web Application Firewall based on OpenResty/lua-nginx-module, implemented in pure Lua, inspired by the BaoTa WAF architecture.

[中文文档](README_zh.md)

## Project Structure

```
waf_nginx_new/
├── init.lua              # Startup entry (init_by_lua_file)
├── waf.lua               # Request entry (access_by_lua_file)
├── guardian.lua          # Detection pipeline orchestrator
├── admin.lua             # Management API
├── config.lua            # Config read/write
├── config.json           # Global configuration
├── site.json             # Per-site configuration overrides
├── domains.json          # Domain name → site identifier mapping
│
├── ip.lua                # IP management, CDN real-IP, graduated blocking
├── ua.lua                # UA filtering, spider identification + DNS verification
├── cc.lua                # CC rate limiting, enhanced captcha
├── detection.lua         # Regex match engine, URL/Cookie/Referer detection
├── post.lua              # POST parameter filtering, file upload validation, ThinkPHP defense
├── scan.lua              # Scanner detection, WebShell scan, per-site custom rules
├── semantics.lua         # SQL injection + XSS semantic analysis engine
├── log.lua               # Logging and statistics
├── body.lua              # Response body content filtering
├── multipart.lua         # multipart/form-data parser
├── socket.lua            # Reverse DNS lookup (spider verification)
│
├── nginx.conf            # Nginx configuration example
├── html/                 # Block pages + admin panel
│   ├── admin.html        # Admin interface (SPA)
│   ├── get.html          # GET/URI block page
│   ├── post.html         # POST block page
│   ├── cookie.html       # Cookie block page
│   ├── user_agent.html   # UA block page
│   └── other.html        # Other block page
├── rule/                 # Rule files (JSON)
│   ├── args.json         # GET parameter rules (29 entries)
│   ├── post.json         # POST parameter rules (18 entries)
│   ├── url.json          # URL path rules (7 entries)
│   ├── cookie.json       # Cookie rules
│   ├── user_agent.json   # UA rules
│   ├── referer.json      # Referer rules
│   ├── ip_black.json     # IP blacklist
│   ├── ip_white.json     # IP whitelist
│   ├── url_white.json    # URL whitelist
│   ├── url_black.json    # URL blacklist
│   ├── cc_uri_white.json # CC whitelist URIs
│   ├── head_white.json   # HEAD whitelist
│   ├── scan_black.json   # Scanner signatures
│   └── cn.json           # China IP ranges
└── logs/                 # Log directory
```

## Deployment

### 1. Requirements

- Nginx + OpenResty (or ngx_lua_module)
- Lua 5.1+
- lua-cjson (typically bundled with OpenResty)
- LuaSocket (for spider DNS verification, optional)

### 2. Copy Files to Server

```bash
# Place the project at your server path, e.g. /www/server/btwaf/
cp -r waf_nginx_new /www/server/btwaf/
```

### 3. Edit Configuration

**a) Update project root path in `config.lua`**

```lua
-- config.lua line 7
_M.root = "/www/server/btwaf/"
```

**b) Update paths in `config.json`**

```json
{
  "logs_path": "/www/wwwlogs/btwaf",
  "reqfile_path": "/www/server/btwaf/html"
}
```

### 4. Configure Nginx

Add the following to `nginx.conf` (or your site config):

```nginx
# In the http {} block
lua_shared_dict waf_cache 30m;
lua_shared_dict waf_drop 30m;
lua_shared_dict waf_stats 30m;
lua_shared_dict waf_data 100m;
lua_package_path "/www/server/btwaf/?.lua";
init_by_lua_file  /www/server/btwaf/init.lua;
access_by_lua_file /www/server/btwaf/waf.lua;
```

If response body filtering is also needed, add:

```nginx
# In the server {} or location {} block
body_filter_by_lua_file /www/server/btwaf/body.lua;
```

### 5. Reload Nginx

```bash
nginx -t        # Test configuration
nginx -s reload # Reload
```

### 6. Verify Operation

```bash
# Check Nginx startup log
tail -f /var/log/nginx/error.log

# Hit admin status endpoint
curl http://127.0.0.1/waf/admin/status

# Expected response: {"success":true,"status":"running",...}
```

## Admin Panel

Browse to `http://your-server/waf/admin`

| Page | Function |
|---|---|
| Dashboard | Block statistics, blocked IPs, site ranking |
| Global Config | WAF switches, CC parameters, per-dimension detection toggles, global security limits |
| Site Management | Multi-site CRUD, domain binding, per-site independent config |
| Rule Management | Online editor for the 14 rule sets |
| IP Blocking | View / unblock / clear blocked IPs |
| Log Viewer | Filter logs by site + date |
| Rule Tester | Regex + payload match testing |

By default only `127.0.0.1` is allowed. To open access, edit the `ADMIN_IPS` table in `admin.lua`.

## Configuration

### Layered Configuration

```
Global config (config.json)  →  shared defaults for all sites
     ↓
Site config (site.json)      →  overrides/extends global per site
```

- **Scalar configs** (CC parameters, retry, detection toggles): site value replaces global
- **List configs** (blocked paths, blocked extensions, blocked upload types, blocked PHP paths): site values append to global

### Adding a Site

Either via the admin panel (Site Management → New Site), or by directly editing `domains.json` and `site.json`:

```json
// domains.json — domain mapping
[
  {"name": "myblog", "path": "/www/wwwroot/myblog", "domains": ["www.example.com", "blog.example.com"]}
]
```

```json
// site.json — site config (unspecified keys inherit from global)
{
  "myblog": {
    "cc": {"open": true, "cycle": 60, "limit": 30, "endtime": 3600},
    "disable_path": ["/admin", "/backup"],
    "disable_upload_ext": ["php", "jsp", "asp"]
  }
}
```

## Detection Pipeline Order

```
Request enters
  ├─ 1.  IP whitelist          → skip all checks
  ├─ 2.  IP blacklist          → block immediately
  ├─ 3.  UA whitelist/blacklist
  ├─ 4.  URI keyword block
  ├─ 5.  CC static asset counter
  ├─ 6.  IP drop-state check
  ├─ 7.  HEAD request handling
  ├─ 8.  HTTP method validation
  ├─ 9.  Header length validation
  ├─ 10. Transfer-Encoding check
  ├─ 11. URL whitelist          → lightweight checks
  │       └─ args + post + multipart
  ├─ 12. URL blacklist
  ├─ 13. Geo blocking
  ├─ 14. WebShell scan
  ├─ 15. Spider identification
  │       ├─ Verified (spider) → lightweight checks (args + scan + thinkphp + post)
  │       └─ Not verified       → full checks
  │           ├─ UA rules
  │           ├─ CC standard + enhanced + adaptive
  │           ├─ URL rules
  │           ├─ Referer / Cookie
  │           ├─ GET param rules + semantic analysis
  │           ├─ Scanner detection
  │           ├─ ThinkPHP RCE
  │           ├─ POST rules + semantic analysis
  │           ├─ File upload validation
  │           └─ Per-site custom rules
```

## Dependencies

No external dependencies — all code is pure Lua. Required runtime components:

| Component | Source | Required |
|---|---|---|
| `cjson` | Built into OpenResty | Yes |
| `lua_socket` | OpenResty optional package | Only for spider verification |
| `ngx.shared.DICT` | lua-nginx-module | Yes |

## License

Apache 2.0

## To-Do / Known Issues

### 🔧 Backend-Implemented but Not Exposed in Admin UI

The following features are implemented in the backend but have no visual management interface; they must be edited in the config files directly:

#### UA Whitelist / Blacklist

```json
// config.json
{
  "ua_white": ["Baiduspider", "Googlebot"],
  "ua_black": ["curl", "wget", "python-requests"]
}
```

Code: `ua.lua` → `check_ua_whitelist()` / `check_ua_blacklist()`

#### Spider Pool Sync

- Built-in `zhi.lua` performs reverse DNS verification of spider identity
- Cloud spider-pool sync is not yet wired up; currently a static built-in list
- Code: `init.lua` → `verify_spider()`


### ⚠️ Suggested Improvements

1. **UA whitelist/blacklist UI** — add `ua_white`/`ua_black` editors to the global config page
2. **Cloud spider pool sync** — integrate a cloud API to auto-update the known spider list
3. **Automatic log cleanup** — `log_save` config exists but needs a scheduled task
4. **Error log viewer** — `waf_error.log` is currently inspected manually; consider adding to the admin panel
5. **Persistent blocked IPs** — the `waf_drop` shared dict is lost on Nginx reload; restore from `stop_ip.json` at startup
6. **Hot reload of rules** — rule files are loaded once at init; currently require `nginx -s reload` after edits
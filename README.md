# Guardian WAF

基于 OpenResty/lua-nginx-module 的 Web 应用防火墙，纯 Lua 实现，灵感来自宝塔 WAF 架构。

## 项目结构

```
waf_nginx_new/
├── init.lua              # 启动入口 (init_by_lua_file)
├── waf.lua               # 请求入口 (access_by_lua_file)
├── guardian.lua          # 检测流水线编排
├── admin.lua             # 管理 API
├── config.lua            # 配置读写
├── config.json           # 全局配置
├── site.json             # 站点配置覆盖
├── domains.json          # 域名 → 站点标识映射
│
├── ip.lua                # IP 管理、CDN 取IP、梯度封锁
├── ua.lua                # UA 过滤、蜘蛛识别+DNS 验证
├── cc.lua                # CC 限速、增强验证码
├── detection.lua         # 正则匹配引擎、URL/Cookie/Referer 检测
├── post.lua              # POST 参数过滤、文件上传校验、ThinkPHP 防护
├── scan.lua              # 扫描器检测、WebShell 扫描、站点自定义规则
├── semantics.lua         # SQL 注入 + XSS 语义分析引擎
├── log.lua               # 日志、统计
├── body.lua              # 响应体内容过滤
├── multipart.lua         # multipart/form-data 解析器
├── socket.lua            # DNS 反向查询 (爬虫验证)
│
├── nginx.conf            # Nginx 配置示例
├── html/                 # 拦截页面 + 管理面板
│   ├── admin.html        # 管理界面 (单页应用)
│   ├── get.html          # GET/URI 拦截页
│   ├── post.html         # POST 拦截页
│   ├── cookie.html       # Cookie 拦截页
│   ├── user_agent.html   # UA 拦截页
│   └── other.html        # 其他拦截页
├── rule/                 # 规则文件 (JSON)
│   ├── args.json         # GET 参数规则 (29条)
│   ├── post.json         # POST 参数规则 (18条)
│   ├── url.json          # URL 路径规则 (7条)
│   ├── cookie.json       # Cookie 规则
│   ├── user_agent.json   # UA 规则
│   ├── referer.json      # Referer 规则
│   ├── ip_black.json     # IP 黑名单
│   ├── ip_white.json     # IP 白名单
│   ├── url_white.json    # URL 白名单
│   ├── url_black.json    # URL 黑名单
│   ├── cc_uri_white.json # CC 白名单 URI
│   ├── head_white.json   # HEAD 白名单
│   ├── scan_black.json   # 扫描器特征
│   └── cn.json           # 中国 IP 段
└── logs/                 # 日志目录
```

## 部署步骤

### 1. 环境要求

- Nginx + OpenResty (或 ngx_lua_module)
- Lua 5.1+
- lua-cjson (通常已包含在 OpenResty 中)
- LuaSocket (用于爬虫 DNS 验证，可选)

### 2. 复制文件到服务器

```bash
# 将项目放到服务器路径，例如 /www/server/btwaf/
cp -r waf_nginx_new /www/server/btwaf/
```

### 3. 修改配置

**a) 修改 `config.lua` 中的项目根路径**

```lua
-- config.lua 第 7 行
_M.root = "/www/server/btwaf/"
```

**b) 修改 `config.json` 中的路径**

```json
{
  "logs_path": "/www/wwwlogs/btwaf",
  "reqfile_path": "/www/server/btwaf/html"
}
```

### 4. 配置 Nginx

在 `nginx.conf` (或站点配置) 中添加：

```nginx
# 在 http 块中添加
lua_shared_dict waf_cache 30m;
lua_shared_dict waf_drop 30m;
lua_shared_dict waf_stats 30m;
lua_shared_dict waf_data 100m;
lua_package_path "/www/server/btwaf/?.lua";
init_by_lua_file  /www/server/btwaf/init.lua;
access_by_lua_file /www/server/btwaf/waf.lua;
```

如果同时需要响应体过滤，添加：

```nginx
# 在 server 块或 location 块中
body_filter_by_lua_file /www/server/btwaf/body.lua;
```

### 5. 重载 Nginx

```bash
nginx -t        # 测试配置
nginx -s reload # 重载
```

### 6. 验证运行

```bash
# 检查 Nginx 启动日志
tail -f /var/log/nginx/error.log

# 浏览器访问管理面板
curl http://127.0.0.1/waf/admin/status

# 应返回 JSON: {"success":true,"status":"running",...}
```

## 管理面板

浏览器访问 `http://your-server/waf/admin`

| 页面 | 功能 |
|---|---|
| 仪表盘 | 拦截统计、封锁 IP、站点排行 |
| 全局配置 | WAF 开关、CC 参数、各检测维度开关、全局安全限制 |
| 站点管理 | 多站点 CRUD、域名绑定、各站点独立配置 |
| 规则管理 | 14 种规则集在线编辑 |
| IP 封锁 | 查看/解封/清空封锁 IP |
| 日志查看 | 按站点+日期过滤查询 |
| 规则测试 | 正则+载荷匹配测试 |

默认仅允许 `127.0.0.1` 访问，如需开放请修改 `admin.lua` 中的 `ADMIN_IPS` 表。

## 配置说明

### 配置分层

```
全局配置 (config.json)  →  所有站点共用默认值
     ↓
站点配置 (site.json)   →  按站点覆盖/叠加全局配置
```

- **标量配置** (CC 参数、retry、检测开关)：站点值替代全局
- **列表配置** (禁止路径、禁止扩展名、禁止上传类型、禁止 PHP 路径)：站点值叠加到全局

### 添加站点

通过管理面板 → 站点管理 → 新建站点，或直接编辑 `domains.json` 和 `site.json`：

```json
// domains.json - 域名映射
[
  {"name": "myblog", "path": "/www/wwwroot/myblog", "domains": ["www.example.com", "blog.example.com"]}
]
```

```json
// site.json - 站点配置 (不设置的项继承全局)
{
  "myblog": {
    "cc": {"open": true, "cycle": 60, "limit": 30, "endtime": 3600},
    "disable_path": ["/admin", "/backup"],
    "disable_upload_ext": ["php", "jsp", "asp"]
  }
}
```

## 检测流水线执行顺序

```
请求进入
  ├─ 1. IP 白名单 → 跳过所有检测
  ├─ 2. IP 黑名单 → 直接拦截
  ├─ 3. UA 白/黑名单
  ├─ 4. URI 关键词拦截
  ├─ 5. CC 静态资源计数
  ├─ 6. IP 封锁状态检查
  ├─ 7. HEAD 请求处理
  ├─ 8. HTTP 方法校验
  ├─ 9. Header 长度校验
  ├─ 10. Transfer-Encoding 检查
  ├─ 11. URL 白名单 → 轻量检测
  │   └─ args + post + multipart
  ├─ 12. URL 黑名单
  ├─ 13. 地理封锁
  ├─ 14. WebShell 扫描
  ├─ 15. 爬虫识别
  │   ├─ 验证通过 → 轻量检测 (args + scan + thinkphp + post)
  │   └─ 未通过 → 全量检测
  │       ├─ UA 规则
  │       ├─ CC 标准+增强+自适应
  │       ├─ URL 规则
  │       ├─ Referer / Cookie
  │       ├─ GET 参数规则 + 语义分析
  │       ├─ 扫描工具检测
  │       ├─ ThinkPHP RCE
  │       ├─ POST 规则 + 语义分析
  │       ├─ 文件上传校验
  │       └─ 站点自定义规则
```

## 包管理 / 依赖

本项目无外部依赖，所有代码均为纯 Lua。需要：

| 组件 | 来源 | 必需 |
|---|---|---|
| `cjson` | OpenResty 内置 | 是 |
| `lua_socket` | OpenResty 可选包 | 仅爬虫验证 |
| `ngx.shared.DICT` | lua-nginx-module | 是 |

## 许可

Apache 2.0

## 待完善 / 已知问题

### 🔧 有代码但管理界面暂未暴露的功能

以下功能后端已实现，但暂无可视化管理界面，需直接编辑配置文件：

#### UA 白/黑名单

```json
// config.json
{
  "ua_white": ["Baiduspider", "Googlebot"],
  "ua_black": ["curl", "wget", "python-requests"]
}
```

对应代码：`ua.lua` → `check_ua_whitelist()` / `check_ua_blacklist()`

#### 蜘蛛池同步

- 内置在 `zhi.lua` 中，通过反向 DNS 验证爬虫身份
- 云端蜘蛛池列表同步功能暂未对接，当前为静态内置列表
- 对应代码：`init.lua` → `verify_spider()`


### ⚠️ 建议改进

1. **UA 白/黑名单管理界面** — 在全局配置页面增加 ua_white/ua_black 编辑区
2. **蜘蛛池云端同步** — 对接云端 API 自动更新已知爬虫列表
3. **日志自动清理** — `log_save` 配置已存在，需后台定时任务配合
4. **错误日志查看** — 当前 `waf_error.log` 需手动查看，可考虑加入管理面板
5. **封锁 IP 持久化** — 当前 `waf_drop` 共享字典在 Nginx reload 后丢失，建议重启时从 `stop_ip.json` 恢复
6. **规则变更热加载** — 当前规则文件在 init 时预加载，修改后需 `nginx -s reload`

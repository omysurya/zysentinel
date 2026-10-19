--[[
	免费WAF (aaPanel plugin: free_waf / "Nginx free firewall")
	Patched for nginx >= 1.22 (tested on 1.31.6) + BT-Panel/aaPanel 8.x

	Perbaikan vs upstream (init.lua 2020-12-16):
	  1. init tidak lagi crash nginx bila config.json / site.json kosong-rusak
	     (dulu: json.decode(nil) -> init_by_lua_file gagal -> nginx gagal start)
	  2. State per-request dipindah ke ngx.ctx (dulu global -> kebocoran antar request)
	  3. 3x crash "attempt to compare number with nil" -> HTTP 500 pada POST tanpa
	     Content-Length (post(), url_rule_ex()) diperbaiki
	  4. Penulisan total.json jadi atomic + throttled (dulu rewrite tiap request,
	     rawan race antar worker dan membebani I/O)
	  5. X-Forwarded-For hanya dipercaya dari proxy yang terdaftar (anti IP-spoofing)
	  6. Bypass "continue_key" (field bernama content/body/file/dll tak pernah discan)
	     diganti jadi lewati hanya bila nilai > 100KB
	  7. is_site_config() aman terhadap site.json versi lama
	  8. url_black() Finally menghormati toggle open
	  9. Mode monitor ("monitor": true di config.json) -> hanya log, tidak memblokir
]]

local cpath = "/www/server/sentinel/waf/lua_waf/"
do
    local fp = io.open(cpath .. "config.json", "r")
    if fp then
        fp:close()
    else
        cpath = "/www/server/lua_waf/"
        local fp2 = io.open(cpath .. "config.json", "r")
        if fp2 then fp2:close() else cpath = "/www/server/sentinel/waf/free_waf/" end
    end
end
local jpath = cpath .. "rule/"
local json = require "cjson"
local ngx_match = ngx.re.find

-- [ZySens] Shared dictionary helpers (dukungan native sentinel_waf dengan fallback free_waf)
local function get_dict_waf()
    return ngx.shared.sentinel_waf or ngx.shared.free_waf
end

local function get_dict_drop_ip()
    return ngx.shared.sentinel_waf_drop_ip or ngx.shared.free_waf_drop_ip
end

local function get_dict_drop_sum()
    return ngx.shared.sentinel_waf_drop_sum or ngx.shared.free_waf_drop_sum
end

local function get_dict_stat()
    return ngx.shared.sentinel_waf_stat or ngx.shared.free_waf_stat
end

local function get_dict_stat_lock()
    return ngx.shared.sentinel_waf_stat_lock or ngx.shared.free_waf_stat_lock
end

--------------------------------------------------------------------- context --
-- Semua state per-request disimpan di ngx.ctx (aman terhadap coroutine).
local function C()
    local c = ngx.ctx.waf
    if c == nil then
        c = {}
        ngx.ctx.waf = c
    end
    return c
end

------------------------------------------------------------------- file i/o --
function read_file_body(filename)
    local fp = io.open(filename, 'r')
    if fp == nil then
        return nil
    end
    local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
    return fbody
end

function write_file(filename, body)
    -- atomic: tulis ke .tmp lalu rename, supaya tidak pernah terbaca setengah
    local tmp = filename .. '.tmp'
    local fp = io.open(tmp, 'w')
    if fp == nil then
        return nil
    end
    fp:write(body)
    fp:flush()
    fp:close()
    os.rename(tmp, filename)
    return true
end

----------------------------------------------------------- json safe loader --
local function safe_json_decode(data, default)
    if data == nil or data == '' then
        return default
    end
    local ok, res = pcall(json.decode, data)
    if not ok or type(res) ~= 'table' then
        return default
    end
    return res
end

function read_file(name)
    local fbody = read_file_body(jpath .. name .. '.json')
    if fbody == nil then
        return {}
    end
    return safe_json_decode(fbody, {})
end

------------------------------------------------------------------- defaults --
-- Dipakai bila config.json hilang / rusak, supaya nginx TETAP bisa start
local default_config = {
    open = true,
    monitor = true,
    reqfile_path = cpath .. "html",
    logs_path = "/www/wwwlogs/free_waf_log",
    log = true,
    log_save = 30,
    start_time = 0,
    retry = 6,
    retry_cycle = 60,
    retry_time = 180,
    cdn_ip = {},
    drop_abroad = { status = 444, open = false, reqfile = "" },
    scan = { status = 444, open = true, reqfile = "" },
    -- 1500 = 1500 permintaan per 60 detik (naik dari 120 pada 2026-10-15).
    -- Harus selalu sama dengan cc.limit di config.json, kalau tidak lalu
    -- config.json yang rusak akan diam-diam memakai angka lama di sini.
    cc = { status = 444, limit = 1500, endtime = 300, open = true, reqfile = "", cycle = 60 },
    get = { status = 403, open = true, reqfile = "get.html" },
    ['user-agent'] = { status = 403, open = true, reqfile = "user_agent.html" },
    other = { status = 403, reqfile = "other.html" },
    cookie = { status = 403, open = true, reqfile = "cookie.html" },
    post = { status = 403, open = true, reqfile = "post.html" },
    url_black = { status = 404, open = false, reqfile = "url_black.html" }
}

local config = safe_json_decode(read_file_body(cpath .. 'config.json'), nil)
if config == nil then
    config = default_config
    ngx.log(ngx.ERR, "free_waf: config.json tidak terbaca, memakai default (WAF non-blocking)")
end
for k, v in pairs(default_config) do
    if config[k] == nil then
        config[k] = v
    end
end
if type(config['monitor']) ~= 'boolean' then
    config['monitor'] = true
end
if type(config['cdn_ip']) ~= 'table' then
    config['cdn_ip'] = {}
end

local site_config = safe_json_decode(read_file_body(cpath .. 'site.json'), {})
error_rule = nil

------------------------------------------------------------------- ip utils --
function is_ipaddr(client_ip)
    if type(client_ip) ~= 'string' then return false end
    local cipn = split(client_ip, '.')
    if arrlen(cipn) < 4 then return false end
    for _, v in ipairs({ 1, 2, 3, 4 }) do
        local ipv = tonumber(cipn[v])
        if ipv == nil then return false end
        if ipv > 255 or ipv < 0 then return false end
    end
    return true
end

function is_loopback(ipstr)
    if type(ipstr) ~= 'string' then return false end
    if ipstr == '::1' or ipstr == '0:0:0:0:0:0:0:1' then return true end
    if not string.find(ipstr, ':') then
        return string.find(ipstr, '^127%.') ~= nil
    end
    return false
end

-- Hanya IP proxy yang terdaftar di config["cdn_ip"] yang boleh men Implants XFF
function is_trusted_proxy(ipstr)
    if type(ipstr) ~= 'string' or ipstr == '' then return false end
    for _, v in ipairs(config['cdn_ip'] or {}) do
        if type(v) == 'string' and v ~= '' then
            if v == ipstr then return true end
        end
    end
    return false
end

function compare_ip_block(ips)
    if not ips then return false end
    if string.find(ips, ':') then return false end
    ips = arrip(ips)
    if not is_max(ips, arrip("127.0.0.255")) then return false end
    if not is_min(ips, arrip("127.0.0.1")) then return false end
    return true
end

function get_client_ip()
    local ctx = C()
    local client_ip = "unknown"
    local remote_addr = ngx.var.remote_addr
    if not site_config[ctx.server_name] then
        return remote_addr or "unknown"
    end
    if site_config[ctx.server_name]['cdn'] then
        -- [FIX 5] hanya percaya XFF bila pengirimnya proxy terdaftar
        if not is_trusted_proxy(remote_addr) then
            return remote_addr or "unknown"
        end
        for _, v in ipairs(site_config[ctx.server_name]['cdn_header'] or {}) do
            local header_tmp = ctx.request_header[v]
            if header_tmp ~= nil and header_tmp ~= "" then
                if type(header_tmp) == "table" then header_tmp = header_tmp[1] end
                if type(header_tmp) == "string" then
                    client_ip = split_bylog(header_tmp, ',')[1]
                    if client_ip and (is_ipaddr(client_ip) or string.find(client_ip, "^[%w:]+$")) then
                        return client_ip
                    end
                end
                break
            end
        end
    end
    return remote_addr or "unknown"
end

function split_bylog(str, reps)
    local resultStrList = {}
    if type(str) ~= 'string' then return resultStrList end
    string.gsub(str, '[^' .. reps .. ']+', function(w)
        table.insert(resultStrList, w)
    end)
    return resultStrList
end

function split(str, reps)
    local resultStrList = {}
    if type(str) ~= 'string' then return resultStrList end
    string.gsub(str, '[^' .. reps .. ']+', function(w)
        table.insert(resultStrList, w)
    end)
    return resultStrList
end

function arrip(ipstr)
    if type(ipstr) ~= 'string' then return { 0, 0, 0, 0 } end
    if string.find(ipstr, ':') then return ipstr end
    if ipstr == 'unknown' then return { 0, 0, 0, 0 } end
    local iparr = split(ipstr, '.')
    iparr[1] = tonumber(iparr[1]) or 0
    iparr[2] = tonumber(iparr[2]) or 0
    iparr[3] = tonumber(iparr[3]) or 0
    iparr[4] = tonumber(iparr[4]) or 0
    return iparr
end

function join(arr, e)
    local result = ''
    local length = arrlen(arr)
    for k, v in ipairs(arr) do
        local sep = e
        if length == k then sep = '' end
        result = result .. tostring(v) .. sep
    end
    return result
end

function arrlen(arr)
    if not arr then return 0 end
    local count = 0
    for _, v in ipairs(arr) do
        count = count + 1
    end
    return count
end

function select_rule(rules)
    if not rules then return {} end
    if type(rules) ~= 'table' then return {} end
    local new_rules = {}
    for _, v in ipairs(rules) do
        if type(v) == 'table' and v[1] == 1 then
            table.insert(new_rules, v[2])
        end
    end
    return new_rules
end

-- [FIX 7] tidak lagi error bila site.json versi lama tidak punya key tsb
function is_site_config(cname)
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if sc == nil then
        return true
    end
    local val = sc[cname]
    if val == nil then
        return true
    end
    if cname == 'cc' then
        if type(val) ~= 'table' then return true end
        if val['open'] == nil then return true end
        return val['open']
    end
    return val
end

function get_boundary()
    local ctx = C()
    local header = ctx.request_header["content-type"]
    if not header then return nil end
    if type(header) == "table" then
        header = header[1]
    end
    if type(header) ~= 'string' then return nil end

    local m = string.match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end
    return string.match(header, ";%s*boundary=([^\",;]+)")
end

------------------------------------------------------------------ rule init --
local get_html = read_file_body(config["reqfile_path"] .. '/' .. config["get"]["reqfile"])
local post_html = read_file_body(config["reqfile_path"] .. '/' .. config["post"]["reqfile"])
local cookie_html = read_file_body(config["reqfile_path"] .. '/' .. config["cookie"]["reqfile"])
local user_agent_html = read_file_body(config["reqfile_path"] .. '/' .. config["user-agent"]["reqfile"])
local other_html = read_file_body(config["reqfile_path"] .. '/' .. config["other"]["reqfile"])
local cnlist = safe_json_decode(read_file_body(cpath .. '/rule/cn.json'), {})
if type(cnlist) ~= 'table' then cnlist = {} end
local scan_black_rules = safe_json_decode(read_file_body(jpath .. 'scan_black.json'), {})
local ip_black_rules = read_file('ip_black')
local ip_white_rules = read_file('ip_white')
local url_white_rules = read_file('url_white')
local url_black_rules = read_file('url_black')
local user_agent_rules = select_rule(read_file('user_agent'))
local post_rules = select_rule(read_file('post'))
local cookie_rules = select_rule(read_file('cookie'))
local args_rules = select_rule(read_file('args'))
local url_rules = select_rule(read_file('url'))
local head_white_rules = read_file('head_white')

------------------------------------------------------------------- ip order --
function is_min(ip1, ip2)
    for _, v in ipairs({ 1, 2, 3, 4 }) do
        if ip1[v] == ip2[v] then
            -- lanjut
        elseif ip1[v] > ip2[v] then
            return false
        else
            return true
        end
    end
    return true
end

function is_max(ip1, ip2)
    for _, v in ipairs({ 1, 2, 3, 4 }) do
        if ip1[v] == ip2[v] then
            -- lanjut
        elseif ip1[v] < ip2[v] then
            return false
        else
            return true
        end
    end
    return true
end

function compare_ip(ips)
    local ctx = C()
    if ctx.ip == 'unknown' then return true end
    if string.find(ctx.ip, ':') then return false end
    if type(ips) ~= 'table' or type(ips[1]) ~= 'table' then return false end
    if not is_max(ctx.ipn, ips[2]) then return false end
    if not is_min(ctx.ipn, ips[1]) then return false end
    return true
end

----------------------------------------------------------- block / monitor --
-- [FIX 9] mode monitor: catat tapi JANGAN blokir, supaya bisa diamati dulu
local function blocked()
    return config['monitor'] == true
end

-- [ZySens] Deteksi tipe request: apakah AJAX / JSON atau HTML biasa
local function is_ajax_or_json_request()
    local ctx = C()
    local headers = ctx.request_header or ngx.req.get_headers() or {}

    -- 1. Header X-Requested-With (jQuery, Axios, XMLHttpRequest, fetch)
    local xrw = headers["x-requested-with"]
    if xrw and type(xrw) == "string" and xrw:lower() == "xmlhttprequest" then
        return true
    end

    -- 2. Header Accept (prioritas JSON)
    local accept = headers["accept"]
    if accept and type(accept) == "string" then
        local acc = accept:lower()
        if acc:find("application/json", 1, true) then
            return true
        end
    end

    -- 3. Header Content-Type
    local ctype = headers["content-type"]
    if ctype and type(ctype) == "string" then
        local ct = ctype:lower()
        if ct:find("application/json", 1, true) then
            return true
        end
    end

    -- 4. Pola URI .json atau /api/
    local uri = ctx.uri or ngx.var.uri or ""
    if uri:sub(-5):lower() == ".json" or uri:find("/api/", 1, true) then
        return true
    end

    return false
end

-- [ZySens] Kirim respon pemblokiran sesuai tipe request (JSON atau HTML)
local function return_blocked_response(status, log_name, log_rule, html_template)
    local ctx = C()
    local ip = ctx.ip or ngx.var.remote_addr or "unknown"
    local st = tonumber(status) or 403
    local req_id = string.format("ZY-%d-%04d", os.time(), math.random(1000, 9999))

    if is_ajax_or_json_request() then
        ngx.status = st
        ngx.header.content_type = "application/json; charset=utf-8"
        ngx.header["X-Protected-By"] = "ZySens"
        local res = {
            status = false,
            code = st,
            error = "Forbidden",
            message = "Permintaan Anda diblokir oleh sistem keamanan web server karena terdeteksi anomali atau ancaman.",
            client_ip = ip,
            incident_id = req_id,
            protected_by = "ZySens"
        }
        ngx.say(json.encode(res))
        ngx.exit(st)
        return true
    else
        ngx.status = st
        ngx.header.content_type = "text/html; charset=utf-8"
        ngx.header["X-Protected-By"] = "ZySens"
        local body = html_template or get_html or ""
        body = body:gsub("{{CLIENT_IP}}", ip)
        body = body:gsub("{{REQ_ID}}", req_id)
        body = body:gsub("{{STATUS}}", tostring(st))
        ngx.say(body)
        ngx.exit(st)
        return true
    end
end

local function deny(status, log_name, log_rule, html_body)
    local ctx = C()
    write_log(log_name, log_rule)
    if blocked() then
        return false
    end
    return_blocked_response(status, log_name, log_rule, html_body)
    return true
end

--------------------------------------------------------------------- log io --
function write_log(name, rule)
    local ctx = C()
    local ip = ctx.ip
    local shared = get_dict_drop_ip()
    if not shared then return false end
    local count = shared:get(ip)
    if count then
        shared:incr(ip, 1)
    else
        local ttl = tonumber(ctx.retry_cycle) or 60
        shared:set(ip, 1, ttl)
    end
    if config['log'] ~= true or is_site_config('log') ~= true then return false end

    local method = ctx.method
    local err = ctx.error_rule
    if err then
        rule = err
        ctx.error_rule = nil
    end

    local retry = tonumber(ctx.retry) or 6
    local retry_time = tonumber(ctx.retry_time) or 180

    local logtmp = { ngx.localtime(), ip, method, ctx.request_uri, ngx.var.http_user_agent, name, rule }
    local logstr = json.encode(logtmp) .. "\n"
    local c2 = shared:get(ip)
    if c2 and c2 > retry and name ~= 'cc' then
        local sum = get_dict_drop_sum()
        local safe_count = 1
        if sum then
            local sc = sum:get(ip)
            if not sc then
                sum:set(ip, 1, 86400)
            else
                sum:incr(ip, 1)
                safe_count = sc + 1
            end
        end
        local lock_time = retry_time * safe_count
        if lock_time > 86400 then lock_time = 86400 end
        local extra = { ngx.localtime(), ip, method, ctx.request_uri, ngx.var.http_user_agent, name,
            (tonumber(ctx.retry_cycle) or 60) .. '秒以内累计超过' .. retry .. '次以上非法请求,封锁' .. lock_time .. '秒' }
        logstr = logstr .. json.encode(extra) .. "\n"
        shared:set(ip, retry + 1, lock_time)
        write_drop_ip('inc', lock_time)
    end
    write_to_file(logstr)
    inc_log(name, rule)
    return true
end

function write_drop_ip(is_drop, drop_time)
    local ctx = C()
    local filename = cpath .. 'drop_ip.log'
    local fp = io.open(filename, 'ab')
    if fp == nil then return false end
    local logtmp = { os.time(), ctx.ip, ctx.server_name, ctx.request_uri, drop_time, is_drop }
    local fp_ok = pcall(function()
        fp:write(json.encode(logtmp) .. "\n")
    end)
    fp:close()
    return fp_ok
end

-- [FIX 4] total.json: akumulasi di shared dict, flush max 1x / 2 detik,
--          tulis atomik. Menghindari rewrite file pada setiap request + race.
local function flush_total()
    local stat = get_dict_stat()
    local lock = get_dict_stat_lock()
    if not stat or not lock then return false end
    local got = lock:incr('lock', 1, 0, 2)
    if not got or got ~= 1 then return false end

    local keys = stat:get_keys(0)
    if not keys or #keys == 0 then return false end

    local total_path = cpath .. 'total.json'
    local total = safe_json_decode(read_file_body(total_path), nil)
    if total == nil then
        total = { total = 0, sites = {}, rules = {} }
    end
    if type(total['sites']) ~= 'table' then total['sites'] = {} end
    if type(total['rules']) ~= 'table' then total['rules'] = {} end

    for _, key in ipairs(keys) do
        local n = stat:get(key)
        if n and n > 0 then
            local parts = {}
            for p in string.gmatch(key, '([^|]+)') do table.insert(parts, p) end
            if #parts == 2 then
                local sn, name = parts[1], parts[2]
                if not total['sites'][sn] then total['sites'][sn] = {} end
                if not total['sites'][sn][name] then total['sites'][sn][name] = 0 end
                if not total['rules'][name] then total['rules'][name] = 0 end
                total['total'] = (tonumber(total['total']) or 0) + n
                total['sites'][sn][name] = total['sites'][sn][name] + n
                total['rules'][name] = total['rules'][name] + n
            end
        end
        stat:delete(key)
    end
    local ok, enc = pcall(json.encode, total)
    if ok and enc then
        write_file(total_path, enc)
    end
    return true
end

function inc_log(name, rule)
    local ctx = C()
    local stat = get_dict_stat()
    if not stat then return false end
    stat:incr(ctx.server_name .. '|' .. name, 1, 0)
    flush_total()
    return true
end

function write_to_file(logstr)
    local ctx = C()
    local filename = config["logs_path"] .. '/' .. ctx.server_name .. '_' .. ngx.today() .. '.log'
    local fp = io.open(filename, 'ab')
    if fp == nil then
        -- [fix] dulu gagal diam-diam: kalau ownership/permission salah, semua
        -- log hilang tanpa jejak dan tidak ada yang menyadari.
        ngx.log(ngx.ERR, "free_waf: cannot open log file (check ownership/permission): ", filename)
        return false
    end
    local ok = pcall(function() fp:write(logstr) end)
    fp:close()
    return ok
end

function drop_abroad()
    local ctx = C()
    if ctx.ip == 'unknown' then return false end
    if not config['drop_abroad'] or not config['drop_abroad']['open'] then return false end
    if not is_site_config('drop_abroad') then return false end
    for _, v in ipairs(cnlist) do
        if compare_ip(v) then return false end
    end
    if blocked() then
        write_log('drop_abroad', '禁止大陆以外地区访问')
        return false
    end
    write_log('drop_abroad', '禁止大陆以外地区访问')
    return_blocked_response(config['drop_abroad']['status'] or 403, 'drop_abroad', 'geo_blocked')
    return true
end

function drop()
    local ctx = C()
    local shared = get_dict_drop_ip()
    if not shared then return false end
    local count = shared:get(ctx.ip)
    if not count then return false end
    if count > (tonumber(ctx.retry) or 6) then
        if blocked() then return false end
        return_blocked_response(config['cc']['status'] or 403, 'drop', 'ip_retry_exceeded')
        return true
    end
    return false
end

function cc()
    local ctx = C()
    if not config['cc'] or not config['cc']['open'] or not ctx.site_cc then return false end
    local shared = get_dict_waf()
    if not shared then return false end
    local token = ngx.md5(ctx.ip .. '_' .. ctx.request_uri)
    local count = shared:get(token)
    local limit = tonumber(ctx.limit) or 120
    if count then
        if count > limit then
            local sum = get_dict_drop_sum()
            local safe_count = 1
            if sum then
                local sc = sum:get(ctx.ip)
                if not sc then
                    sum:set(ctx.ip, 1, 86400)
                else
                    sum:incr(ctx.ip, 1)
                    safe_count = sc + 1
                end
            end
            local endtime = tonumber(ctx.endtime) or 300
            local lock_time = (endtime * safe_count)
            if lock_time > 86400 then lock_time = 86400 end
            if get_dict_drop_ip() then
                get_dict_drop_ip():set(ctx.ip, (tonumber(ctx.retry) or 6) + 1, lock_time)
            end
            local msg = (tonumber(ctx.cycle) or 60) .. '秒内累计超过' .. limit .. '次请求,封锁' .. lock_time .. '秒'
            write_log('cc', msg)
            write_drop_ip('cc', lock_time)
            if blocked() then return false end
            return_blocked_response(config['cc']['status'] or 403, 'cc', msg)
            return true
        else
            shared:incr(token, 1)
        end
    else
        shared:set(token, 1, tonumber(ctx.cycle) or 60)
    end
    return false
end

function cc2()
    local ctx = C()
    if not config['cc'] or not config['cc']['open'] or not ctx.site_cc then return false end
    if not site_config[ctx.server_name] then return false end
    local cc_conf = site_config[ctx.server_name]['cc']
    if type(cc_conf) ~= 'table' or not cc_conf['increase'] then return false end
    if ngx_match(ctx.uri, "\\.(jpg|png|gif|css|js|swf|ts)$", "isjo") then return false end
    local shared = get_dict_waf()
    if not shared then return false end
    local sv = shared:get(ctx.ip)
    if sv == 666 then return false end
    local rh = ctx.request_header
    local token2 = ngx.md5(ctx.method .. ctx.server_name .. tostring(rh['user-agent']) .. tostring(rh['host'])
        .. tostring(rh['accept-language']) .. tostring(rh['connection']) .. tostring(rh['accept'])
        .. tostring(rh['accept-encoding']) .. tostring(rh['upgrade-insecure-requests'])
        .. tostring(rh['cache-control'])) .. '_' .. 'cc2'
    local limit = tonumber(ctx.limit) or 120
    local cc2_limit = limit * 3
    local count = shared:get(token2)
    if count then
        if count > cc2_limit then
            local sum = get_dict_drop_sum()
            local safe_count = 1
            if sum then
                local sc = sum:get(ctx.ip)
                if not sc then
                    sum:set(ctx.ip, 1, 86400)
                else
                    sum:incr(ctx.ip, 1)
                    safe_count = sc + 1
                end
            end
            local retry = tonumber(ctx.retry) or 6
            if safe_count > retry then
                local endtime = tonumber(ctx.endtime) or 300
                local lock_time = (endtime * safe_count)
                if lock_time > 86400 then lock_time = 86400 end
                if get_dict_drop_ip() then
                    get_dict_drop_ip():set(ctx.ip, retry + 1, lock_time)
                end
                local msg = (tonumber(ctx.cycle) or 60) .. '秒内累计超过' .. limit .. '次请求,封锁' .. lock_time .. '秒'
                write_log('cc', msg)
                write_drop_ip('cc', lock_time)
                if blocked() then return false end
                return_blocked_response(config['cc']['status'] or 403, 'cc', msg)
                return true
            end
            if not blocked() then
                security_verification()
            end
        else
            shared:incr(token2, 1)
        end
    else
        local ok = pcall(function() shared:safe_set(token2, 1, tonumber(ctx.cycle) or 60) end)
        if not ok then shared:set(token2, 1, tonumber(ctx.cycle) or 60) end
    end
    return false
end

function security_verification()
    local ctx = C()
    if blocked() then return false end
    if ctx.uri_request_args['btwaf'] then
        local vn3 = get_dict_waf():get(ctx.ip)
        if tostring(vn3) == ctx.uri_request_args['btwaf'] then
            get_dict_waf():delete(ctx.ip)
            get_dict_waf():delete(ngx.md5(ctx.ip .. '_' .. ctx.uri))
            get_dict_waf():set(ctx.ip, 666, 3600)
            return false
        end
    end
    local n1 = math.random(0, 20)
    local n2 = math.random(0, 20)
    local n3 = n1 + n2
    get_dict_waf():set(ctx.ip, n3, 300)
    local vargs = '&btwaf='
    local sargs = string.gsub(ctx.request_uri, '.?btwaf=.*', '')
    if not string.find(sargs, '?', 1, true) then vargs = '?btwaf=' end
    ngx.header.charset = 'utf-8'
    local jsbody = string.format([[
<script type="text/javascript">var pre = prompt("Permintaan tidak normal!\nHitung: %s = ?");window.location.href='%s'+pre</script>
    ]], tostring(n1) .. ' + ' .. tostring(n2), sargs .. vargs)
    ngx.header.content_type = "text/html;charset=utf8"
    ngx.say(jsbody)
    ngx.exit(403)
end

function scan_black()
    local ctx = C()
    if not config['scan'] or not config['scan']['open'] or not is_site_config('scan') then return false end
    if is_ngx_match(scan_black_rules['cookie'], ctx.request_header['cookie'], false) then
        return deny(config['scan']['status'], 'scan', 'regular')
    end
    if is_ngx_match(scan_black_rules['args'], ctx.request_uri, false) then
        return deny(config['scan']['status'], 'scan', 'regular')
    end
    for key, _ in pairs(ctx.request_header) do
        if is_ngx_match(scan_black_rules['header'], key, false) then
            return deny(config['scan']['status'], 'scan', 'regular')
        end
    end
    return false
end

function ip_black()
    for _, rule in ipairs(ip_black_rules) do
        if compare_ip(rule) then
            return deny(config['cc']['status'], 'ip_black', tostring(rule[1] or ''))
        end
    end
    return false
end

function ip_white()
    for _, rule in ipairs(ip_white_rules) do
        if compare_ip(rule) then
            return true
        end
    end
    return false
end

function split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter == '') then return false end
    local pos, arr = 0, {}
    for st, sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

function url_white()
    local ctx = C()
    if ngx.var.document_root == '/www/server/phpmyadmin' then return true end
    if ctx.uri and (ctx.uri:sub(1, 28) == "/.well-known/acme-challenge/" or ctx.uri:sub(1, 13) == "/.well-known/") then
        return true
    end
    if is_ngx_match(url_white_rules, ctx.request_uri, false) then
        local url_data = split2(ctx.request_uri, '?')
        if not url_data or not url_data[1] then
            url_data = ctx.request_uri
        end
        if ngx.re.match(url_data, '/\\.\\./') then return false end
        return true
    end
    if site_config[ctx.server_name] ~= nil then
        if is_ngx_match(site_config[ctx.server_name]['url_white'], ctx.request_uri, false) then
            local url_data = split2(ctx.request_uri, '?')
            if not url_data or not url_data[1] then
                url_data = ctx.request_uri
            end
            if ngx.re.match(url_data, '/\\.\\./') then return false end
            return true
        end
    end
    return false
end

-- [FIX 8] dulu url_black() selalu aktif mengabaikan toggle "open"
function url_black()
    local ctx = C()
    if not config['url_black'] or not config['url_black']['open'] then return false end
    if is_ngx_match(url_black_rules, ctx.request_uri, false) then
        return deny(config['url_black']['status'], 'url_black', 'regular')
    end
    return false
end

function head()
    local ctx = C()
    if ctx.method ~= 'HEAD' then return false end
    for _, v in ipairs(head_white_rules) do
        if ngx_match(ctx.uri, v, "isjo") then
            return false
        end
    end
    local spiders = { 'spider', 'bot' }
    for _, v in ipairs(spiders) do
        if ngx_match(ctx.request_header['user-agent'], v, "isjo") then
            return false
        end
    end
    return deny(444, 'head', 'HEAD request forbidden')
end

function user_agent()
    local ctx = C()
    if not config['user-agent'] or not config['user-agent']['open'] or not is_site_config('user-agent') then
        return false
    end
    if is_ngx_match(user_agent_rules, ctx.request_header['user-agent'], 'user_agent') then
        return deny(config['user-agent']['status'], 'user_agent', 'regular', user_agent_html)
    end
    return false
end

function post()
    local ctx = C()
    if not config['post'] or not config['post']['open'] or not is_site_config('post') then return false end
    if ctx.method ~= "POST" then return false end
    -- [FIX 3] content-length bisa nil (chunked / tanpa header) -> crash 500
    local content_length = tonumber(ctx.request_header['content-length'])
    local max_len = 64 * 1024
    if content_length and content_length > max_len then return false end
    if get_boundary() then return false end
    local ok, args = pcall(function()
        ngx.req.read_body()
        return ngx.req.get_post_args()
    end)
    if not ok or not args then
        return false
    end
    ctx.request_args = args

    if is_ngx_match(post_rules, args, 'post') then
        return deny(config['post']['status'], 'post', 'regular', post_html)
    end
    return false
end

function disable_upload_ext(ext)
    local ctx = C()
    if not ext then return false end
    ext = string.lower(ext)
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    if is_key(sc['disable_upload_ext'], ext) then
        return deny(config['other']['status'], 'upload_ext', '黑名单扩展名', other_html)
    end
    return false
end

function post_data()
    local ctx = C()
    if ctx.method ~= "POST" then return false end
    local content_length = tonumber(ctx.request_header['content-length'])
    if not content_length then return false end
    local max_len = 256 * 1024
    if content_length > max_len then return false end
    local boundary = get_boundary()
    if boundary then
        local ok, data = pcall(function()
            ngx.req.read_body()
            return ngx.req.get_body_data()
        end)
        if not ok or not data then return false end
        local tmp = ngx.re.match(data, [[filename=\"(.+)\.(.*)\"]])
        if not tmp then return false end
        if not tmp[2] then return false end
        disable_upload_ext(tmp[2])
    end
    return false
end

function cookie()
    local ctx = C()
    if not config['cookie'] or not config['cookie']['open'] or not is_site_config('cookie') then return false end
    if not ctx.request_header['cookie'] then return false end
    if type(ctx.request_header['cookie']) == "table" then return false end
    ctx.request_cookie = string.lower(ctx.request_header['cookie'])
    if is_ngx_match(cookie_rules, ctx.request_cookie, 'cookie') then
        return deny(config['cookie']['status'], 'cookie', 'regular', cookie_html)
    end
    return false
end

function args()
    local ctx = C()
    if not config['get'] or not config['get']['open'] or not is_site_config('get') then return false end
    if is_ngx_match(args_rules, ctx.uri_request_args, 'args') then
        return deny(config['get']['status'], 'args', 'regular', get_html)
    end
    return false
end

function url()
    local ctx = C()
    if not config['get'] or not config['get']['open'] or not is_site_config('get') then return false end
    if is_ngx_match(url_rules, ctx.uri, 'url') then
        return deny(config['get']['status'], 'url', 'regular', get_html)
    end
    return false
end

function php_path()
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    for _, rule in ipairs(sc['disable_php_path'] or {}) do
        if ngx_match(ctx.uri, rule .. "/.*\\.php$", "isjo") then
            return deny(config['other']['status'], 'php_path', 'regular', other_html)
        end
    end
    return false
end

function url_path()
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    for _, rule in ipairs(sc['disable_path'] or {}) do
        if ngx_match(ctx.uri, rule, "isjo") then
            return deny(config['other']['status'], 'path', 'regular', other_html)
        end
    end
    return false
end

function url_ext()
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    for _, rule in ipairs(sc['disable_ext'] or {}) do
        if ngx_match(ctx.uri, "\\." .. rule .. "$", "isjo") then
            return deny(config['other']['status'], 'url_ext', 'regular', other_html)
        end
    end
    return false
end

function url_rule_ex()
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    if ctx.method == "POST" and not ctx.request_args then
        -- [FIX 3] content_length bisa nil -> crash 500
        local content_length = tonumber(ctx.request_header['content-length'])
        local max_len = 64 * 1024
        if content_length == nil or content_length < max_len then
            local ok, args = pcall(function()
                ngx.req.read_body()
                return ngx.req.get_post_args()
            end)
            if ok and args then
                ctx.request_args = args
            end
        end
    end
    for _, rule in ipairs(sc['url_rule'] or {}) do
        if ngx_match(ctx.uri, rule[1], "isjo") then
            if is_ngx_match(rule[2], ctx.uri_request_args, false) then
                return deny(config['other']['status'], 'url_rule', 'regular', other_html)
            end
            if ctx.method == "POST" and ctx.request_args ~= nil then
                if is_ngx_match(rule[2], ctx.request_args, 'post') then
                    return deny(config['other']['status'], 'post', 'regular', other_html)
                end
            end
        end
    end
    return false
end

function url_tell()
    local ctx = C()
    local sc = site_config[ctx.server_name]
    if type(sc) ~= 'table' then return false end
    for _, rule in ipairs(sc['url_tell'] or {}) do
        if ngx_match(ctx.uri, rule[1], "isjo") then
            if ctx.uri_request_args[rule[2]] ~= rule[3] then
                return deny(config['other']['status'], 'url_tell', 'regular', other_html)
            end
        end
    end
    return false
end

-- [FIX 6] dulu: lewati SEMUA key bernama content/body/msg/file/files/img/"" ->
--        POST dengan field "content" tidak pernah discan (bypass).
--        Sekarang: lewati hanya bila nilainya > 100KB (alasannya performa).
local function too_big(body)
    if type(body) == 'string' then
        return #body > 100 * 1024
    end
    return false
end

function is_ngx_match(rules, sbody, rule_name)
    local ctx = C()
    if rules == nil or sbody == nil then return false end
    if type(sbody) == "string" then
        sbody = { sbody }
    end
    if type(rules) == "string" then
        rules = { rules }
    end
    if type(rules) ~= 'table' or type(sbody) ~= 'table' then return false end

    for k, body in pairs(sbody) do
        if not too_big(body) then
            for i, rule in ipairs(rules) do
                if type(rule) ~= 'string' then
                    -- bukan string: Rules nonaktif
                elseif site_config[ctx.server_name] and rule_name then
                    local n = i - 1
                    local dr = site_config[ctx.server_name]['disable_rule']
                    if type(dr) == 'table' and type(dr[rule_name]) == 'table' then
                        for _, j in ipairs(dr[rule_name]) do
                            if n == j then
                                rule = ""
                            end
                        end
                    end
                    if body and rule ~= "" then
                        if type(body) == "string" then
                            if ngx_match(ngx.unescape_uri(body), rule, "isjo") then
                                ctx.error_rule = rule .. ' >> ' .. tostring(k) .. ':' .. body
                                return true
                            end
                        end
                        if type(k) == "string" then
                            if ngx_match(ngx.unescape_uri(k), rule, "isjo") then
                                ctx.error_rule = rule .. ' >> ' .. k
                                return true
                            end
                        end
                    end
                else
                    if body and rule ~= "" then
                        if type(body) == "string" then
                            if ngx_match(ngx.unescape_uri(body), rule, "isjo") then
                                ctx.error_rule = rule .. ' >> ' .. tostring(k) .. ':' .. body
                                return true
                            end
                        end
                        if type(k) == "string" then
                            if ngx_match(ngx.unescape_uri(k), rule, "isjo") then
                                ctx.error_rule = rule .. ' >> ' .. k
                                return true
                            end
                        end
                    end
                end
            end
        end
    end
    return false
end

function is_key(keys, values)
    if keys == nil or values == nil then return false end
    if type(values) == "string" then
        values = { values }
    end
    if type(keys) == "string" then
        keys = { keys }
    end
    if type(keys) ~= 'table' or type(values) ~= 'table' then return false end
    for _, value in pairs(values) do
        if type(value) == "boolean" or value == "" then return false end
        if type(value) ~= 'string' then return false end
        local sval = ngx.unescape_uri(string.lower(ngx.unescape_uri(value)))
        for _, v in ipairs(keys) do
            if v == sval then
                return true
            end
        end
    end
    return false
end

function get_return_state(rstate, rmsg)
    local result = {}
    result['status'] = rstate
    result['msg'] = rmsg
    return result
end

function get_btwaf_drop_ip()
    local shared = get_dict_drop_ip()
    if not shared then return {} end
    return shared:get_keys(0)
end

function remove_btwaf_drop_ip()
    local ctx = C()
    local target = ctx.uri_request_args['ip']
    if not target or not is_ipaddr(target) then return get_return_state(true, '格式错误') end
    if get_dict_drop_ip() then
        get_dict_drop_ip():delete(target)
    end
    return get_return_state(true, target .. '已解封')
end

function clean_btwaf_drop_ip()
    local data = get_btwaf_drop_ip()
    if get_dict_drop_ip() then
        for _, value in ipairs(data) do
            get_dict_drop_ip():delete(value)
        end
    end
    return get_return_state(true, '已解封所有封锁IP')
end

-- [FIX 10] endpoint admin (unban / clear ban) hanya untuk loopback
function min_route()
    local ctx = C()
    if not is_loopback(ngx.var.remote_addr) then return false end
    if ctx.uri == '/get_btwaf_drop_ip' then
        return_message(200, get_btwaf_drop_ip())
    elseif ctx.uri == '/remove_btwaf_drop_ip' then
        return_message(200, remove_btwaf_drop_ip())
    elseif ctx.uri == '/clean_btwaf_drop_ip' then
        return_message(200, clean_btwaf_drop_ip())
    end
    return false
end

function return_message(status, msg)
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.header["X-Protected-By"] = "ZySens"
    ngx.status = status
    ngx.say(json.encode(msg))
    ngx.exit(status)
end

function return_html(status, html)
    return return_blocked_response(status, "block", "html_direct", html)
end

------------------------------------------------------------------- main loop --
function run_btwaf()
    local ctx = C()
    ctx.server_name = ngx.var.server_name
    if not config['open'] or not is_site_config('open') then return false end
    ctx.error_rule = nil
    ctx.request_header = ngx.req.get_headers() or {}
    ctx.method = ngx.req.get_method()
    ctx.ip = get_client_ip()
    ctx.ipn = arrip(ctx.ip)
    ctx.request_uri = ngx.var.request_uri
    ctx.uri = ngx.unescape_uri(ngx.var.uri)

    -- Bypass WAF inspection for Let's Encrypt / ACME challenge verification
    if ctx.uri and (ctx.uri:sub(1, 28) == "/.well-known/acme-challenge/" or ctx.uri:sub(1, 13) == "/.well-known/") then
        return false
    end
    ctx.uri_request_args = ngx.req.get_uri_args() or {}
    ctx.cycle = config['cc']['cycle']
    ctx.endtime = config['cc']['endtime']
    ctx.limit = config['cc']['limit']
    ctx.retry = config['retry']
    ctx.retry_time = config['retry_time']
    ctx.retry_cycle = config['retry_cycle']
    ctx.site_cc = is_site_config('cc')

    min_route()

    if site_config[ctx.server_name] and ctx.site_cc then
        local cc_conf = site_config[ctx.server_name]['cc']
        if type(cc_conf) == 'table' then
            ctx.cycle = cc_conf['cycle'] or ctx.cycle
            ctx.endtime = cc_conf['endtime'] or ctx.endtime
            ctx.limit = cc_conf['limit'] or ctx.limit
        end
    end
    if site_config[ctx.server_name] then
        ctx.retry = site_config[ctx.server_name]['retry'] or ctx.retry
        ctx.retry_time = site_config[ctx.server_name]['retry_time'] or ctx.retry_time
        ctx.retry_cycle = site_config[ctx.server_name]['retry_cycle'] or ctx.retry_cycle
    end

    if ip_white() then return true end
    if ip_black() then return true end
    if url_white() then return true end
    if url_black() then return true end
    if drop() then return true end
    if drop_abroad() then return true end
    if cc() then return true end
    if cc2() then return true end
    if user_agent() then return true end
    if url() then return true end
    if args() then return true end
    if cookie() then return true end
    if scan_black() then return true end
    if post() then return true end
    if site_config[ctx.server_name] then
        if php_path() then return true end
        if url_path() then return true end
        if url_ext() then return true end
        if url_rule_ex() then return true end
        if url_tell() then return true end
        if post_data() then return true end
    end
    return false
end

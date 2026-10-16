-- free_waf entry point (access_by_lua_file)
--
-- Fail-open by design: kalau ada error di logika WAF, request diteruskan
-- normal dan errornya dicatat ke error_log. Tanpa ini, satu bug di rules
-- akan membuat seluruh situs 500.
local ok, err = pcall(run_btwaf)
if not ok then
    ngx.log(ngx.ERR, "free_waf: request aborted, passing through. error=", tostring(err))
end

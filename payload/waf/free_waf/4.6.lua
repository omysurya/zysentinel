--[[
	免费WAF 功能比较少
	
]]--
local cpath = "/www/server/free_waf/"
local jpath = cpath .. "rule/"
local json = require "cjson"
local ngx_match = ngx.re.find
local multipart = require "multipart"
error_rule = nil

function read_file(name)
    fbody = read_file_body(jpath .. name .. '.json')
    if fbody == nil then
        return {}
    end
    return json.decode(fbody)
end

function read_file_body(filename)
	fp = io.open(filename,'r')
	if fp == nil then
        return nil
    end
	fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

function write_file(filename,body)
	fp = io.open(filename,'w')
	if fp == nil then
        return nil
    end
	fp:write(body)
	fp:flush()
	fp:close()
	return true
end

local config = json.decode(read_file_body(cpath .. 'config.json'))
local site_config = json.decode(read_file_body(cpath .. 'site.json'))

function is_ipaddr(client_ip)
	local cipn = split(client_ip,'.')
	if arrlen(cipn) < 4 then return false end
	for _,v in ipairs({1,2,3,4})
	do
		local ipv = tonumber(cipn[v])
		if ipv == nil then return false end
		if ipv > 255 or ipv < 0 then return false end
	end
	return true
end


function http_log()
    data=''
    data=method..' ' ..request_uri.. ' '..  'HTTP/1.1\n'
    if not ngx.req.get_headers() then return data end
    for key,valu in pairs(ngx.req.get_headers()) do 
        if type(valu)=='string' then 
            data=data..key..':'..valu..'\n'
        end
    end
    data=data..'\n'
    if method ~='GET' then 
        ngx.req.read_body()
        if get_boundary() then
            if ngx.req.get_body_data() then 
                data =data ..ngx.req.get_body_data()
            else
            	request_args2=ngx.req.get_body_file()
		    	request_args2=read_file_body(request_args2)
		    	data =data ..request_args2
            end
            return data
        else
	        request_args = ngx.req.get_post_args(1000000)
	        coun=0
	        if not request_args then return data end 
	        for i,v in pairs(request_args) do
	            if type(v) =='table' then 
	                for i2,v2 in pairs(v) do 
	                    if type(v2)=='string' then 
	                        if coun ==0 then 
	                            data=data..i..'='..v2
	                        else
	                             data=data..'&'..i..'='..v2
	                        end
	                        coun=coun+1
	                    end 
	                end 
	            elseif  type(v)=='string' then 
    	            if coun ==0 then 
                        data=data..i..'='..v
                    else
                         data=data..'&'..i..'='..v
    	            end 
                    coun=coun+1
                end 
            end
            return data
        end
    else
        return data
    end
end 

function compare_ip_block(ips)
	if not ips then return false end
	if string.find(ips,':') then return false end
	ips = arrip(ips)
	if not is_max(ips,arrip("127.0.0.255")) then return false end
	if not is_min(ips,arrip("127.0.0.1")) then return false end
	return true
end

function de_dict (l_key,l_data)
	if type(l_data) ~= "table" then return l_data end
	if arrlen(l_data) == 0 then return l_data end
	if not l_data then return false end
	local r_data = {}
	if arrlen(l_data) >= 500 then 
		lan_ip('args','非法请求')
		return true
	end
	for li,lv in pairs(l_data)
	do
		r_data[l_key..tostring(li)] = lv
	end

	return r_data
end

function get_client_ip()
	local client_ip = "unknown"
	if site_config[server_name] then
		if site_config[server_name]['cdn'] then
			for _,v in ipairs(site_config[server_name]['cdn_header'])
			do
				if request_header[v] ~= nil and request_header[v] ~= "" then
					local header_tmp = request_header[v]
					if type(header_tmp) == "table" then header_tmp = header_tmp[1] end
					client_ip = split_bylog(header_tmp,',')[1]
					if compare_ip_block(client_ip) then
						if tostring(ngx.var.remote_addr) == tostring(client_ip) then
							client_ip = ngx.var.remote_addr
						else
							client_ip = ngx.var.remote_addr
						end
					end
					break;
				end
			end
		end
	end
	if type(client_ip) == 'table' then client_ip = "" end
	if (string.match(client_ip,"^%d+%.%d+%.%d+%.%d+$") == nil and string.match(client_ip,"^[%w:]+$") == nil) or client_ip == 'unknown'  then
		client_ip = ngx.var.remote_addr
		if client_ip == nil then
			client_ip = "unknown"
		end
	end
	return client_ip
end

function split_bylog( str,reps )
	local resultStrList = {}
	string.gsub(str,'[^'..reps..']+',function(w)
		table.insert(resultStrList,w)
	end)
	return resultStrList
end


function split( str,reps )
    local resultStrList = {}
    string.gsub(str,'[^'..reps..']+',function(w)
        table.insert(resultStrList,w)
    end)
    return resultStrList
end

function arrip(ipstr)
    if string.find(ipstr,':') then return ipstr end
	if ipstr == 'unknown' then return {0,0,0,0} end
	iparr = split(ipstr,'.')
	iparr[1] = tonumber(iparr[1])
	iparr[2] = tonumber(iparr[2])
	iparr[3] = tonumber(iparr[3])
	iparr[4] = tonumber(iparr[4])
	return iparr
end

function join(arr,e)
	result = ''
	length = arrlen(arr)
	for k,v in ipairs(arr)
	do
		if length == k then e = '' end
		result = result .. v .. e
	end
	return result
end

function arrlen(arr)
	if not arr then return 0 end
	count = 0
	for _,v in ipairs(arr)
	do
		count = count + 1
	end
	return count
end

function select_rule(rules)
	if not rules then return {} end
	new_rules = {}
	for i,v in ipairs(rules)
	do 
		if v[1] == 1 then
			table.insert(new_rules,v[2])
		end
	end
	return new_rules
end

function return_error()
    error_rule='http包非法,并且被封锁IP,如果自定义了from-data可能会导致误报。如果大量出现当前问题。可以选择在全局设置中关闭From-data协议'
    write_log('post','regular')
	return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
end 


function is_site_config(cname)
	if site_config[server_name] ~= nil then
		if cname == 'cc' then
			return site_config[server_name][cname]['open']
		else
			return site_config[server_name][cname]
		end
	end
	return true
end

function get_boundary()
    local header = request_header["content-type"]
    if not header then return nil end
    if type(header) == "table" then
        return_error()
    end
	if header then
    	if ngx.re.find(header,[[multipart]],'ijo') then
    		if not ngx.re.match(header,'^multipart/form-data; boundary=') then 
    				return_error()
    		end
    		return true
    	else
    		return false
    	end 
    end 
end

local get_html = read_file_body(config["reqfile_path"] .. '/' .. config["get"]["reqfile"])
local post_html = read_file_body('/www/server/free_waf/html/post.html')
local cookie_html = read_file_body(config["reqfile_path"] .. '/' .. config["cookie"]["reqfile"])
local user_agent_html = read_file_body(config["reqfile_path"] .. '/' .. config["user-agent"]["reqfile"])
local other_html = read_file_body(config["reqfile_path"] .. '/' .. config["other"]["reqfile"])
local cnlist = json.decode(read_file_body(cpath .. '/rule/cn.json'))
local scan_black_rules = read_file('scan_black')
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


function is_min(ip1,ip2)
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] > ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

function is_max(ip1,ip2)
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] < ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

function compare_ip(ips)
	if ip == 'unknown' then return true end
	if string.find(ip,':') then return false end
	if not is_max(ipn,ips[2]) then return false end
	if not is_min(ipn,ips[1]) then return false end
	return true
end

function write_log(name,rule)
	local count,_ = ngx.shared.free_waf_drop_ip:get(ip)
	if count then
		ngx.shared.free_waf_drop_ip:incr(ip,1)
	else
		ngx.shared.free_waf_drop_ip:set(ip,1,retry_cycle)
	end
	if config['log'] ~= true or is_site_config('log') ~= true then return false end
	local method = ngx.req.get_method()
	if error_rule then 
		rule = error_rule
		error_rule = nil
	end
	
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,rule,http_log()}
	local logstr = json.encode(logtmp) .. "\n"
	local count,_ = ngx.shared.free_waf_drop_ip:get(ip)	
	if count > retry and name ~= 'cc' then
		local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
		if not safe_count then
			ngx.shared.free_waf_drop_sum:set(ip,1,86400)
			safe_count = 1
		else
			ngx.shared.free_waf_drop_sum:incr(ip,1)
		end
		local lock_time = retry_time * safe_count
		if lock_time > 86400 then lock_time = 86400 end
		logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,retry_cycle .. '秒以内累计超过'..retry..'次以上非法请求,封锁'.. lock_time ..'秒',http_log()}
		logstr = logstr .. json.encode(logtmp) .. "\n"
		ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
		write_drop_ip('inc',lock_time)
	end
	write_to_file(logstr)
	inc_log(name,rule)
end

function write_drop_ip(is_drop,drop_time)
	local filename = cpath .. 'drop_ip.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	local logtmp = {os.time(),ip,server_name,request_uri,drop_time,is_drop}
	local logstr = json.encode(logtmp) .. "\n"
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end

function inc_log(name,rule)
	local total_path = cpath .. 'total.json'
	local tbody = read_file_body(total_path)
	if not tbody then return false end
	local total = json.decode(tbody)
	if not total['sites'] then total['sites'] = {} end
	if not total['sites'][server_name] then total['sites'][server_name] = {} end
	if not total['sites'][server_name][name] then total['sites'][server_name][name] = 0 end
	if not total['rules'] then total['rules'] = {} end
	if not total['rules'][name] then total['rules'][name] = 0 end
	if not total['total'] then total['total'] = 0 end
	total['total'] = total['total'] + 1
	total['sites'][server_name][name] = total['sites'][server_name][name] + 1
	total['rules'][name] = total['rules'][name] + 1
	local total_log = json.encode(total)
	if not total_log then return false end
	write_file(total_path,total_log)
end

function write_to_file(logstr)
	local filename = config["logs_path"] .. '/' .. server_name .. '_' .. ngx.today() .. '.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end

function drop_abroad()
	if ip == 'unknown' then return false end
	if not config['drop_abroad']['open'] or not is_site_config('drop_abroad') then return false end	
	for _,v in ipairs(cnlist)
	do
		if compare_ip(v) then return false end
	end
	ngx.exit(config['drop_abroad']['status'])
	return true
end

function drop()
	local count,_ = ngx.shared.free_waf_drop_ip:get(ip)
	if not count then return false end
	if count > retry then
		ngx.exit(config['cc']['status'])
		return true
	end
	return false
end

function cc()
	if not config['cc']['open'] or not site_cc then return false end
	local token = ngx.md5(ip .. '_' .. request_uri)
	local count,_ = ngx.shared.free_waf:get(token)
	if count then
		if count > limit then
			local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
			if not safe_count then
				ngx.shared.free_waf_drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.free_waf_drop_sum:incr(ip,1)
			end
			local lock_time = (endtime * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
			write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
			write_drop_ip('cc',lock_time)
			ngx.exit(config['cc']['status'])
			return true
		else
			ngx.shared.free_waf:incr(token,1)
		end
	else
		ngx.shared.free_waf:set(token,1,cycle)
	end
	return false
end

function cc2()
	if not config['cc']['open'] or not site_cc then return false end
	if not site_config[server_name] then return false end
	if not site_config[server_name]['cc']['increase'] then return false end
	if ngx_match(uri,"\\.(jpg|png|gif|css|js|swf|ts)$","isjo") then return false end
	sv,_ = ngx.shared.free_waf:get(ip)
	if sv == 666 then return false end
	local token2 = ngx.md5(method .. server_name .. tostring(request_header['user-agent']) .. tostring(request_header['host']) .. tostring(request_header['accept-language']) .. tostring(request_header['connection']) .. tostring(request_header['accept']) .. tostring(request_header['accept-encoding']) .. tostring(request_header['upgrade-insecure-requests']) .. tostring(request_header['cache-control'])) .. '_' .. 'cc2'
	local cc2_limit = limit * 3
	local count,_ = ngx.shared.free_waf:get(token2)
	if count then
		if count > cc2_limit then
			local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
			if not safe_count then
				ngx.shared.free_waf_drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.free_waf_drop_sum:incr(ip,1)
			end
			if safe_count > retry then 
				local lock_time = (endtime * safe_count)
				if lock_time > 86400 then lock_time = 86400 end
				ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
				write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
				write_drop_ip('cc',lock_time)
				ngx.exit(config['cc']['status'])
				return true
			end
			security_verification()
		else
			ngx.shared.free_waf:incr(token2,1)
		end
	else
		ngx.shared.free_waf:safe_set(token2,1,cycle)
	end
	return false
end

function security_verification()
	if uri_request_args['btwaf'] then
		vn3,_ = ngx.shared.free_waf:get(ip)
		if tostring(vn3) == uri_request_args['btwaf'] then
			ngx.shared.free_waf:delete(ip)
			ngx.shared.free_waf:delete(ngx.md5(ip .. '_' .. uri))
			ngx.shared.free_waf:set(ip,666,3600)
			return false
		end
	end
	math.randomseed(tostring(os.time()):reverse():sub(1, 6))
	local n1 = math.random(0,20)
	local n2 = math.random(0,20)
	local n3 = n1 + n2
	ngx.shared.free_waf:set(ip,n3,300)
	local vargs = '&btwaf='
	sargs = string.gsub(request_uri,'.?btwaf=.*','')
	if not string.find(sargs,'?',1,true) then vargs = '?btwaf=' end
	ngx.header.charset = 'utf-8'
	local jsbody = string.format([[
<script type="text/javascript">var pre = prompt("检测到您的请求异常!\n请输入右边的计算结果: %s = ?");window.location.href='%s'+pre</script>
	]],tostring(n1) .. ' + ' .. tostring(n2),sargs .. vargs)
	ngx.header.content_type = "text/html;charset=utf8"
	ngx.say(jsbody)
	ngx.exit(403)
end

function scan_black()
	if not config['scan']['open'] or not is_site_config('scan') then return false end
	if is_ngx_match(scan_black_rules['cookie'],request_header['cookie'],false) then
		write_log('scan','regular')
		ngx.exit(config['scan']['status'])
		return true
	end
	if is_ngx_match(scan_black_rules['args'],request_uri,false) then
		write_log('scan','regular')
		ngx.exit(config['scan']['status'])
		return true
	end
	for key,value in pairs(request_header)
	do
		if is_ngx_match(scan_black_rules['header'],key,false) then
			write_log('scan','regular')
			ngx.exit(config['scan']['status'])
			return true
		end
	end
	return false
end

function ip_black()
	for _,rule in ipairs(ip_black_rules)
	do
		if compare_ip(rule) then 
			ngx.exit(config['cc']['status'])
			return true 
		end
	end
	return false
end

function ip_white()
	for _,rule in ipairs(ip_white_rules)
	do
		if compare_ip(rule) then 
			return true 
		end
	end
	return false
end

function split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

function url_white()
	if ngx.var.document_root=='/www/server/phpmyadmin' then return true end
	if is_ngx_match(url_white_rules,request_uri,false) then
        url_data=split2(request_uri,'?')
        if not url_data then url_data=request_uri end 
        if not url_data[1] then 
            url_data=request_uri 
        else
            url_data=url_data[1]
        end
        if ngx.re.match(url_data,'/\\.\\./') then return false end
		return true
	end
	if site_config[server_name] ~= nil then
		if is_ngx_match(site_config[server_name]['url_white'],request_uri,false) then
            url_data=split2(request_uri,'?')
            if not url_data then url_data=request_uri end 
            if not url_data[1] then 
                url_data=request_uri 
            else
                url_data=url_data[1]
            end
            if ngx.re.match(url_data,'/\\.\\./') then return false end
    		return true
    	end
	end
	return false
end

function url_black()
	if is_ngx_match(url_black_rules,request_uri,false) then
		ngx.exit(config['get']['status'])
		return true
	end
	return false
end

function head()
	if method ~= 'HEAD' then return false end
	for _,v in ipairs(head_white_rules)
	do
		if ngx_match(uri,v,"isjo") then
			return false
		end
	end
	spiders = {'spider','bot'}
	for _,v in ipairs(spiders)
	do
		if ngx_match(request_header['user-agent'],v,"isjo") then
			return false
		end
	end
	write_log('head','禁止HEAD请求')
	ngx.shared.free_waf:set(ip,retry,endtime)
	write_drop_ip('head',endtime)
	ngx.exit(444)
end

function user_agent()
	if not config['user-agent']['open'] or not is_site_config('user-agent') then return false end	
	if is_ngx_match(user_agent_rules,request_header['user-agent'],'user_agent') then
		write_log('user_agent','regular')
		return_html(config['user-agent']['status'],user_agent_html)
		return true
	end
	return false
end


local function _process_json_args(json_args,t)
		if type(json_args)~='table' then return {} end
        local t = t or {}
        for k,v in pairs(json_args) do
                if type(v) == 'table' then
                        for _k,_v in pairs(v) do
                                if type(_v) == "table" then
                                    t = _process_json_args(_v,t)

                                else
                                        if type(t[k]) == "table" then
                                                table.insert(t[k],_v)

                                        elseif type(t[k]) == "string" then
                                                local tmp = {}
                                                table.insert(tmp,t[k])
                                                table.insert(tmp,_v)
                                                t[k] = tmp
                                        else

                                        t[k] = _v
                                        end
                                end

                        end
                else
                                         if type(t[k]) == "table" then
                                                table.insert(t[k],v)
                                        elseif type(t[k]) == "string" then
                                                local tmp = {}
                                                table.insert(tmp,t[k])
                                                table.insert(tmp,v)
                                                t[k] = tmp
                                        else

                                        t[k] = v
                                        end
                end
        end
        return t
end

function split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end


function post()
	if not config['post']['open'] or not is_site_config('post') then return false end	
	if method == "GET"  then return false end
	content_length=tonumber(request_header['content-length'])
	if content_length == nil then return false end
	local content_type = ngx.req.get_headers()["Content-type"]
	if not content_type then return false end 
	if type(content_type)~='string' then 
		return_error()
	end 
	if content_type and ngx.re.find(content_type, 'multipart',"oij") then return false end 
	ngx.req.read_body()
	request_args = ngx.req.get_post_args(1000000)
	if not request_args then
		if content_length >10000 then 
		    request_uri22=split2(request_uri,'?')
		    request_uri22=request_uri22[1]
			local check_html = [[<html><meta charset="utf-8" /><title>Nginx缓冲区溢出</title><div>宝塔免费WAF提醒您,Nginx缓冲区溢出,传递的参数超过接受参数的大小,出现异常,<br>第一种解决方案:把当前url-->]]..'^'..request_uri22..[[加入到URL白名单中</br>第二种解决方案:面板-->nginx管理->性能调整-->client_body_buffer_size的值调整为10240K 或者5024K(PS:可能会一直请求失败建议加入白名单)</br></div></html>]]
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.say(check_html)
			ngx.exit(403)
		end 
		return true
	end
	list_data={}
	if type(request_args)=='table' then
		for k,v in pairs(request_args)
		do
			if type(v)=='table' then
				table.insert(list_data,de_dict(k,v))
			end
            if type(v)=='string' then
				if not  string.find(v,'^data:.+/.+;base64,') then
					if (#v) >=200000 then
						write_log('post',k..'     参数值长度超过20w已被系统拦截')
						return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
						return true
					end
				end
			end
		end
	end
	
	if content_type and  ngx.re.find(content_type, '^application/json',"oij") and ngx.req.get_headers()["Content-Length"] and tonumber(ngx.req.get_headers()["Content-Length"]) ~= 0 then
		local ok ,request_args = pcall(function()
			return json.decode(ngx.req.get_body_data())
		end)
		if not ok then
			local check_html = [[<html><meta charset="utf-8" /><title>json格式错误</title><div>请传递正确的json参数</div></html>]]
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.say(check_html)
			ngx.exit(403)
		end
		if type(request_args)~='table' then return false end 
		request_args=_process_json_args(request_args)
		if is_ngx_match(post_rules,request_args,'post') then
			write_log('post','regular')
			return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
			return true
		end	
	else
		if list_data then 
			if arrlen(list_data)>=1 then 
				for i2,v2 in ipairs(list_data) do 
					request_args=_process_json_args(v2,request_args)
				end 
			else 
				request_args=_process_json_args(list_data,request_args)
			end 
		else
			request_args =_process_json_args(request_args)
		end
		if count_sieze(request_args)>=800 then
			error_rule = '参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		    write_log('post','参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报')
		    local check_html = [[<html><meta charset="utf-8" /><title>参数太多</title><div>宝塔免费WAF提醒您,POST传递的参数数量超过800,拒绝访问,如有误报请点击误报</div></html>]]
				ngx.header.content_type = "text/html;charset=utf8"
				ngx.say(check_html)
				ngx.exit(403)
		end
		if list_data then
		    for i2,v2 in ipairs(list_data) do 
	    		if is_ngx_match(post_rules,v2,'post') then
	    			write_log('args','regular')
	    			return_html(config['get']['status'],get_html)
	    			return true
	    		end	
	    	end
		end
		if is_ngx_match(post_rules,request_args,'post') then
			write_log('post','regular')
			return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
			return true
		end	
	end
	return false
end


function disable_upload_ext(ext)
	if not ext then return false end
	if is_key(site_config[server_name]['disable_upload_ext'],ext) then
		write_log('upload_ext','上传扩展名黑名单')
		return_html(config['other']['status'],other_html)
		return true
	end
end

function disable_upload_ext2(ext)
	if not ext then return false end
    if type(ext)~='table' then return false end 
	for i,k in pairs(ext) do 
	    for i2,k2 in pairs(k) do
	       check_file=ngx.re.gmatch(k2,[[filename=]],'ijo')
	       ret={}
	       while true do
    		    local m, err = check_file()
    	      	if m then 
    	      		table.insert(ret,m)
    	      	else
    	      		break
    	      	end 
	       end
            if arrlen(ret)>1 then 
                return_error()
            end
    	    if not ngx.re.match(k2,[[filename=""]],'ijo') and  not ngx.re.match(k2,[[filename=".+"]],'ijo') then 
				return_error()
    	    else 
    	        k2 = string.lower(k2)
    	        if site_config[server_name] ==nil then return false end 
	        	disa=site_config[server_name]['disable_upload_ext']
            	if is_ngx_match(disa,k2,'post') then
            		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP2')
            		return true
            	end
    	    end
		
    	 end 
	end 
	
end


function  from_data(data,data2,data3)
	if arrlen(data) ==0 then return false end 
	local count=0
	for k,v in pairs(data) do
	    if ngx.re.match(v[0],'filename=') then 
	        if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename=""\r*$') then 
	            if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename="[^"]+"\r*$') then 
	                return_error2()
	            end
	        end
	        count=count+1
	        disable_upload_ext(v[0])
	    end
		if config['from_data'] then 
			if not ngx.re.match(v[0],'filename=') and  not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"\r*$')  then 
				return_error2()
			end
		end
	end
    len_count=arrlen(data2)+arrlen(data3)
	if count ~=len_count then
	       return_error2()
	 end 
end

function  return_error2()
	error_rule = 'from-data 请求异常,拒绝访问,如有误报请点击误报'
	write_log('post','from-data 请求异常,拒绝访问,如有误报请点击误报')
    local check_html = [[<html><meta charset="utf-8" /><title>from-data请求error</title><div>宝塔免费WAF提醒您,from-data 请求异常,拒绝访问,如有误报请点击误报</div></html>]]
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.say(check_html)
		ngx.exit(200)

end 

function lan_ip(type,name)
	local safe_count,_ = ngx.shared.free_waf_drop_sum:get(ip)
	if not safe_count then
		ngx.shared.free_waf_drop_sum:set(ip,1,86400)
		safe_count = 1
	else
		ngx.shared.free_waf_drop_sum:incr(ip,1)
	end
	local lock_time = (endtime * safe_count)
	if lock_time > 86400 then lock_time = 86400 end
	ngx.shared.free_waf_drop_ip:set(ip,retry+1,lock_time)
	--write_log(type,name)
	local method = ngx.req.get_method()
	if error_rule then 
		rule = error_rule
		error_rule = nil
	end
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,type,name,http_log()}
	local logstr = json.encode(logtmp) .. "\n"
	write_to_file(logstr)
	inc_log(type,rule)
	if type =='args' or type=='post' or type =='inc' then 
		write_drop_ip('inc',lock_time)
	else
		write_drop_ip(type,lock_time)
	end 
	ngx.exit(config['cc']['status'])
end


function gusb_string(table)
	ret={"-","]","@","#","&","_","{","}"}
	ret2={}
	if arrlen(table)==0 then return table end 
	for _,v in pairs(table) do
		for _,v2 in pairs(ret) do 
			if ngx.re.find(v[0],v2) then 
				v[0]=ngx.re.gsub(v[0],v2,'baota')
			end
		end
		v[0]=string.gsub(v[0],'%[','baota')
		v[0]=string.gsub(v[0],'%(','baota')
		v[0]=string.gsub(v[0],'%)','baota')
		v[0]=string.gsub(v[0],'%+','baota')
		v[0]=string.gsub(v[0],'%$','baota')
		v[0]=string.gsub(v[0],'%?','baota')
	end
	return table
end 

function disable_upload_ext3(ext,check)
	if not ext then return false end
    if type(ext)~='table' then return false end 
    for i2,k2 in pairs(ext) do
        check_file=ngx.re.gmatch(k2,[[filename=]],'ijo')
       ret={}
       while true do
    	    local m, err = check_file()
          	if m then 
          		table.insert(ret,m)
          	else
          		break
          	end 
       end
        if arrlen(ret)>1 then 
            return_error()
        end
        if check==1 then
             if arrlen(ret)==0 then 
            	if not k2 then return false end 
				kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
			    if not kkkkk then 
                	if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP1') end 
                		return return_error2('','')
                	end
                else
                    k2=kkkkk[0]
                    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP2') end
                		return return_error2('','')
                	end
                end
                if k2 then 
                	k2=string.gsub(k2,'\r','')
            		if ngx.re.match(k2,[[filename=]],'ijo') then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP3') end 
                end
            	if ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r]],'ijos') then 
            	    tttt=ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r\s]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return return_error2(tttt[1],tttt[1]) end
            	end
            	if ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos') then 
            	    tttt=ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end 
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return return_error2(tttt[1],tttt[1]) end
            	end
			else
				if not k2 then return false end 
				k2=string.gsub(k2,'\r','')
				kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
				if not kkkkk then 
				    k3=ngx.re.match(k2,[[Content-Disposition:.+Content-Type:]])
				    if not k3 then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP4') end 
				    
				    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then 
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP5')
            	    end 
				else 
				    k3=ngx.re.match(kkkkk[0],[[Content-Disposition:.+Content-Type:]])
					if not k3 then return return_html(config['post']['status'],post_html) end

				    --if not k3 then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP6') end 
				     if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP7')
            	    end 
				end
				
				if site_config[server_name] ==nil then return false end 
            	disa=site_config[server_name]['disable_upload_ext']
            	if is_ngx_match(disa,k3,'post') then
            		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP')
            	end
            	if #k3[0] >200 then 
        	       ret10={}
            	   local tmp10 = ngx.re.gmatch(k3[0],'form-data')
            	   while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                   if tonumber(arrlen(ret10)) >1 then return false end 
                   if ngx.re.match(k3[0],'--$') then return false end
                   return return_message(200,'error1->The upload file name is too long')
        	   	end
            	local tmp8 = ngx.re.gmatch(k3[0],'\"')
            	local tmp9 = ngx.re.gmatch(k3[0],'=')
            	local tmp10 = ngx.re.gmatch(k3[0],';')
                ret8={}
                ret9={}
                ret10={}
                while true do local m, err = tmp8() if m then  table.insert(ret8,m) else break end  end
                while true do local m, err = tmp9() if m then  table.insert(ret9,m) else break end  end
                while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                if tonumber(arrlen(ret9))==2 and tonumber(arrlen(ret8))==4 and tonumber(arrlen(ret10))==2 then
                    return false
                end 
                error_rule = '非法文件上传请求。已经被系统拦截'
		    write_log('post','非法文件上传请求。已经被系统拦截')
		    local check_html = [[<html><meta charset="utf-8" /><title>非法请求</title><div>宝塔免费WAF提醒您,文件上传参数错误。文件名或者参数中不能存在分号、等号、和双引号。如有误报请点击误报</div></html>]]
				ngx.header.content_type = "text/html;charset=utf8"
				ngx.say(check_html)
				ngx.exit(403)
			end
        else 
            if arrlen(ret)==0 then
                return false
            else 
        	    if not ngx.re.match(k2,[[filename=""Content-Type]],'ijo') and  not ngx.re.match(k2,[[filename=".+"Content-Type]],'ijo') then 
        			return_error()
        	    else
        	    	check_filename=ngx.re.match(k2,[[filename="(.+)"Content-Type]],'ijo')
        	        if check_filename then 
        	            if check_filename[1] then
        	                if ngx.re.match(check_filename[1],'name=','ijo') then return return_error() end 
        	                if ngx.re.match(check_filename[1],'php','ijo') then return return_error() end 
        	                if ngx.re.match(check_filename[1],'jsp','ijo') then return return_error() end 
        	            end 
        	        end
        	        if #k2 >200 then 
        	           ret11={}
                	   local tmp11 = ngx.re.gmatch(k2,'form-data')
                	   while true do local m, err = tmp11() if m then  table.insert(ret11,m) else break end  end
                       if tonumber(arrlen(ret11)) >1 then return false end
                       if #k2 >5000 and ngx.re.match(k2,'--$') then return false end 
                       write_log('post','文件上传存在异常。如有误报请点击误报')
                       return return_message(200,'文件上传存在异常。如有误报请点击误报')
        	        end
        	        k2 = string.lower(k2)
        	        if site_config[server_name] ==nil then return false end 
                	disa=site_config[server_name]['disable_upload_ext']
                	if is_ngx_match(disa,k2,'post') then
                		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP'..' >> '..k2)
                		return true
                	end
        	    end
            end 
        end 
	 end
end

function table_key(tbl, key)
    if tbl == nil then
        return false
    end
    for k, v in pairs(tbl) do
        if k == key then
            return true
        end
    end
    return false
end

local function chsize(char)
	if not char then
		print("not char")
		return 0
	elseif char > 240 then
		return 4
	elseif char > 225 then
		return 3
	elseif char > 192 then
		return 2
	else
		return 1
	end
end

function ReadFileHelper(str)
	 if type(str)~='string' then return str end
	 res = string.gsub(str, "\r", "")
	 res = string.gsub(res, "\n", "")
    return res
end
function utf8sub(str, startChar, numChars)
	local startIndex = 1
	while startChar > 1 do
		local char = string.byte(str, startIndex)
		startIndex = startIndex + chsize(char)
		startChar = startChar - 1
	end

	local currentIndex = startIndex

	while numChars > 0 and currentIndex <= #str do
		local char = string.byte(str, currentIndex)
		currentIndex = currentIndex + chsize(char)
		numChars = numChars -1
	end
	return str:sub(startIndex, currentIndex - 1)
end


function return_post_data2()
	if method ~= "POST" then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	local boundary = get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
            data=read_file_body(data) 
		end
		if not data then return false end 
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=]],'ijo')
		ret={}
		while true do
		    local m, err = tmp2()
	      	if m then 
	      		table.insert(ret,m)
	      	else
	      		break
	      	end 
	    end
	    ret=gusb_string(ret)
	    if arrlen(ret)>=1 then  
		    for _,v in pairs(ret) do 
				if not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=".+"; filename=') and not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=”.+”; filename=') then 
					return_error()
				end
		    end
	    end
	    if arrlen(ret)==1 then 
	    	return 1 
	    else
	    	return 2 
	    end
	end
	return 3
end


function  post_data_chekc()
	if not config['post']['open'] or not is_site_config('post') then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end
	if method =="POST" then
		return_post_data=return_post_data2()
		if not return_post_data then return false end 
		if return_post_data==3 then return false end 
		ngx.req.read_body()
		request_args2=ngx.req.get_body_data()
		if not request_args2 then 
		    request_args2=ngx.req.get_body_file()
		    request_args2=read_file_body(request_args2)
		end
		if not request_args2  then return false end 
		if not request_header['Content-Type'] then return false end
		if type(request_header['Content-Type']) ~= "string" then 
			if type(request_header['Content-Type']) ~= "string" then 
				return_error()
			end
		end
        local p, err = multipart.new(request_args2, ngx.var.http_content_type)
        if not p then
           return false 
        end
        if not ngx.re.match(ReadFileHelper(p['body']),ReadFileHelper(p['boundary2'])..'--$','ijo') then
            return_error()
        end
        site_count=0
        local array = {}
        while true do
           local part_body, name, mime, filename = p:parse_part()
           if not part_body then
              break
           end
           site_count=site_count+1
            if filename ~=nil then 
                if ngx.re.match(filename,'name=','ijo') then return return_error() end 
            end 
            if name ==nil then 
              if part_body then
                    if #part_body>30 then 
                        array[utf8sub(part_body,1,30)]=part_body
                    else
                        array[part_body]=part_body
                    end 
              end
            else
                if #name >300 then 
                  return_error()
                end 
               if filename ==nil then
                   if table_key(array,name) then
                        for i=1, 1000 do
                            if not table_key(array,name..'_'..i) then 
                                 if #name>30 then 
                                    array[utf8sub(name,1,30)..'_'..i]=part_body 
                                 else
                                     array[name..'_'..i]=part_body 
                                 end 
                                 break
                            end 
                        end 
                    else
                        if #name >30 then 
                            array[utf8sub(name,1,30)]=part_body
                        else 
                            array[name]=part_body
                        end
                    end
                    if type(part_body)=='string' then
	    					if (#part_body) >=200000 then
	    						write_log('post',name..'     参数值长度超过20w已被系统拦截')
	    						return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
	    						return true
	    					end
	    			end
                else
                    if type(part_body) =='string' and  part_body ~=nil then 
					    if ngx.re.find(part_body,[[phpinfo\(]],'ijo') or ngx.re.find(part_body,[[\$_SERVER]],'ijo') or ngx.re.find(part_body,[[<\?php]],'ijo') or ngx.re.find(part_body,[[fputs]],'ijo') or ngx.re.find(part_body,[[file_put_contents]],'ijo') or ngx.re.find(part_body,[[file_get_contents]],'ijo') or ngx.re.find(part_body,[[eval\(]],'ijo') or ngx.re.find(part_body,[[\$_POST]],'ijo')  or ngx.re.find(part_body,[[\$_GET]],'ijo') or ngx.re.find(part_body,[[base64_decode\(]],'ijo') or ngx.re.find(part_body,[[\$_REQUEST]],'ijo') or ngx.re.find(part_body,[[assert\(]],'ijo') or ngx.re.find(part_body,[[copy\(]],'ijo') or ngx.re.find(part_body,[[create_function\(]],'ijo') or ngx.re.find(part_body,[[preg_replace\(]],'ijo') or ngx.re.find(part_body,[[preg_filter\(]],'ijo') or ngx.re.find(part_body,[[system\(]],'ijo') or ngx.re.find(part_body,[[header_register_callback\(]],'ijo') or ngx.re.find(part_body,[[curl_init\(]],'ijo') or ngx.re.find(part_body,[[curl_error\(]],'ijo') or ngx.re.find(part_body,[[fopen\(]],'ijo')  or ngx.re.find(part_body,[[stream_context_create\(]],'ijo') or ngx.re.find(part_body,[[fsockopen\(]],'ijo') or ngx.re.find(part_body,[[readfile\(]],'ijo') then
                            lan_ip('disable_upload_ext','webshell防御.拦截木马上传,并被封锁IP')
                        end 
                    end 
               end
            end
        end
        if site_count==0 then
        	if  config['from_data'] then 
        		return return_error2() 
        	end
        end
        if count_sieze(array)>=1000 then
			error_rule = '参数太多POST传递的参数数量超过1000,拒绝访问,如有误报请点击误报'
		    write_log('post','参数太多POST传递的参数数量超过1000,拒绝访问,如有误报请点击误报')
		    local check_html = [[<html><meta charset="utf-8" /><title>参数太多</title><div>宝塔免费WAF提醒您,multipart/from-data传递的参数数量超过1000,拒绝访问,如有误报请点击误报</div></html>]]
				ngx.header.content_type = "text/html;charset=utf8"
				ngx.say(check_html)
				ngx.exit(403)
		end
		if array['_method']  and array['method'] and array['server[REQUEST_METHOD]'] then
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击')
		end
		if array['_method']  and array['method'] and array['server[]'] and array['get[]'] then
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
		if array['_method'] and ngx.re.match(array['_method'],'construct','ijo') then
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
        if is_ngx_match(post_rules,array,'post') then
			write_log('post','regular')
			return_html(config['post']['status'],read_file_body('/www/server/free_waf/html/post.html'))
			return true
		end	
	end
end

function post_data()
	if not config['post']['open'] or not is_site_config('post') then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end
	if not content_length then return false end
	local boundary = get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
            data=read_file_body(data) 
		end
		if not data then return false end
		data233=string.gsub(data,'\r','')
		local tmp4 = ngx.re.gmatch(data,[[Content-Disposition.+]],'ijo')
		local tmp5 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=".+"\r\nContent-Type:]],'ijo')
		local tmp6 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=""\r\nContent-Type:]],'ijo')
		ret3={}
		while true do local m, err = tmp4() if m then table.insert(ret3,m) else break end  end
		ret5={}
		while true do local m, err = tmp5() if m then  table.insert(ret5,m) else break end end
	    ret6={}
		while true do  local m, err = tmp6() if m then  table.insert(ret6,m) else break end  end
		from_data(ret3,ret5,ret6)
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=.+]],'ijo')
		local tmp3 = ngx.re.gmatch(data,[[Content-Disposition.+\s*f\r*\n*o\r*\n*r\r*\n*m\r*\n*-\r*\n*d\r*\n*a\r*\n*t\r*\n*a\r*\n*\s*;\r*\n*\s*n\r*\n*a\r*\n*m\r*\n*e=\r*\n*.+;\s*f\n*\s*\r*i\n*\s*\r*l\n*\s*\r*e\n*\s*\r*n\n*\s*\r*a\n*\s*\r*m\n*\s*\r*e\n*\s*\r*=.+\n*\s*\r*]],'ijo')
		ret={}
		while true do local m, err = tmp2() if m then  table.insert(ret,m) else break end  end
		ret2={}
		while true do local m, err = tmp3() if m then  table.insert(ret2,m) else break end  end
		disable_upload_ext2(ret2)
	    if arrlen(ret)==0 and arrlen(ret2)>0 then 
	        return_error()
	    end
	    ret=gusb_string(ret)
		for k,v in pairs(ret) do 
			disable_upload_ext(v)
		end
-- 		local tmp2=ngx.re.match(data,[[Content-Type:[^\+]{100}]],'ijo')
-- 		if tmp2 and tmp2[0] then 
-- 			data_in_php(tmp2[0])
-- 		end
		av=ngx.re.match(ngx.req.get_headers()['Content-Type'],"=.+")
		if not av then return return_error() end  
		header_data=ngx.re.gsub(av[0],'=','')
		if #header_data>200 then 
		    return_error()
		end
		
	    data=string.gsub(data,'\n','')
		data=string.gsub(data,'\t','')
		local tmp_pyload2 = ngx.re.match(data,'Content-Disposition:.+\r--','ijo')
 		if tmp_pyload2==nil then return false end 
 		tmpe_data2=split2(tmp_pyload2[0],header_data)
		if arrlen(tmpe_data2)>0 then
			if config['from_data'] then 
	    		disable_upload_ext3(tmpe_data2,1)
	    	end
		end
		data=string.gsub(data,'\r','')
		local tmp_pyload = ngx.re.match(data,'Content-Disposition:.+Content-Type','ijo')
         if tmp_pyload==nil then return false end 
		tmpe_data=split2(tmp_pyload[0],header_data)
		if arrlen(tmpe_data)>0 then 
		    disable_upload_ext3(tmpe_data,2)
		end 
	end
	return false
end

function cookie()
	if not config['cookie']['open'] or not is_site_config('cookie') then return false end
	if not request_header['cookie'] then return false end
	if type(request_header['cookie']) == "table" then return false end
	request_cookie = string.lower(request_header['cookie'])
	if is_ngx_match(cookie_rules,request_cookie,'cookie') then
		write_log('cookie','regular')
		return_html(config['cookie']['status'],cookie_html)
		return true
	end
	return false
end


function count_sieze(data)
    count=0
	for k,v in pairs(data) 
	do
	    count=count+1
	end 
	return count
end 

function de_dict2(l_key,l_data)
	if type(l_data) ~= "table" then return l_data end
	if arrlen(l_data) == 0 then return l_data end
	if not l_data then return false end
	local r_data = {}
	if arrlen(l_data) >= 100 then 
		lan_ip('args','非法请求')
		return true
	end
	for li,lv in pairs(l_data)
	do
		r_data[l_key..tostring(li)] = lv
	end
	return r_data
end


function args()
	if not config['get']['open'] or not is_site_config('get') then return false end
	local rd_data = {}
	if type(uri_request_args)=='table' then
		for k,v in pairs(uri_request_args)
		do
			if type(v)=='table' then
				table.insert(rd_data,de_dict2(k,v))
			end
		end
	end
	if count_sieze(uri_request_args)>=800 then
		error_rule = '参数太多GET传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		write_log('args','参数太多GET传递的参数数量超过800,拒绝访问,如有误报请点击误报')
	    local check_html = [[<html><meta charset="utf-8" /><title>参数太多</title><div>宝塔免费WAF提醒您,传递的参数数量超过800,拒绝访问,如有误报请点击误报</div></html>]]
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.say(check_html)
			ngx.exit(403)
	end
	
	if rd_data then
	    for i2,v2 in ipairs(rd_data) do 
    		if is_ngx_match(args_rules,v2,'post') then
    			write_log('args','regular')
    			return_html(config['get']['status'],get_html)
    			return true
    		end	
    	end 
	end
	if is_ngx_match(args_rules,uri_request_args,'args') then
		write_log('args','regular')
		return_html(config['get']['status'],get_html)
		return true
	end
    return false
end

function url()
	if not config['get']['open'] or not is_site_config('get') then return false end

	--正则--
	if is_ngx_match(url_rules,uri,'url') then
		write_log('url','regular')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

function php_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_php_path'])
	do
		if ngx_match(uri,rule .. "/.*\\.php$","isjo") then
			write_log('php_path','regular')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

function url_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_path'])
	do
		if ngx_match(uri,rule,"isjo") then
			write_log('path','regular')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

function url_ext()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_ext'])
	do
		if ngx_match(uri,"\\."..rule.."$","isjo") then
			write_log('url_ext','regular')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

function url_rule_ex()
	if site_config[server_name] == nil then return false end
	if method == "POST" and not request_args then
		content_length=tonumber(request_header['content-length'])
		max_len = 64 * 1024
		request_args = nil
		if content_length < max_len then
			ngx.req.read_body()
			request_args = ngx.req.get_post_args()
		end
	end
	for _,rule in ipairs(site_config[server_name]['url_rule'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if is_ngx_match(rule[2],uri_request_args,false) then
				write_log('url_rule','regular')
				return_html(config['other']['status'],other_html)
				return true
			end
			
			if method == "POST" and request_args ~= nil then 
				if is_ngx_match(rule[2],request_args,'post') then
					write_log('post','regular')
					return_html(config['other']['status'],other_html)
					return true
				end
			end
		end
	end
	return false
end

function url_tell()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['url_tell'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if uri_request_args[rule[2]] ~= rule[3] then
				write_log('url_tell','regular')
				return_html(config['other']['status'],other_html)
				return true
			end
		end
	end
	return false
end

function continue_key(key)
	key = tostring(key)
	if string.len(key) > 64 then return false end;
	local keys = {"content","contents","body","msg","file","files","img","newcontent","message","subject","kw","srchtxt",""}
	for _,k in ipairs(keys)
	do
		if k == key then return false end;
	end
	return true;
end

function is_ngx_match(rules,sbody,rule_name)
	if rules == nil or sbody == nil then return false end
	if type(sbody) == "string" then
		sbody = {sbody}
	end
	
	if type(rules) == "string" then
		rules = {rules}
	end
	
	for k,body in pairs(sbody)
	do
		if continue_key(k) then
			for i,rule in ipairs(rules)
			do
				if site_config[server_name] and rule_name then
					local n = i - 1
					for _,j in ipairs(site_config[server_name]['disable_rule'][rule_name])
					do
						if n == j then
							rule = ""
						end
					end
				end
				
				if body and rule ~="" then
					if type(body) == "string" then
						if ngx_match(ngx.unescape_uri(body),rule,"isjo") then
							error_rule = rule .. ' >> ' .. k .. ':' .. body
							return true
						end
					end
					if type(k) == "string" then
						if ngx_match(ngx.unescape_uri(k),rule,"isjo") then
							error_rule = rule .. ' >> ' .. k
							return true
						end
					end
				end
			end
		end
	end
	return false
end

function is_key(keys,values)
	if keys == nil or values == nil then return false end
	if type(values) == "string" then
		values = {values}
	end
	
	if type(keys) == "string" then
		keys = {keys}
	end
	
	for _,value in pairs(values)
	do
		if type(value) == "boolean" or value == "" then return false end
		sval = ngx.unescape_uri(string.lower(ngx.unescape_uri(value)))
		for _,v in ipairs(keys)
        do
			if v == sval then
				return true
			end
        end
	end
	return false
end

function get_return_state(rstate,rmsg)
	result = {}
	result['status'] = rstate
	result['msg'] = rmsg
	return result
end

function get_btwaf_drop_ip()
	local data =  ngx.shared.free_waf_drop_ip:get_keys(0)
	return data
end

function remove_btwaf_drop_ip()
	if not uri_request_args['ip'] or not is_ipaddr(uri_request_args['ip']) then return get_return_state(true,'格式错误') end
	ngx.shared.free_waf_drop_ip:delete(uri_request_args['ip'])
	return get_return_state(true,uri_request_args['ip'] .. '已解封')
end

function clean_btwaf_drop_ip()
	local data = get_btwaf_drop_ip()
	for _,value in ipairs(data)
	do
		ngx.shared.free_waf_drop_ip:delete(value)
	end
	return get_return_state(true,'已解封所有封锁IP')
end

function min_route()
	if ngx.var.remote_addr ~= '127.0.0.1' then return false end
	if uri == '/get_btwaf_drop_ip' then
		return_message(200,get_btwaf_drop_ip())
	elseif uri == '/remove_btwaf_drop_ip' then
		return_message(200,remove_btwaf_drop_ip())
	elseif uri == '/clean_btwaf_drop_ip' then
		return_message(200,clean_btwaf_drop_ip())
	end
end

function return_message(status,msg)
	ngx.header.content_type = "application/json;"
	ngx.status = status
	ngx.say(json.encode(msg))
    ngx.exit(status)
end

function return_html(status,html)
	ngx.header.content_type = "text/html"
    ngx.status = status
    ngx.say(html)
    ngx.exit(status)
end


function run_btwaf()
	server_name = ngx.var.server_name
	if not config['open'] or not is_site_config('open') then return false end
	error_rule = nil
	request_header = ngx.req.get_headers()
	method = ngx.req.get_method()
	ip = get_client_ip()
	ipn = arrip(ip)
	request_uri = ngx.var.request_uri
	uri = ngx.unescape_uri(ngx.var.uri)
	uri_request_args = ngx.req.get_uri_args()
	cycle = config['cc']['cycle']
	endtime = config['cc']['endtime']
	limit = config['cc']['limit']
	retry = config['retry']
	retry_time = config['retry_time']
	retry_cycle = config['retry_cycle']
	min_route()
	site_cc = is_site_config('cc')
	if site_config[server_name] and site_cc then
		cycle = site_config[server_name]['cc']['cycle']
		endtime = site_config[server_name]['cc']['endtime']
		limit = site_config[server_name]['cc']['limit']
	end

	if site_config[server_name] then
		retry = site_config[server_name]['retry']
		retry_time = site_config[server_name]['retry_time']
		retry_cycle = site_config[server_name]['retry_cycle']
	end
	
	if ip_white() then return true end
	ip_black()

	if url_white() then return true end
	url_black()
	
	drop()
	drop_abroad()
	cc()
	cc2()
	user_agent()
	url()
	args()
	cookie()
	scan_black()
	post()
	post_data_chekc()
	if site_config[server_name] then
		php_path()
		url_path()
		url_ext()
		url_rule_ex()
		url_tell()
		post_data()
	end
end
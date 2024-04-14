function ddos_mitigation()
	local redis = require "resty.redis"
	local red = redis:new()

	red:set_timeout(1000) -- 1 sec

	-- Connect to Redis
	local ok, err = red:connect("127.0.0.1", 6379)
	if not ok then
		ngx.log(ngx.ALERT, "Failed to connect to redis")
		return
	end

	-- Get the client IP
	local client_ip = ngx.var.remote_addr

	-- Check if the IP is in the blacklist
	local is_blacklisted, err = red:get("blacklist:" .. client_ip)
	if is_blacklisted == "1" then
		ngx.log(ngx.ALERT, "\nBlocked request from blacklisted ip: ", client_ip)
		ngx.exit(ngx.HTTP_FORBIDDEN)
		return
	end

	-- Increment the request count for this IP
	local newval, err = red:incr("reqs:" .. client_ip)
	if not newval then
		ngx.log(ngx.ALERT, "Failed to increment request count: ", err)
		return
	end

	-- If this is the first request from this IP, set the key to expire in a minute
	if newval == 1 then
		red:expire("reqs:" .. client_ip, 60)
	end

	-- If the IP has made more than 100 requests in a minute, add it to the blacklist
	if newval > 15 then
		red:set("blacklist:" .. client_ip, 1)
		red:expire("blacklist:" .. client_ip, 5) -- Expire after an hour
	end

end

function get_detected_rules(detected)
	local result = ""
	for rule_name, matched in pairs(detected) do
		result = result .. "	" .. rule_name .. " -> matched: " .. matched .. "\n"
	end
	return result
end

function check_request(rulesets, ip_blacklist, user_agents_blacklist, waf_mode, score_threshold)
	ngx.req.read_body()

	ddos_mitigation()

	local allowed_methods = {}
	allowed_methods['GET'] = true
	allowed_methods['POST'] = true
	allowed_methods['HEAD'] = true
	allowed_methods['OPTIONS'] = true

	local method_name = string.upper(ngx.req.get_method())
	if not allowed_methods[method_name] then
	    ngx.log(ngx.ALERT, "Blocked request with unallowed method: ", method_name)
	    ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	
	local client_ip = ngx.var.remote_addr
	for _, blacklisted_ip in pairs(ip_blacklist) do
		if client_ip == blacklisted_ip then
			ngx.log(ngx.ALERT, "\nBlocked request from tor/vpn ip: ", client_ip)
			ngx.exit(ngx.HTTP_FORBIDDEN)
		end
	end

	local user_agent = ngx.req.get_headers()["user-agent"]
	if ngx.re.find(user_agent, user_agents_blacklist, "ioj") 
			or user_agent == nil
			or type(user_agent) ~= "string"
			or user_agent == ""
			or ngx.re.find(user_agent, "^PHP", "ioj")
			or ngx.re.find(user_agent, "^WordPress", "ioj") then
		ngx.log(ngx.ALERT, "\nBlocked request with unwanted user-agent: ", user_agent)
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end

    local raw_header = ngx.req.raw_header()
    local body_data = ngx.req.get_body_data()
    local from, to, err  = ngx.re.find(raw_header, "/(.*?) HTTP/")
    local path = string.sub(raw_header, from, to-5)

	local req_args = {}
	if path ~= "/ " then
		req_args['path'] = path
    end
    if body_data ~= nil then
    	req_args['body_data'] = body_data
    end
	
	local h, err = ngx.req.get_headers()

	for k, v in pairs(h) do
		if v and k ~= "accept" and k ~= "sec-ch-ua" and k ~= "soapaction" and k ~= "sec-ch-ua-platform" then
			req_args[k] = v    
		end
	end		

	local score = 0
	local detected = {}
	for arg_name, arg_val in pairs(req_args) do
		for _, ruleset in pairs(rulesets) do
			for rule_name, rule_data in pairs(ruleset) do
				local from, to, err = ngx.re.find(arg_val, rule_data.regex, "ioj")
				if from then
					local matched = string.sub(arg_val, from, to)
					if detected[rule_name] then
						detected[rule_name] = detected[rule_name] .. " | " .. "in " .. arg_name .. ": " .. matched
					else
						detected[rule_name] = "in " .. arg_name .. ": " .. matched
					end
					score = score + rule_data.score
				else
					if err then
						ngx.log(ngx.ERR, "Error while checking arg: ", err)
						ngx.exit(ngx.ERROR)
					end
				end
			end
		end
	end

	if score ~= 0 then
		if waf_mode == "On" and score >= score_threshold then		
			ngx.log(ngx.ALERT, "\nBlocked malicious request with score ", score, " according to the rules:\n", get_detected_rules(detected), "Original args:\n	path: ", path, "\n	body_data: ", body_data, "\n")
			ngx.exit(ngx.HTTP_FORBIDDEN)	
		else
			ngx.log(ngx.ALERT, "\nDetected suspicious request with score ", score, " according to the rules:\n", get_detected_rules(detected), "Original args:\n	path: ", path, "\n	body_data: ", body_data, "\n")
		end
	end
end


local waf = require("waf_init")

if  not ngx.req.is_internal() and waf.waf_mode ~= "Off" and ngx.var.remote_addr ~= ngx.var.server_addr then 
	local rulesets = waf.rulesets
	local user_agents_blacklist = waf.user_agents_blacklist
	local ip_blacklist = waf.ip_blacklist
	local waf_mode = waf.waf_mode
	local score_threshold = waf.score_threshold
	check_request(rulesets, ip_blacklist, user_agents_blacklist, waf_mode, score_threshold)
end

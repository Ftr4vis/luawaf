local waf_init = {}

waf_init.waf_mode = "Off"
waf_init.score_threshold = 8

local available_modes = {}
available_modes['On'] = true
available_modes['Detection'] = true
available_modes['Off'] = true

if not available_modes[waf_init.waf_mode] then
    ngx.log(ngx.WARN, "Invalid WAF mode specified. Defaulting to 'On'.")
    waf_init.waf_mode = "On"
end

if waf_init.score_threshold < 0 then
    ngx.log(ngx.WARN, "score_threshold can't be negative. Defaulting to 10.")
    waf_init.score_threshold = 10
end

waf_init.allowed_methods = {}
waf_init.allowed_methods['GET'] = true
waf_init.allowed_methods['POST'] = true
waf_init.allowed_methods['HEAD'] = true
waf_init.allowed_methods['OPTIONS'] = true

if waf_init.waf_mode ~= "Off" then
    waf_init.rulesets = dofile("/usr/local/openresty/luawaf/get_rules.lua")
    waf_init.user_agents_scanners = dofile("/usr/local/openresty/luawaf/user_agents/user_agents_scanners.lua")
    waf_init.torvpn_ip_list = dofile("/usr/local/openresty/luawaf/ip/torvpn_ip_list.lua")
end

return waf_init

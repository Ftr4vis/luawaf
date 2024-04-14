local http = require "resty.http"
local redis = require "resty.redis"

local waf_init = {}

waf_init.waf_mode = "On"
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

if waf_init.waf_mode ~= "Off" then
    waf_init.rulesets = dofile("/usr/local/openresty/luawaf/get_rules.lua")
    waf_init.user_agents_blacklist = dofile("/usr/local/openresty/luawaf/user_agents/user_agents_blacklist.lua")
    waf_init.ip_blacklist = dofile("/usr/local/openresty/luawaf/ip/ip_blacklist.lua")
end

return waf_init

function get_files_in_dir(dir)
    local files = {}
    local pfile = io.popen('ls "'..dir..'"')
    for filename in pfile:lines() do
        table.insert(files, filename)
    end
    pfile:close()
    return files
end

-- Dir with rules
local rules_dir = "/usr/local/openresty/luawaf/rules"

-- List of files with rules
local files = get_files_in_dir(rules_dir)

local rulesets = {}

-- Loading rules from files like rules_*.lua
for _, filename in pairs(files) do
    if ngx.re.match(filename, "^rules_.+.lua$") then
	    local rule_file = filename
        local filepath = rules_dir .. "/" .. rule_file
	    local ruleset = dofile(filepath)
        if ruleset == nil then
            ngx.log(ngx.ALERT, "Error while loading rules " .. rule_file)
            ngx.exit(ngx.ERROR)
        else
            table.insert(rulesets, ruleset)
        end 
    end
end

return rulesets

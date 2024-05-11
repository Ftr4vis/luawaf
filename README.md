# Installation
1. Create luawaf directory in /usr/local/openresty/ and move all the files there,
2. Move waf_init.lua to /usr/local/openresty/lualib directory,
3. Edit the nginx.conf file as per below:
```
http {
	init_by_lua_block {
    		require "waf_init"
  	}
}
```
4. Add in the proxy site configuration file the following lines:
```
server {
	...
	access_by_lua_file /usr/local/openresty/luawaf/waf_protect.lua;
  	...
  	location / {
    		proxy_pass http://<your_site>:80;
    		try_files $uri $uri/ =404;
  	}
}
```
5.
```
systemctl restart openresty
```
6. (Optional) You can change luawaf settings in waf_init.lua. And don't forget to restart openresty service to apply changes.

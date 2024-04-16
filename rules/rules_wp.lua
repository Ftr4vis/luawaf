rules_wp = {}
rules_wp['wordpress_sensitive_files'] = {regex = "(wp\\-cron)|(wp\\-config)|(install)|(version)|(xmlrpc)\\.php", score = 50}
return rules_wp

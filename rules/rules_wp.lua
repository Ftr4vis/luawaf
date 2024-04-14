rules_wp = {}
rules_wp['wordpress_sensitive_files'] = {regex = "(wp\\-cron)|(wp\\-config)\\.php", score = 5}
return rules_wp

rules_wp = {}
rules_wp['wordpress_sensitive_files'] = {regex = "(wp\\-cron|wp\\-config|install|version|xmlrpc)\\.php", score = 50}
rules_wp['wordpress_admin_files'] = {regex = "(admin\\-post|admin\\-ajax|admin\\-footer|admin\\-functions|admin\\-header|admin)\\.php", score = 50}
rules_wp['wordpress_common_dirs_checked'] = {regex = "(\\/backup\\/|\\/blog\\/|\\/cms\\/|\\/demo\\/|\\/dev\\/|\\/home\\/|\\/main\\/|\\/new\\/|\\/old\\/|\\/portal\\/|\\/site\\/|\\/test\\/|\\/tmp\\/|\\/web\\/|\\/wordpress\\/|\\/wp\\/)", score = 50}
return rules_wp

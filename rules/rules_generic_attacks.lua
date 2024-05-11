rules_generic_attacks = {}
rules_generic_attacks['os_command_injection_detected'] = {regex = "(?:(?:[\\;\\|\\`]\\W*?\\bcc|\\b(wget|curl))\\b|\\/cc(?:[\\'\\\"\\|\\;\\`\\-\\s]|$))", score = 7}
rules_generic_attacks['repetitive_non_word_chars'] = {regex = "[^\\w\\r\\n]{4,}", score = 7}
rules_generic_attacks['ssi_injection'] = {regex = "<!--\\W*?#\\W*?(?:e(?:cho|xec)|printenv|include|cmd)", score = 7}
rules_generic_attacks['http_response_splitting_1'] = {regex = "[\\n\\r](?:content-(type|length)|set-cookie|location):", score = 7}
rules_generic_attacks['http_response_splitting_2'] = {regex = "(?:\\bhttp\\/(?:0\\.9|1\\.[01])|<(?:html|meta)\\b)", score = 7}
rules_generic_attacks['rfi_url_in_request_arg'] = {regex = "^(?:ht|f)tps?:\\/\\/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})", score = 7}
rules_generic_attacks['rfi_php_include_func'] = {regex = "(?:(\\binclude\\s*\\([^)]*|mosConfig_absolute_path|_CONF\\[path\\]|_SERVER\\[DOCUMENT_ROOT\\]|GALLERY_BASEDIR|path\\[docroot\\]|appserv_root|config\\[root_dir\\])=(ht|f)tps?:\\/\\/)", score = 7}
rules_generic_attacks['rfi_data_ends_with_question_mark'] = {regex = "^(?:ft|htt)ps?(.*?)\\?+$", score = 7}
rules_generic_attacks['session_fixation'] = {regex = "(?:\\.cookie\\b.*?;\\W*?(?:expires|domain)\\W*?=|\\bhttp-equiv\\W+set-cookie\\b)", score = 7}
rules_generic_attacks['system_file_access'] = {regex = "(?:\\b(?:\\.(?:ht(?:access|passwd|group)|www_?acl)|global\\.asa|httpd\\.conf|boot\\.ini)\\b|\\/etc\\/)", score = 7}
rules_generic_attacks['system_command_access'] = {regex = "\\b(?:(?:n(?:map|et|c)|w(?:guest|sh)|telnet|rcmd|ftp)\\.exe\\b|cmd(?:(?:32)?\\.exe\\b|\\b\\W*?\\/c))", score = 7}
rules_generic_attacks['system_command_injection'] = {regex = "(?:\\b(?:(?:n(?:et(?:\\b\\W+?\\blocalgroup|\\.exe)|(?:map|c)\\.exe)|t(?:racer(?:oute|t)|elnet\\.exe|clsh8?|ftp)|(?:w(?:guest|sh)|rcmd|ftp)\\.exe|echo\\b\\W*?\\by+)\\b|c(?:md(?:(?:\\.exe|32)\\b|\\b\\W*?\\/c)|d(?:\\b\\W*?[\\\\/]|\\W*?\\.\\.)|hmod.{0,40}?\\+.{0,3}x))|[\\;\\|\\`]\\W*?\\b(?:(?:c(?:h(?:grp|mod|own|sh)|md|pp)|p(?:asswd|ython|erl|ing|s)|n(?:asm|map|c)|f(?:inger|tp)|(?:kil|mai)l|(?:xte)?rm|ls(?:of)?|telnet|uname|echo|id)\\b|g(?:\\+\\+|cc\\b)))", score = 7}
rules_generic_attacks['php_injection_1'] = {regex = "<\\?(?!xml)", score = 7}
rules_generic_attacks['php_injection_2'] = {regex = "(?:\\b(?:f(?:tp_(?:nb_)?f?(?:ge|pu)t|get(?:s?s|c)|scanf|write|open|read)|gz(?:(?:encod|writ)e|compress|open|read)|s(?:ession_start|candir)|read(?:(?:gz)?file|dir)|move_uploaded_file|(?:proc_|bz)open|call_user_func)|\\$_(?:(?:pos|ge)t|session))\\b", score = 7}
rules_generic_attacks['php_injection_3'] = {regex = "(?:(?:(?:(?:a(?:llow_url_includ|uto_prepend_fil)e|s(?:uhosin.simulation|afe_mode)|disable_functions|open_basedir)=|php://input)))", score = 7}
rules_generic_attacks['dir_traversal_volatile_match'] = {regex = "(?:\\x5c|(?:%(?:2(?:5(?:2f|5c)|%46|f)|c(?:0%(?:9v|af)|1%1c)|u(?:221[56]|002f)|%32(?:%46|F)|e0%80%af|1u|5c)|\\/))(?:%(?:2(?:(?:52)?e|%45)|(?:e0%8|c)0%ae|u(?:002e|2024)|%32(?:%45|E))|\\.){2}(?:\\x5c|(?:%(?:2(?:5(?:2f|5c)|%46|f)|c(?:0%(?:9v|af)|1%1c)|u(?:221[56]|002f)|%32(?:%46|F)|e0%80%af|1u|5c)|\\/))", score = 7}
rules_generic_attacks['null_byte_at_end_of_uri'] = {regex = "%00+$", score = 5}
rules_generic_attacks['email_injection'] = {regex = "[\\n\\r]\\s*\\b(?:to|b?cc)\\b\\s*:.*?\\@", score = 7}


rules_generic_attacks['coldfusion_injection'] = {regex = "\\bcf(?:usion_(?:d(?:bconnections_flush|ecrypt)|set(?:tings_refresh|odbcini)|getodbc(?:dsn|ini)|verifymail|encrypt)|_(?:(?:iscoldfusiondatasourc|getdatasourceusernam)e|setdatasource(?:password|username))|newinternal(?:adminsecurit|registr)y|admin_registry_(?:delete|set)|internaldebug|execute)\\b", score = 5}
rules_generic_attacks['ldap_injection'] = {regex = "(?:\\((?:\\W*?(?:objectc(?:ategory|lass)|homedirectory|[gu]idnumber|cn)\\b\\W*?=|[^\\w\\x80-\\xFF]*?[\\!\\&\\|][^\\w\\x80-\\xFF]*?\\()|\\)[^\\w\\x80-\\xFF]*?\\([^\\w\\x80-\\xFF]*?[\\!\\&\\|])", score = 5}
rules_generic_attacks['updf_xss'] = {regex = "http:\\/\\/[\\w\\.]+?\\/.*?\\.pdf\\b[^\\x0d\\x0a]*#", score = 5}

rules_generic_attacks['lfi'] = {regex = "(\\.)+(\\\\|\\/)+(\\.)+(\\\\|\\/)+", score = 5}

return rules_generic_attacks

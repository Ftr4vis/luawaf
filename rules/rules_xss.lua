rules_xss = {}
rules_xss['xss_1'] = {regex = "\\bgetparentfolder\\b", score = 7}
rules_xss['xss_2'] = {regex = "\\bonmousedown\\b\\W*?\\=", score = 7}
rules_xss['xss_3'] = {regex = "\\bsrc\\b\\W*?\\bshell:", score = 7}
rules_xss['xss_4'] = {regex = "\\bmocha:", score = 7}
rules_xss['xss_5'] = {regex = "\\bonabort\\b", score = 7}
rules_xss['xss_6'] = {regex = "\\blowsrc\\b\\W*?\\bhttp:", score = 7}
rules_xss['xss_7'] = {regex = "\\bonmouseup\\b\\W*?\\=", score = 7}
rules_xss['xss_8'] = {regex = "\\bstyle\\b\\W*\\=.*\\bexpression\\b\\W*\\(", score = 7}
rules_xss['xss_9'] = {regex = "\\bhref\\b\\W*?\\bshell:", score = 7}
rules_xss['xss_10'] = {regex = "\\bcreatetextrange\\b", score = 7}
rules_xss['xss_11'] = {regex = "\\bondragdrop\\b\\W*?\\=", score = 7}
rules_xss['xss_12'] = {regex = "\\bcopyparentfolder\\b", score = 7}
rules_xss['xss_13'] = {regex = "\\bonunload\\b\\W*?\\=", score = 7}
rules_xss['xss_14'] = {regex = "\\.execscript\\b", score = 7}
rules_xss['xss_15'] = {regex = "\\bgetspecialfolder\\b", score = 7}
rules_xss['xss_16'] = {regex = "<body\\b.*?\\bonload\\b", score = 7}
rules_xss['xss_17'] = {regex = "\\burl\\b\\W*?\\bvbscript:", score = 7}
rules_xss['xss_18'] = {regex = "\\bonkeydown\\b\\W*?\\=", score = 7}
rules_xss['xss_19'] = {regex = "\\bonmousemove\\b\\W*?\\=", score = 7}
rules_xss['xss_19'] = {regex = "\\blivescript:", score = 7}
rules_xss['xss_20'] = {regex = "\\bonblur\\b\\W*?\\=", score = 7}
rules_xss['xss_21'] = {regex = "\\bonmove\\b\\W*?\\=", score = 7}
rules_xss['xss_22'] = {regex = "\\bsettimeout\\b\\W*?\\(", score = 7}
rules_xss['xss_23'] = {regex = "< ?iframe", score = 7}
rules_xss['xss_24'] = {regex = "\\bsrc\\b\\W*?\\bjavascript:", score = 7}
rules_xss['xss_25'] = {regex = "<body\\b.*?\\bbackground\\b", score = 7}
rules_xss['xss_26'] = {regex = "\\bsrc\\b\\W*?\\bvbscript:", score = 7}
rules_xss['xss_27'] = {regex = "\\btype\\b\\W*?\\btext\\b\\W*?\\becmascript\\b", score = 7}
rules_xss['xss_28'] = {regex = "\\bonfocus\\b\\W*?\\=", score = 7}
rules_xss['xss_29'] = {regex = "\\bdocument\\b\\s*\\.\\s*\\bcookie\\b", score = 7}
rules_xss['xss_30'] = {regex = "\\<\\!\\[cdata\\[", score = 7}
rules_xss['xss_31'] = {regex = "\\bonerror\\b\\W*?\\=", score = 7}
rules_xss['xss_32'] = {regex = "\\blowsrc\\b\\W*?\\bjavascript:", score = 7}
rules_xss['xss_33'] = {regex = "\\bactivexobject\\b", score = 7}
rules_xss['xss_34'] = {regex = "\\bonkeypress\\b\\W*?\\=", score = 7}
rules_xss['xss_35'] = {regex = "\\bonsubmit\\b\\W*?\\=", score = 7}
rules_xss['xss_36'] = {regex = "\\btype\\b\\W*?\\bapplication\\b\\W*?\\bx-javascript\\b", score = 7}
rules_xss['xss_37'] = {regex = "\\.addimport\\b", score = 7}
rules_xss['xss_38'] = {regex = "\\bhref\\b\\W*?\\bjavascript:", score = 7}
rules_xss['xss_39'] = {regex = "\\bonchange\\b\\W*?\\=", score = 7}
rules_xss['xss_40'] = {regex = "\\btype\\b\\W*?\\btext\\b\\W*?\\bjscript\\b", score = 7}
rules_xss['xss_41'] = {regex = "\\balert\\b\\W*?\\(", score = 7}
rules_xss['xss_42'] = {regex = "\\btype\\b\\W*?\\bapplication\\b\\W*?\\bx-vbscript\\b", score = 7}
rules_xss['xss_43'] = {regex = "< ?meta", score = 7}
rules_xss['xss_44'] = {regex = "\\bsrc\\b\\W*?\\bhttp:", score = 7}
rules_xss['xss_45'] = {regex = "\\btype\\b\\W*?\\btext\\b\\W*?\\bvbscript\\b", score = 7}
rules_xss['xss_46'] = {regex = "\\bonmouseout\\b\\W*?\\=", score = 7}
rules_xss['xss_47'] = {regex = "\\blowsrc\\b\\W*?\\bshell:", score = 7}
rules_xss['xss_48'] = {regex = "\\basfunction:", score = 7}
rules_xss['xss_49'] = {regex = "\\bonmouseover\\b\\W*?\\=", score = 7}
rules_xss['xss_50'] = {regex = "\\bhref\\b\\W*?\\bvbscript:", score = 7}
rules_xss['xss_51'] = {regex = "\\burl\\b\\W*?\\bjavascript:", score = 7}
rules_xss['xss_52'] = {regex = "\\.innerhtml\\b", score = 7}
rules_xss['xss_53'] = {regex = "\\bonselect\\b\\W*?\\=", score = 7}
rules_xss['xss_54'] = {regex = "\\import\\b", score = 7}
rules_xss['xss_55'] = {regex = "\\blowsrc\\b\\W*?\\bvbscript:", score = 7}
rules_xss['xss_56'] = {regex = "\\bonload\\b\\W*?\\=", score = 7}
rules_xss['xss_57'] = {regex = "< ?script\\b", score = 7}
rules_xss['xss_58'] = {regex = "\\bonresize\\b\\W*?\\=", score = 7}
rules_xss['xss_59'] = {regex = "\\bonclick\\b\\W*?\\=", score = 7}
rules_xss['xss_60'] = {regex = "\\biframe\\b.{0,100}?\\bsrc\\b", score = 7}
rules_xss['xss_61'] = {regex = "\\bbackground-image:", score = 7}
rules_xss['xss_62'] = {regex = "\\bonkeyup\\b\\W*?\\=", score = 7}
rules_xss['xss_63'] = {regex = "<input\\b.*?\\btype\\b\\W*?\\bimage\\b", score = 7}
rules_xss['xss_64'] = {regex = "\\burl\\b\\W*?\\bshell:", score = 7}
rules_xss['xss_65'] = {regex = "\\btype\\b\\W*?\\btext\\b\\W*?\\bjavascript\\b", score = 7}
rules_xss['xss_66'] = {regex = "\\.fromcharcode\\b", score = 7}
rules_xss['xss_html_tag_handler'] = {regex = "<(a|abbr|acronym|address|applet|area|audioscope|b|base|basefront|bdo|bgsound|big|blackface|blink|blockquote|body|bq|br|button|caption|center|cite|code|col|colgroup|comment|dd|del|dfn|dir|div|dl|dt|em|embed|fieldset|fn|font|form|frame|frameset|h1|head|hr|html|i|iframe|ilayer|img|input|ins|isindex|kdb|keygen|label|layer|legend|li|limittext|link|listing|map|marquee|menu|meta|multicol|nobr|noembed|noframes|noscript|nosmartquotes|object|ol|optgroup|option|p|param|plaintext|pre|q|rt|ruby|s|samp|script|select|server|shadow|sidebar|small|spacer|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|wbr|xml|xmp)\\W", score = 7}
rules_xss['xss_67'] = {regex = "\\ballowscriptaccess\\b|\\brel\\b\\W*?=", score = 7}
rules_xss['xss_68'] = {regex = ".+application/x-shockwave-flash|image/svg\\+xml|text/(css|html|ecmascript|javascript|vbscript|x-(javascript|scriptlet|vbscript)).+", score = 7}
rules_xss['xss_69'] = {regex = "\\bon(abort|blur|change|click|dblclick|dragdrop|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|move|readystatechange|reset|resize|select|submit|unload)\\b\\W*?=", score = 7}
rules_xss['xss_70'] = {regex = "\\b(background|dynsrc|href|lowsrc|src)\\b\\W*?=", score = 7}
rules_xss['xss_71'] = {regex = "(asfunction|javascript|vbscript|data|mocha|livescript):", score = 7}
rules_xss['xss_style_tag_manipulation'] = {regex = "\\bstyle\\b\\W*?=", score = 7}
rules_xss['xss_js_fragments'] = {regex = "(fromcharcode|alert|eval)\\s*\\(", score = 7}
rules_xss['xss_css_fragments'] = {regex = "background\\b\\W*?:\\W*?url|background-image\\b\\W*?:|behavior\\b\\W*?:\\W*?url|-moz-binding\\b|@import\\b|expression\\b\\W*?\\(", score = 7}
rules_xss['xss_72'] = {regex = "<!\\[cdata\\[|\\]\\]>", score = 7}
rules_xss['xss_testing_alert_1'] = {regex = "[/'\\\"<]xss[/'\\\">]", score = 7}
rules_xss['xss_ascii_alert'] = {regex = "(88,83,83)", score = 7}
rules_xss['xss_testing_alert_2'] = {regex = "'';!--\\\"<xss>=&{()}", score = 7}
rules_xss['xss_ie_filter_1'] = {regex = "(?:<script.*?>)", score = 7}
rules_xss['xss_ie_filter_2'] = {regex = "(?:<style.*?>.*?((@[i\\\\\\\\])|(([:=]|(&#x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\\\\\]|(&#x?0*((40)|(28)|(92)|(5C));?)))))", score = 7}
rules_xss['xss_ie_filter_3'] = {regex = "(?:<script.*?[ /+\\t]*?((src)|(xlink:href)|(href))[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_4'] = {regex = "(?:<[i]?frame.*?[ /+\\t]*?src[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_5'] = {regex = "(?i:<.*[:]vmlframe.*?[ /+\\t]*?src[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_6'] = {regex = "(?:(j|(&#x?0*((74)|(4A)|(106)|(6A));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(a|(&#x?0*((65)|(42)|(97)|(61));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(v|(&#x?0*((86)|(56)|(118)|(76));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(a|(&#x?0*((65)|(42)|(97)|(61));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(s|(&#x?0*((83)|(53)|(115)|(73));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(c|(&#x?0*((67)|(43)|(99)|(63));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(r|(&#x?0*((82)|(52)|(114)|(72));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(i|(&#x?0*((73)|(49)|(105)|(69));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(p|(&#x?0*((80)|(50)|(112)|(70));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(t|(&#x?0*((84)|(54)|(116)|(74));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(:|(&((#x?0*((58)|(3A));?)|(colon;)))).)", score = 7}
rules_xss['xss_ie_filter_7'] = {regex = "(?:(v|(&#x?0*((86)|(56)|(118)|(76));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(b|(&#x?0*((66)|(42)|(98)|(62));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(s|(&#x?0*((83)|(53)|(115)|(73));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(c|(&#x?0*((67)|(43)|(99)|(63));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(r|(&#x?0*((82)|(52)|(114)|(72));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(i|(&#x?0*((73)|(49)|(105)|(69));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(p|(&#x?0*((80)|(50)|(112)|(70));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(t|(&#x?0*((84)|(54)|(116)|(74));?))([\\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(:|(&((#x?0*((58)|(3A));?)|(colon;)))).)", score = 7}
rules_xss['xss_ie_filter_8'] = {regex = "(?:<EMBED /+\\t].*?((src)|(type)).*?=)", score = 7}
rules_xss['xss_ie_filter_9'] = {regex = "(?:<[?]?import /+\\t].*?implementation[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_10'] = {regex = "(?:<META /+\\t].*?http-equiv[ /+\\t]*=[ /+\\t]*[\\\"\\'`]?(((c|(&#x?0*((67)|(43)|(99)|(63));?)))|((r|(&#x?0*((82)|(52)|(114)|(72));?)))|((s|(&#x?0*((83)|(53)|(115)|(73));?)))))", score = 7}
rules_xss['xss_ie_filter_11'] = {regex = "(?:<META /+\\t].*?charset[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_12'] = {regex = "(?:<LINK /+\\t].*?href[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_13'] = {regex = "(?:<BASE /+\\t].*?href[ /+\\t]*=)", score = 7}
rules_xss['xss_ie_filter_14'] = {regex = "(?:<APPLET /+\\t>])", score = 7}
rules_xss['xss_ie_filter_15'] = {regex = "(?:<OBJECT /+\\t].*?((type)|(codetype)|(classid)|(code)|(data))[ /+\\t]*=)", score = 7}
rules_xss['xss_73'] = {regex = "\"<!(doctype|entity)", score = 7}
rules_xss['xss_101'] = {regex = "(^|\\W)alert\\/?(\\.(source|call|apply|bind|valueof))?[\\(\\`\\&\\]]", score = 7}
rules_xss['xss_102'] = {regex = "on(error|cut|begin|wheel|blur|change|input|reset|select|down|keypress|keyup|paste|copy|toggle)(\\s|\\+)*\\=", score = 7}
rules_xss['xss_103'] = {regex = "(^|\\W)location\\.(assign|reload|replace|tostring)\\(", score = 7}
rules_xss['xss_104'] = {regex = "(^|\\W)history(\\.[a-z]+)+\\(", score = 7}
rules_xss['xss_105'] = {regex = "(^|\\W)(local|session)Storage\\(", score = 7}

return rules_xss

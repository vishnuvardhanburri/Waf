import re

SECURITY_RULES = {
    'SQL_INJECTION': [
        {'id': 'SQL_01', 'pattern': re.compile(r'(?i)\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)\b'), 'description': 'SQL keywords', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_02', 'pattern': re.compile(r"""(?i)['"][\s]*OR[\s]+['"]?\d+['"]?[\s]*=[\s]*['"]?\d+|['"][\s]*OR[\s]+['"][^'"]*['"][\s]*=[\s]*['"]"""), 'description': 'Tautology', 'severity': 'critical', 'enabled': True},
        {'id': 'SQL_03', 'pattern': re.compile(r'(?i)--|#|/\*\*/'), 'description': 'SQL comments', 'severity': 'medium', 'enabled': True},
        {'id': 'SQL_04', 'pattern': re.compile(r'(?i)\b(WAITFOR DELAY|BENCHMARK|SLEEP)\b'), 'description': 'Time-based SQLi', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_05', 'pattern': re.compile(r'(?i)(0x[0-9a-f]+|char\()'), 'description': 'Hex encoding/char functions', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_06', 'pattern': re.compile(r'(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC)'), 'description': 'Stacked queries', 'severity': 'critical', 'enabled': True},
        {'id': 'SQL_07', 'pattern': re.compile(r'(?i)(AND|OR)[\s]*[\d]+[\s]*=[\s]*[\d]+'), 'description': 'Logic injection', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_08', 'pattern': re.compile(r'(?i)(AND|OR)[\s]*\'[^\']*\'[\s]*=[\s]*\'[^\']*\''), 'description': 'String logic injection', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_09', 'pattern': re.compile(r'(?i)HAVING[\s]*1=1'), 'description': 'Having injection', 'severity': 'high', 'enabled': True},
        {'id': 'SQL_10', 'pattern': re.compile(r'(?i)ORDER BY[\s]*\d+'), 'description': 'Order by injection', 'severity': 'medium', 'enabled': True},
        {'id': 'SQL_11', 'pattern': re.compile(r'(?i)\bINTO OUTFILE\b'), 'description': 'Into outfile', 'severity': 'critical', 'enabled': True},
        {'id': 'SQL_12', 'pattern': re.compile(r'(?i)\bLOAD_FILE\b'), 'description': 'Load file', 'severity': 'critical', 'enabled': True},
        {'id': 'SQL_13', 'pattern': re.compile(r'(?i)\b(xp_cmdshell|sp_executesql)\b'), 'description': 'Stored procedures', 'severity': 'critical', 'enabled': True},
        {'id': 'SQL_14', 'pattern': re.compile(r'(?i)(?:\b(AND|OR|HAVING|WHERE)\b.+?(?:=|LIKE|IN|IS|NOT)\s*[\'"]?\w+)'), 'description': 'Generic SQLi', 'severity': 'medium', 'enabled': True},
        {'id': 'SQL_15', 'pattern': re.compile(r'(?i)\b(INFORMATION_SCHEMA|SYS|SYSOBJECTS|SYSCOLUMNS)\b'), 'description': 'Metadata access', 'severity': 'high', 'enabled': True},
    ],
    'XSS_ATTACK': [
        {'id': 'XSS_01', 'pattern': re.compile(r'(?i)<script(?:.*?)>(.*?)</script>'), 'description': 'Script tag', 'severity': 'critical', 'enabled': True},
        {'id': 'XSS_02', 'pattern': re.compile(r'(?i)<(img|svg|iframe|object|embed|body|div)'), 'description': 'HTML tags with potential XSS', 'severity': 'medium', 'enabled': True},
        {'id': 'XSS_03', 'pattern': re.compile(r'(?i)(javascript:|vbscript:|data:text/html)'), 'description': 'JS/VBS/Data pseudo-protocols', 'severity': 'high', 'enabled': True},
        {'id': 'XSS_04', 'pattern': re.compile(r'(?i)\b(onerror|onload|onmouseover|onfocus|onclick|onblur|onchange)='), 'description': 'Event handlers', 'severity': 'high', 'enabled': True},
        {'id': 'XSS_05', 'pattern': re.compile(r'(?i)\b(eval|alert|prompt|confirm)\s*\('), 'description': 'JS functions', 'severity': 'high', 'enabled': True},
        {'id': 'XSS_06', 'pattern': re.compile(r'(?i)document\.(cookie|write)|window\.location'), 'description': 'DOM manipulation', 'severity': 'high', 'enabled': True},
        {'id': 'XSS_07', 'pattern': re.compile(r'(?i)(expression|url)\s*\('), 'description': 'CSS expressions', 'severity': 'medium', 'enabled': True},
        {'id': 'XSS_08', 'pattern': re.compile(r'(?i)&#x?[0-9a-f]+;'), 'description': 'HTML entity encoding', 'severity': 'low', 'enabled': True},
        {'id': 'XSS_09', 'pattern': re.compile(r'(?i)\\x[0-9a-f]{2}'), 'description': 'Hex encoding', 'severity': 'low', 'enabled': True},
        {'id': 'XSS_10', 'pattern': re.compile(r'(?i)%[0-9a-f]{2}'), 'description': 'URL encoding (suspicious)', 'severity': 'low', 'enabled': True},
        {'id': 'XSS_11', 'pattern': re.compile(r'(?i)String\.fromCharCode'), 'description': 'String from char code', 'severity': 'high', 'enabled': True},
        {'id': 'XSS_12', 'pattern': re.compile(r'(?i)setTimeout\s*\('), 'description': 'setTimeout execution', 'severity': 'medium', 'enabled': True},
        {'id': 'XSS_13', 'pattern': re.compile(r'(?i)setInterval\s*\('), 'description': 'setInterval execution', 'severity': 'medium', 'enabled': True},
        {'id': 'XSS_14', 'pattern': re.compile(r'(?i)Function\s*\('), 'description': 'Function constructor', 'severity': 'medium', 'enabled': True},
        {'id': 'XSS_15', 'pattern': re.compile(r'(?i)innerHTML|outerHTML'), 'description': 'Inner/Outer HTML manipulation', 'severity': 'medium', 'enabled': True},
    ],
    'PATH_TRAVERSAL': [
        {'id': 'PT_01', 'pattern': re.compile(r'\.\./'), 'description': 'Directory traversal', 'severity': 'high', 'enabled': True},
        {'id': 'PT_02', 'pattern': re.compile(r'\.\.\\'), 'description': 'Directory traversal (Windows)', 'severity': 'high', 'enabled': True},
        {'id': 'PT_03', 'pattern': re.compile(r'(?i)%2e%2e%2f'), 'description': 'URL encoded directory traversal', 'severity': 'high', 'enabled': True},
        {'id': 'PT_04', 'pattern': re.compile(r'(?i)%2e%2e/|\.\.%2f'), 'description': 'Partially URL encoded directory traversal', 'severity': 'high', 'enabled': True},
        {'id': 'PT_05', 'pattern': re.compile(r'(?i)/etc/(passwd|shadow|group|hosts)'), 'description': 'Sensitive file access (Linux)', 'severity': 'critical', 'enabled': True},
        {'id': 'PT_06', 'pattern': re.compile(r'(?i)\\windows\\system32'), 'description': 'Sensitive file access (Windows)', 'severity': 'critical', 'enabled': True},
        {'id': 'PT_07', 'pattern': re.compile(r'%00|\x00'), 'description': 'Null byte injection', 'severity': 'high', 'enabled': True},
        {'id': 'PT_08', 'pattern': re.compile(r'(?i)\bboot\.ini\b'), 'description': 'Windows boot.ini access', 'severity': 'critical', 'enabled': True},
        {'id': 'PT_09', 'pattern': re.compile(r'(?i)/var/log/'), 'description': 'Log file access', 'severity': 'high', 'enabled': True},
        {'id': 'PT_10', 'pattern': re.compile(r'(?i)\.ht(access|passwd)'), 'description': 'Apache sensitive file access', 'severity': 'high', 'enabled': True},
    ],
    'COMMAND_INJECTION': [
        {'id': 'CI_01', 'pattern': re.compile(r'`.*`'), 'description': 'Backtick command execution', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_02', 'pattern': re.compile(r'\$\(.*?\)'), 'description': 'Dollar-parentheses command execution', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_03', 'pattern': re.compile(r';\s*(ls|cat|rm|pwd|echo|ping|whoami|id|wget|curl|nc|bash|sh|zsh|kill|chmod|mv|cp|mkdir|chown|ps|env|uname|hostname|ifconfig|netstat|ss|chroot|nc|ncat|telnet|ssh|scp|rsync|tar|gzip|gunzip|openssl|base64|xxd|hexdump|nmap|sqlmap)'), 'description': 'Command separator with dangerous command', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_04', 'pattern': re.compile(r'\|\s*(ls|cat|rm|pwd|echo|ping|whoami|id|wget|curl|nc|bash|sh|zsh|kill|chmod|mv|cp|mkdir|chown|ps|env|uname|hostname|ifconfig|netstat|ss|chroot|nc|ncat|telnet|ssh|scp|rsync|tar|gzip|gunzip|openssl|base64|xxd|hexdump|nmap|sqlmap)'), 'description': 'Pipe with dangerous command', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_05', 'pattern': re.compile(r'&&?\s*(ls|cat|rm|pwd|echo|ping|whoami|id|wget|curl|nc|bash|sh|zsh|kill|chmod|mv|cp|mkdir|chown|ps|env|uname|hostname|ifconfig|netstat|ss|chroot|nc|ncat|telnet|ssh|scp|rsync|tar|gzip|gunzip|openssl|base64|xxd|hexdump|nmap|sqlmap)'), 'description': 'Logical AND with dangerous command', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_06', 'pattern': re.compile(r'\|\|\s*(ls|cat|rm|pwd|echo|ping|whoami|id|wget|curl|nc|bash|sh|zsh|kill|chmod|mv|cp|mkdir|chown|ps|env|uname|hostname|ifconfig|netstat|ss|chroot|nc|ncat|telnet|ssh|scp|rsync|tar|gzip|gunzip|openssl|base64|xxd|hexdump|nmap|sqlmap)'), 'description': 'Logical OR with dangerous command', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_07', 'pattern': re.compile(r'(?i)/bin/(sh|bash|zsh|dash)'), 'description': 'Shell execution', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_08', 'pattern': re.compile(r'(?i)cmd\.exe|powershell(\.exe)?'), 'description': 'Windows shell execution', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_09', 'pattern': re.compile(r'(?i)\brm\s+-rf\b'), 'description': 'Recursive delete', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_10', 'pattern': re.compile(r'(?i)\b(wget|curl|nc)\s'), 'description': 'Network tools execution', 'severity': 'high', 'enabled': True},
        {'id': 'CI_11', 'pattern': re.compile(r'(?i)\b(python|python3|perl|ruby|node|php|ruby|java|lua|tcl|groovy)\s+-[a-zA-Z]'), 'description': 'Interpreter inline execution flags', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_12', 'pattern': re.compile(r'(?i)\b(perl|ruby|php|python|node)\s+-[a-z]?e\b'), 'description': 'One-liner interpreter execution (perl -e, python -c, etc.)', 'severity': 'critical', 'enabled': True},
        {'id': 'CI_13', 'pattern': re.compile(r'(?i)\b(python|perl|ruby|node|php)\s*\(\s*[A-Za-z_]\w*\s*\('), 'description': 'Indirect invocation via temp file args', 'severity': 'high', 'enabled': True},
        {'id': 'CI_14', 'pattern': re.compile(r'(?i)\b(eval|exec|system|passthru|shell_exec|popen|subprocess|Popen|fork|spawn|Compile|load|require)\s*\('), 'description': 'In-process code execution calls', 'severity': 'high', 'enabled': True},
        {'id': 'CI_15', 'pattern': re.compile(r'(?i)>(>?)\s*/\w+'), 'description': 'Output redirection to file', 'severity': 'high', 'enabled': True},
    ],
    'LDAP_INJECTION': [
        {'id': 'LDAP_01', 'pattern': re.compile(r'\)\('), 'description': 'LDAP filter manipulation', 'severity': 'high', 'enabled': True},
        {'id': 'LDAP_02', 'pattern': re.compile(r'\*\)\('), 'description': 'LDAP wildcard manipulation', 'severity': 'high', 'enabled': True},
        {'id': 'LDAP_03', 'pattern': re.compile(r'\|\(cn=\*'), 'description': 'LDAP OR filter', 'severity': 'high', 'enabled': True},
        {'id': 'LDAP_04', 'pattern': re.compile(r'\(&\('), 'description': 'LDAP AND filter', 'severity': 'high', 'enabled': True},
        {'id': 'LDAP_05', 'pattern': re.compile(r'\)\(objectClass='), 'description': 'LDAP objectClass injection', 'severity': 'high', 'enabled': True},
    ],
    'HEADER_INJECTION': [
        {'id': 'HI_01', 'pattern': re.compile(r'\r\n'), 'description': 'CRLF injection', 'severity': 'high', 'enabled': True},
        {'id': 'HI_02', 'pattern': re.compile(r'(?i)%0d%0a'), 'description': 'URL encoded CRLF injection', 'severity': 'high', 'enabled': True},
        {'id': 'HI_03', 'pattern': re.compile(r'\n'), 'description': 'LF injection', 'severity': 'medium', 'enabled': True},
        {'id': 'HI_04', 'pattern': re.compile(r'(?i)%0a'), 'description': 'URL encoded LF injection', 'severity': 'medium', 'enabled': True},
        {'id': 'HI_05', 'pattern': re.compile(r'(?i)Set-Cookie:'), 'description': 'Cookie injection', 'severity': 'high', 'enabled': True},
    ],
    'BAD_BOTS': [
        {'id': 'BOT_01', 'pattern': re.compile(r'(?i)(python-requests|urllib|libwww-perl|wget|curl)'), 'description': 'Common script/cli user agents', 'severity': 'low', 'enabled': True},
        {'id': 'BOT_02', 'pattern': re.compile(r'(?i)(HTTrack|Zmeu|grabber|masscan)'), 'description': 'Known bad scrapers/crawlers', 'severity': 'high', 'enabled': True},
    ],
    'SECURITY_SCANNER': [
        {'id': 'SCAN_01', 'pattern': re.compile(r'(?i)(sqlmap|nikto|dirbuster|nmap|zaproxy|w3af|nessus|openvas)'), 'description': 'Security vulnerability scanner', 'severity': 'critical', 'enabled': True},
        {'id': 'SCAN_02', 'pattern': re.compile(r'(?i)acunetix|netsparker|arachni|burpcollaborator'), 'description': 'Commercial web scanner', 'severity': 'critical', 'enabled': True},
    ]
}

def get_rules(sensitivity='standard'):
    """
    Returns rules filtered by sensitivity level.

    Sensitivity levels:
        - 'permissive': Only critical severity rules
        - 'standard': Critical + high severity rules (default)
        - 'strict': Critical + high + medium severity rules
        - 'paranoid': All rules including low severity

    Args:
        sensitivity: One of 'permissive', 'standard', 'strict', 'paranoid'

    Returns:
        Dict of category -> list of enabled rules matching the threshold
    """
    thresholds = {
        'permissive': ['critical'],
        'standard': ['critical', 'high'],
        'strict': ['critical', 'high', 'medium'],
        'paranoid': ['critical', 'high', 'medium', 'low']
    }

    allowed_severities = thresholds.get(sensitivity, thresholds['standard'])

    filtered_rules = {}
    for category, category_rules in SECURITY_RULES.items():
        filtered = [
            rule for rule in category_rules
            if rule['enabled'] and rule['severity'] in allowed_severities
        ]
        if filtered:
            filtered_rules[category] = filtered

    return filtered_rules

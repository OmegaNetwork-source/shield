// STRIX Unified Vulnerability Scanner
// Combines web security + blockchain/Web3 scanning

import type {
    ScanTarget,
    ScanOptions,
    ScanResult,
    ScanProgress,
    UnifiedVulnerability,
    CrawlResult,
    FormInfo,
    HeaderAnalysis,
    SslInfo
} from './types';
import { detectWeb3, analyzeScript, extractSecrets, extractContracts } from './web3-detector';
import { analyzeContract } from '../blockchain';
import {
    XSS_PAYLOADS_EXTENDED,
    SQLI_PAYLOADS_EXTENDED,
    DIRECTORY_WORDLIST,
    COMMON_PARAMETERS as COMMON_PARAMS,
} from './deep-scan';
import {
    SSRF_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    XXE_PAYLOADS,
    SSTI_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_PARAMS,
    CORS_ORIGINS_TO_TEST,
    detectSSRF,
    detectCommandInjection,
    detectPathTraversal,
    detectXXE,
    detectSSTI,
    detectOpenRedirect,
    detectCORSMisconfig,
    createVulnerabilityFromTest
} from './advanced-tests';
import {
    SQL_ERROR_PATTERNS,
    detectSqlError,
    detectXssReflection
} from './deep-scan';
import {
    scanForSourceMaps,
    scanCredentialFiles,
    fetchSensitiveFileContent
} from './tests/directory-enum';

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

// IPC interface for Electron
interface WebScanResponse {
    success: boolean;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: string;
    error?: string;
    url?: string;
}

// Generate unique ID
function generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

/**
 * Fetch URL - uses Electron IPC if available, otherwise browser fetch
 */
async function scanFetch(url: string, options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
} = {}): Promise<{ ok: boolean; status: number; headers: Headers | Record<string, string>; text: () => Promise<string>; error?: string }> {
    if (isElectron) {
        // Use Electron IPC to bypass CORS
        // @ts-ignore
        const response: WebScanResponse = await window.ipcRenderer.invoke('web-scan-fetch', {
            url,
            method: options.method || 'GET',
            headers: options.headers,
            body: options.body,
            timeout: options.timeout || 15000
        });

        if (!response.success) {
            return {
                ok: false,
                status: 0,
                headers: {},
                text: async () => '',
                error: response.error || 'Request failed'
            };
        }

        return {
            ok: response.status ? response.status >= 200 && response.status < 400 : false,
            status: response.status || 0,
            headers: response.headers || {},
            text: async () => response.body || ''
        };
    } else {
        // Browser mode - try fetch but it will likely fail due to CORS
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), options.timeout || 15000);

            const response = await fetch(url, {
                method: options.method || 'GET',
                headers: options.headers,
                body: options.body,
                signal: controller.signal,
                mode: 'cors' // This will likely fail for cross-origin
            });

            clearTimeout(timeoutId);

            return {
                ok: response.ok,
                status: response.status,
                headers: response.headers,
                text: () => response.text()
            };
        } catch (error) {
            // CORS or network error
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const isCors = errorMessage.includes('CORS') ||
                errorMessage.includes('Failed to fetch') ||
                errorMessage.includes('NetworkError') ||
                errorMessage.includes('blocked');

            return {
                ok: false,
                status: 0,
                headers: {},
                text: async () => '',
                error: isCors
                    ? 'CORS blocked - Run STRIX in Electron desktop mode for full scanning capabilities'
                    : errorMessage
            };
        }
    }
}

// Vulnerability templates
const VULN_TEMPLATES = {
    // Security Headers
    missingHSTS: {
        category: 'configuration' as const,
        severity: 'medium' as const,
        title: 'Missing HTTP Strict Transport Security',
        description: 'The Strict-Transport-Security header is not set. This allows attackers to perform downgrade attacks.',
        recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" header.',
        cwe: 'CWE-319',
        owasp: 'A05'
    },
    missingCSP: {
        category: 'configuration' as const,
        severity: 'medium' as const,
        title: 'Missing Content Security Policy',
        description: 'No Content-Security-Policy header. This increases risk of XSS attacks.',
        recommendation: 'Implement a strict Content-Security-Policy header.',
        cwe: 'CWE-1021',
        owasp: 'A05'
    },
    missingXFrame: {
        category: 'configuration' as const,
        severity: 'medium' as const,
        title: 'Missing X-Frame-Options',
        description: 'Page can be embedded in iframes, potentially enabling clickjacking attacks.',
        recommendation: 'Add "X-Frame-Options: DENY" or "SAMEORIGIN" header.',
        cwe: 'CWE-1021',
        owasp: 'A05'
    },
    missingXContentType: {
        category: 'configuration' as const,
        severity: 'low' as const,
        title: 'Missing X-Content-Type-Options',
        description: 'Browser may MIME-sniff responses, potentially leading to XSS.',
        recommendation: 'Add "X-Content-Type-Options: nosniff" header.',
        cwe: 'CWE-16',
        owasp: 'A05'
    },
    insecureCSP: {
        category: 'configuration' as const,
        severity: 'high' as const,
        title: 'Insecure Content Security Policy',
        description: 'CSP contains unsafe directives like unsafe-inline or unsafe-eval.',
        recommendation: 'Remove unsafe-inline and unsafe-eval from CSP. Use nonces or hashes instead.',
        cwe: 'CWE-79',
        owasp: 'A05'
    },

    // SSL/TLS
    expiringSsl: {
        category: 'crypto' as const,
        severity: 'high' as const,
        title: 'SSL Certificate Expiring Soon',
        description: 'The SSL certificate will expire within 30 days.',
        recommendation: 'Renew the SSL certificate before expiration.',
        cwe: 'CWE-295',
        owasp: 'A02'
    },
    weakCipher: {
        category: 'crypto' as const,
        severity: 'medium' as const,
        title: 'Weak SSL Cipher Suite',
        description: 'Server supports weak cipher suites that may be vulnerable to attacks.',
        recommendation: 'Configure server to use only strong cipher suites (TLS 1.2+ with AEAD).',
        cwe: 'CWE-327',
        owasp: 'A02'
    },

    // XSS
    reflectedXss: {
        category: 'xss' as const,
        severity: 'high' as const,
        title: 'Reflected Cross-Site Scripting (XSS)',
        description: 'User input is reflected in the response without proper encoding.',
        recommendation: 'Encode all user input before rendering. Implement CSP.',
        cwe: 'CWE-79',
        owasp: 'A03'
    },
    domXss: {
        category: 'xss' as const,
        severity: 'high' as const,
        title: 'DOM-based Cross-Site Scripting',
        description: 'JavaScript code uses user input in dangerous sinks without sanitization.',
        recommendation: 'Avoid using innerHTML, document.write. Use textContent instead.',
        cwe: 'CWE-79',
        owasp: 'A03'
    },

    // Injection
    sqlInjection: {
        category: 'injection' as const,
        severity: 'critical' as const,
        title: 'SQL Injection',
        description: 'Application appears vulnerable to SQL injection attacks.',
        recommendation: 'Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
        cwe: 'CWE-89',
        owasp: 'A03'
    },
    commandInjection: {
        category: 'injection' as const,
        severity: 'critical' as const,
        title: 'Command Injection',
        description: 'User input may be passed to system commands without sanitization.',
        recommendation: 'Avoid system calls with user input. Use allowlists if necessary.',
        cwe: 'CWE-78',
        owasp: 'A03'
    },

    // Information Disclosure
    errorDisclosure: {
        category: 'disclosure' as const,
        severity: 'low' as const,
        title: 'Verbose Error Messages',
        description: 'Application returns detailed error messages that may reveal sensitive information.',
        recommendation: 'Implement custom error pages. Log details server-side only.',
        cwe: 'CWE-209',
        owasp: 'A04'
    },
    serverBanner: {
        category: 'disclosure' as const,
        severity: 'info' as const,
        title: 'Server Version Disclosure',
        description: 'Server header reveals software version information.',
        recommendation: 'Remove or customize the Server header.',
        cwe: 'CWE-200',
        owasp: 'A05'
    },
    directoryListing: {
        category: 'disclosure' as const,
        severity: 'medium' as const,
        title: 'Directory Listing Enabled',
        description: 'Directory contents are visible when no index file exists.',
        recommendation: 'Disable directory listing in web server configuration.',
        cwe: 'CWE-548',
        owasp: 'A01'
    },

    // Authentication
    missingCsrf: {
        category: 'authentication' as const,
        severity: 'high' as const,
        title: 'Missing CSRF Protection',
        description: 'Form does not include CSRF token, enabling cross-site request forgery.',
        recommendation: 'Implement CSRF tokens for all state-changing operations.',
        cwe: 'CWE-352',
        owasp: 'A01'
    },
    insecureCookie: {
        category: 'authentication' as const,
        severity: 'medium' as const,
        title: 'Insecure Cookie Configuration',
        description: 'Session cookie is missing Secure, HttpOnly, or SameSite attributes.',
        recommendation: 'Set Secure, HttpOnly, and SameSite=Strict on session cookies.',
        cwe: 'CWE-614',
        owasp: 'A07'
    },

    // Web3/Blockchain
    exposedPrivateKey: {
        category: 'smart-contract' as const,
        severity: 'critical' as const,
        title: 'Exposed Private Key',
        description: 'Private key or mnemonic phrase found in client-side code.',
        recommendation: 'IMMEDIATELY rotate all exposed keys. Never store private keys in client code.',
        cwe: 'CWE-798',
        owasp: 'A02',
        attackVector: 'Private Key Theft'
    },
    exposedApiKey: {
        category: 'disclosure' as const,
        severity: 'high' as const,
        title: 'Exposed API Key',
        description: 'API key (Infura, Alchemy, Etherscan) found in client-side code.',
        recommendation: 'Move API keys to server-side. Use environment variables.',
        cwe: 'CWE-798',
        owasp: 'A02'
    },
    unverifiedContract: {
        category: 'smart-contract' as const,
        severity: 'medium' as const,
        title: 'Unverified Smart Contract',
        description: 'Application interacts with unverified smart contract.',
        recommendation: 'Verify contract source code on block explorer. Review before interaction.',
        cwe: 'CWE-345',
        owasp: 'A08',
        attackVector: 'Malicious Contract'
    },
    unsafeContractCall: {
        category: 'smart-contract' as const,
        severity: 'high' as const,
        title: 'Unsafe Contract Interaction Pattern',
        description: 'Application uses unsafe patterns when interacting with smart contracts.',
        recommendation: 'Implement proper error handling. Validate contract responses.',
        cwe: 'CWE-252',
        owasp: 'A08',
        attackVector: 'Contract Exploitation'
    },
    frontRunningRisk: {
        category: 'smart-contract' as const,
        severity: 'medium' as const,
        title: 'Front-Running Risk',
        description: 'Transaction parameters visible in code may enable front-running attacks.',
        recommendation: 'Use private mempools (Flashbots). Implement commit-reveal schemes.',
        cwe: 'CWE-362',
        owasp: 'A04',
        attackVector: 'MEV/Front-running'
    }
};

// XSS test payloads
const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
];

// SQLi test payloads
const SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "' AND '1'='1",
];

// SQLi error patterns
const SQLI_ERROR_PATTERNS = [
    /sql syntax/i,
    /mysql_fetch/i,
    /ORA-\d{5}/i,
    /PostgreSQL.*ERROR/i,
    /SQLite3::SQLException/i,
    /Microsoft.*ODBC.*SQL Server/i,
    /unclosed quotation mark/i,
    /quoted string not properly terminated/i,
    /SQL command not properly ended/i,
];

/**
 * Wrapper to get response with proper typing
 */
async function fetchForScan(url: string, options: {
    method?: string;
    headers?: Record<string, string>;
    timeout?: number;
} = {}): Promise<{
    ok: boolean;
    status: number;
    body: string;
    headers: Record<string, string>;
    error?: string;
}> {
    const response = await scanFetch(url, {
        method: options.method || 'GET',
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) STRIX-Scanner/1.0',
            ...options.headers
        },
        timeout: options.timeout || 15000
    });

    const body = await response.text();

    // Convert Headers to Record if needed
    let headersRecord: Record<string, string> = {};
    if (response.headers instanceof Headers) {
        response.headers.forEach((value, key) => {
            headersRecord[key.toLowerCase()] = value;
        });
    } else {
        headersRecord = response.headers as Record<string, string>;
    }

    return {
        ok: response.ok,
        status: response.status,
        body,
        headers: headersRecord,
        error: response.error
    };
}

/**
 * Analyze security headers
 */
const SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'x-xss-protection',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy'
];

/**
 * Analyze headers from Record (for Electron IPC responses)
 */
function analyzeHeadersFromRecord(headers: Record<string, string>): HeaderAnalysis {
    const present: Record<string, string> = {};
    const missing: string[] = [];
    const misconfigured: Array<{ header: string; issue: string }> = [];

    // Normalize header names to lowercase
    for (const [key, value] of Object.entries(headers)) {
        present[key.toLowerCase()] = value;
    }

    // Check for missing security headers
    for (const header of SECURITY_HEADERS) {
        if (!present[header]) {
            missing.push(header);
        }
    }

    // Check for misconfigurations
    const csp = present['content-security-policy'];
    if (csp) {
        if (csp.includes("'unsafe-inline'")) {
            misconfigured.push({ header: 'content-security-policy', issue: "Contains 'unsafe-inline'" });
        }
        if (csp.includes("'unsafe-eval'")) {
            misconfigured.push({ header: 'content-security-policy', issue: "Contains 'unsafe-eval'" });
        }
        if (csp.includes('*')) {
            misconfigured.push({ header: 'content-security-policy', issue: 'Contains wildcard source' });
        }
    }

    const hsts = present['strict-transport-security'];
    if (hsts) {
        const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
        if (maxAge < 31536000) {
            misconfigured.push({ header: 'strict-transport-security', issue: 'max-age is less than 1 year' });
        }
    }

    // Calculate score
    const maxScore = SECURITY_HEADERS.length * 10;
    const presentScore = (SECURITY_HEADERS.length - missing.length) * 10;
    const penaltyScore = misconfigured.length * 5;
    const score = Math.max(0, Math.min(100, ((presentScore - penaltyScore) / maxScore) * 100));

    return { present, missing, misconfigured, score };
}

function analyzeHeaders(headers: Headers): HeaderAnalysis {
    const present: Record<string, string> = {};
    const missing: string[] = [];
    const misconfigured: Array<{ header: string; issue: string }> = [];

    // Check each header
    for (const [key, value] of headers.entries()) {
        present[key.toLowerCase()] = value;
    }

    // Check for missing security headers
    for (const header of SECURITY_HEADERS) {
        if (!present[header]) {
            missing.push(header);
        }
    }

    // Check for misconfigurations
    const csp = present['content-security-policy'];
    if (csp) {
        if (csp.includes("'unsafe-inline'")) {
            misconfigured.push({ header: 'content-security-policy', issue: "Contains 'unsafe-inline'" });
        }
        if (csp.includes("'unsafe-eval'")) {
            misconfigured.push({ header: 'content-security-policy', issue: "Contains 'unsafe-eval'" });
        }
        if (csp.includes('*')) {
            misconfigured.push({ header: 'content-security-policy', issue: 'Contains wildcard source' });
        }
    }

    const hsts = present['strict-transport-security'];
    if (hsts) {
        const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
        if (maxAge < 31536000) {
            misconfigured.push({ header: 'strict-transport-security', issue: 'max-age is less than 1 year' });
        }
    }

    // Calculate score
    const maxScore = SECURITY_HEADERS.length * 10;
    const presentScore = (SECURITY_HEADERS.length - missing.length) * 10;
    const penaltyScore = misconfigured.length * 5;
    const score = Math.max(0, Math.min(100, ((presentScore - penaltyScore) / maxScore) * 100));

    return { present, missing, misconfigured, score };
}

/**
 * Extract forms from HTML
 */
function extractForms(html: string, baseUrl: string): FormInfo[] {
    const forms: FormInfo[] = [];
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;

    let match;
    while ((match = formRegex.exec(html)) !== null) {
        const formHtml = match[0];
        const formContent = match[1];

        // Extract action
        const actionMatch = formHtml.match(/action=["']([^"']+)["']/i);
        let action = actionMatch?.[1] || '';
        if (action && !action.startsWith('http')) {
            action = new URL(action, baseUrl).href;
        }

        // Extract method
        const methodMatch = formHtml.match(/method=["']([^"']+)["']/i);
        const method = (methodMatch?.[1] || 'GET').toUpperCase();

        // Extract inputs
        const inputs: FormInfo['inputs'] = [];
        const inputRegex = /<input[^>]*>/gi;
        let inputMatch;
        while ((inputMatch = inputRegex.exec(formContent)) !== null) {
            const inputHtml = inputMatch[0];
            const nameMatch = inputHtml.match(/name=["']([^"']+)["']/i);
            const typeMatch = inputHtml.match(/type=["']([^"']+)["']/i);
            const valueMatch = inputHtml.match(/value=["']([^"']+)["']/i);

            if (nameMatch) {
                inputs.push({
                    name: nameMatch[1],
                    type: typeMatch?.[1] || 'text',
                    value: valueMatch?.[1]
                });
            }
        }

        // Check for file upload
        const hasFileUpload = /<input[^>]*type=["']file["']/i.test(formContent);

        // Check for CSRF token
        const hasCsrfToken = /csrf|_token|authenticity_token/i.test(formContent);

        forms.push({
            action: action || baseUrl,
            method,
            inputs,
            hasFileUpload,
            hasCsrfToken
        });
    }

    return forms;
}

/**
 * Test for XSS vulnerabilities
 */
async function testXss(url: string, parameter: string, options?: ScanOptions): Promise<UnifiedVulnerability[]> {
    const vulns: UnifiedVulnerability[] = [];

    for (const payload of XSS_PAYLOADS.slice(0, 3)) { // Test first 3 payloads for speed
        try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await fetchForScan(testUrl.toString(), {
                headers: options?.headers,
                timeout: options?.timeout || 5000
            });

            if (!response.ok || response.error) continue;

            // Check if payload is reflected
            if (response.body.includes(payload)) {
                vulns.push({
                    id: generateId(),
                    ...VULN_TEMPLATES.reflectedXss,
                    url,
                    parameter,
                    payload,
                    evidence: `Payload "${payload}" reflected in response`,
                    location: url
                });
                break; // One finding per parameter is enough
            }
        } catch (e) {
            // Request failed, continue
        }
    }

    return vulns;
}

/**
 * Test for SQL injection
 */
async function testSqli(url: string, parameter: string, options?: ScanOptions): Promise<UnifiedVulnerability[]> {
    const vulns: UnifiedVulnerability[] = [];

    // Get baseline response
    let baselineLength = 0;
    try {
        const baseline = await fetchForScan(url, {
            headers: options?.headers,
            timeout: options?.timeout || 5000
        });
        if (!baseline.ok || baseline.error) return vulns;
        baselineLength = baseline.body.length;
    } catch {
        return vulns;
    }

    for (const payload of SQLI_PAYLOADS.slice(0, 3)) {
        try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await fetchForScan(testUrl.toString(), {
                headers: options?.headers,
                timeout: options?.timeout || 5000
            });

            if (!response.ok || response.error) continue;

            const body = response.body;

            // Check for SQL error messages
            for (const pattern of SQLI_ERROR_PATTERNS) {
                if (pattern.test(body)) {
                    vulns.push({
                        id: generateId(),
                        ...VULN_TEMPLATES.sqlInjection,
                        url,
                        parameter,
                        payload,
                        evidence: `SQL error detected: ${body.match(pattern)?.[0]}`,
                        location: url
                    });
                    return vulns; // Critical finding, stop testing
                }
            }

            // Check for significant response length change (boolean-based)
            const lengthDiff = Math.abs(body.length - baselineLength);
            if (lengthDiff > baselineLength * 0.5 && payload.includes('OR')) {
                vulns.push({
                    id: generateId(),
                    ...VULN_TEMPLATES.sqlInjection,
                    severity: 'high',
                    url,
                    parameter,
                    payload,
                    evidence: `Response length changed significantly (${baselineLength} -> ${body.length})`,
                    location: url
                });
                return vulns;
            }
        } catch (e) {
            // Request failed
        }
    }

    return vulns;
}

/**
 * Extract links from HTML for crawling
 */
function extractLinksFromHtml(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seen = new Set<string>();
    const base = new URL(baseUrl);

    // Extract href links (handling single, double, or no quotes)
    const hrefRegex = /href=["']?([^"'\s>]+)["']?/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
        try {
            const relativeUrl = match[1];
            // Skip empty, javascript:, mailto:, tel:
            if (!relativeUrl || relativeUrl.startsWith('javascript:') || relativeUrl.startsWith('mailto:') || relativeUrl.startsWith('tel:') || relativeUrl.startsWith('#')) {
                continue;
            }

            const url = new URL(relativeUrl, baseUrl);

            // Only same-origin links, skip static assets
            if (url.origin === base.origin &&
                !url.pathname.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/i) &&
                !seen.has(url.href)) {
                seen.add(url.href);
                links.push(url.href);
            }
        } catch { }
    }

    return links.slice(0, 100); // Limit to 100 links per page
}

/**
 * Extract parameters from URL
 */
function extractParamsFromUrl(url: string): string[] {
    try {
        const urlObj = new URL(url);
        return Array.from(urlObj.searchParams.keys());
    } catch {
        return [];
    }
}

/**
 * Extended XSS testing with comprehensive payloads
 */
async function testXssExtended(url: string, parameter: string, maxPayloads: number, options?: ScanOptions): Promise<UnifiedVulnerability[]> {
    const vulns: UnifiedVulnerability[] = [];
    const payloads = XSS_PAYLOADS_EXTENDED.slice(0, maxPayloads);

    for (const payload of payloads) {
        try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await fetchForScan(testUrl.toString(), {
                headers: options?.headers,
                timeout: options?.timeout || 8000
            });

            if (!response.ok || response.error) continue;

            const body = response.body;

            // Check for reflection
            if (detectXssReflection(body, payload)) {
                // Find index of reflection for context
                const index = body.indexOf(payload);
                const context = index !== -1
                    ? `...${body.substring(Math.max(0, index - 50), Math.min(body.length, index + payload.length + 50))}...`
                    : 'Payload reflected in response';

                vulns.push({
                    id: generateId(),
                    ...VULN_TEMPLATES.reflectedXss,
                    url: testUrl.toString(),
                    parameter,
                    payload,
                    evidence: [
                        `HOW: Injected payload into parameter "${parameter}"`,
                        `PAYLOAD: ${payload}`,
                        `WHY: Payload was reflected in the page source:`,
                        `CONTEXT: ${context}`
                    ].join('\n'),
                    location: url
                });
                return vulns; // Found one, stop testing this param
            }
        } catch (e) {
            // Request failed
        }
    }

    return vulns;
}

/**
 * Extended SQLi testing with comprehensive payloads
 */
async function testSqliExtended(url: string, parameter: string, maxPayloads: number, options?: ScanOptions): Promise<UnifiedVulnerability[]> {
    const vulns: UnifiedVulnerability[] = [];
    const payloads = SQLI_PAYLOADS_EXTENDED.slice(0, maxPayloads);

    // Get baseline response
    let baselineLength = 0;
    try {
        const baseResponse = await fetchForScan(url, { timeout: 8000 });
        if (baseResponse.ok) {
            baselineLength = baseResponse.body.length;
        }
    } catch { }

    for (const payload of payloads) {
        try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const response = await fetchForScan(testUrl.toString(), {
                headers: options?.headers,
                timeout: options?.timeout || 8000
            });

            if (!response.ok || response.error) continue;

            const body = response.body;

            // Check for SQL errors
            const sqlError = detectSqlError(body);
            if (sqlError.detected) {
                vulns.push({
                    id: generateId(),
                    ...VULN_TEMPLATES.sqlInjection,
                    severity: 'critical',
                    url: testUrl.toString(),
                    parameter,
                    payload,
                    evidence: [
                        `HOW: Injected SQL payload into parameter "${parameter}"`,
                        `PAYLOAD: ${payload}`,
                        `WHY: Database error detected in response:`,
                        `ERROR: ${sqlError.snippet || sqlError.pattern}`,
                        `TYPE: Error-based SQL Injection`
                    ].join('\n'),
                    location: url
                });
                return vulns; // Found one, stop testing
            }

            // Check for significant response difference (boolean-based)
            if (baselineLength > 0) {
                const diff = Math.abs(body.length - baselineLength);
                if (diff > baselineLength * 0.3 && (payload.includes("'1'='1") || payload.includes('1=1'))) {
                    vulns.push({
                        id: generateId(),
                        ...VULN_TEMPLATES.sqlInjection,
                        severity: 'high',
                        url: testUrl.toString(),
                        parameter,
                        payload,
                        evidence: [
                            `HOW: Injected boolean logic into parameter "${parameter}"`,
                            `PAYLOAD: ${payload}`,
                            `WHY: Response length changed significantly compared to baseline (${baselineLength} bytes -> ${body.length} bytes).`,
                            `TYPE: Boolean-based Blind SQL Injection`
                        ].join('\n'),
                        location: url
                    });
                    return vulns;
                }
            }
        } catch (e) {
            // Request failed
        }
    }

    return vulns;
}

/**
 * Time-based blind injection testing
 */
async function testTimeBasedBlind(url: string, parameter: string, options?: ScanOptions): Promise<UnifiedVulnerability[]> {
    const vulns: UnifiedVulnerability[] = [];

    // Time-based payloads
    const timePayloads = [
        { payload: "' AND SLEEP(5)--", delay: 5000, type: 'MySQL' },
        { payload: "'; WAITFOR DELAY '0:0:5'--", delay: 5000, type: 'MSSQL' },
        { payload: "' || pg_sleep(5)--", delay: 5000, type: 'PostgreSQL' },
        { payload: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", delay: 5000, type: 'MySQL' },
    ];

    // Get baseline response time
    let baselineTime = 0;
    try {
        const start = Date.now();
        await fetchForScan(url, { timeout: 10000 });
        baselineTime = Date.now() - start;
    } catch { }

    for (const { payload, delay, type } of timePayloads) {
        try {
            const testUrl = new URL(url);
            testUrl.searchParams.set(parameter, payload);

            const start = Date.now();
            await fetchForScan(testUrl.toString(), {
                headers: options?.headers,
                timeout: delay + 10000 // Allow for delay + network time
            });
            const elapsed = Date.now() - start;

            // Check if response was significantly delayed
            if (elapsed > delay - 500 && elapsed > baselineTime + 3000) {
                vulns.push({
                    id: generateId(),
                    ...VULN_TEMPLATES.sqlInjection,
                    severity: 'critical',
                    title: `Time-based Blind SQL Injection (${type})`,
                    url: testUrl.toString(),
                    parameter,
                    payload,
                    evidence: [
                        `HOW: Injected time-delay command into parameter "${parameter}"`,
                        `PAYLOAD: ${payload}`,
                        `WHY: Server took ${elapsed}ms to respond (expected ~${delay}ms delay).`,
                        `BASELINE: ${baselineTime}ms`,
                        `TYPE: Time-based Blind SQL Injection (${type})`
                    ].join('\n'),
                    location: url
                });
                return vulns; // Confirmed, stop testing
            }
        } catch (e) {
            // Timeout might actually indicate success
            if (e instanceof Error && e.message.includes('timeout')) {
                // Could be vulnerable - timeout happened
            }
        }
    }

    return vulns;
}

/**
 * Main unified scanner class
 */
export class UnifiedScanner {
    private results: Map<string, ScanResult> = new Map();
    private onProgress?: (progress: ScanProgress) => void;

    constructor(onProgress?: (progress: ScanProgress) => void) {
        this.onProgress = onProgress;
    }

    private currentVulns: UnifiedVulnerability[] = [];

    private updateProgress(phase: string, current: number, total: number, message: string, findings: number, vulns?: UnifiedVulnerability[]) {
        if (vulns) {
            this.currentVulns = vulns;
        }
        if (this.onProgress) {
            this.onProgress({
                phase,
                current,
                total,
                message,
                findings,
                currentFindings: this.currentVulns
            });
        }
    }

    /**
     * Scan a website for vulnerabilities
     */
    async scan(target: ScanTarget): Promise<ScanResult> {
        const scanId = generateId();
        const startTime = new Date();

        const result: ScanResult = {
            id: scanId,
            target: target.url,
            startTime,
            status: 'running',
            vulnerabilities: [],
            summary: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
                total: 0,
                webVulns: 0,
                blockchainVulns: 0,
                riskScore: 0,
                riskLevel: 'safe'
            },
            recommendations: []
        };

        this.results.set(scanId, result);

        const options = target.options || {};
        const vulns: UnifiedVulnerability[] = [];

        try {
            // Phase 1: Initial request
            this.updateProgress('Fetching', 1, 6, `Fetching ${target.url}`, 0);

            let response = await fetchForScan(target.url, {
                headers: options.headers,
                timeout: options.timeout || 15000
            });

            // Auto-fallback from HTTPS to HTTP if it fails (common for older test sites)
            if (response.error && target.url.startsWith('https://')) {
                const httpUrl = target.url.replace('https://', 'http://');
                this.updateProgress('Fetching', 1, 6, `HTTPS failed, trying HTTP: ${httpUrl}`, 0);
                const httpResponse = await fetchForScan(httpUrl, {
                    headers: options.headers,
                    timeout: options.timeout || 10000
                });

                if (httpResponse.ok || (!httpResponse.error && httpResponse.status > 0)) {
                    response = httpResponse;
                    target.url = httpUrl;
                }
            }

            // Check for errors (CORS, network, etc.)
            if (response.error) {
                vulns.push({
                    id: generateId(),
                    category: 'infrastructure',
                    severity: 'info',
                    title: 'Scan Limitation',
                    description: response.error,
                    recommendation: response.error.includes('CORS')
                        ? 'Run STRIX as an Electron desktop application to bypass browser CORS restrictions and enable full scanning.'
                        : 'Check that the target URL is accessible and try again. If it is an internal or old site, try using http:// specifically.',
                    url: target.url,
                    location: target.url
                });
            }

            const html = response.body;

            // Phase 2: Header Analysis
            this.updateProgress('Headers', 2, 6, 'Analyzing security headers', vulns.length, vulns);

            if (options.scanHeaders !== false && response.ok) {
                const headerAnalysis = analyzeHeadersFromRecord(response.headers);
                result.headerAnalysis = headerAnalysis;

                // Generate vulnerabilities for missing headers
                if (headerAnalysis.missing.includes('strict-transport-security')) {
                    vulns.push({ id: generateId(), ...VULN_TEMPLATES.missingHSTS, url: target.url, location: target.url });
                }
                if (headerAnalysis.missing.includes('content-security-policy')) {
                    vulns.push({ id: generateId(), ...VULN_TEMPLATES.missingCSP, url: target.url, location: target.url });
                }
                if (headerAnalysis.missing.includes('x-frame-options')) {
                    vulns.push({ id: generateId(), ...VULN_TEMPLATES.missingXFrame, url: target.url, location: target.url });
                }
                if (headerAnalysis.missing.includes('x-content-type-options')) {
                    vulns.push({ id: generateId(), ...VULN_TEMPLATES.missingXContentType, url: target.url, location: target.url });
                }

                // Check for misconfigured CSP
                for (const misconfig of headerAnalysis.misconfigured) {
                    if (misconfig.header === 'content-security-policy') {
                        vulns.push({
                            id: generateId(),
                            ...VULN_TEMPLATES.insecureCSP,
                            url: target.url,
                            location: target.url,
                            evidence: misconfig.issue
                        });
                    }
                }

                // Check Server header
                const serverHeader = response.headers['server'];
                if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
                    vulns.push({
                        id: generateId(),
                        ...VULN_TEMPLATES.serverBanner,
                        url: target.url,
                        location: target.url,
                        evidence: `Server: ${serverHeader}`
                    });
                }
            }

            // Phase 3: Web3/Blockchain Detection
            this.updateProgress('Web3', 3, 6, 'Detecting Web3/Blockchain integration', vulns.length, vulns);

            if (options.scanBlockchain !== false || options.testWeb3 !== false) {
                // Extract inline scripts
                const scriptContents: string[] = [];
                const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
                let scriptMatch;
                while ((scriptMatch = scriptRegex.exec(html)) !== null) {
                    if (scriptMatch[1].trim()) {
                        scriptContents.push(scriptMatch[1]);
                    }
                }

                // Extract and fetch external script URLs (up to 5 main bundles)
                const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
                const externalScripts: string[] = [];
                let srcMatch;
                while ((srcMatch = scriptSrcRegex.exec(html)) !== null) {
                    const scriptUrl = srcMatch[1];
                    // Only fetch main bundle scripts, not analytics/tracking
                    if (scriptUrl &&
                        !scriptUrl.includes('analytics') &&
                        !scriptUrl.includes('gtag') &&
                        !scriptUrl.includes('facebook') &&
                        !scriptUrl.includes('twitter') &&
                        (scriptUrl.includes('.js') || scriptUrl.includes('chunk') || scriptUrl.includes('bundle') || scriptUrl.includes('main'))) {
                        externalScripts.push(scriptUrl);
                    }
                }

                // Fetch up to 5 external scripts for deeper analysis
                const fetchedScripts: string[] = [];
                const fetchedScriptUrls: string[] = [];
                for (const scriptUrl of externalScripts.slice(0, 5)) {
                    try {
                        const fullUrl = scriptUrl.startsWith('http') ? scriptUrl : new URL(scriptUrl, target.url).href;
                        this.updateProgress('Web3', 3, 6, `Fetching script: ${scriptUrl.slice(-30)}`, vulns.length, vulns);

                        const scriptResponse = await fetchForScan(fullUrl, { timeout: 10000 });
                        if (scriptResponse.ok && scriptResponse.body) {
                            fetchedScripts.push(scriptResponse.body);
                            fetchedScriptUrls.push(fullUrl);
                        }
                    } catch (e) {
                        // Skip failed script fetches
                    }
                }

                // Check for source maps (exposed source code)
                if (fetchedScriptUrls.length > 0) {
                    this.updateProgress('Web3', 3, 6, 'Checking for source maps...', vulns.length, vulns);
                    try {
                        const sourceMaps = await scanForSourceMaps(fetchedScriptUrls, (c, t, f) => {
                            this.updateProgress('Web3', 3, 6, `Checking source maps: ${f.split('/').pop()} (${c}/${t})`, vulns.length, vulns);
                        });
                        for (const sourceMap of sourceMaps) {
                            vulns.push({
                                id: generateId(),
                                category: 'disclosure',
                                severity: 'high',
                                title: 'Source Map Exposed',
                                description: 'JavaScript source map file is publicly accessible, exposing original source code which may contain secrets, internal logic, and API endpoints.',
                                recommendation: 'Remove source map files from production servers or restrict access to them.',
                                url: sourceMap.url,
                                location: sourceMap.url,
                                evidence: `Source map found: ${sourceMap.url}${sourceMap.contentLength ? ` (${Math.round(sourceMap.contentLength / 1024)}KB)` : ''}`,
                                cwe: 'CWE-540',
                                owasp: 'A05'
                            });
                        }
                    } catch (e) {
                        // Skip source map check errors
                    }
                }

                // Check for exposed credential files
                this.updateProgress('Web3', 3, 6, 'Probing for sensitive files...', vulns.length, vulns);
                try {
                    const credFiles = await scanCredentialFiles(target.url, (c, t, f) => {
                        this.updateProgress('Web3', 3, 6, `Probing files: ${f} (${c}/${t})`, vulns.length, vulns);
                    });
                    for (const credFile of credFiles) {
                        // Scan the content for secrets
                        const fileSecrets = extractSecrets(credFile.content, credFile.url);

                        if (fileSecrets.length > 0) {
                            for (const secret of fileSecrets) {
                                const serviceName = secret.serviceName || 'Unknown Service';
                                const actualSeverity = secret.serviceSeverity || 'high';

                                vulns.push({
                                    id: generateId(),
                                    category: 'disclosure',
                                    severity: actualSeverity as any,
                                    title: `Exposed ${serviceName} Credentials in ${credFile.file}`,
                                    description: `${secret.serviceDescription || 'API credentials'} found in publicly accessible configuration file.`,
                                    recommendation: 'Remove sensitive files from public web root and use environment variables for secrets.',
                                    url: credFile.url,
                                    location: credFile.url,
                                    evidence: `File: ${credFile.file}\nValue: ${secret.value}\n${secret.serviceImpact || ''}`,
                                    cwe: 'CWE-312',
                                    owasp: 'A01',
                                    // Extended properties for UI display
                                    secretType: secret.type,
                                    secretValue: secret.value,
                                    secretService: serviceName,
                                    secretServiceDesc: secret.serviceDescription,
                                    secretImpact: secret.serviceImpact,
                                } as any);
                            }
                        } else if (credFile.hasSecrets) {
                            // File looks sensitive but no specific secret pattern matched
                            vulns.push({
                                id: generateId(),
                                category: 'disclosure',
                                severity: 'medium',
                                title: `Potentially Sensitive File Exposed: ${credFile.file}`,
                                description: 'Configuration file is publicly accessible and may contain sensitive information.',
                                recommendation: 'Review file contents and restrict access or remove from public web root.',
                                url: credFile.url,
                                location: credFile.url,
                                evidence: `File accessible at: ${credFile.url}\nContent preview: ${credFile.content.substring(0, 200)}...`,
                                cwe: 'CWE-538',
                                owasp: 'A05'
                            });
                        }
                    }
                } catch (e) {
                    // Skip credential file check errors
                }

                // Combine all scripts for analysis
                const allScripts = [...scriptContents, ...fetchedScripts];

                const web3Detection = detectWeb3(html, allScripts);
                result.web3Detection = web3Detection;

                // Add extended info to result
                const extendedDetection = web3Detection as any;

                if (web3Detection.hasWeb3) {
                    // Check for exposed secrets
                    const allContent = html + '\n' + allScripts.join('\n');
                    const secrets = extractSecrets(allContent, target.url);

                    for (const secret of secrets) {
                        // Build detailed evidence with all available info
                        const serviceName = secret.serviceName || 'Unknown Service';
                        const serviceDesc = secret.serviceDescription || '';
                        const serviceImpact = secret.serviceImpact || 'Potential unauthorized access';
                        const lineInfo = secret.lineNumber ? `Line ~${secret.lineNumber}` : 'Unknown line';

                        // Create comprehensive evidence report
                        const detailedEvidence = [
                            `═══════════════════════════════════════════════════════════`,
                            `SERVICE: ${serviceName}${serviceDesc ? ` (${serviceDesc})` : ''}`,
                            `═══════════════════════════════════════════════════════════`,
                            ``,
                            `SECRET VALUE:`,
                            `  ${secret.value}`,
                            ``,
                            `LOCATION:`,
                            `  URL: ${secret.location}`,
                            `  Position: ${lineInfo}`,
                            ``,
                            `DETECTION CONFIDENCE: ${secret.confidence.toUpperCase()}`,
                            ``,
                            `SECURITY IMPACT:`,
                            `  ${serviceImpact}`,
                            ``,
                            `CODE CONTEXT:`,
                            `───────────────────────────────────────────────────────────`,
                            secret.context || 'No context available',
                            `───────────────────────────────────────────────────────────`,
                        ].join('\n');

                        // Use service-specific severity instead of generic HIGH
                        const actualSeverity = secret.serviceSeverity ||
                            (secret.type === 'private_key' || secret.type === 'wallet' ? 'critical' : 'high');

                        if (secret.type === 'private_key' || secret.type === 'wallet') {
                            vulns.push({
                                id: generateId(),
                                ...VULN_TEMPLATES.exposedPrivateKey,
                                severity: actualSeverity,  // Override with accurate severity
                                title: secret.serviceName ? `Exposed ${secret.serviceName}` : 'Exposed Private Key',
                                url: target.url,
                                location: secret.location || target.url,
                                evidence: detailedEvidence,
                                // Additional details for expanded view
                                secretType: secret.type,
                                secretValue: secret.value,
                                secretContext: secret.context,
                                secretConfidence: secret.confidence,
                                secretService: secret.serviceName,
                                secretServiceDesc: secret.serviceDescription,
                                secretImpact: secret.serviceImpact,
                                secretLine: secret.lineNumber
                            });
                        } else if (secret.type === 'api_key') {
                            vulns.push({
                                id: generateId(),
                                ...VULN_TEMPLATES.exposedApiKey,
                                severity: actualSeverity,  // Override with accurate severity
                                title: `Exposed ${serviceName} API Key`,
                                url: target.url,
                                location: secret.location || target.url,
                                evidence: detailedEvidence,
                                secretType: secret.type,
                                secretValue: secret.value,
                                secretContext: secret.context,
                                secretConfidence: secret.confidence,
                                secretService: secret.serviceName,
                                secretServiceDesc: secret.serviceDescription,
                                secretImpact: secret.serviceImpact,
                                secretLine: secret.lineNumber
                            });
                        }
                    }

                    // Report detected chains
                    if (extendedDetection.detectedChains?.length > 0) {
                        vulns.push({
                            id: generateId(),
                            category: 'blockchain',
                            severity: 'info',
                            title: 'Blockchain Integration Detected',
                            description: `This application integrates with: ${extendedDetection.detectedChains.join(', ')}`,
                            recommendation: 'Ensure all blockchain interactions are secure and validated.',
                            url: target.url,
                            location: target.url,
                            evidence: `Chains: ${extendedDetection.detectedChains.join(', ')}`
                        });
                    }

                    // Report detected libraries
                    if (extendedDetection.detectedLibraries?.length > 0) {
                        vulns.push({
                            id: generateId(),
                            category: 'blockchain',
                            severity: 'info',
                            title: 'Web3 Libraries Detected',
                            description: `Libraries found: ${extendedDetection.detectedLibraries.join(', ')}`,
                            recommendation: 'Keep libraries updated to latest secure versions.',
                            url: target.url,
                            location: target.url,
                            evidence: `Libraries: ${extendedDetection.detectedLibraries.join(', ')}`
                        });
                    }

                    // Report DeFi features
                    if (extendedDetection.detectedFeatures?.length > 0) {
                        vulns.push({
                            id: generateId(),
                            category: 'smart-contract',
                            severity: 'info',
                            title: 'DeFi Features Detected',
                            description: `DeFi functionality: ${extendedDetection.detectedFeatures.join(', ')}`,
                            recommendation: 'Review DeFi interactions for slippage protection and approval limits.',
                            url: target.url,
                            location: target.url,
                            evidence: `Features: ${extendedDetection.detectedFeatures.join(', ')}`
                        });
                    }

                    // Analyze detected contracts
                    for (const contract of web3Detection.contracts) {
                        const severity = contract.verified ? 'info' : 'low';
                        vulns.push({
                            id: generateId(),
                            category: 'smart-contract',
                            severity,
                            title: contract.name || `${contract.chain.charAt(0).toUpperCase() + contract.chain.slice(1)} Contract`,
                            description: contract.name
                                ? `Known program: ${contract.name} (${contract.type || 'unknown'})`
                                : `Application interacts with ${contract.type || 'unknown'} contract on ${contract.chain}`,
                            recommendation: contract.verified
                                ? 'Known program - verify expected behavior.'
                                : 'Verify contract is legitimate and audited before interaction.',
                            contractAddress: contract.address,
                            chain: contract.chain,
                            url: target.url,
                            location: target.url,
                            evidence: `Contract: ${contract.address} (${contract.chain})`
                        });
                    }

                    // Check for front-running risks
                    if (allContent.includes('amountOutMin') && /0|['"]0['"]/.test(allContent)) {
                        vulns.push({
                            id: generateId(),
                            ...VULN_TEMPLATES.frontRunningRisk,
                            url: target.url,
                            location: target.url,
                            evidence: 'Zero slippage tolerance detected in swap parameters'
                        });
                    }
                }

                // Analyze scripts for suspicious patterns
                for (const script of scriptContents) {
                    const analysis = analyzeScript(script);
                    for (const suspicious of analysis.suspiciousPatterns) {
                        vulns.push({
                            id: generateId(),
                            category: 'xss',
                            severity: 'medium',
                            title: 'Suspicious JavaScript Pattern',
                            description: suspicious,
                            recommendation: 'Review and sanitize dangerous JavaScript patterns.',
                            url: target.url,
                            location: target.url,
                            cwe: 'CWE-79',
                            owasp: 'A03'
                        });
                    }
                }
            }

            // Phase 4: Form Analysis
            this.updateProgress('Forms', 4, 6, 'Analyzing forms and CSRF protection', vulns.length, vulns);

            const forms = extractForms(html, target.url);
            const crawlResult: CrawlResult = {
                url: target.url,
                status: response.status,
                contentType: response.headers['content-type'] || undefined,
                forms,
                links: [],
                scripts: [],
                apiEndpoints: [],
                comments: [],
                emails: [],
                secrets: extractSecrets(html, target.url)
            };
            result.crawlResults = [crawlResult];

            // Check forms for CSRF
            for (const form of forms) {
                if (form.method === 'POST' && !form.hasCsrfToken) {
                    vulns.push({
                        id: generateId(),
                        ...VULN_TEMPLATES.missingCsrf,
                        url: form.action,
                        location: form.action,
                        evidence: `POST form to ${form.action} lacks CSRF token`
                    });
                }
            }

            // Phase 5: Active Testing (XSS, SQLi)
            // Determine scan intensity
            const isDeep = options.depth === 'deep' || options.depth === 'comprehensive';
            const isComprehensive = options.depth === 'comprehensive';
            const payloadsPerParam = options.payloadsPerParam || (isComprehensive ? 50 : isDeep ? 20 : 10);
            const maxParams = options.testAllParams ? 50 : (isDeep ? 15 : 5);
            const delay = options.delayBetweenRequests || 100;

            if (options.depth !== 'quick') {
                this.updateProgress('Testing', 5, 10, 'Testing for injection vulnerabilities', vulns.length, vulns);

                // Collect all pages to test
                let pagesToTest: Array<{ url: string; params: string[]; forms: FormInfo[] }> = [
                    { url: target.url, params: extractParamsFromUrl(target.url), forms }
                ];

                // Phase 5a: Crawl pages if enabled
                if (options.crawlPages && isDeep) {
                    this.updateProgress('Crawling', 5, 10, 'Discovering pages...', vulns.length, vulns);
                    const maxPages = options.maxPages || 50;
                    const crawledUrls = new Set<string>([target.url]);
                    const toCrawl = [target.url];

                    while (toCrawl.length > 0 && crawledUrls.size < maxPages) {
                        const currentUrl = toCrawl.shift()!;
                        this.updateProgress('Crawling', 5, 10, `Crawling ${crawledUrls.size}/${maxPages}: ${new URL(currentUrl).pathname}`, vulns.length, vulns);

                        try {
                            const pageResponse = await fetchForScan(currentUrl, { timeout: 10000 });
                            if (pageResponse.ok && pageResponse.body) {
                                const pageHtml = pageResponse.body;

                                // Extract links to continue crawling
                                const links = extractLinksFromHtml(pageHtml, currentUrl);
                                for (const link of links) {
                                    if (!crawledUrls.has(link) && crawledUrls.size < maxPages) {
                                        crawledUrls.add(link);
                                        toCrawl.push(link);

                                        // We will extract params/forms when we fetch this link in the next iteration
                                    }
                                }

                                // Extract page info for testing the current page
                                const pageParams = extractParamsFromUrl(currentUrl);
                                const pageForms = extractForms(pageHtml, currentUrl);

                                // Only add if it has something to test (to save time)
                                if (pageParams.length > 0 || pageForms.length > 0) {
                                    // Check if we already have this URL in pagesToTest
                                    if (!pagesToTest.some(p => p.url === currentUrl)) {
                                        pagesToTest.push({ url: currentUrl, params: pageParams, forms: pageForms });
                                    }
                                }
                            }
                        } catch (e) {
                            // Skip failed pages
                        }

                        // Delay between requests
                        if (delay > 0) await new Promise(r => setTimeout(r, delay));
                    }

                    this.updateProgress('Crawling', 5, 10, `Discovered ${pagesToTest.length} pages`, vulns.length, vulns);
                }

                // Phase 5b: Directory enumeration if enabled
                if (options.directoryEnum && isDeep) {
                    this.updateProgress('DirEnum', 6, 10, 'Checking for hidden directories...', vulns.length, vulns);

                    const wordlistSize = options.dirWordlist || 'medium';
                    const dirList = DIRECTORY_WORDLIST.slice(0,
                        wordlistSize === 'small' ? 100 : wordlistSize === 'medium' ? 500 : 2000
                    );

                    const baseUrl = new URL(target.url).origin;
                    let checkedDirs = 0;

                    // Helper to validate if content is actually sensitive (not just SPA routing)
                    const validateSensitiveContent = (content: string, path: string): {
                        isSensitive: boolean;
                        severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
                        evidence: string;
                        reason: string;
                    } => {
                        const contentLower = content.toLowerCase();
                        const contentSnippet = content.slice(0, 500);

                        // Check if it's just HTML (SPA routing returning index.html)
                        const isHtml = contentLower.includes('<!doctype html') ||
                            contentLower.includes('<html') ||
                            (contentLower.includes('<head') && contentLower.includes('<body'));

                        // Check for "soft 404" - HTTP 200 but page says 404/Not Found
                        const isSoft404 = isHtml && (
                            contentLower.includes('404') ||
                            contentLower.includes('not found') ||
                            contentLower.includes('page not found') ||
                            contentLower.includes('does not exist') ||
                            contentLower.includes('doesn\'t exist') ||
                            contentLower.includes('cannot be found') ||
                            contentLower.includes('no longer exists') ||
                            contentLower.includes('page doesn\'t exist') ||
                            contentLower.includes('nothing here') ||
                            contentLower.includes('oops') ||
                            /error[:\s]*404/i.test(content)
                        );

                        // Check for actual sensitive content patterns
                        const envVarPattern = /^[A-Z][A-Z0-9_]+=.+/m;
                        const hasEnvVars = envVarPattern.test(content);

                        const gitConfigPattern = /\[core\]|\[remote|\[branch/i;
                        const hasGitConfig = gitConfigPattern.test(content);

                        const sqlPattern = /CREATE TABLE|INSERT INTO|DROP TABLE|SELECT \* FROM/i;
                        const hasSql = sqlPattern.test(content);

                        const secretPatterns = /password\s*[:=]/i.test(content) ||
                            /api[_-]?key\s*[:=]/i.test(content) ||
                            /secret\s*[:=]/i.test(content) ||
                            /private[_-]?key/i.test(content) ||
                            /aws[_-]?access/i.test(content) ||
                            /database[_-]?url\s*[:=]/i.test(content);

                        // .git/config or .git/HEAD exposure
                        const isGitExposure = path.includes('.git') && (hasGitConfig || content.includes('ref: refs/'));

                        // Actual .env file with variables
                        const isEnvExposure = path.includes('.env') && hasEnvVars && !isHtml;

                        // SQL dump
                        const isSqlExposure = (path.includes('.sql') || path.includes('backup')) && hasSql;

                        // Config file with secrets
                        const isConfigExposure = path.includes('config') && secretPatterns && !isHtml;

                        if (isGitExposure) {
                            return {
                                isSensitive: true,
                                severity: 'high',
                                evidence: `Git repository exposed:\n${contentSnippet}`,
                                reason: 'Git configuration/history exposed - may leak source code and credentials'
                            };
                        }

                        if (isEnvExposure) {
                            // Check if it contains actual secrets
                            const hasCriticalSecrets = secretPatterns;
                            return {
                                isSensitive: true,
                                severity: hasCriticalSecrets ? 'critical' : 'high',
                                evidence: `Environment file with variables:\n${contentSnippet}`,
                                reason: hasCriticalSecrets
                                    ? 'Environment file contains credentials/secrets'
                                    : 'Environment file exposed - may contain sensitive configuration'
                            };
                        }

                        if (isSqlExposure) {
                            return {
                                isSensitive: true,
                                severity: 'high',
                                evidence: `SQL content found:\n${contentSnippet}`,
                                reason: 'Database dump/backup exposed - may contain sensitive data'
                            };
                        }

                        if (isConfigExposure) {
                            return {
                                isSensitive: true,
                                severity: 'high',
                                evidence: `Config with sensitive data:\n${contentSnippet}`,
                                reason: 'Configuration file with potential credentials exposed'
                            };
                        }

                        // Soft 404 - server returns 200 but page shows "Not Found"
                        // Skip these entirely - they're false positives
                        if (isSoft404) {
                            return {
                                isSensitive: false,
                                severity: 'info',
                                evidence: `Soft 404 - Page displays "Not Found" despite HTTP 200`,
                                reason: 'SKIP' // Special marker to skip this finding entirely
                            };
                        }

                        // If it's just HTML, it's likely SPA routing - not a real exposure
                        if (isHtml) {
                            return {
                                isSensitive: false,
                                severity: 'info',
                                evidence: `Path returns HTML (likely SPA routing)`,
                                reason: 'HTTP 200 but returns HTML - probably not actual file exposure'
                            };
                        }

                        // Non-HTML response but no obvious sensitive content
                        return {
                            isSensitive: false,
                            severity: 'low',
                            evidence: `Path accessible:\n${contentSnippet.slice(0, 200)}`,
                            reason: 'Path exists but content does not appear sensitive'
                        };
                    };

                    // Process directories in parallel batches for speed
                    const BATCH_SIZE = 15; // Check 15 directories concurrently
                    const REQUEST_TIMEOUT = 2500; // 2.5 second timeout per request

                    // Wrapper to ensure requests never hang
                    const withTimeout = <T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> => {
                        return Promise.race([
                            promise,
                            new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms))
                        ]);
                    };


                    // Helper to check if response is a soft 404 (HTTP 200 but shows "Not Found")
                    const isSoft404Response = (body: string): boolean => {
                        if (!body) return false;
                        const lower = body.toLowerCase();

                        // Check if it's HTML
                        const isHtml = lower.includes('<!doctype html') ||
                            lower.includes('<html') ||
                            (lower.includes('<head') && lower.includes('<body'));

                        if (!isHtml) return false;

                        // Check for 404 indicators in the page
                        return (
                            lower.includes('404') ||
                            lower.includes('not found') ||
                            lower.includes('page not found') ||
                            lower.includes('does not exist') ||
                            lower.includes('doesn\'t exist') ||
                            lower.includes('cannot be found') ||
                            lower.includes('no longer exists') ||
                            lower.includes('nothing here') ||
                            lower.includes('page doesn\'t exist') ||
                            /error[:\s]*404/i.test(body) ||
                            /<title>.*404.*<\/title>/i.test(body) ||
                            /<title>.*not found.*<\/title>/i.test(body)
                        );
                    };

                    // Helper to check if response is just SPA routing (returns index.html for everything)
                    const isSpaRouting = (body: string, originalUrl: string, path: string): boolean => {
                        if (!body) return false;
                        const lower = body.toLowerCase();

                        // Check if it's HTML with typical SPA indicators
                        const isHtml = lower.includes('<!doctype html') || lower.includes('<html');
                        if (!isHtml) return false;

                        // If we asked for a non-HTML file (like .env, .git, .zip) and got HTML back, 
                        // it's definitely a catch-all redirect (Soft 404 for our purposes)
                        const requestedExtension = path.split('/').pop()?.split('.').pop();
                        if (requestedExtension && ['env', 'git', 'zip', 'bak', 'sql', 'config', 'xml', 'json'].includes(requestedExtension)) {
                            return true;
                        }

                        // SPA indicators: React, Vue, Angular root divs, or bundle scripts
                        return (
                            lower.includes('id="root"') ||
                            lower.includes('id="app"') ||
                            lower.includes('id="__next"') ||
                            lower.includes('ng-app') ||
                            lower.includes('data-reactroot') ||
                            /bundle\.(js|min\.js)/i.test(body) ||
                            /main\.[a-f0-9]+\.js/i.test(body) ||
                            /chunk\.[a-f0-9]+\.js/i.test(body)
                        );
                    };

                    const checkDirectory = async (dir: string): Promise<void> => {
                        try {
                            const testUrl = `${baseUrl}/${dir}`;
                            const isSensitivePath = /\.env|\.git|backup|config|\.sql|\.bak|private|secret|\.key|\.pem|\.conf/i.test(dir);

                            // Always use GET so we can check body for soft 404s
                            const dirResponse = await withTimeout(
                                fetchForScan(testUrl, {
                                    method: 'GET',
                                    timeout: REQUEST_TIMEOUT
                                }),
                                REQUEST_TIMEOUT + 500,
                                { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                            );

                            if (dirResponse.ok && dirResponse.status !== 404) {
                                const body = dirResponse.body || '';

                                // SKIP: Soft 404s (page shows "Not Found" but HTTP 200)
                                if (isSoft404Response(body)) {
                                    return; // Skip this finding entirely
                                }

                                // SKIP: SPA routing (returns same index.html for all paths)
                                if (isSpaRouting(body, testUrl, dir)) {
                                    return; // Skip SPA routes
                                }

                                let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'medium';
                                let title = 'Hidden Path Discovered';
                                let description = `The path /${dir} exists and is accessible (HTTP ${dirResponse.status}).`;
                                let evidence = `GET ${testUrl} returned HTTP ${dirResponse.status}`;
                                let recommendation = 'Review if this path should be publicly accessible.';

                                // For sensitive paths, validate the actual content
                                let skipFinding = false;
                                if (isSensitivePath && body) {
                                    const validation = validateSensitiveContent(body, dir);
                                    severity = validation.severity;

                                    if (validation.reason === 'SKIP') {
                                        skipFinding = true;
                                    } else if (validation.isSensitive) {
                                        title = 'Confirmed Sensitive File Exposed';
                                        description = validation.reason;
                                        evidence = validation.evidence;
                                        recommendation = 'Remove this file immediately and rotate any exposed credentials.';
                                    } else if (validation.severity === 'info') {
                                        skipFinding = true;
                                    } else {
                                        title = 'Path Accessible';
                                        description = `/${dir} exists but content does not appear sensitive.`;
                                        evidence = validation.evidence;
                                    }
                                } else if (!isSensitivePath) {
                                    // Non-sensitive path - check content type
                                    const contentType = dirResponse.headers['content-type'] || '';

                                    // If it's HTML, likely just the app - downgrade to low/info
                                    if (contentType.includes('text/html')) {
                                        severity = 'low';
                                        title = 'Path Accessible';
                                        description = `The path /${dir} returns HTML content.`;
                                    } else if (contentType.includes('application/json')) {
                                        // JSON response - could be an API endpoint
                                        severity = 'medium';
                                        title = 'API Endpoint Discovered';
                                        description = `The path /${dir} returns JSON - possible API endpoint.`;
                                        evidence = `Response: ${body.slice(0, 200)}`;
                                    }
                                }

                                // Only add real findings
                                if (!skipFinding && severity !== 'info') {
                                    vulns.push({
                                        id: generateId(),
                                        category: 'disclosure',
                                        severity,
                                        title,
                                        description,
                                        recommendation,
                                        url: testUrl,
                                        location: testUrl,
                                        evidence,
                                        reproCommand: `curl -i "${testUrl}"`,
                                        reproSteps: [
                                            `Open a terminal or command prompt`,
                                            `Execute the following command: curl -i "${testUrl}"`,
                                            `Observe that the server returns a ${dirResponse.status} status code and reveals content that should be protected`
                                        ]
                                    });
                                }
                            }
                        } catch (e) {
                            // Skip errors
                        }
                    };

                    // Process in batches
                    for (let i = 0; i < dirList.length; i += BATCH_SIZE) {
                        const batch = dirList.slice(i, i + BATCH_SIZE);
                        checkedDirs = i + batch.length;

                        // Update progress every batch
                        this.updateProgress('DirEnum', 6, 10, `Checking directories ${checkedDirs}/${dirList.length}`, vulns.length, vulns);

                        // Run batch in parallel
                        await Promise.all(batch.map(dir => checkDirectory(dir)));

                        // Small delay between batches to avoid rate limiting
                        if (delay > 0) await new Promise(r => setTimeout(r, delay));
                    }
                }

                // Phase 5c: Test parameters on all discovered pages
                this.updateProgress('Injection', 7, 10, 'Testing parameters for injection...', vulns.length, vulns);

                let totalParamsTested = 0;
                for (const page of pagesToTest) {
                    // Extract parameters from URL
                    const urlObj = new URL(page.url);
                    const params = Array.from(urlObj.searchParams.keys());

                    // Add form inputs
                    for (const form of page.forms) {
                        for (const input of form.inputs) {
                            if (!params.includes(input.name)) {
                                params.push(input.name);
                            }
                        }
                    }

                    // In deep scans, always add a small set of critical injectable params
                    // These are the most commonly vulnerable parameters
                    const criticalParams = ['id', 'cat', 'page', 'q', 'search', 'query', 'item', 'product', 'user', 'name'];
                    if (isDeep && params.length === 0) {
                        // No params found - add critical ones to test
                        for (const criticalParam of criticalParams) {
                            if (!params.includes(criticalParam)) {
                                params.push(criticalParam);
                            }
                        }
                    }

                    // Also add common parameter names if testing all params
                    if (options.testAllParams && isDeep) {
                        for (const commonParam of COMMON_PARAMS.slice(0, 20)) {
                            if (!params.includes(commonParam)) {
                                params.push(commonParam);
                            }
                        }
                    }

                    // Test each parameter
                    for (const param of params.slice(0, maxParams)) {
                        totalParamsTested++;
                        this.updateProgress('Injection', 7, 10,
                            `Testing ${param} on ${new URL(page.url).pathname} (${totalParamsTested} params)`,
                            vulns.length,
                            vulns
                        );

                        // XSS testing with extended payloads
                        if (options.testXss !== false) {
                            const xssVulns = await testXssExtended(page.url, param, payloadsPerParam, options);
                            vulns.push(...xssVulns);
                        }

                        // SQLi testing with extended payloads
                        if (options.testSqli !== false) {
                            const sqliVulns = await testSqliExtended(page.url, param, payloadsPerParam, options);
                            vulns.push(...sqliVulns);
                        }

                        // Time-based blind tests if enabled
                        if (options.timeBasedTests && isComprehensive) {
                            const blindVulns = await testTimeBasedBlind(page.url, param, options);
                            vulns.push(...blindVulns);
                        }

                        // Delay between parameters
                        if (delay > 0) await new Promise(r => setTimeout(r, delay));
                    }
                }

                this.updateProgress('Testing', 8, 10, `Tested ${totalParamsTested} parameters across ${pagesToTest.length} pages`, vulns.length, vulns);

                // Phase 5d: Advanced vulnerability tests (SSRF, Command Injection, LFI, XXE, SSTI, Open Redirect, CORS)
                // Only run for deep/comprehensive scans
                if (isDeep || isComprehensive) {
                    this.updateProgress('Advanced', 8, 10, 'Running advanced vulnerability tests...', vulns.length, vulns);

                    const baseUrl = new URL(target.url).origin;
                    const advancedPayloadsPerTest = isComprehensive ? 15 : 8;

                    // Wrapper for timeout
                    const withAdvancedTimeout = <T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> => {
                        return Promise.race([
                            promise,
                            new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms))
                        ]);
                    };

                    // Test CORS misconfiguration
                    this.updateProgress('Advanced', 8, 10, 'Testing CORS configuration...', vulns.length, vulns);
                    try {
                        for (const corsTest of CORS_ORIGINS_TO_TEST.slice(0, 5)) {
                            const corsResponse = await withAdvancedTimeout(
                                fetchForScan(target.url, {
                                    headers: { 'Origin': corsTest.origin },
                                    timeout: 3000
                                }),
                                4000,
                                { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                            );

                            if (corsResponse.ok) {
                                const corsResult = detectCORSMisconfig(corsResponse.headers, corsTest.origin);
                                if (corsResult.vulnerable) {
                                    const corsVuln = createVulnerabilityFromTest('cors', corsResult, target.url);
                                    if (corsVuln) vulns.push(corsVuln);
                                }
                            }
                        }
                    } catch (e) { /* Skip CORS errors */ }

                    // Get parameters to test from discovered pages
                    const paramsToTest: { url: string; param: string }[] = [];
                    for (const page of pagesToTest.slice(0, 10)) {
                        const urlObj = new URL(page.url);
                        for (const [key] of urlObj.searchParams) {
                            paramsToTest.push({ url: page.url, param: key });
                        }
                        // Add common redirect params
                        for (const param of REDIRECT_PARAMS.slice(0, 10)) {
                            paramsToTest.push({ url: page.url, param });
                        }
                    }

                    // Test Open Redirect
                    this.updateProgress('Advanced', 8, 10, 'Testing for Open Redirect...', vulns.length, vulns);
                    for (const { url, param } of paramsToTest.slice(0, 20)) {
                        for (const redirectPayload of OPEN_REDIRECT_PAYLOADS.slice(0, advancedPayloadsPerTest)) {
                            try {
                                const testUrl = new URL(url);
                                testUrl.searchParams.set(param, redirectPayload.payload);

                                const response = await withAdvancedTimeout(
                                    fetchForScan(testUrl.toString(), { timeout: 3000 }),
                                    4000,
                                    { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                );

                                const result = detectOpenRedirect(response.status, response.headers, redirectPayload.payload);
                                if (result.vulnerable) {
                                    const vuln = createVulnerabilityFromTest('open_redirect', result, testUrl.toString(), param);
                                    if (vuln) vulns.push(vuln);
                                    break; // One redirect vuln per param is enough
                                }
                            } catch (e) { /* Skip */ }
                        }
                        if (delay > 0) await new Promise(r => setTimeout(r, delay / 2));
                    }

                    // Test Path Traversal / LFI
                    this.updateProgress('Advanced', 8, 10, 'Testing for Path Traversal/LFI...', vulns.length, vulns);
                    const fileParams = ['file', 'path', 'page', 'document', 'folder', 'doc', 'template', 'include', 'inc', 'dir'];
                    for (const param of fileParams) {
                        for (const lfiPayload of PATH_TRAVERSAL_PAYLOADS.slice(0, advancedPayloadsPerTest)) {
                            try {
                                const testUrl = new URL(target.url);
                                testUrl.searchParams.set(param, lfiPayload.payload);

                                const response = await withAdvancedTimeout(
                                    fetchForScan(testUrl.toString(), { timeout: 3000 }),
                                    4000,
                                    { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                );

                                if (response.ok && response.body) {
                                    const result = detectPathTraversal(response.body);
                                    if (result.vulnerable) {
                                        const vuln = createVulnerabilityFromTest('lfi', { ...result, payload: lfiPayload.payload }, testUrl.toString(), param);
                                        if (vuln) vulns.push(vuln);
                                        break;
                                    }
                                }
                            } catch (e) { /* Skip */ }
                        }
                    }

                    // Test SSRF
                    this.updateProgress('Advanced', 8, 10, 'Testing for SSRF...', vulns.length, vulns);
                    const urlParams = ['url', 'uri', 'link', 'src', 'source', 'redirect', 'dest', 'destination', 'next', 'callback', 'image', 'img'];
                    for (const param of urlParams) {
                        for (const ssrfPayload of SSRF_PAYLOADS.slice(0, advancedPayloadsPerTest)) {
                            try {
                                const testUrl = new URL(target.url);
                                testUrl.searchParams.set(param, ssrfPayload.payload);

                                const startTime = Date.now();
                                const response = await withAdvancedTimeout(
                                    fetchForScan(testUrl.toString(), { timeout: 5000 }),
                                    6000,
                                    { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                );
                                const responseTime = Date.now() - startTime;

                                if (response.ok && response.body) {
                                    const result = detectSSRF(response.body, ssrfPayload.payload);
                                    if (result.vulnerable) {
                                        const vuln = createVulnerabilityFromTest('ssrf', { ...result, payload: ssrfPayload.payload }, testUrl.toString(), param);
                                        if (vuln) vulns.push(vuln);
                                        break;
                                    }
                                }
                            } catch (e) { /* Skip */ }
                        }
                    }

                    // Test Command Injection (time-based for comprehensive)
                    if (isComprehensive) {
                        this.updateProgress('Advanced', 9, 10, 'Testing for Command Injection...', vulns.length, vulns);
                        const cmdParams = ['cmd', 'exec', 'command', 'run', 'ping', 'query', 'jump', 'code', 'process', 'daemon'];
                        for (const param of cmdParams) {
                            for (const cmdPayload of COMMAND_INJECTION_PAYLOADS.slice(0, 10)) {
                                try {
                                    const testUrl = new URL(target.url);
                                    testUrl.searchParams.set(param, cmdPayload.payload);

                                    const startTime = Date.now();
                                    const response = await withAdvancedTimeout(
                                        fetchForScan(testUrl.toString(), { timeout: 8000 }),
                                        9000,
                                        { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                    );
                                    const responseTime = Date.now() - startTime;

                                    if (response.body) {
                                        const result = detectCommandInjection(response.body, 0, responseTime);
                                        if (result.vulnerable) {
                                            const vuln = createVulnerabilityFromTest('command_injection', { ...result, payload: cmdPayload.payload }, testUrl.toString(), param);
                                            if (vuln) vulns.push(vuln);
                                            break;
                                        }
                                    }
                                } catch (e) { /* Skip */ }
                            }
                        }

                        // Test SSTI
                        this.updateProgress('Advanced', 9, 10, 'Testing for SSTI...', vulns.length, vulns);
                        const templateParams = ['template', 'name', 'message', 'email', 'username', 'search', 'q', 'query', 'content', 'text'];
                        for (const param of templateParams) {
                            for (const sstiPayload of SSTI_PAYLOADS.slice(0, 10)) {
                                try {
                                    const testUrl = new URL(target.url);
                                    testUrl.searchParams.set(param, sstiPayload.payload);

                                    const response = await withAdvancedTimeout(
                                        fetchForScan(testUrl.toString(), { timeout: 3000 }),
                                        4000,
                                        { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                    );

                                    if (response.ok && response.body) {
                                        const result = detectSSTI(response.body, sstiPayload);
                                        if (result.vulnerable) {
                                            const vuln = createVulnerabilityFromTest('ssti', { ...result, payload: sstiPayload.payload }, testUrl.toString(), param);
                                            if (vuln) vulns.push(vuln);
                                            break;
                                        }
                                    }
                                } catch (e) { /* Skip */ }
                            }
                        }

                        // Test XXE on endpoints that might accept XML
                        this.updateProgress('Advanced', 9, 10, 'Testing for XXE...', vulns.length, vulns);
                        const xmlEndpoints = ['/api', '/soap', '/xml', '/service', '/ws', '/rpc'];
                        for (const endpoint of xmlEndpoints) {
                            try {
                                const testUrl = `${baseUrl}${endpoint}`;

                                for (const xxePayload of XXE_PAYLOADS.slice(0, 5)) {
                                    const response = await withAdvancedTimeout(
                                        fetchForScan(testUrl, {
                                            headers: { 'Content-Type': xxePayload.contentType },
                                            timeout: 3000
                                        }),
                                        4000,
                                        { ok: false, status: 0, body: '', headers: {}, error: 'Timeout' }
                                    );

                                    if (response.body) {
                                        const result = detectXXE(response.body);
                                        if (result.vulnerable) {
                                            const vuln = createVulnerabilityFromTest('xxe', { ...result, payload: xxePayload.name }, testUrl);
                                            if (vuln) vulns.push(vuln);
                                            break;
                                        }
                                    }
                                }
                            } catch (e) { /* Skip */ }
                        }
                    }

                    this.updateProgress('Advanced', 9, 10, 'Advanced testing complete', vulns.length, vulns);
                }
            }

            // Phase 6: Finalize
            this.updateProgress('Finalizing', 10, 10, 'Generating report', vulns.length, vulns);

            // Deduplicate vulnerabilities
            const seen = new Set<string>();
            const uniqueVulns = vulns.filter(v => {
                const key = `${v.title}:${v.url}:${v.parameter || ''}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });

            result.vulnerabilities = uniqueVulns;

            // Calculate summary
            result.summary.critical = uniqueVulns.filter(v => v.severity === 'critical').length;
            result.summary.high = uniqueVulns.filter(v => v.severity === 'high').length;
            result.summary.medium = uniqueVulns.filter(v => v.severity === 'medium').length;
            result.summary.low = uniqueVulns.filter(v => v.severity === 'low').length;
            result.summary.info = uniqueVulns.filter(v => v.severity === 'info').length;
            result.summary.total = uniqueVulns.length;
            result.summary.webVulns = uniqueVulns.filter(v =>
                ['web', 'injection', 'xss', 'authentication', 'configuration', 'disclosure'].includes(v.category)
            ).length;
            result.summary.blockchainVulns = uniqueVulns.filter(v =>
                ['blockchain', 'smart-contract', 'crypto'].includes(v.category)
            ).length;

            // Calculate risk score
            result.summary.riskScore =
                result.summary.critical * 40 +
                result.summary.high * 20 +
                result.summary.medium * 10 +
                result.summary.low * 5 +
                result.summary.info * 1;
            result.summary.riskScore = Math.min(100, result.summary.riskScore);

            // Determine risk level
            if (result.summary.critical > 0) result.summary.riskLevel = 'critical';
            else if (result.summary.high > 0) result.summary.riskLevel = 'high';
            else if (result.summary.medium > 0) result.summary.riskLevel = 'medium';
            else if (result.summary.low > 0) result.summary.riskLevel = 'low';
            else result.summary.riskLevel = 'safe';

            // Generate recommendations
            if (result.summary.critical > 0) {
                result.recommendations.push('🚨 CRITICAL: Immediately address critical vulnerabilities before production use.');
            }
            if (result.web3Detection?.hasWeb3) {
                result.recommendations.push('🔗 Web3 integration detected. Ensure all smart contracts are audited.');
            }
            if (result.headerAnalysis && result.headerAnalysis.score < 50) {
                result.recommendations.push('🛡️ Security headers are poorly configured. Implement CSP, HSTS, and X-Frame-Options.');
            }
            if (uniqueVulns.some(v => v.category === 'injection')) {
                result.recommendations.push('💉 Injection vulnerabilities detected. Use parameterized queries and input validation.');
            }
            if (uniqueVulns.some(v => v.category === 'xss')) {
                result.recommendations.push('⚡ XSS vulnerabilities found. Implement output encoding and CSP.');
            }

            result.status = 'completed';
            result.endTime = new Date();
            result.duration = result.endTime.getTime() - startTime.getTime();

        } catch (error) {
            result.status = 'failed';
            result.endTime = new Date();
            result.recommendations.push(`❌ Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }

        this.results.set(scanId, result);
        return result;
    }

    /**
     * Get scan result by ID
     */
    getResult(scanId: string): ScanResult | undefined {
        return this.results.get(scanId);
    }

    /**
     * Get all scan results
     */
    getAllResults(): ScanResult[] {
        return Array.from(this.results.values());
    }

    /**
     * Clear results
     */
    clearResults(): void {
        this.results.clear();
    }
}

// Export convenience functions
export async function quickScan(url: string): Promise<ScanResult> {
    const scanner = new UnifiedScanner();
    return scanner.scan({
        url,
        type: 'website',
        options: { depth: 'quick' }
    });
}

export async function fullScan(url: string, options?: ScanOptions): Promise<ScanResult> {
    const scanner = new UnifiedScanner();
    return scanner.scan({
        url,
        type: 'website',
        options: { depth: 'deep', ...options }
    });
}

export default UnifiedScanner;

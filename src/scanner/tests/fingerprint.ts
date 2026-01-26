// STRIX Technology Fingerprinting Module
// Comprehensive detection of servers, frameworks, CMS, WAF, and vulnerable components

import type { UnifiedVulnerability } from '../types';

// ============================================================================
// FINGERPRINT DATABASES
// ============================================================================

// Server signatures
export const SERVER_SIGNATURES: Record<string, { pattern: RegExp; name: string; type: string }[]> = {
    headers: [
        // Web servers
        { pattern: /Apache\/?([\d.]+)?/i, name: 'Apache', type: 'webserver' },
        { pattern: /nginx\/?([\d.]+)?/i, name: 'nginx', type: 'webserver' },
        { pattern: /Microsoft-IIS\/?([\d.]+)?/i, name: 'IIS', type: 'webserver' },
        { pattern: /LiteSpeed/i, name: 'LiteSpeed', type: 'webserver' },
        { pattern: /Caddy/i, name: 'Caddy', type: 'webserver' },
        { pattern: /Tomcat\/?([\d.]+)?/i, name: 'Apache Tomcat', type: 'webserver' },
        { pattern: /Jetty/i, name: 'Jetty', type: 'webserver' },
        { pattern: /openresty\/?([\d.]+)?/i, name: 'OpenResty', type: 'webserver' },
        { pattern: /gunicorn\/?([\d.]+)?/i, name: 'Gunicorn', type: 'webserver' },
        { pattern: /Werkzeug\/?([\d.]+)?/i, name: 'Werkzeug', type: 'webserver' },
        { pattern: /uvicorn/i, name: 'Uvicorn', type: 'webserver' },
        
        // Frameworks from X-Powered-By
        { pattern: /PHP\/?([\d.]+)?/i, name: 'PHP', type: 'language' },
        { pattern: /ASP\.NET/i, name: 'ASP.NET', type: 'framework' },
        { pattern: /Express/i, name: 'Express.js', type: 'framework' },
        { pattern: /Next\.js/i, name: 'Next.js', type: 'framework' },
        { pattern: /Nuxt/i, name: 'Nuxt.js', type: 'framework' },
        { pattern: /Django/i, name: 'Django', type: 'framework' },
        { pattern: /Flask/i, name: 'Flask', type: 'framework' },
        { pattern: /Rails/i, name: 'Ruby on Rails', type: 'framework' },
        { pattern: /Laravel/i, name: 'Laravel', type: 'framework' },
        { pattern: /Symfony/i, name: 'Symfony', type: 'framework' },
        { pattern: /Spring/i, name: 'Spring', type: 'framework' },
        { pattern: /Kestrel/i, name: 'Kestrel', type: 'webserver' },
        
        // Cloud/CDN
        { pattern: /cloudflare/i, name: 'Cloudflare', type: 'cdn' },
        { pattern: /AmazonS3/i, name: 'Amazon S3', type: 'cdn' },
        { pattern: /Akamai/i, name: 'Akamai', type: 'cdn' },
        { pattern: /Fastly/i, name: 'Fastly', type: 'cdn' },
        { pattern: /Vercel/i, name: 'Vercel', type: 'platform' },
        { pattern: /Netlify/i, name: 'Netlify', type: 'platform' },
    ]
};

// CMS signatures
export const CMS_SIGNATURES: Array<{
    name: string;
    patterns: Array<{ type: 'html' | 'header' | 'path'; pattern: RegExp | string }>;
    version?: RegExp;
}> = [
    {
        name: 'WordPress',
        patterns: [
            { type: 'html', pattern: /wp-content|wp-includes/i },
            { type: 'html', pattern: /\/wp-json\//i },
            { type: 'html', pattern: /<meta name="generator" content="WordPress/i },
            { type: 'path', pattern: '/wp-login.php' },
            { type: 'path', pattern: '/wp-admin/' },
            { type: 'path', pattern: '/xmlrpc.php' },
        ],
        version: /WordPress\s+([\d.]+)/i
    },
    {
        name: 'Drupal',
        patterns: [
            { type: 'html', pattern: /Drupal/i },
            { type: 'html', pattern: /\/sites\/default\/files/i },
            { type: 'header', pattern: /X-Drupal-Cache/i },
            { type: 'header', pattern: /X-Generator.*Drupal/i },
            { type: 'path', pattern: '/misc/drupal.js' },
        ],
        version: /Drupal\s+([\d.]+)/i
    },
    {
        name: 'Joomla',
        patterns: [
            { type: 'html', pattern: /\/media\/jui\//i },
            { type: 'html', pattern: /\/components\/com_/i },
            { type: 'html', pattern: /<meta name="generator" content="Joomla/i },
            { type: 'path', pattern: '/administrator/' },
        ],
        version: /Joomla!\s+([\d.]+)/i
    },
    {
        name: 'Magento',
        patterns: [
            { type: 'html', pattern: /Mage\.Cookies|\/skin\/frontend/i },
            { type: 'html', pattern: /\/static\/version/i },
            { type: 'path', pattern: '/downloader/' },
        ]
    },
    {
        name: 'Shopify',
        patterns: [
            { type: 'html', pattern: /cdn\.shopify\.com/i },
            { type: 'html', pattern: /Shopify\.theme/i },
        ]
    },
    {
        name: 'Wix',
        patterns: [
            { type: 'html', pattern: /static\.wixstatic\.com/i },
            { type: 'html', pattern: /wix-code-sdk/i },
        ]
    },
    {
        name: 'Squarespace',
        patterns: [
            { type: 'html', pattern: /static\.squarespace\.com/i },
            { type: 'html', pattern: /squarespace-cdn\.com/i },
        ]
    },
    {
        name: 'Ghost',
        patterns: [
            { type: 'html', pattern: /<meta name="generator" content="Ghost/i },
            { type: 'html', pattern: /ghost\.org/i },
        ],
        version: /Ghost\s+([\d.]+)/i
    },
    {
        name: 'SharePoint',
        patterns: [
            { type: 'header', pattern: /MicrosoftSharePointTeamServices/i },
            { type: 'html', pattern: /_layouts\/|SPWebPartManager/i },
        ]
    },
];

// JavaScript libraries with known vulnerabilities
export const JS_LIBRARIES: Array<{
    name: string;
    patterns: RegExp[];
    versionPattern?: RegExp;
    vulnerableVersions?: Array<{ version: string; cve?: string; severity: string; description: string }>;
}> = [
    {
        name: 'jQuery',
        patterns: [/jquery[.-]?([\d.]+)?(?:\.min)?\.js/i, /jquery.*version.*["']([\d.]+)/i],
        versionPattern: /jquery[.-]?([\d.]+)/i,
        vulnerableVersions: [
            { version: '<1.9.0', cve: 'CVE-2012-6708', severity: 'medium', description: 'XSS via location.hash' },
            { version: '<1.12.0', cve: 'CVE-2015-9251', severity: 'medium', description: 'XSS via cross-domain ajax' },
            { version: '<3.4.0', cve: 'CVE-2019-11358', severity: 'medium', description: 'Prototype pollution' },
            { version: '<3.5.0', cve: 'CVE-2020-11022', severity: 'medium', description: 'XSS in jQuery.htmlPrefilter' },
        ]
    },
    {
        name: 'Angular',
        patterns: [/angular[.-]?([\d.]+)?(?:\.min)?\.js/i, /ng-app|ng-controller/i],
        versionPattern: /angular[.-]?([\d.]+)/i,
        vulnerableVersions: [
            { version: '<1.6.0', severity: 'high', description: 'Sandbox escape XSS' },
        ]
    },
    {
        name: 'AngularJS',
        patterns: [/angular(?:\.min)?\.js/i],
        vulnerableVersions: [
            { version: '<1.8.0', severity: 'medium', description: 'Template injection' },
        ]
    },
    {
        name: 'React',
        patterns: [/react[.-]?([\d.]+)?(?:\.min)?\.js/i, /react-dom/i, /__REACT_DEVTOOLS/],
        versionPattern: /react.*version.*["']([\d.]+)/i,
    },
    {
        name: 'Vue.js',
        patterns: [/vue[.-]?([\d.]+)?(?:\.min)?\.js/i, /__VUE__/],
        versionPattern: /vue[.-]?([\d.]+)/i,
    },
    {
        name: 'Lodash',
        patterns: [/lodash[.-]?([\d.]+)?(?:\.min)?\.js/i],
        versionPattern: /lodash[.-]?([\d.]+)/i,
        vulnerableVersions: [
            { version: '<4.17.12', cve: 'CVE-2019-10744', severity: 'critical', description: 'Prototype pollution' },
            { version: '<4.17.21', cve: 'CVE-2021-23337', severity: 'high', description: 'Command injection' },
        ]
    },
    {
        name: 'Moment.js',
        patterns: [/moment[.-]?([\d.]+)?(?:\.min)?\.js/i],
        versionPattern: /moment[.-]?([\d.]+)/i,
        vulnerableVersions: [
            { version: '<2.29.4', cve: 'CVE-2022-31129', severity: 'high', description: 'Path traversal' },
        ]
    },
    {
        name: 'Bootstrap',
        patterns: [/bootstrap[.-]?([\d.]+)?(?:\.min)?\.js/i],
        versionPattern: /bootstrap[.-]?([\d.]+)/i,
        vulnerableVersions: [
            { version: '<3.4.0', cve: 'CVE-2018-14040', severity: 'medium', description: 'XSS in data-target' },
            { version: '<4.3.1', cve: 'CVE-2019-8331', severity: 'medium', description: 'XSS in tooltip/popover' },
        ]
    },
    {
        name: 'Handlebars',
        patterns: [/handlebars[.-]?([\d.]+)?(?:\.min)?\.js/i],
        vulnerableVersions: [
            { version: '<4.7.7', cve: 'CVE-2021-23369', severity: 'critical', description: 'Prototype pollution RCE' },
        ]
    },
    {
        name: 'DOMPurify',
        patterns: [/purify[.-]?([\d.]+)?(?:\.min)?\.js/i, /DOMPurify/],
        vulnerableVersions: [
            { version: '<2.2.2', severity: 'medium', description: 'XSS bypass' },
        ]
    },
];

// WAF signatures
export const WAF_SIGNATURES: Array<{
    name: string;
    patterns: Array<{ type: 'header' | 'cookie' | 'body'; pattern: RegExp }>;
}> = [
    {
        name: 'Cloudflare',
        patterns: [
            { type: 'header', pattern: /cf-ray/i },
            { type: 'header', pattern: /cloudflare/i },
            { type: 'cookie', pattern: /__cfduid|cf_clearance/i },
        ]
    },
    {
        name: 'AWS WAF',
        patterns: [
            { type: 'header', pattern: /x-amzn-requestid/i },
            { type: 'header', pattern: /awselb|awsalb/i },
        ]
    },
    {
        name: 'Akamai',
        patterns: [
            { type: 'header', pattern: /akamai/i },
            { type: 'cookie', pattern: /akamai|ak_bmsc/i },
        ]
    },
    {
        name: 'Imperva/Incapsula',
        patterns: [
            { type: 'header', pattern: /x-cdn.*incapsula/i },
            { type: 'cookie', pattern: /incap_ses|visid_incap/i },
        ]
    },
    {
        name: 'Sucuri',
        patterns: [
            { type: 'header', pattern: /x-sucuri/i },
            { type: 'body', pattern: /sucuri\.net/i },
        ]
    },
    {
        name: 'ModSecurity',
        patterns: [
            { type: 'header', pattern: /mod_security|modsecurity/i },
            { type: 'body', pattern: /mod_security|modsecurity/i },
        ]
    },
    {
        name: 'F5 BIG-IP',
        patterns: [
            { type: 'cookie', pattern: /BIGip/i },
            { type: 'header', pattern: /BigIP/i },
        ]
    },
    {
        name: 'Barracuda',
        patterns: [
            { type: 'cookie', pattern: /barra_counter_session/i },
        ]
    },
    {
        name: 'DenyAll',
        patterns: [
            { type: 'cookie', pattern: /sessioncookie/i },
            { type: 'body', pattern: /Condition Intercepted/i },
        ]
    },
];

// ============================================================================
// INTERFACES
// ============================================================================

export interface Technology {
    name: string;
    type: 'webserver' | 'framework' | 'cms' | 'library' | 'cdn' | 'waf' | 'language' | 'platform' | 'database' | 'other';
    version?: string;
    confidence: 'high' | 'medium' | 'low';
    source: string;
}

export interface FingerprintResult {
    url: string;
    technologies: Technology[];
    server?: string;
    framework?: string;
    cms?: string;
    waf?: string;
    jsLibraries: Array<{ name: string; version?: string }>;
    vulnerableComponents: UnifiedVulnerability[];
    headers: Record<string, string>;
}

// ============================================================================
// FINGERPRINTING FUNCTIONS
// ============================================================================

/**
 * Fingerprint a target URL
 */
export async function fingerprint(
    url: string,
    html: string,
    headers: Record<string, string>
): Promise<FingerprintResult> {
    const result: FingerprintResult = {
        url,
        technologies: [],
        jsLibraries: [],
        vulnerableComponents: [],
        headers
    };
    
    // Analyze headers
    analyzeHeaders(headers, result);
    
    // Analyze HTML
    analyzeHtml(html, result);
    
    // Check for vulnerable components
    checkVulnerableComponents(result);
    
    // Set summary fields
    result.server = result.technologies.find(t => t.type === 'webserver')?.name;
    result.framework = result.technologies.find(t => t.type === 'framework')?.name;
    result.cms = result.technologies.find(t => t.type === 'cms')?.name;
    result.waf = result.technologies.find(t => t.type === 'waf')?.name;
    
    return result;
}

/**
 * Analyze response headers for technology signatures
 */
function analyzeHeaders(headers: Record<string, string>, result: FingerprintResult): void {
    // Normalize header names to lowercase
    const normalizedHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
        normalizedHeaders[key.toLowerCase()] = value;
    }
    
    // Check Server header
    const server = normalizedHeaders['server'];
    if (server) {
        for (const sig of SERVER_SIGNATURES.headers) {
            const match = server.match(sig.pattern);
            if (match) {
                result.technologies.push({
                    name: sig.name,
                    type: sig.type as Technology['type'],
                    version: match[1],
                    confidence: 'high',
                    source: 'Server header'
                });
            }
        }
    }
    
    // Check X-Powered-By header
    const poweredBy = normalizedHeaders['x-powered-by'];
    if (poweredBy) {
        for (const sig of SERVER_SIGNATURES.headers) {
            const match = poweredBy.match(sig.pattern);
            if (match) {
                result.technologies.push({
                    name: sig.name,
                    type: sig.type as Technology['type'],
                    version: match[1],
                    confidence: 'high',
                    source: 'X-Powered-By header'
                });
            }
        }
    }
    
    // Check other headers
    const aspVersion = normalizedHeaders['x-aspnet-version'];
    if (aspVersion) {
        result.technologies.push({
            name: 'ASP.NET',
            type: 'framework',
            version: aspVersion,
            confidence: 'high',
            source: 'X-AspNet-Version header'
        });
    }
    
    const aspMvcVersion = normalizedHeaders['x-aspnetmvc-version'];
    if (aspMvcVersion) {
        result.technologies.push({
            name: 'ASP.NET MVC',
            type: 'framework',
            version: aspMvcVersion,
            confidence: 'high',
            source: 'X-AspNetMvc-Version header'
        });
    }
    
    // Check for WAF
    for (const waf of WAF_SIGNATURES) {
        for (const { type, pattern } of waf.patterns) {
            if (type === 'header') {
                for (const [, value] of Object.entries(normalizedHeaders)) {
                    if (pattern.test(value)) {
                        result.technologies.push({
                            name: waf.name,
                            type: 'waf',
                            confidence: 'high',
                            source: 'Headers'
                        });
                        break;
                    }
                }
            } else if (type === 'cookie') {
                const cookies = normalizedHeaders['set-cookie'] || '';
                if (pattern.test(cookies)) {
                    result.technologies.push({
                        name: waf.name,
                        type: 'waf',
                        confidence: 'high',
                        source: 'Cookies'
                    });
                }
            }
        }
    }
}

/**
 * Analyze HTML for technology signatures
 */
function analyzeHtml(html: string, result: FingerprintResult): void {
    // Check CMS signatures
    for (const cms of CMS_SIGNATURES) {
        let detected = false;
        let version: string | undefined;
        
        for (const { type, pattern } of cms.patterns) {
            if (type === 'html') {
                if ((pattern as RegExp).test(html)) {
                    detected = true;
                }
            }
        }
        
        if (detected) {
            // Try to extract version
            if (cms.version) {
                const versionMatch = html.match(cms.version);
                if (versionMatch) {
                    version = versionMatch[1];
                }
            }
            
            result.technologies.push({
                name: cms.name,
                type: 'cms',
                version,
                confidence: 'high',
                source: 'HTML content'
            });
        }
    }
    
    // Check JavaScript libraries
    for (const lib of JS_LIBRARIES) {
        for (const pattern of lib.patterns) {
            if (pattern.test(html)) {
                let version: string | undefined;
                
                // Try to extract version
                if (lib.versionPattern) {
                    const versionMatch = html.match(lib.versionPattern);
                    if (versionMatch) {
                        version = versionMatch[1];
                    }
                }
                
                result.technologies.push({
                    name: lib.name,
                    type: 'library',
                    version,
                    confidence: version ? 'high' : 'medium',
                    source: 'JavaScript'
                });
                
                result.jsLibraries.push({ name: lib.name, version });
                break;
            }
        }
    }
    
    // Additional HTML-based detection
    
    // React
    if (/__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot|data-reactid/.test(html)) {
        result.technologies.push({
            name: 'React',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Vue.js
    if (/v-bind:|v-model|v-if|v-for|__VUE__|data-v-[a-f0-9]/.test(html)) {
        result.technologies.push({
            name: 'Vue.js',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Angular
    if (/ng-app|ng-controller|\*ngIf|\*ngFor|_ngcontent/.test(html)) {
        result.technologies.push({
            name: 'Angular',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Next.js
    if (/__NEXT_DATA__|_next\/static/.test(html)) {
        result.technologies.push({
            name: 'Next.js',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Nuxt.js
    if (/__NUXT__|_nuxt\//.test(html)) {
        result.technologies.push({
            name: 'Nuxt.js',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Gatsby
    if (/gatsby/.test(html) && /___gatsby/.test(html)) {
        result.technologies.push({
            name: 'Gatsby',
            type: 'framework',
            confidence: 'high',
            source: 'HTML markers'
        });
    }
    
    // Tailwind CSS
    if (/tailwindcss|class="[^"]*(?:flex|grid|mt-|mb-|pt-|pb-|text-|bg-|hover:)[^"]*"/.test(html)) {
        result.technologies.push({
            name: 'Tailwind CSS',
            type: 'library',
            confidence: 'medium',
            source: 'CSS classes'
        });
    }
    
    // Google Analytics
    if (/google-analytics\.com|gtag|ga\(/.test(html)) {
        result.technologies.push({
            name: 'Google Analytics',
            type: 'other',
            confidence: 'high',
            source: 'Script'
        });
    }
}

/**
 * Check for vulnerable components
 */
function checkVulnerableComponents(result: FingerprintResult): void {
    for (const tech of result.technologies) {
        if (tech.type !== 'library' || !tech.version) continue;
        
        // Find the library in our database
        const libData = JS_LIBRARIES.find(l => l.name === tech.name);
        if (!libData?.vulnerableVersions) continue;
        
        // Check each vulnerable version
        for (const vuln of libData.vulnerableVersions) {
            if (isVersionVulnerable(tech.version, vuln.version)) {
                result.vulnerableComponents.push({
                    id: `vuln-${tech.name}-${Date.now()}`,
                    category: 'component',
                    severity: vuln.severity as UnifiedVulnerability['severity'],
                    title: `Vulnerable ${tech.name} Version`,
                    description: `${tech.name} ${tech.version} is vulnerable: ${vuln.description}`,
                    url: result.url,
                    location: 'JavaScript Library',
                    evidence: `Detected version: ${tech.version}`,
                    recommendation: `Update ${tech.name} to the latest secure version`,
                    cwe: 'CWE-1104',
                    owasp: 'A06:2021',
                    cve: vuln.cve
                });
            }
        }
    }
}

/**
 * Check if a version is vulnerable
 * Supports: <X.Y.Z, <=X.Y.Z, ranges
 */
function isVersionVulnerable(detected: string, vulnSpec: string): boolean {
    // Parse version spec
    const ltMatch = vulnSpec.match(/^<([\d.]+)$/);
    const leMatch = vulnSpec.match(/^<=([\d.]+)$/);
    
    if (ltMatch) {
        return compareVersions(detected, ltMatch[1]) < 0;
    }
    if (leMatch) {
        return compareVersions(detected, leMatch[1]) <= 0;
    }
    
    // Exact match
    return detected === vulnSpec;
}

/**
 * Compare semantic versions
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 */
function compareVersions(a: string, b: string): number {
    const partsA = a.split('.').map(p => parseInt(p) || 0);
    const partsB = b.split('.').map(p => parseInt(p) || 0);
    
    const maxLen = Math.max(partsA.length, partsB.length);
    
    for (let i = 0; i < maxLen; i++) {
        const partA = partsA[i] || 0;
        const partB = partsB[i] || 0;
        
        if (partA < partB) return -1;
        if (partA > partB) return 1;
    }
    
    return 0;
}

/**
 * Quick fingerprint from URL
 */
export async function quickFingerprint(url: string): Promise<FingerprintResult> {
    // @ts-ignore
    const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;
    
    let html = '';
    let headers: Record<string, string> = {};
    
    if (isElectron) {
        // @ts-ignore
        const response = await window.ipcRenderer.invoke('web-scan-fetch', {
            url,
            method: 'GET',
            timeout: 15000
        });
        html = response.body || '';
        headers = response.headers || {};
    } else {
        try {
            const response = await fetch(url);
            html = await response.text();
            response.headers.forEach((v, k) => headers[k] = v);
        } catch {
            // Ignore errors
        }
    }
    
    return fingerprint(url, html, headers);
}

export default {
    fingerprint,
    quickFingerprint,
    SERVER_SIGNATURES,
    CMS_SIGNATURES,
    JS_LIBRARIES,
    WAF_SIGNATURES
};

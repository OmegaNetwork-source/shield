// STRIX Site Crawler / Spider
// DoD-grade recursive web crawler for comprehensive attack surface discovery

import type { CrawlResult, FormInfo, ScriptInfo } from './types';

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

export interface CrawlerConfig {
    maxDepth: number;           // Maximum recursion depth
    maxPages: number;           // Maximum pages to crawl
    maxTime: number;            // Maximum crawl time in ms
    rateLimit: number;          // Requests per second
    timeout: number;            // Request timeout in ms
    followRedirects: boolean;   // Follow HTTP redirects
    respectRobotsTxt: boolean;  // Honor robots.txt
    includedPaths?: string[];   // Only crawl these path prefixes
    excludedPaths?: string[];   // Skip these path prefixes
    excludedExtensions?: string[]; // Skip these file extensions
    headers?: Record<string, string>; // Custom headers
    cookies?: string;           // Session cookies
    userAgent?: string;         // Custom user agent
    scope: 'strict' | 'subdomain' | 'loose'; // Crawl scope
}

export interface CrawledPage {
    url: string;
    depth: number;
    status: number;
    contentType: string;
    title: string;
    headers: Record<string, string>;
    links: string[];
    forms: FormInfo[];
    scripts: ScriptInfo[];
    parameters: ParameterInfo[];
    comments: string[];
    emails: string[];
    endpoints: EndpointInfo[];
    responseSize: number;
    responseTime: number;
    error?: string;
}

export interface ParameterInfo {
    name: string;
    type: 'query' | 'body' | 'path' | 'header' | 'cookie';
    value?: string;
    source: string; // URL where found
}

export interface EndpointInfo {
    url: string;
    method: string;
    parameters: ParameterInfo[];
    contentType?: string;
    source: string; // Where discovered (link, form, js, etc.)
}

export interface RobotsRule {
    userAgent: string;
    allowed: string[];
    disallowed: string[];
    sitemaps: string[];
    crawlDelay?: number;
}

export interface CrawlProgress {
    phase: string;
    pagesDiscovered: number;
    pagesCrawled: number;
    formsFound: number;
    parametersFound: number;
    currentUrl: string;
    elapsedTime: number;
}

export type CrawlProgressCallback = (progress: CrawlProgress) => void;

const DEFAULT_CONFIG: CrawlerConfig = {
    maxDepth: 5,
    maxPages: 500,
    maxTime: 300000, // 5 minutes
    rateLimit: 10,
    timeout: 15000,
    followRedirects: true,
    respectRobotsTxt: true,
    excludedExtensions: [
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.ico',
        '.css', '.woff', '.woff2', '.ttf', '.eot',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z'
    ],
    userAgent: 'STRIX-Scanner/1.0 (Security Audit)',
    scope: 'strict'
};

// Default excluded paths (usually not interesting for security testing)
const DEFAULT_EXCLUDED_PATHS = [
    '/cdn-cgi/',
    '/.well-known/',
    '/static/fonts/',
    '/assets/images/',
];

/**
 * Fetch URL using Electron IPC or browser fetch
 */
async function crawlFetch(url: string, config: CrawlerConfig): Promise<{
    ok: boolean;
    status: number;
    headers: Record<string, string>;
    body: string;
    responseTime: number;
    error?: string;
    finalUrl?: string;
}> {
    const startTime = Date.now();
    
    if (isElectron) {
        try {
            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url,
                method: 'GET',
                headers: {
                    'User-Agent': config.userAgent || DEFAULT_CONFIG.userAgent,
                    ...(config.cookies ? { 'Cookie': config.cookies } : {}),
                    ...config.headers
                },
                timeout: config.timeout,
                followRedirects: config.followRedirects
            });
            
            return {
                ok: response.success && response.status >= 200 && response.status < 400,
                status: response.status || 0,
                headers: response.headers || {},
                body: response.body || '',
                responseTime: Date.now() - startTime,
                finalUrl: response.url,
                error: response.error
            };
        } catch (error) {
            return {
                ok: false,
                status: 0,
                headers: {},
                body: '',
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Request failed'
            };
        }
    } else {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.timeout);
            
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'User-Agent': config.userAgent || DEFAULT_CONFIG.userAgent!,
                    ...(config.cookies ? { 'Cookie': config.cookies } : {}),
                    ...config.headers
                },
                signal: controller.signal,
                redirect: config.followRedirects ? 'follow' : 'manual'
            });
            
            clearTimeout(timeoutId);
            
            const body = await response.text();
            const headers: Record<string, string> = {};
            response.headers.forEach((value, key) => {
                headers[key] = value;
            });
            
            return {
                ok: response.ok,
                status: response.status,
                headers,
                body,
                responseTime: Date.now() - startTime,
                finalUrl: response.url
            };
        } catch (error) {
            return {
                ok: false,
                status: 0,
                headers: {},
                body: '',
                responseTime: Date.now() - startTime,
                error: error instanceof Error ? error.message : 'Request failed'
            };
        }
    }
}

/**
 * Parse robots.txt content
 */
export function parseRobotsTxt(content: string): RobotsRule[] {
    const rules: RobotsRule[] = [];
    let currentRule: RobotsRule | null = null;
    
    const lines = content.split('\n');
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        
        const colonIndex = trimmed.indexOf(':');
        if (colonIndex === -1) continue;
        
        const directive = trimmed.substring(0, colonIndex).toLowerCase().trim();
        const value = trimmed.substring(colonIndex + 1).trim();
        
        switch (directive) {
            case 'user-agent':
                if (currentRule) rules.push(currentRule);
                currentRule = {
                    userAgent: value,
                    allowed: [],
                    disallowed: [],
                    sitemaps: []
                };
                break;
            case 'allow':
                if (currentRule) currentRule.allowed.push(value);
                break;
            case 'disallow':
                if (currentRule) currentRule.disallowed.push(value);
                break;
            case 'sitemap':
                if (currentRule) currentRule.sitemaps.push(value);
                else rules.push({ userAgent: '*', allowed: [], disallowed: [], sitemaps: [value] });
                break;
            case 'crawl-delay':
                if (currentRule) currentRule.crawlDelay = parseFloat(value);
                break;
        }
    }
    
    if (currentRule) rules.push(currentRule);
    return rules;
}

/**
 * Parse sitemap.xml content (handles both index and regular sitemaps)
 */
export function parseSitemap(content: string): string[] {
    const urls: string[] = [];
    
    // Match <loc> tags
    const locRegex = /<loc>([^<]+)<\/loc>/gi;
    let match;
    while ((match = locRegex.exec(content)) !== null) {
        urls.push(match[1].trim());
    }
    
    return urls;
}

/**
 * Extract links from HTML
 */
export function extractLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seen = new Set<string>();
    const base = new URL(baseUrl);
    
    // Standard href links
    const hrefRegex = /href\s*=\s*["']([^"'#]+)/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
        try {
            const url = normalizeUrl(match[1], base);
            if (url && !seen.has(url)) {
                seen.add(url);
                links.push(url);
            }
        } catch {}
    }
    
    // src attributes (for scripts, iframes)
    const srcRegex = /src\s*=\s*["']([^"']+)/gi;
    while ((match = srcRegex.exec(html)) !== null) {
        try {
            const url = normalizeUrl(match[1], base);
            if (url && !seen.has(url)) {
                seen.add(url);
                links.push(url);
            }
        } catch {}
    }
    
    // action attributes (forms)
    const actionRegex = /action\s*=\s*["']([^"']+)/gi;
    while ((match = actionRegex.exec(html)) !== null) {
        try {
            const url = normalizeUrl(match[1], base);
            if (url && !seen.has(url)) {
                seen.add(url);
                links.push(url);
            }
        } catch {}
    }
    
    // data-href, data-url, data-src attributes
    const dataRegex = /data-(?:href|url|src)\s*=\s*["']([^"']+)/gi;
    while ((match = dataRegex.exec(html)) !== null) {
        try {
            const url = normalizeUrl(match[1], base);
            if (url && !seen.has(url)) {
                seen.add(url);
                links.push(url);
            }
        } catch {}
    }
    
    return links;
}

/**
 * Extract links from JavaScript code
 */
export function extractJsLinks(js: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seen = new Set<string>();
    const base = new URL(baseUrl);
    
    // URL strings in JS
    const patterns = [
        // fetch/axios calls
        /(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
        // XMLHttpRequest
        /\.open\s*\(\s*["'][^"']+["']\s*,\s*["']([^"']+)["']/gi,
        // window.location
        /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/gi,
        // Router paths
        /(?:path|to|href|url|route)\s*:\s*["']([^"']+)["']/gi,
        // API endpoints
        /["'](\/api\/[^"']+)["']/gi,
        /["'](\/v\d+\/[^"']+)["']/gi,
        // Relative URLs
        /["'](\/[a-zA-Z][a-zA-Z0-9\-_\/]*\.(?:html|php|asp|aspx|jsp|json))["']/gi,
    ];
    
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(js)) !== null) {
            try {
                const url = normalizeUrl(match[1], base);
                if (url && !seen.has(url)) {
                    seen.add(url);
                    links.push(url);
                }
            } catch {}
        }
    }
    
    return links;
}

/**
 * Extract forms from HTML
 */
export function extractForms(html: string, baseUrl: string): FormInfo[] {
    const forms: FormInfo[] = [];
    const base = new URL(baseUrl);
    
    // Match form tags with their content
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch;
    
    while ((formMatch = formRegex.exec(html)) !== null) {
        const attributes = formMatch[1];
        const content = formMatch[2];
        
        // Extract action
        const actionMatch = /action\s*=\s*["']([^"']+)["']/i.exec(attributes);
        const action = actionMatch ? normalizeUrl(actionMatch[1], base) || baseUrl : baseUrl;
        
        // Extract method
        const methodMatch = /method\s*=\s*["']([^"']+)["']/i.exec(attributes);
        const method = (methodMatch ? methodMatch[1].toUpperCase() : 'GET') as 'GET' | 'POST';
        
        // Extract enctype
        const enctypeMatch = /enctype\s*=\s*["']([^"']+)["']/i.exec(attributes);
        const enctype = enctypeMatch ? enctypeMatch[1] : undefined;
        
        // Extract inputs
        const inputs: FormInfo['inputs'] = [];
        
        // Input fields
        const inputRegex = /<input([^>]*)>/gi;
        let inputMatch;
        while ((inputMatch = inputRegex.exec(content)) !== null) {
            const inputAttrs = inputMatch[1];
            const nameMatch = /name\s*=\s*["']([^"']+)["']/i.exec(inputAttrs);
            const typeMatch = /type\s*=\s*["']([^"']+)["']/i.exec(inputAttrs);
            const valueMatch = /value\s*=\s*["']([^"']+)["']/i.exec(inputAttrs);
            
            if (nameMatch) {
                inputs.push({
                    name: nameMatch[1],
                    type: typeMatch ? typeMatch[1] : 'text',
                    value: valueMatch ? valueMatch[1] : undefined
                });
            }
        }
        
        // Textarea fields
        const textareaRegex = /<textarea([^>]*)>/gi;
        while ((inputMatch = textareaRegex.exec(content)) !== null) {
            const nameMatch = /name\s*=\s*["']([^"']+)["']/i.exec(inputMatch[1]);
            if (nameMatch) {
                inputs.push({
                    name: nameMatch[1],
                    type: 'textarea'
                });
            }
        }
        
        // Select fields
        const selectRegex = /<select([^>]*)>/gi;
        while ((inputMatch = selectRegex.exec(content)) !== null) {
            const nameMatch = /name\s*=\s*["']([^"']+)["']/i.exec(inputMatch[1]);
            if (nameMatch) {
                inputs.push({
                    name: nameMatch[1],
                    type: 'select'
                });
            }
        }
        
        // Check for CSRF token
        const hasCSRF = inputs.some(i => 
            /csrf|token|nonce|authenticity/i.test(i.name) ||
            i.type === 'hidden' && /^[a-f0-9]{32,}$/i.test(i.value || '')
        );
        
        // Check for file upload
        const hasFileUpload = inputs.some(i => i.type === 'file');
        
        forms.push({
            action,
            method,
            inputs,
            hasCSRF,
            enctype,
            hasFileUpload
        });
    }
    
    return forms;
}

/**
 * Extract URL parameters
 */
export function extractParameters(url: string): ParameterInfo[] {
    const params: ParameterInfo[] = [];
    
    try {
        const parsed = new URL(url);
        
        // Query parameters
        parsed.searchParams.forEach((value, name) => {
            params.push({
                name,
                type: 'query',
                value,
                source: url
            });
        });
        
        // Path parameters (e.g., /users/123/posts/456)
        const pathParts = parsed.pathname.split('/');
        for (let i = 0; i < pathParts.length; i++) {
            const part = pathParts[i];
            // Detect numeric IDs or UUIDs in path
            if (/^\d+$/.test(part) || /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(part)) {
                params.push({
                    name: `path_${i}`,
                    type: 'path',
                    value: part,
                    source: url
                });
            }
        }
    } catch {}
    
    return params;
}

/**
 * Extract HTML comments
 */
export function extractComments(html: string): string[] {
    const comments: string[] = [];
    const commentRegex = /<!--([\s\S]*?)-->/g;
    let match;
    
    while ((match = commentRegex.exec(html)) !== null) {
        const comment = match[1].trim();
        // Skip empty or conditional comments
        if (comment && !comment.startsWith('[if') && comment.length > 3) {
            comments.push(comment);
        }
    }
    
    return comments;
}

/**
 * Extract email addresses
 */
export function extractEmails(content: string): string[] {
    const emails: string[] = [];
    const seen = new Set<string>();
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    let match;
    
    while ((match = emailRegex.exec(content)) !== null) {
        const email = match[0].toLowerCase();
        if (!seen.has(email) && !email.includes('example.com') && !email.includes('test.com')) {
            seen.add(email);
            emails.push(email);
        }
    }
    
    return emails;
}

/**
 * Extract script information
 */
export function extractScripts(html: string, baseUrl: string): ScriptInfo[] {
    const scripts: ScriptInfo[] = [];
    const base = new URL(baseUrl);
    
    const scriptRegex = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
    let match;
    
    while ((match = scriptRegex.exec(html)) !== null) {
        const attributes = match[1];
        const content = match[2];
        
        const srcMatch = /src\s*=\s*["']([^"']+)["']/i.exec(attributes);
        const typeMatch = /type\s*=\s*["']([^"']+)["']/i.exec(attributes);
        
        if (srcMatch) {
            // External script
            scripts.push({
                src: normalizeUrl(srcMatch[1], base) || srcMatch[1],
                type: typeMatch ? typeMatch[1] : 'text/javascript',
                inline: false
            });
        } else if (content.trim()) {
            // Inline script
            scripts.push({
                type: typeMatch ? typeMatch[1] : 'text/javascript',
                inline: true,
                content: content.length > 1000 ? content.substring(0, 1000) + '...' : content
            });
        }
    }
    
    return scripts;
}

/**
 * Normalize URL to absolute form
 */
function normalizeUrl(url: string, base: URL): string | null {
    if (!url) return null;
    
    // Skip javascript:, mailto:, tel:, data: URLs
    if (/^(javascript|mailto|tel|data|#):/i.test(url)) return null;
    
    try {
        const resolved = new URL(url, base.href);
        // Remove fragment
        resolved.hash = '';
        return resolved.href;
    } catch {
        return null;
    }
}

/**
 * Check if URL is in scope
 */
function isInScope(url: string, baseUrl: string, scope: CrawlerConfig['scope']): boolean {
    try {
        const target = new URL(url);
        const base = new URL(baseUrl);
        
        switch (scope) {
            case 'strict':
                return target.origin === base.origin;
            case 'subdomain':
                const baseDomain = base.hostname.split('.').slice(-2).join('.');
                const targetDomain = target.hostname.split('.').slice(-2).join('.');
                return targetDomain === baseDomain;
            case 'loose':
                return true;
            default:
                return target.origin === base.origin;
        }
    } catch {
        return false;
    }
}

/**
 * Check if URL should be excluded based on path or extension
 */
function shouldExclude(url: string, config: CrawlerConfig): boolean {
    try {
        const parsed = new URL(url);
        const path = parsed.pathname.toLowerCase();
        
        // Check excluded extensions
        const extensions = config.excludedExtensions || DEFAULT_CONFIG.excludedExtensions!;
        for (const ext of extensions) {
            if (path.endsWith(ext)) return true;
        }
        
        // Check excluded paths
        const excludedPaths = [...DEFAULT_EXCLUDED_PATHS, ...(config.excludedPaths || [])];
        for (const excludedPath of excludedPaths) {
            if (path.startsWith(excludedPath)) return true;
        }
        
        // Check included paths (if specified)
        if (config.includedPaths && config.includedPaths.length > 0) {
            const isIncluded = config.includedPaths.some(p => path.startsWith(p));
            if (!isIncluded) return true;
        }
        
        return false;
    } catch {
        return true;
    }
}

/**
 * Check if URL is allowed by robots.txt
 */
function isAllowedByRobots(url: string, rules: RobotsRule[]): boolean {
    try {
        const parsed = new URL(url);
        const path = parsed.pathname;
        
        // Find applicable rule (prefer specific user-agent, fallback to *)
        const rule = rules.find(r => r.userAgent === 'STRIX-Scanner') || 
                     rules.find(r => r.userAgent === '*');
        
        if (!rule) return true;
        
        // Check disallowed first
        for (const disallowed of rule.disallowed) {
            if (path.startsWith(disallowed)) {
                // Check if explicitly allowed
                for (const allowed of rule.allowed) {
                    if (path.startsWith(allowed)) return true;
                }
                return false;
            }
        }
        
        return true;
    } catch {
        return true;
    }
}

/**
 * Main Crawler Class
 */
export class SiteCrawler {
    private config: CrawlerConfig;
    private visited: Set<string> = new Set();
    private queue: Array<{ url: string; depth: number }> = [];
    private pages: Map<string, CrawledPage> = new Map();
    private robotsRules: RobotsRule[] = [];
    private startTime: number = 0;
    private onProgress?: CrawlProgressCallback;
    private aborted: boolean = false;
    
    constructor(config: Partial<CrawlerConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
    }
    
    /**
     * Start crawling from a URL
     */
    async crawl(startUrl: string, onProgress?: CrawlProgressCallback): Promise<CrawlResult> {
        this.onProgress = onProgress;
        this.startTime = Date.now();
        this.visited.clear();
        this.queue = [];
        this.pages.clear();
        this.aborted = false;
        
        const base = new URL(startUrl);
        const baseUrl = base.origin;
        
        // Phase 1: Fetch robots.txt
        this.updateProgress('Fetching robots.txt', 0, 0, 0, startUrl);
        if (this.config.respectRobotsTxt) {
            await this.fetchRobotsTxt(baseUrl);
        }
        
        // Phase 2: Fetch sitemap
        this.updateProgress('Parsing sitemap', 0, 0, 0, startUrl);
        const sitemapUrls = await this.fetchSitemap(baseUrl);
        
        // Add sitemap URLs to queue
        for (const url of sitemapUrls) {
            if (isInScope(url, startUrl, this.config.scope) && !shouldExclude(url, this.config)) {
                this.addToQueue(url, 0);
            }
        }
        
        // Add start URL
        this.addToQueue(startUrl, 0);
        
        // Phase 3: Crawl pages
        const rateDelay = 1000 / this.config.rateLimit;
        
        while (this.queue.length > 0 && !this.aborted) {
            // Check limits
            if (this.pages.size >= this.config.maxPages) break;
            if (Date.now() - this.startTime > this.config.maxTime) break;
            
            const { url, depth } = this.queue.shift()!;
            
            if (this.visited.has(url)) continue;
            this.visited.add(url);
            
            // Check robots.txt
            if (this.config.respectRobotsTxt && !isAllowedByRobots(url, this.robotsRules)) {
                continue;
            }
            
            this.updateProgress('Crawling', this.queue.length + this.visited.size, this.pages.size, 
                this.countForms(), url);
            
            // Crawl page
            const page = await this.crawlPage(url, depth);
            if (page) {
                this.pages.set(url, page);
                
                // Add discovered links to queue
                if (depth < this.config.maxDepth) {
                    for (const link of page.links) {
                        if (isInScope(link, startUrl, this.config.scope) && !shouldExclude(link, this.config)) {
                            this.addToQueue(link, depth + 1);
                        }
                    }
                }
            }
            
            // Rate limiting
            await this.sleep(rateDelay);
        }
        
        // Compile results
        return this.compileResults(startUrl);
    }
    
    /**
     * Stop the crawler
     */
    abort(): void {
        this.aborted = true;
    }
    
    /**
     * Crawl a single page
     */
    private async crawlPage(url: string, depth: number): Promise<CrawledPage | null> {
        const response = await crawlFetch(url, this.config);
        
        if (!response.ok) {
            return {
                url,
                depth,
                status: response.status,
                contentType: '',
                title: '',
                headers: response.headers,
                links: [],
                forms: [],
                scripts: [],
                parameters: extractParameters(url),
                comments: [],
                emails: [],
                endpoints: [],
                responseSize: 0,
                responseTime: response.responseTime,
                error: response.error
            };
        }
        
        const contentType = response.headers['content-type'] || '';
        const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');
        
        if (!isHtml) {
            return {
                url,
                depth,
                status: response.status,
                contentType,
                title: '',
                headers: response.headers,
                links: [],
                forms: [],
                scripts: [],
                parameters: extractParameters(url),
                comments: [],
                emails: [],
                endpoints: [],
                responseSize: response.body.length,
                responseTime: response.responseTime
            };
        }
        
        const html = response.body;
        
        // Extract title
        const titleMatch = /<title>([^<]+)<\/title>/i.exec(html);
        const title = titleMatch ? titleMatch[1].trim() : '';
        
        // Extract various elements
        const links = extractLinks(html, url);
        const forms = extractForms(html, url);
        const scripts = extractScripts(html, url);
        const comments = extractComments(html);
        const emails = extractEmails(html);
        const parameters = extractParameters(url);
        
        // Extract inline script links
        for (const script of scripts) {
            if (script.inline && script.content) {
                const jsLinks = extractJsLinks(script.content, url);
                links.push(...jsLinks);
            }
        }
        
        // Add form parameters
        for (const form of forms) {
            for (const input of form.inputs) {
                parameters.push({
                    name: input.name,
                    type: 'body',
                    value: input.value,
                    source: form.action
                });
            }
        }
        
        // Build endpoint list
        const endpoints: EndpointInfo[] = [];
        for (const form of forms) {
            endpoints.push({
                url: form.action,
                method: form.method,
                parameters: form.inputs.map(i => ({
                    name: i.name,
                    type: 'body' as const,
                    value: i.value,
                    source: form.action
                })),
                contentType: form.enctype,
                source: 'form'
            });
        }
        
        return {
            url,
            depth,
            status: response.status,
            contentType,
            title,
            headers: response.headers,
            links: [...new Set(links)],
            forms,
            scripts,
            parameters,
            comments,
            emails,
            endpoints,
            responseSize: html.length,
            responseTime: response.responseTime
        };
    }
    
    /**
     * Fetch and parse robots.txt
     */
    private async fetchRobotsTxt(baseUrl: string): Promise<void> {
        try {
            const response = await crawlFetch(`${baseUrl}/robots.txt`, this.config);
            if (response.ok) {
                this.robotsRules = parseRobotsTxt(response.body);
                
                // Add sitemap URLs from robots.txt
                for (const rule of this.robotsRules) {
                    for (const sitemap of rule.sitemaps) {
                        this.queue.push({ url: sitemap, depth: 0 });
                    }
                }
            }
        } catch {}
    }
    
    /**
     * Fetch and parse sitemap
     */
    private async fetchSitemap(baseUrl: string): Promise<string[]> {
        const urls: string[] = [];
        const sitemapUrls = [`${baseUrl}/sitemap.xml`, `${baseUrl}/sitemap_index.xml`];
        
        // Add sitemaps from robots.txt
        for (const rule of this.robotsRules) {
            sitemapUrls.push(...rule.sitemaps);
        }
        
        for (const sitemapUrl of [...new Set(sitemapUrls)]) {
            try {
                const response = await crawlFetch(sitemapUrl, this.config);
                if (response.ok) {
                    const parsed = parseSitemap(response.body);
                    
                    // Check if it's a sitemap index
                    for (const url of parsed) {
                        if (url.includes('sitemap') && url.endsWith('.xml')) {
                            // It's a sub-sitemap, fetch it
                            const subResponse = await crawlFetch(url, this.config);
                            if (subResponse.ok) {
                                urls.push(...parseSitemap(subResponse.body));
                            }
                        } else {
                            urls.push(url);
                        }
                    }
                }
            } catch {}
        }
        
        return [...new Set(urls)];
    }
    
    /**
     * Add URL to queue if not visited
     */
    private addToQueue(url: string, depth: number): void {
        if (!this.visited.has(url) && !this.queue.some(q => q.url === url)) {
            this.queue.push({ url, depth });
        }
    }
    
    /**
     * Count total forms discovered
     */
    private countForms(): number {
        let count = 0;
        for (const page of this.pages.values()) {
            count += page.forms.length;
        }
        return count;
    }
    
    /**
     * Count total parameters discovered
     */
    private countParameters(): number {
        const seen = new Set<string>();
        for (const page of this.pages.values()) {
            for (const param of page.parameters) {
                seen.add(`${param.type}:${param.name}`);
            }
        }
        return seen.size;
    }
    
    /**
     * Compile crawl results
     */
    private compileResults(startUrl: string): CrawlResult {
        const allLinks: string[] = [];
        const allForms: FormInfo[] = [];
        const allScripts: ScriptInfo[] = [];
        const allEmails: string[] = [];
        const allComments: string[] = [];
        const allEndpoints: EndpointInfo[] = [];
        const allParameters: ParameterInfo[] = [];
        
        for (const page of this.pages.values()) {
            allLinks.push(...page.links);
            allForms.push(...page.forms);
            allScripts.push(...page.scripts);
            allEmails.push(...page.emails);
            allComments.push(...page.comments);
            allEndpoints.push(...page.endpoints);
            allParameters.push(...page.parameters);
        }
        
        return {
            url: startUrl,
            links: [...new Set(allLinks)],
            forms: allForms,
            scripts: allScripts,
            emails: [...new Set(allEmails)],
            comments: [...new Set(allComments)],
            technologies: this.detectTechnologies(),
            pages: Array.from(this.pages.values()),
            endpoints: allEndpoints,
            parameters: this.dedupeParameters(allParameters),
            crawlStats: {
                pagesDiscovered: this.visited.size,
                pagesCrawled: this.pages.size,
                formsFound: allForms.length,
                parametersFound: this.countParameters(),
                duration: Date.now() - this.startTime
            }
        };
    }
    
    /**
     * Deduplicate parameters
     */
    private dedupeParameters(params: ParameterInfo[]): ParameterInfo[] {
        const seen = new Map<string, ParameterInfo>();
        for (const param of params) {
            const key = `${param.type}:${param.name}`;
            if (!seen.has(key)) {
                seen.set(key, param);
            }
        }
        return Array.from(seen.values());
    }
    
    /**
     * Detect technologies from crawled pages
     */
    private detectTechnologies(): string[] {
        const techs = new Set<string>();
        
        for (const page of this.pages.values()) {
            // From headers
            const server = page.headers['server'];
            if (server) techs.add(`Server: ${server}`);
            
            const powered = page.headers['x-powered-by'];
            if (powered) techs.add(powered);
            
            // From scripts
            for (const script of page.scripts) {
                if (script.src) {
                    if (script.src.includes('react')) techs.add('React');
                    if (script.src.includes('vue')) techs.add('Vue.js');
                    if (script.src.includes('angular')) techs.add('Angular');
                    if (script.src.includes('jquery')) techs.add('jQuery');
                    if (script.src.includes('bootstrap')) techs.add('Bootstrap');
                }
            }
        }
        
        return Array.from(techs);
    }
    
    /**
     * Update progress callback
     */
    private updateProgress(phase: string, discovered: number, crawled: number, forms: number, currentUrl: string): void {
        if (this.onProgress) {
            this.onProgress({
                phase,
                pagesDiscovered: discovered,
                pagesCrawled: crawled,
                formsFound: forms,
                parametersFound: this.countParameters(),
                currentUrl,
                elapsedTime: Date.now() - this.startTime
            });
        }
    }
    
    /**
     * Sleep helper
     */
    private sleep(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * Quick crawl helper function
 */
export async function quickCrawl(url: string, maxPages: number = 50): Promise<CrawlResult> {
    const crawler = new SiteCrawler({
        maxPages,
        maxDepth: 3,
        maxTime: 60000,
        rateLimit: 20
    });
    return crawler.crawl(url);
}

/**
 * Deep crawl helper function  
 */
export async function deepCrawl(url: string, onProgress?: CrawlProgressCallback): Promise<CrawlResult> {
    const crawler = new SiteCrawler({
        maxPages: 500,
        maxDepth: 10,
        maxTime: 600000, // 10 minutes
        rateLimit: 5
    });
    return crawler.crawl(url, onProgress);
}

export default SiteCrawler;

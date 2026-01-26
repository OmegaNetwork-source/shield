// STRIX Unified Scanner Types
// Types for integrated web + blockchain vulnerability scanning

export type VulnerabilityCategory =
    | 'web'
    | 'blockchain'
    | 'infrastructure'
    | 'configuration'
    | 'authentication'
    | 'injection'
    | 'xss'
    | 'crypto'
    | 'smart-contract'
    | 'api'
    | 'disclosure'
    | 'ssrf'
    | 'path-traversal'
    | 'open-redirect'
    | 'misconfiguration';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface UnifiedVulnerability {
    id: string;
    category: VulnerabilityCategory;
    severity: SeverityLevel;
    title: string;
    description: string;
    evidence?: string;
    location?: string;
    recommendation: string;
    references?: string[];
    cwe?: string;
    cvss?: number;
    owasp?: string;
    // Blockchain specific
    contractAddress?: string;
    chain?: string;
    attackVector?: string;
    // Web specific
    url?: string;
    parameter?: string;
    method?: string;
    payload?: string;
    // STIG mapping
    stigId?: string;
    nistControl?: string;
    // Exploitation info
    reproCommand?: string;
    reproSteps?: string[];
    // Secret/API key specific (for live findings display)
    secretType?: string;
    secretService?: string;
    secretServiceDesc?: string;
    secretValue?: string;
    secretImpact?: string;
    secretLine?: number;
    secretConfidence?: string;
    secretContext?: string;
}

export interface ScanTarget {
    url: string;
    type: 'website' | 'api' | 'dapp' | 'smart-contract';
    options?: ScanOptions;
}

export interface ScanOptions {
    // Scan depth
    depth?: 'quick' | 'standard' | 'deep' | 'comprehensive';
    // What to scan
    scanWeb?: boolean;
    scanBlockchain?: boolean;
    scanApi?: boolean;
    scanHeaders?: boolean;
    scanSsl?: boolean;
    scanPorts?: boolean;
    // Specific tests
    testXss?: boolean;
    testSqli?: boolean;
    testCsrf?: boolean;
    testSsrf?: boolean;
    testLfi?: boolean;
    testRce?: boolean;
    testWeb3?: boolean;
    // Deep scan options
    crawlPages?: boolean;           // Crawl and discover pages
    maxPages?: number;              // Maximum pages to crawl
    maxDepth?: number;              // Maximum crawl depth
    directoryEnum?: boolean;        // Directory enumeration
    dirWordlist?: 'small' | 'medium' | 'large';  // Wordlist size
    timeBasedTests?: boolean;       // Time-based blind injection tests
    testAllParams?: boolean;        // Test all discovered parameters
    payloadsPerParam?: number;      // Number of payloads per parameter
    // Advanced tests (SSRF, Command Injection, LFI, XXE, SSTI, Open Redirect, CORS)
    advancedTests?: boolean;        // Enable advanced vulnerability tests
    testSSRF?: boolean;             // Test for Server-Side Request Forgery
    testCommandInjection?: boolean; // Test for OS command injection
    testLFI?: boolean;              // Test for Local File Inclusion
    testXXE?: boolean;              // Test for XML External Entity injection
    testSSTI?: boolean;             // Test for Server-Side Template Injection
    testOpenRedirect?: boolean;     // Test for Open Redirect
    testCORS?: boolean;             // Test for CORS misconfiguration
    // Rate limiting
    requestsPerSecond?: number;
    timeout?: number;
    delayBetweenRequests?: number;  // Delay in ms
    // Authentication
    cookies?: string;
    headers?: Record<string, string>;
    authToken?: string;
    // Network
    proxy?: {
        url: string;
        username?: string;
        password?: string;
    };
}

export interface Web3Detection {
    hasWeb3: boolean;
    provider?: string;
    contracts: DetectedContract[];
    walletConnections: string[];
    chainIds: number[];
    rpcEndpoints: string[];
    ipfsLinks: string[];
    ensNames: string[];
}

export interface DetectedContract {
    address: string;
    chain: string;
    chainId: number;
    type?: 'erc20' | 'erc721' | 'erc1155' | 'defi' | 'unknown';
    name?: string;
    functions: string[];
    verified?: boolean;
}

export interface SslInfo {
    valid: boolean;
    issuer?: string;
    subject?: string;
    validFrom?: Date;
    validTo?: Date;
    daysUntilExpiry?: number;
    protocol?: string;
    cipher?: string;
    keySize?: number;
    vulnerabilities: string[];
}

export interface HeaderAnalysis {
    present: Record<string, string>;
    missing: string[];
    misconfigured: Array<{ header: string; issue: string }>;
    score: number;
}

export interface CrawlResult {
    url: string;
    status?: number;
    contentType?: string;
    forms: FormInfo[];
    links: string[];
    scripts: ScriptInfo[];
    apiEndpoints?: string[];
    comments: string[];
    emails: string[];
    secrets?: SecretFinding[];
    technologies?: string[];
    pages?: CrawledPage[];
    endpoints?: EndpointInfo[];
    parameters?: ParameterInfo[];
    crawlStats?: CrawlStats;
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
    source: string;
}

export interface EndpointInfo {
    url: string;
    method: string;
    parameters: ParameterInfo[];
    contentType?: string;
    source: string;
}

export interface CrawlStats {
    pagesDiscovered: number;
    pagesCrawled: number;
    formsFound: number;
    parametersFound: number;
    duration: number;
}

export interface FormInfo {
    action: string;
    method: 'GET' | 'POST' | string;
    inputs: Array<{ name: string; type: string; value?: string }>;
    hasFileUpload?: boolean;
    hasCSRF?: boolean;
    hasCsrfToken?: boolean;
    enctype?: string;
}

export interface ScriptInfo {
    src?: string;
    inline: boolean;
    hasWeb3: boolean;
    libraries: string[];
    suspiciousPatterns: string[];
}

export interface SecretFinding {
    type: 'api_key' | 'private_key' | 'password' | 'token' | 'credential' | 'wallet';
    value: string;           // Full value for security review
    fullValue?: string;      // Full value for detailed review
    location: string;
    confidence: 'high' | 'medium' | 'low';
    context?: string;        // Extended code context (surrounding code)
    serviceName?: string;    // Identified service (Infura, Alchemy, etc.)
    serviceDescription?: string;  // What the service does
    serviceImpact?: string;  // Security impact of exposure
    serviceSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';  // Appropriate severity for this type
    lineNumber?: number;     // Approximate line number in source
}

export interface ScanProgress {
    phase: string;
    current: number;
    total: number;
    message: string;
    findings: number;
    // Real-time findings for live display
    currentFindings?: UnifiedVulnerability[];
}

export interface ScanResult {
    id: string;
    target: string;
    startTime: Date;
    endTime?: Date;
    duration?: number;
    status: 'running' | 'completed' | 'failed' | 'cancelled';
    progress?: ScanProgress;

    // Results
    vulnerabilities: UnifiedVulnerability[];
    web3Detection?: Web3Detection;
    sslInfo?: SslInfo;
    headerAnalysis?: HeaderAnalysis;
    crawlResults?: CrawlResult[];

    // Summary
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
        webVulns: number;
        blockchainVulns: number;
        riskScore: number;
        riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe';
    };

    // Recommendations
    recommendations: string[];
}

// OWASP Top 10 2021 mapping
export const OWASP_TOP_10 = {
    'A01': { name: 'Broken Access Control', cwe: ['CWE-200', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-639'] },
    'A02': { name: 'Cryptographic Failures', cwe: ['CWE-259', 'CWE-327', 'CWE-331', 'CWE-798'] },
    'A03': { name: 'Injection', cwe: ['CWE-79', 'CWE-89', 'CWE-94', 'CWE-77'] },
    'A04': { name: 'Insecure Design', cwe: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'] },
    'A05': { name: 'Security Misconfiguration', cwe: ['CWE-16', 'CWE-611', 'CWE-1004'] },
    'A06': { name: 'Vulnerable Components', cwe: ['CWE-1104'] },
    'A07': { name: 'Auth Failures', cwe: ['CWE-287', 'CWE-384', 'CWE-613', 'CWE-620'] },
    'A08': { name: 'Software & Data Integrity', cwe: ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494'] },
    'A09': { name: 'Logging Failures', cwe: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'] },
    'A10': { name: 'SSRF', cwe: ['CWE-918'] }
};

// Smart Contract vulnerability categories (SWC Registry)
export const SWC_REGISTRY = {
    'SWC-100': 'Function Default Visibility',
    'SWC-101': 'Integer Overflow and Underflow',
    'SWC-102': 'Outdated Compiler Version',
    'SWC-103': 'Floating Pragma',
    'SWC-104': 'Unchecked Call Return Value',
    'SWC-105': 'Unprotected Ether Withdrawal',
    'SWC-106': 'Unprotected SELFDESTRUCT',
    'SWC-107': 'Reentrancy',
    'SWC-108': 'State Variable Default Visibility',
    'SWC-109': 'Uninitialized Storage Pointer',
    'SWC-110': 'Assert Violation',
    'SWC-111': 'Use of Deprecated Solidity Functions',
    'SWC-112': 'Delegatecall to Untrusted Callee',
    'SWC-113': 'DoS with Failed Call',
    'SWC-114': 'Transaction Order Dependence',
    'SWC-115': 'Authorization through tx.origin',
    'SWC-116': 'Block values as a proxy for time',
    'SWC-117': 'Signature Malleability',
    'SWC-118': 'Incorrect Constructor Name',
    'SWC-119': 'Shadowing State Variables',
    'SWC-120': 'Weak Sources of Randomness',
    'SWC-121': 'Missing Protection against Signature Replay',
    'SWC-122': 'Lack of Proper Signature Verification',
    'SWC-123': 'Requirement Violation',
    'SWC-124': 'Write to Arbitrary Storage Location',
    'SWC-125': 'Incorrect Inheritance Order',
    'SWC-126': 'Insufficient Gas Griefing',
    'SWC-127': 'Arbitrary Jump with Function Type Variable',
    'SWC-128': 'DoS With Block Gas Limit',
    'SWC-129': 'Typographical Error',
    'SWC-130': 'Right-To-Left-Override control character',
    'SWC-131': 'Presence of unused variables',
    'SWC-132': 'Unexpected Ether balance',
    'SWC-133': 'Hash Collisions With Multiple Variable Length Arguments',
    'SWC-134': 'Message call with hardcoded gas amount',
    'SWC-135': 'Code With No Effects',
    'SWC-136': 'Unencrypted Private Data On-Chain'
};

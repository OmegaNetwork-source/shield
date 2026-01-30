// STRIX Code Scanner Component
// SAST and GitHub Secret Scanner UI

import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
    Code, Shield, AlertTriangle, CheckCircle2, XCircle,
    Play, Loader2, FileText, FolderOpen, Github,
    ChevronDown, ChevronUp, ExternalLink, Copy, RefreshCw,
    AlertCircle, Info, Search, Eye, Filter, Download,
    Lock, Key, Database, FileCode, Braces, Terminal,
    FileWarning, ShieldAlert, ShieldCheck, Bug, Scan, Wallet, DollarSign
} from 'lucide-react';
import {
    SASTScanner,
    scanContent,
    GitHubScanner,
    scanRepository,
    SECRET_DORKS,
    generateHtmlReport,
    generateGitHubHtmlReport,
    generateCsvReport,
    generateGitHubCsvReport,
    generateJsonReport,
    downloadSASTReport,
    checkAllBalances,
    checkSolanaWallet,
    checkBitcoinWallet,
    extractAddresses,
    extractSolanaAddresses,
    extractBitcoinAddresses,
    extractAllAddresses,
    extractMnemonics,
    isMnemonicPhrase,
    checkMnemonicBalances,
    filterFindingsWithBalance,
    checkTextForFundedAddresses,
    testAPICredentials,
    detectServiceFromKey,
    type ScanResult,
    type GitHubScanResult,
    type SASTFinding,
    type GitHubSecretFinding,
    type ScanProgress,
    type GitHubSearchProgress,
    type SeverityLevel,
    type VulnerabilityCategory,
    type WalletCheckResult,
    type MnemonicCheckResult,
    type APITestResult,
    type APIService,
} from '../sast';



// Severity colors
const SEVERITY_COLORS: Record<SeverityLevel, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-blue-500',
    info: 'text-gray-400',
};

const SEVERITY_BG: Record<SeverityLevel, string> = {
    critical: 'bg-red-500/20 border-red-500/50',
    high: 'bg-orange-500/20 border-orange-500/50',
    medium: 'bg-yellow-500/20 border-yellow-500/50',
    low: 'bg-blue-500/20 border-blue-500/50',
    info: 'bg-gray-500/20 border-gray-500/50',
};

// Category icons
const CATEGORY_ICONS: Record<VulnerabilityCategory, React.ReactNode> = {
    'hardcoded-secret': <Key className="w-4 h-4" />,
    'injection': <Terminal className="w-4 h-4" />,
    'xss': <Code className="w-4 h-4" />,
    'path-traversal': <FolderOpen className="w-4 h-4" />,
    'insecure-crypto': <Lock className="w-4 h-4" />,
    'insecure-deserialization': <Braces className="w-4 h-4" />,
    'authentication': <ShieldAlert className="w-4 h-4" />,
    'authorization': <Shield className="w-4 h-4" />,
    'sensitive-data-exposure': <Eye className="w-4 h-4" />,
    'security-misconfiguration': <FileWarning className="w-4 h-4" />,
    'vulnerable-dependency': <Bug className="w-4 h-4" />,
    'code-quality': <FileCode className="w-4 h-4" />,
    'other': <AlertCircle className="w-4 h-4" />,
};

type ScanTab = 'local' | 'paste' | 'github';

export type ScanSeverityCounts = { critical: number; high: number; medium: number; low: number };

interface CodeScannerProps {
    darkMode?: boolean;
    onScanResultsChange?: (counts: ScanSeverityCounts | null) => void;
}

export function CodeScanner({ darkMode = true, onScanResultsChange }: CodeScannerProps) {
    const [activeTab, setActiveTab] = useState<ScanTab>('paste');
    const [isScanning, setIsScanning] = useState(false);
    const [progress, setProgress] = useState<ScanProgress | GitHubSearchProgress | null>(null);
    const [error, setError] = useState<string | null>(null);

    // Local scan state
    const [localPath, setLocalPath] = useState('');
    const [localResult, setLocalResult] = useState<ScanResult | null>(null);

    // Paste scan state
    const [pasteContent, setPasteContent] = useState('');
    const [pasteFilename, setPasteFilename] = useState('code.js');
    const [pasteFindings, setPasteFindings] = useState<SASTFinding[]>([]);

    // GitHub scan state
    const [githubQuery, setGithubQuery] = useState('');
    const [githubToken, setGithubToken] = useState('');
    const [selectedDork, setSelectedDork] = useState<string>('');
    const [githubResult, setGithubResult] = useState<GitHubScanResult | null>(null);
    const [liveFindings, setLiveFindings] = useState<GitHubSecretFinding[]>([]);

    // GitHub scan options
    const [activeReposOnly, setActiveReposOnly] = useState(true); // Filter to repos active in past year
    const [maxRepoAgeDays, setMaxRepoAgeDays] = useState(365); // Default 1 year
    const [directRepoScan, setDirectRepoScan] = useState(''); // Repo to scan directly (e.g., "owner/repo")

    // UI state
    const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
    const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>('all');
    const [hideGeneric, setHideGeneric] = useState(false); // Hide "Potential Secret" generic matches
    const [showErrors, setShowErrors] = useState(true);
    const scannerRef = useRef<SASTScanner | GitHubScanner | null>(null);

    // Wallet balance checking state
    const [balanceChecks, setBalanceChecks] = useState<Record<string, WalletCheckResult | MnemonicCheckResult | 'loading' | 'error'>>({});

    // Balance filter state - only show findings with funded wallets
    const [onlyShowWithBalance, setOnlyShowWithBalance] = useState(false);
    const [isFilteringByBalance, setIsFilteringByBalance] = useState(false);
    const [balanceFilterProgress, setBalanceFilterProgress] = useState<{ checked: number; total: number; funded: number } | null>(null);

    // Notify parent of scan severity counts for sidebar status box
    useEffect(() => {
        if (!onScanResultsChange) return;
        const allFindings: { severity: string }[] = [
            ...(localResult?.findings ?? []),
            ...pasteFindings,
            ...(githubResult?.findings ?? []),
            ...liveFindings
        ];
        if (allFindings.length === 0) {
            onScanResultsChange(null);
            return;
        }
        const sev = (s: string) => (s || '').toLowerCase();
        onScanResultsChange({
            critical: allFindings.filter(f => sev(f.severity) === 'critical').length,
            high: allFindings.filter(f => sev(f.severity) === 'high').length,
            medium: allFindings.filter(f => sev(f.severity) === 'medium').length,
            low: allFindings.filter(f => sev(f.severity) === 'low' || sev(f.severity) === 'info').length
        });
    }, [localResult, pasteFindings, githubResult, liveFindings, onScanResultsChange]);
    const [fundedFindingIds, setFundedFindingIds] = useState<Set<string>>(new Set());
    const [balanceInfoCache, setBalanceInfoCache] = useState<Record<string, { address: string; type: string; balances: string[] }>>({});

    // API credential testing state
    const [apiTests, setApiTests] = useState<Record<string, APITestResult | 'loading' | 'error'>>({});

    // Check if a finding is crypto-related and can have balance checked
    const isCryptoFinding = (finding: GitHubSecretFinding): boolean => {
        const cryptoTypes = [
            'ethereum', 'private key', 'wallet', 'mnemonic', 'seed',
            'crypto', 'infura', 'alchemy', 'web3', '0x', 'phrase'
        ];
        const secretType = finding.secretType.toLowerCase();
        const snippet = finding.match.snippet.toLowerCase();
        return cryptoTypes.some(t => secretType.includes(t) || snippet.includes(t));
    };

    // Check if finding contains mnemonic/seed phrase
    const isMnemonicFinding = (finding: GitHubSecretFinding): boolean => {
        const mnemonicTypes = ['mnemonic', 'seed', 'phrase', 'recovery', 'bip39', 'bip-39'];
        const secretType = finding.secretType.toLowerCase();
        const snippet = finding.match.snippet.toLowerCase();

        // Check secret type
        if (mnemonicTypes.some(t => secretType.includes(t))) return true;

        const foundMnemonics = extractMnemonics(snippet);
        return foundMnemonics.length > 0;
    };

    // Extract wallet address from finding
    const extractWalletFromFinding = (finding: GitHubSecretFinding): string | null => {
        const addresses = extractAddresses(finding.match.snippet);
        return addresses.length > 0 ? addresses[0] : null;
    };

    // Check if a finding is an API key that can be tested
    const isAPIKeyFinding = (finding: GitHubSecretFinding): { canTest: boolean; service: APIService | null; key: string | null; secretKey?: string } => {
        const apiKeyTypes = [
            'github', 'stripe', 'sendgrid', 'slack', 'discord', 'twilio',
            'binance', 'coinbase', 'kraken', 'kucoin', 'bybit', 'okx', 'gateio', 'htx', 'bitfinex', 'gemini',
            'etherscan', 'infura', 'alchemy', 'aws', 'api key', 'api_key', 'apikey', 'token', 'secret'
        ];
        const secretType = finding.secretType.toLowerCase();
        const snippet = finding.match.snippet;

        // Check if it's an API key type
        const isAPIType = apiKeyTypes.some(t => secretType.includes(t));

        // Map secret type to service first
        let service: APIService | null = null;
        if (secretType.includes('github')) service = 'github';
        else if (secretType.includes('stripe')) service = 'stripe';
        else if (secretType.includes('sendgrid')) service = 'sendgrid';
        else if (secretType.includes('slack')) service = 'slack';
        else if (secretType.includes('binance')) service = 'binance';
        else if (secretType.includes('coinbase')) service = 'coinbase';
        else if (secretType.includes('kraken')) service = 'kraken';
        else if (secretType.includes('kucoin')) service = 'kucoin';
        else if (secretType.includes('bybit')) service = 'bybit';
        else if (secretType.includes('okx') || secretType.includes('okex')) service = 'okx';
        else if (secretType.includes('gate')) service = 'gateio';
        else if (secretType.includes('htx') || secretType.includes('huobi')) service = 'htx';
        else if (secretType.includes('bitfinex')) service = 'bitfinex';
        else if (secretType.includes('gemini')) service = 'gemini';
        else if (secretType.includes('etherscan')) service = 'etherscan';
        else if (secretType.includes('infura')) service = 'infura';
        else if (secretType.includes('alchemy')) service = 'alchemy';

        // Extract API key and secret from snippet based on service
        let extractedKey: string | null = null;
        let extractedSecret: string | undefined = undefined;

        // Service-specific extraction patterns
        if (service === 'binance' || secretType.includes('binance')) {
            // Look for BINANCE_API_KEY=xxx and BINANCE_API_SECRET=xxx
            const keyMatch = snippet.match(/(?:BINANCE[_\s-]?API[_\s-]?KEY|api[_\s-]?key)\s*[=:]\s*["']?([A-Za-z0-9]{64})["']?/i);
            const secretMatch = snippet.match(/(?:BINANCE[_\s-]?(?:API[_\s-]?)?SECRET|secret[_\s-]?key)\s*[=:]\s*["']?([A-Za-z0-9]{64})["']?/i);
            if (keyMatch) extractedKey = keyMatch[1];
            if (secretMatch) extractedSecret = secretMatch[1];
            // If only one 64-char found, it might be either key or secret
            if (!extractedKey && !extractedSecret) {
                const anyMatch = snippet.match(/[A-Za-z0-9]{64}/);
                if (anyMatch) extractedKey = anyMatch[0];
            }
            service = 'binance';
        } else if (service === 'github' || secretType.includes('github')) {
            const match = snippet.match(/gh[pous]_[A-Za-z0-9]{36}/);
            if (match) extractedKey = match[0];
            service = 'github';
        } else if (service === 'stripe' || secretType.includes('stripe')) {
            const match = snippet.match(/[sr]k_(?:live|test)_[0-9a-zA-Z]{24,}/);
            if (match) extractedKey = match[0];
            service = 'stripe';
        } else if (service === 'etherscan') {
            const match = snippet.match(/[A-Z0-9]{34}/);
            if (match) extractedKey = match[0];
        } else {
            // Generic extraction - try multiple patterns
            const keyPatterns = [
                /ghp_[A-Za-z0-9]{36}/,                    // GitHub PAT
                /gho_[A-Za-z0-9]{36}/,                    // GitHub OAuth
                /ghu_[A-Za-z0-9]{36}/,                    // GitHub User
                /ghs_[A-Za-z0-9]{36}/,                    // GitHub Server
                /sk_(?:live|test)_[0-9a-zA-Z]{24,}/,      // Stripe
                /rk_(?:live|test)_[0-9a-zA-Z]{24,}/,      // Stripe restricted
                /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/, // SendGrid
                /xox[bpars]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/,  // Slack
                /[A-Za-z0-9]{64}/,                       // Binance-style 64-char
                /[a-f0-9]{32}/i,                         // Infura/generic 32-hex
                /[A-Z0-9]{34}/,                          // Etherscan
                /[A-Za-z0-9_-]{32,}/,                    // Generic long alphanumeric
            ];

            for (const pattern of keyPatterns) {
                const match = snippet.match(pattern);
                if (match) {
                    extractedKey = match[0];
                    break;
                }
            }
        }

        // Try to detect service from key if not clear from type
        if (!service && extractedKey) {
            service = detectServiceFromKey(extractedKey);
        }

        // canTest is true if we have a service OR if the finding looks API-related
        const canTest = isAPIType || service !== null;

        return {
            canTest,
            service,
            key: extractedKey,
            secretKey: extractedSecret,
        };
    };

    // Test API credentials for a finding
    const testFindingAPI = useCallback(async (finding: GitHubSecretFinding) => {
        const snippet = finding.match.snippet;
        let service: APIService | null = null;
        let key: string | null = null;
        let secretKey: string | undefined = undefined;

        // Extract Binance credentials by label (most reliable)
        // Matches: BINANCE_API_KEY, BINANCE_KEY, BINANCE-API-KEY, etc.
        const binanceKeyMatch = snippet.match(/BINANCE[_-]?(?:API[_-]?)?KEY\s*[=:]\s*["']?([A-Za-z0-9]+)["']?/i);
        // Matches: BINANCE_API_SECRET, BINANCE_SECRET, BINANCE_SECRET_KEY, etc.
        const binanceSecretMatch = snippet.match(/BINANCE[_-]?(?:API[_-]?)?SECRET[_-]?(?:KEY)?\s*[=:]\s*["']?([A-Za-z0-9]+)["']?/i);

        if (binanceKeyMatch || binanceSecretMatch || finding.secretType.toLowerCase().includes('binance')) {
            service = 'binance';
            key = binanceKeyMatch ? binanceKeyMatch[1] : null;
            secretKey = binanceSecretMatch ? binanceSecretMatch[1] : undefined;

            // If no labeled key found, look for 64-char strings
            if (!key) {
                const longKey = snippet.match(/[A-Za-z0-9]{64}/);
                if (longKey) key = longKey[0];
            }
        }

        // GitHub tokens
        if (!key) {
            const ghMatch = snippet.match(/gh[pous]_[A-Za-z0-9]{36}/);
            if (ghMatch) {
                service = 'github';
                key = ghMatch[0];
            }
        }

        // Stripe keys
        if (!key) {
            const stripeMatch = snippet.match(/[sr]k_(?:live|test)_[A-Za-z0-9]{24,}/);
            if (stripeMatch) {
                service = 'stripe';
                key = stripeMatch[0];
            }
        }

        // Generic fallback from apiInfo
        if (!service || !key) {
            const apiInfo = isAPIKeyFinding(finding);
            service = apiInfo.service;
            key = apiInfo.key;
            secretKey = apiInfo.secretKey || secretKey;
        }

        if (!service || !key) {
            alert('Could not extract API credentials from this finding.');
            return;
        }

        console.log('Testing:', service, 'Key:', key?.substring(0, 15) + '...', 'Secret:', secretKey ? 'found' : 'not found');

        setApiTests(prev => ({ ...prev, [finding.id]: 'loading' }));

        try {
            const result = await testAPICredentials({
                service,
                apiKey: key,
                secretKey,
            });

            setApiTests(prev => ({ ...prev, [finding.id]: result }));

            // Show result
            if (result.isActive) {
                alert(`✓ ${service.toUpperCase()} API KEY IS ACTIVE!\n\n` +
                    (result.balance ? `Balance: ${result.balance}\n` : '') +
                    (result.permissions?.length ? `Permissions: ${result.permissions.join(', ')}\n` : '') +
                    (result.accountInfo ? `Info: ${JSON.stringify(result.accountInfo)}` : ''));
            } else {
                alert(`✗ ${service.toUpperCase()} test result:\n\n${result.error || 'Invalid or inactive key'}`);
            }
        } catch (e: any) {
            const errorResult: APITestResult = {
                service,
                isActive: false,
                error: e.message || 'Unknown error',
                testTime: new Date(),
            };
            setApiTests(prev => ({ ...prev, [finding.id]: errorResult }));
            alert(`Error testing ${service.toUpperCase()}:\n\n${e.message}`);
        }
    }, []);

    // Check balance for a finding (handles both private keys and mnemonics)
    const checkFindingBalance = useCallback(async (finding: GitHubSecretFinding) => {
        const isMnemonic = isMnemonicFinding(finding);

        if (isMnemonic) {
            // Handle mnemonic phrase checking
            const foundMnemonics = extractMnemonics(finding.match.snippet);

            // Prompt user for the wallet address derived from mnemonic
            const userAddress = prompt(
                foundMnemonics.length > 0
                    ? `Found potential mnemonic:\n"${foundMnemonics[0].substring(0, 50)}..."\n\nEnter the wallet address derived from this mnemonic to check its balance:`
                    : 'Enter the wallet address derived from this seed phrase:',
                '0x...'
            );

            if (!userAddress || !userAddress.startsWith('0x') || userAddress.length !== 42) {
                return;
            }

            setBalanceChecks(prev => ({ ...prev, [finding.id]: 'loading' }));
            try {
                const result = await checkMnemonicBalances(
                    foundMnemonics[0] || 'unknown',
                    [userAddress]
                );
                setBalanceChecks(prev => ({ ...prev, [finding.id]: result }));
            } catch (e) {
                setBalanceChecks(prev => ({ ...prev, [finding.id]: 'error' }));
            }
            return;
        }

        // Handle regular private key / address checking
        const address = extractWalletFromFinding(finding);
        if (!address) {
            // Try to find address in context - prompt user
            const userAddress = prompt(
                'Could not auto-detect wallet address.\n\nEnter the wallet address to check:',
                '0x...'
            );
            if (!userAddress || !userAddress.startsWith('0x') || userAddress.length !== 42) {
                return;
            }
            setBalanceChecks(prev => ({ ...prev, [finding.id]: 'loading' }));
            try {
                const result = await checkAllBalances(userAddress);
                setBalanceChecks(prev => ({ ...prev, [finding.id]: result }));
            } catch (e) {
                setBalanceChecks(prev => ({ ...prev, [finding.id]: 'error' }));
            }
            return;
        }

        setBalanceChecks(prev => ({ ...prev, [finding.id]: 'loading' }));
        try {
            const result = await checkAllBalances(address, true); // Include tokens
            setBalanceChecks(prev => ({ ...prev, [finding.id]: result }));
        } catch (e) {
            setBalanceChecks(prev => ({ ...prev, [finding.id]: 'error' }));
        }
    }, []);

    // Scan all findings for balances and filter to only show funded ones
    const scanFindingsForBalances = useCallback(async (findings: GitHubSecretFinding[]) => {
        setIsFilteringByBalance(true);
        setBalanceFilterProgress({ checked: 0, total: findings.length, funded: 0 });
        setFundedFindingIds(new Set());
        setBalanceInfoCache({});

        try {
            const { fundedFindings, balanceInfo } = await filterFindingsWithBalance(
                findings,
                (checked, total, funded) => {
                    setBalanceFilterProgress({ checked, total, funded });
                }
            );

            setFundedFindingIds(new Set(fundedFindings.map(f => f.id)));
            setBalanceInfoCache(balanceInfo);
        } catch (e) {
            console.error('Error filtering by balance:', e);
        } finally {
            setIsFilteringByBalance(false);
            setBalanceFilterProgress(null);
        }
    }, []);

    // Toggle balance filter - triggers scan if enabling
    const handleBalanceFilterToggle = useCallback(async (enabled: boolean) => {
        setOnlyShowWithBalance(enabled);

        if (enabled) {
            const findings = liveFindings.length > 0 ? liveFindings : (githubResult?.findings || []);
            if (findings.length > 0 && fundedFindingIds.size === 0) {
                // Only scan if we haven't already
                await scanFindingsForBalances(findings);
            }
        }
    }, [liveFindings, githubResult, fundedFindingIds.size, scanFindingsForBalances]);

    // Theme classes
    const bgMain = darkMode ? 'bg-gray-900' : 'bg-gray-50';
    const bgCard = darkMode ? 'bg-gray-800' : 'bg-white';
    const bgInput = darkMode ? 'bg-gray-700' : 'bg-gray-100';
    const borderColor = darkMode ? 'border-gray-700' : 'border-gray-200';
    const textPrimary = darkMode ? 'text-white' : 'text-gray-900';
    const textSecondary = darkMode ? 'text-gray-400' : 'text-gray-600';
    const textMuted = darkMode ? 'text-gray-500' : 'text-gray-400';

    // Handle local directory scan (Electron only)
    const handleLocalScan = useCallback(async () => {
        console.log('[CodeScanner] handleLocalScan called, path:', localPath);

        if (!localPath) {
            alert('Please enter a directory path');
            return;
        }

        // Check if IPC is available
        const hasIPC = typeof window !== 'undefined' &&
            'ipcRenderer' in window &&
            typeof (window as any).ipcRenderer?.invoke === 'function';

        console.log('[CodeScanner] IPC available:', hasIPC);

        if (!hasIPC) {
            setError('Local scanning requires Electron desktop app. IPC not available.');
            return;
        }

        setIsScanning(true);
        setLocalResult(null);
        setProgress(null);
        setError(null);

        try {
            console.log('[CodeScanner] Creating scanner for:', localPath);
            const scanner = new SASTScanner({
                targetPath: localPath,
                onProgress: (p) => {
                    console.log('[CodeScanner] Progress:', p);
                    setProgress(p);
                },
            });
            scannerRef.current = scanner;

            console.log('[CodeScanner] Starting scan...');
            const result = await scanner.scanDirectory(localPath);
            console.log('[CodeScanner] Scan complete:', result);
            setLocalResult(result);
        } catch (err: any) {
            console.error('[CodeScanner] Scan error:', err);
            setError(`Scan failed: ${err.message}`);
            alert(`Scan failed: ${err.message}`);
        } finally {
            setIsScanning(false);
            scannerRef.current = null;
        }
    }, [localPath]);

    // Handle paste content scan
    const handlePasteScan = useCallback(() => {
        if (!pasteContent.trim()) return;

        setIsScanning(true);
        setPasteFindings([]);
        setError(null);

        try {
            const findings = scanContent(pasteContent, pasteFilename);
            setPasteFindings(findings);
        } catch (err: any) {
            console.error('Scan error:', err);
            setError(`Scan failed: ${err.message}`);
        } finally {
            setIsScanning(false);
        }
    }, [pasteContent, pasteFilename]);

    // Handle GitHub search
    const handleGitHubScan = useCallback(async () => {
        // Check if doing direct repo scan
        const isDirectRepoScan = directRepoScan.trim().length > 0;

        if (!isDirectRepoScan) {
            const searchQuery = githubQuery || (selectedDork ? SECRET_DORKS[selectedDork as keyof typeof SECRET_DORKS]?.[0] : '');
            if (!searchQuery && !selectedDork) {
                setError('Please enter a search query, select a preset, or enter a repo to scan directly');
                return;
            }
        }

        setIsScanning(true);
        setGithubResult(null);
        setLiveFindings([]); // Clear previous live findings
        setProgress(null);
        setError(null);
        setShowErrors(true); // Reset error visibility for new scan

        // Check if we have a token for GitHub API
        if (!githubToken) {
            setError('GitHub token is required for code search. The GitHub Code Search API requires authentication.');
            setIsScanning(false);
            return;
        }

        try {
            const scanner = new GitHubScanner({
                token: githubToken,
                onProgress: (p) => setProgress(p as any),
                // Apply active repos filter
                maxRepoAgeDays: activeReposOnly ? maxRepoAgeDays : undefined,
                // Real-time finding callback - update UI immediately as secrets are found
                onFinding: (finding) => {
                    setLiveFindings(prev => {
                        // Dedupe by checking if we already have this
                        const key = `${finding.repository.fullName}:${finding.file.path}`;
                        if (prev.some(f => `${f.repository.fullName}:${f.file.path}` === key)) {
                            return prev;
                        }
                        return [...prev, finding];
                    });
                },
            });
            scannerRef.current = scanner;

            let result: GitHubScanResult;

            if (isDirectRepoScan) {
                // Direct repo scan - scan a specific repository
                result = await scanner.scanRepository({
                    repoFullName: directRepoScan.trim(),
                });
            } else if (selectedDork && !githubQuery) {
                result = await scanner.searchByCategory(selectedDork as any);
            } else {
                const searchQuery = githubQuery || (selectedDork ? SECRET_DORKS[selectedDork as keyof typeof SECRET_DORKS]?.[0] : '');
                result = await scanner.searchForSecrets({ query: searchQuery });
            }

            setGithubResult(result);

            if (result.errors && result.errors.length > 0) {
                setError(result.errors.map(e => e.message).join('\n'));
            }
        } catch (err: any) {
            console.error('GitHub scan error:', err);
            setError(`GitHub scan failed: ${err.message}`);
        } finally {
            setIsScanning(false);
            scannerRef.current = null;
        }
    }, [githubQuery, githubToken, selectedDork, directRepoScan, activeReposOnly, maxRepoAgeDays]);

    // Abort scan
    const handleAbort = useCallback(() => {
        console.log('[CodeScanner] Abort requested');
        if (scannerRef.current) {
            console.log('[CodeScanner] Calling scanner.abort()');
            scannerRef.current.abort();
        }
        // Force stop the UI state regardless
        setIsScanning(false);
        setProgress(null);
        scannerRef.current = null;
        console.log('[CodeScanner] Scan aborted, UI reset');
    }, []);

    // Toggle finding expansion
    const toggleFinding = useCallback((id: string) => {
        setExpandedFindings(prev => {
            const next = new Set(prev);
            if (next.has(id)) {
                next.delete(id);
            } else {
                next.add(id);
            }
            return next;
        });
    }, []);

    // Copy to clipboard
    const copyToClipboard = useCallback((text: string) => {
        navigator.clipboard.writeText(text);
    }, []);

    // Download report
    const downloadReport = useCallback((format: 'html' | 'csv' | 'json' | 'pdf') => {
        // Handle PDF separately since it uses jsPDF
        if (format === 'pdf') {
            if (localResult) {
                const projectName = localPath.split(/[/\\]/).pop() || 'Project';
                downloadSASTReport(localResult, {
                    projectName,
                    scannerUser: 'STRIX Scanner',
                    title: 'Static Application Security Testing Report',
                    redactSecrets: true,
                });
            }
            return;
        }

        let content: string;
        let filename: string;
        let mimeType: string;

        if (activeTab === 'github' && githubResult) {
            switch (format) {
                case 'html':
                    content = generateGitHubHtmlReport(githubResult);
                    filename = 'github-secrets-report.html';
                    mimeType = 'text/html';
                    break;
                case 'csv':
                    content = generateGitHubCsvReport(githubResult);
                    filename = 'github-secrets-report.csv';
                    mimeType = 'text/csv';
                    break;
                case 'json':
                    content = generateJsonReport(githubResult);
                    filename = 'github-secrets-report.json';
                    mimeType = 'application/json';
                    break;
            }
        } else if (localResult) {
            switch (format) {
                case 'html':
                    content = generateHtmlReport(localResult);
                    filename = 'sast-report.html';
                    mimeType = 'text/html';
                    break;
                case 'csv':
                    content = generateCsvReport(localResult);
                    filename = 'sast-report.csv';
                    mimeType = 'text/csv';
                    break;
                case 'json':
                    content = generateJsonReport(localResult);
                    filename = 'sast-report.json';
                    mimeType = 'application/json';
                    break;
            }
        } else {
            return;
        }

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }, [activeTab, githubResult, localResult, localPath]);

    // Filter findings by severity, type, and balance
    const filterFindings = useCallback((findings: SASTFinding[] | GitHubSecretFinding[]) => {
        let filtered: (SASTFinding | GitHubSecretFinding)[] = findings;

        // Filter by severity
        if (severityFilter !== 'all') {
            filtered = filtered.filter(f => f.severity === severityFilter);
        }

        // Filter out generic "Potential Secret" if hideGeneric is enabled
        if (hideGeneric) {
            filtered = filtered.filter(f => {
                const secretType = 'secretType' in f ? f.secretType : '';
                return secretType !== 'Potential Secret' &&
                    secretType !== 'Base64 Encoded Secret' &&
                    !secretType.includes('Potential');
            });
        }

        // Filter to only show findings with funded wallets
        if (onlyShowWithBalance && fundedFindingIds.size > 0) {
            filtered = filtered.filter(f => fundedFindingIds.has(f.id));
        }

        return filtered as any;
    }, [severityFilter, hideGeneric, onlyShowWithBalance, fundedFindingIds]);

    // Render SAST finding
    const renderSASTFinding = (finding: SASTFinding) => {
        const isExpanded = expandedFindings.has(finding.id);

        return (
            <div
                key={finding.id}
                className={`border rounded-lg overflow-hidden ${SEVERITY_BG[finding.severity]}`}
            >
                <div
                    className="p-4 cursor-pointer flex items-start gap-3"
                    onClick={() => toggleFinding(finding.id)}
                >
                    <div className={`mt-0.5 ${SEVERITY_COLORS[finding.severity]}`}>
                        {CATEGORY_ICONS[finding.category] || <AlertCircle className="w-4 h-4" />}
                    </div>

                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                            <span className={`font-medium ${textPrimary}`}>{finding.title}</span>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BG[finding.severity]} ${SEVERITY_COLORS[finding.severity]}`}>
                                {finding.severity}
                            </span>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} ${textSecondary}`}>
                                {finding.confidence} confidence
                            </span>
                        </div>

                        <div className={`text-sm font-mono ${textSecondary}`}>
                            {finding.location.file}:{finding.location.line}
                        </div>
                    </div>

                    {isExpanded ? (
                        <ChevronUp className={`w-5 h-5 ${textSecondary}`} />
                    ) : (
                        <ChevronDown className={`w-5 h-5 ${textSecondary}`} />
                    )}
                </div>

                {isExpanded && (
                    <div className={`px-4 pb-4 space-y-3 border-t ${borderColor}`}>
                        <div className="pt-3">
                            <p className={`text-sm ${textSecondary}`}>{finding.description}</p>
                        </div>

                        <div className={`${darkMode ? 'bg-gray-900/50' : 'bg-gray-100'} rounded-lg p-3 font-mono text-sm overflow-x-auto`}>
                            <pre className={textSecondary} style={{ whiteSpace: 'pre-wrap' }}>{finding.location.snippet}</pre>
                        </div>

                        {finding.location.context && (
                            <div>
                                <div className={`text-xs ${textMuted} mb-1`}>Context:</div>
                                <div className={`${darkMode ? 'bg-gray-900/50' : 'bg-gray-100'} rounded-lg p-3 font-mono text-xs overflow-x-auto`}>
                                    {finding.location.context.map((line, i) => (
                                        <div key={i} className={textMuted}>{line}</div>
                                    ))}
                                </div>
                            </div>
                        )}

                        <div className="flex flex-wrap gap-2 text-xs">
                            {finding.cwe?.map(cwe => (
                                <a
                                    key={cwe}
                                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="px-2 py-1 rounded bg-purple-500/20 text-purple-400 hover:bg-purple-500/30"
                                >
                                    {cwe}
                                </a>
                            ))}
                            {finding.owasp?.map(owasp => (
                                <span
                                    key={owasp}
                                    className="px-2 py-1 rounded bg-blue-500/20 text-blue-400"
                                >
                                    {owasp}
                                </span>
                            ))}
                        </div>

                        {finding.remediation && (
                            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-3">
                                <div className="flex items-center gap-2 text-emerald-400 font-medium text-sm mb-1">
                                    <ShieldCheck className="w-4 h-4" />
                                    Remediation
                                </div>
                                <p className={`text-sm ${textSecondary}`}>{finding.remediation}</p>
                            </div>
                        )}

                        <div className="flex gap-2">
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    copyToClipboard(`${finding.location.file}:${finding.location.line}`);
                                }}
                                className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700 text-gray-300 hover:bg-gray-600' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'} flex items-center gap-1`}
                            >
                                <Copy className="w-3 h-3" /> Copy Location
                            </button>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    // Render GitHub finding
    const renderGitHubFinding = (finding: GitHubSecretFinding) => {
        const isExpanded = expandedFindings.has(finding.id);
        const isCrypto = isCryptoFinding(finding);
        const balanceCheck = balanceChecks[finding.id];

        return (
            <div
                key={finding.id}
                className={`border rounded-lg overflow-hidden ${SEVERITY_BG[finding.severity]}`}
            >
                <div
                    className="p-4 cursor-pointer flex items-start gap-3"
                    onClick={() => toggleFinding(finding.id)}
                >
                    <div className={`mt-0.5 ${SEVERITY_COLORS[finding.severity]}`}>
                        <Key className="w-4 h-4" />
                    </div>

                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span className={`font-medium ${textPrimary}`}>{finding.secretType}</span>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BG[finding.severity]} ${SEVERITY_COLORS[finding.severity]}`}>
                                {finding.severity}
                            </span>
                            {/* Balance indicator - from individual check */}
                            {balanceCheck && balanceCheck !== 'loading' && balanceCheck !== 'error' && (('isLive' in balanceCheck && balanceCheck.isLive) || ('hasValue' in balanceCheck && balanceCheck.hasValue)) && (
                                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/30 text-emerald-400 flex items-center gap-1">
                                    <DollarSign className="w-3 h-3" />
                                    HAS FUNDS
                                </span>
                            )}
                            {/* Balance indicator - from filter scan */}
                            {!balanceCheck && balanceInfoCache[finding.id] && (
                                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/30 text-emerald-400 flex items-center gap-1" title={balanceInfoCache[finding.id].balances.join(' | ')}>
                                    <DollarSign className="w-3 h-3" />
                                    💰 FUNDED ({balanceInfoCache[finding.id].type.toUpperCase()})
                                </span>
                            )}
                        </div>

                        <div className="flex items-center gap-2 flex-wrap">
                            <a
                                href={finding.repository.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sm text-cyan-500 hover:text-cyan-400 flex items-center gap-1"
                                onClick={(e) => e.stopPropagation()}
                            >
                                <Github className="w-3 h-3" />
                                {finding.repository.fullName}
                                <ExternalLink className="w-3 h-3" />
                            </a>
                            {/* Repo metadata */}
                            {finding.repository.pushedAt && (
                                <span className={`text-xs ${textMuted}`}>
                                    · Updated {new Date(finding.repository.pushedAt).toLocaleDateString()}
                                </span>
                            )}
                            {finding.repository.stars !== undefined && finding.repository.stars > 0 && (
                                <span className={`text-xs ${textMuted}`}>
                                    · ⭐ {finding.repository.stars}
                                </span>
                            )}
                        </div>
                    </div>

                    {isExpanded ? (
                        <ChevronUp className={`w-5 h-5 ${textSecondary}`} />
                    ) : (
                        <ChevronDown className={`w-5 h-5 ${textSecondary}`} />
                    )}
                </div>

                {isExpanded && (
                    <div className={`px-4 pb-4 space-y-3 border-t ${borderColor}`}>
                        <div className="pt-3">
                            <div className={`text-sm ${textSecondary} mb-2`}>
                                File: <a
                                    href={finding.file.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-cyan-500 hover:text-cyan-400"
                                >
                                    {finding.file.path}
                                </a>
                                {finding.match.line && ` (line ${finding.match.line})`}
                            </div>
                        </div>

                        <div className={`${darkMode ? 'bg-gray-900/50' : 'bg-gray-100'} rounded-lg p-3 font-mono text-sm overflow-x-auto`}>
                            <pre className={textSecondary} style={{ whiteSpace: 'pre-wrap' }}>{finding.match.snippet}</pre>
                        </div>

                        <div className="flex gap-2 flex-wrap">
                            <a
                                href={finding.file.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs px-2 py-1 rounded bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 flex items-center gap-1"
                                onClick={(e) => e.stopPropagation()}
                            >
                                <ExternalLink className="w-3 h-3" /> View on GitHub
                            </a>
                            <button
                                onClick={(e) => {
                                    e.stopPropagation();
                                    copyToClipboard(finding.file.url);
                                }}
                                className={`text-xs px-2 py-1 rounded ${darkMode ? 'bg-gray-700 text-gray-300 hover:bg-gray-600' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'} flex items-center gap-1`}
                            >
                                <Copy className="w-3 h-3" /> Copy URL
                            </button>

                            {/* Balance Check Button - shown for crypto findings */}
                            {isCrypto && (
                                <button
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        checkFindingBalance(finding);
                                    }}
                                    disabled={balanceCheck === 'loading'}
                                    className="text-xs px-2 py-1 rounded bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 disabled:opacity-50 flex items-center gap-1"
                                >
                                    {balanceCheck === 'loading' ? (
                                        <>
                                            <Loader2 className="w-3 h-3 animate-spin" /> Checking...
                                        </>
                                    ) : isMnemonicFinding(finding) ? (
                                        <>
                                            <Key className="w-3 h-3" /> Check Seed Phrase
                                        </>
                                    ) : (
                                        <>
                                            <Wallet className="w-3 h-3" /> Check Balance
                                        </>
                                    )}
                                </button>
                            )}

                            {/* API Test Button - shown for API key findings */}
                            {(() => {
                                const apiInfo = isAPIKeyFinding(finding);
                                const apiTest = apiTests[finding.id];
                                const secretTypeLower = finding.secretType.toLowerCase();

                                // Show button for API-related findings (broader check)
                                const showButton = apiInfo.canTest ||
                                    secretTypeLower.includes('api') ||
                                    secretTypeLower.includes('key') ||
                                    secretTypeLower.includes('token') ||
                                    secretTypeLower.includes('secret');

                                if (!showButton) return null;

                                return (
                                    <button
                                        type="button"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            testFindingAPI(finding);
                                        }}
                                        disabled={apiTest === 'loading'}
                                        className="text-xs px-2 py-1 rounded bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 disabled:opacity-50 flex items-center gap-1"
                                    >
                                        {apiTest === 'loading' ? (
                                            <>
                                                <Loader2 className="w-3 h-3 animate-spin" /> Testing...
                                            </>
                                        ) : (
                                            <>
                                                <Shield className="w-3 h-3" /> Test API
                                            </>
                                        )}
                                    </button>
                                );
                            })()}
                        </div>

                        {/* Balance Check Results */}
                        {balanceCheck && balanceCheck !== 'loading' && balanceCheck !== 'error' && (
                            <div className={`mt-3 p-3 rounded-lg ${('isLive' in balanceCheck && balanceCheck.isLive) || ('hasValue' in balanceCheck && balanceCheck.hasValue)
                                ? 'bg-emerald-500/20 border border-emerald-500/30'
                                : `${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`
                                }`}>
                                {/* Mnemonic Check Result */}
                                {'mnemonic' in balanceCheck ? (
                                    <>
                                        <div className="flex items-center gap-2 mb-2">
                                            <Key className={`w-4 h-4 ${balanceCheck.hasValue ? 'text-emerald-400' : textSecondary}`} />
                                            <span className={`font-medium text-sm ${balanceCheck.hasValue ? 'text-emerald-400' : textSecondary}`}>
                                                {balanceCheck.hasValue ? 'LIVE MNEMONIC - Has Funds!' : 'No Balance Found'}
                                            </span>
                                        </div>

                                        <div className={`text-xs font-mono ${textSecondary} mb-2`}>
                                            Mnemonic: {balanceCheck.mnemonic.substring(0, 30)}... ({balanceCheck.wordCount} words)
                                        </div>

                                        {balanceCheck.derivedAddresses.map((derived, idx) => (
                                            <div key={idx} className="mt-2">
                                                <div className={`text-xs ${textMuted} mb-1`}>
                                                    Path: {derived.path}
                                                </div>
                                                <div className={`text-xs font-mono ${textSecondary}`}>
                                                    {derived.address}
                                                </div>

                                                {derived.balanceResult?.isLive && (
                                                    <div className="mt-1 space-y-1">
                                                        {derived.balanceResult.balances
                                                            .filter(b => b.hasBalance)
                                                            .map(b => (
                                                                <div key={b.chain} className="flex items-center justify-between text-sm">
                                                                    <span className={textSecondary}>{b.chainName}:</span>
                                                                    <a
                                                                        href={b.explorerUrl}
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                        className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                                                                        onClick={(e) => e.stopPropagation()}
                                                                    >
                                                                        {b.balanceFormatted} {b.symbol}
                                                                        <ExternalLink className="w-3 h-3" />
                                                                    </a>
                                                                </div>
                                                            ))}
                                                    </div>
                                                )}
                                            </div>
                                        ))}

                                        {!balanceCheck.hasValue && (
                                            <div className={`text-xs ${textMuted} mt-2`}>
                                                Checked {balanceCheck.totalChains} chains across {balanceCheck.derivedAddresses.length} address(es)
                                            </div>
                                        )}
                                    </>
                                ) : (
                                    /* Regular Wallet Check Result */
                                    <>
                                        <div className="flex items-center gap-2 mb-2">
                                            <Wallet className={`w-4 h-4 ${balanceCheck.isLive ? 'text-emerald-400' : textSecondary}`} />
                                            <span className={`font-medium text-sm ${balanceCheck.isLive ? 'text-emerald-400' : textSecondary}`}>
                                                {balanceCheck.isLive ? 'LIVE WALLET - Has Funds!' : 'No Balance Found'}
                                            </span>
                                        </div>

                                        <div className={`text-xs font-mono ${textSecondary} mb-2`}>
                                            Address: {balanceCheck.address}
                                        </div>

                                        {balanceCheck.isLive && (
                                            <div className="space-y-1">
                                                {balanceCheck.balances
                                                    .filter(b => b.hasBalance)
                                                    .map(b => (
                                                        <div key={b.chain} className="flex items-center justify-between text-sm">
                                                            <span className={textSecondary}>{b.chainName}:</span>
                                                            <a
                                                                href={b.explorerUrl}
                                                                target="_blank"
                                                                rel="noopener noreferrer"
                                                                className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                                                                onClick={(e) => e.stopPropagation()}
                                                            >
                                                                {b.balanceFormatted} {b.symbol}
                                                                <ExternalLink className="w-3 h-3" />
                                                            </a>
                                                        </div>
                                                    ))}
                                            </div>
                                        )}

                                        {!balanceCheck.isLive && (
                                            <div className={`text-xs ${textMuted}`}>
                                                Checked {balanceCheck.totalChains} chains: {balanceCheck.balances.map(b => b.chainName).join(', ')}
                                            </div>
                                        )}
                                    </>
                                )}
                            </div>
                        )}

                        {balanceCheck === 'error' && (
                            <div className="mt-3 p-3 rounded-lg bg-red-500/20 border border-red-500/30">
                                <span className="text-sm text-red-400">Failed to check balance. Try entering address manually.</span>
                            </div>
                        )}

                        {/* API Test Results */}
                        {(() => {
                            const apiTest = apiTests[finding.id];
                            if (!apiTest || apiTest === 'loading') return null;

                            if (apiTest === 'error') {
                                return (
                                    <div className="mt-3 p-3 rounded-lg bg-red-500/20 border border-red-500/30">
                                        <span className="text-sm text-red-400">Failed to test API credentials.</span>
                                    </div>
                                );
                            }

                            return (
                                <div className={`mt-3 p-3 rounded-lg ${apiTest.isActive
                                    ? 'bg-red-500/20 border border-red-500/30'
                                    : `${darkMode ? 'bg-gray-800' : 'bg-gray-100'} border ${borderColor}`
                                    }`}>
                                    <div className="flex items-center gap-2 mb-2">
                                        {apiTest.isActive ? (
                                            <>
                                                <ShieldAlert className="w-4 h-4 text-red-400" />
                                                <span className="font-medium text-sm text-red-400">
                                                    ACTIVE API KEY - {apiTest.service.toUpperCase()}
                                                </span>
                                            </>
                                        ) : (
                                            <>
                                                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                                                <span className={`font-medium text-sm ${textSecondary}`}>
                                                    Invalid/Inactive - {apiTest.service.toUpperCase()}
                                                </span>
                                            </>
                                        )}
                                    </div>

                                    {apiTest.error && (
                                        <div className={`text-xs ${textSecondary} mb-2`}>
                                            Error: {apiTest.error}
                                        </div>
                                    )}

                                    {apiTest.isActive && apiTest.accountInfo && (
                                        <div className="space-y-1">
                                            {Object.entries(apiTest.accountInfo).map(([key, value]) => (
                                                <div key={key} className="flex items-center justify-between text-sm">
                                                    <span className={textMuted}>{key}:</span>
                                                    <span className={textSecondary}>
                                                        {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
                                                    </span>
                                                </div>
                                            ))}
                                        </div>
                                    )}

                                    {apiTest.isActive && apiTest.permissions && apiTest.permissions.length > 0 && (
                                        <div className="mt-2">
                                            <span className={`text-xs ${textMuted}`}>Permissions: </span>
                                            <span className="text-xs text-purple-400">
                                                {apiTest.permissions.join(', ')}
                                            </span>
                                        </div>
                                    )}

                                    {apiTest.isActive && apiTest.balance && (
                                        <div className="mt-2">
                                            <span className={`text-xs ${textMuted}`}>Balance: </span>
                                            <span className="text-xs text-emerald-400 font-medium">
                                                {apiTest.balance}
                                            </span>
                                        </div>
                                    )}

                                    {apiTest.rateLimit && (
                                        <div className="mt-2">
                                            <span className={`text-xs ${textMuted}`}>
                                                Rate Limit: {apiTest.rateLimit.remaining}/{apiTest.rateLimit.total}
                                            </span>
                                        </div>
                                    )}
                                </div>
                            );
                        })()}
                    </div>
                )}
            </div>
        );
    };

    // Render summary
    const renderSummary = (result: ScanResult | null, githubResult: GitHubScanResult | null) => {
        const summary = result?.summary || githubResult?.summary;
        if (!summary) return null;

        return (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
                <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-red-500">{summary.bySeverity.critical}</div>
                    <div className={`text-xs ${textSecondary}`}>Critical</div>
                </div>
                <div className="bg-orange-500/20 border border-orange-500/30 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-orange-500">{summary.bySeverity.high}</div>
                    <div className={`text-xs ${textSecondary}`}>High</div>
                </div>
                <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-yellow-500">{summary.bySeverity.medium}</div>
                    <div className={`text-xs ${textSecondary}`}>Medium</div>
                </div>
                <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-3 text-center">
                    <div className="text-2xl font-bold text-blue-500">{summary.bySeverity.low}</div>
                    <div className={`text-xs ${textSecondary}`}>Low</div>
                </div>
                <div className={`${darkMode ? 'bg-gray-700/50 border-gray-600' : 'bg-gray-200/50 border-gray-300'} border rounded-lg p-3 text-center`}>
                    <div className={`text-2xl font-bold ${textSecondary}`}>{summary.bySeverity.info}</div>
                    <div className={`text-xs ${textSecondary}`}>Info</div>
                </div>
            </div>
        );
    };

    return (
        <div className={`min-h-full ${bgMain} ${textPrimary} p-6`}>
            {/* Header */}
            <div className="mb-6">
                <div className="flex items-center gap-3 mb-2">
                    <Scan className="w-8 h-8 text-cyan-500" />
                    <h1 className="text-2xl font-bold">Code Scanner</h1>
                </div>
                <p className={textSecondary}>
                    Static Application Security Testing (SAST) & GitHub Secret Scanner
                </p>
            </div>

            {/* Tabs */}
            <div className={`${bgCard} rounded-t-xl border-b ${borderColor}`}>
                <div className="flex gap-1 p-1">
                    <button
                        onClick={() => { setActiveTab('paste'); setError(null); }}
                        className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === 'paste'
                            ? 'bg-cyan-500/20 text-cyan-500'
                            : `${textSecondary} hover:${textPrimary}`
                            }`}
                    >
                        <Code className="w-4 h-4 inline-block mr-2" />
                        Paste Code
                    </button>
                    <button
                        onClick={() => { setActiveTab('local'); setError(null); }}
                        className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === 'local'
                            ? 'bg-cyan-500/20 text-cyan-500'
                            : `${textSecondary} hover:${textPrimary}`
                            }`}
                    >
                        <FolderOpen className="w-4 h-4 inline-block mr-2" />
                        Local Directory
                    </button>
                    <button
                        onClick={() => { setActiveTab('github'); setError(null); }}
                        className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${activeTab === 'github'
                            ? 'bg-cyan-500/20 text-cyan-500'
                            : `${textSecondary} hover:${textPrimary}`
                            }`}
                    >
                        <Github className="w-4 h-4 inline-block mr-2" />
                        GitHub Search
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <div className={`${bgCard} rounded-b-xl border border-t-0 ${borderColor} p-6`}>
                {/* Error Display */}
                {error && showErrors && (
                    <div className="mb-4 p-4 bg-red-500/20 border border-red-500/50 rounded-lg">
                        <div className="flex items-start gap-2">
                            <AlertCircle className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between">
                                    <div className="font-medium text-red-500">Error</div>
                                    <button
                                        onClick={() => setShowErrors(false)}
                                        className="text-red-400 hover:text-red-300 text-sm"
                                    >
                                        Dismiss
                                    </button>
                                </div>
                                <div className={`text-sm ${textSecondary} whitespace-pre-wrap max-h-32 overflow-y-auto`}>
                                    {error.includes('rate limit')
                                        ? 'Rate limit exceeded. Results shown are from queries that completed before the limit was hit. Try again in a few minutes.'
                                        : error}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Paste Code Tab */}
                {activeTab === 'paste' && (
                    <div className="space-y-4">
                        <div className="flex items-center gap-4 mb-4">
                            <input
                                type="text"
                                value={pasteFilename}
                                onChange={(e) => setPasteFilename(e.target.value)}
                                placeholder="filename.js"
                                className={`px-3 py-2 ${bgInput} border ${borderColor} rounded-lg text-sm focus:outline-none focus:border-cyan-500`}
                            />
                            <span className={`text-sm ${textSecondary}`}>
                                (helps detect language-specific vulnerabilities)
                            </span>
                        </div>

                        <textarea
                            value={pasteContent}
                            onChange={(e) => setPasteContent(e.target.value)}
                            placeholder="Paste your code here to scan for vulnerabilities and secrets..."
                            className={`w-full h-64 px-4 py-3 ${bgInput} border ${borderColor} rounded-lg font-mono text-sm resize-none focus:outline-none focus:border-cyan-500`}
                        />

                        <div className="flex justify-between items-center">
                            <span className={`text-sm ${textSecondary}`}>
                                {pasteContent.split('\n').length} lines
                            </span>

                            <button
                                onClick={handlePasteScan}
                                disabled={isScanning || !pasteContent.trim()}
                                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg font-medium flex items-center gap-2 transition-colors text-white"
                            >
                                {isScanning ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>
                                        <Play className="w-4 h-4" />
                                        Scan Code
                                    </>
                                )}
                            </button>
                        </div>

                        {/* Paste Results */}
                        {pasteFindings.length > 0 && (
                            <div className="space-y-4 mt-6">
                                <div className="flex items-center justify-between">
                                    <h2 className="text-lg font-semibold flex items-center gap-2">
                                        <AlertTriangle className="w-5 h-5 text-yellow-500" />
                                        {pasteFindings.length} Finding{pasteFindings.length !== 1 ? 's' : ''}
                                    </h2>
                                </div>

                                <div className="space-y-3">
                                    {pasteFindings.map(finding => renderSASTFinding(finding))}
                                </div>
                            </div>
                        )}

                        {pasteFindings.length === 0 && pasteContent.trim() && !isScanning && (
                            <div className="bg-emerald-500/20 border border-emerald-500/30 rounded-lg p-6 text-center mt-6">
                                <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
                                <h3 className="text-lg font-semibold text-emerald-400">No Issues Found</h3>
                                <p className={`text-sm mt-1 ${textSecondary}`}>
                                    No security issues detected in the provided code.
                                </p>
                            </div>
                        )}
                    </div>
                )}

                {/* Local Directory Tab */}
                {activeTab === 'local' && (
                    <div className="space-y-4">
                        <div className="flex items-center gap-2">
                            <div className="flex-1">
                                <input
                                    type="text"
                                    value={localPath}
                                    onChange={(e) => setLocalPath(e.target.value)}
                                    placeholder="Enter directory path or click Browse..."
                                    className={`w-full px-4 py-2 ${bgInput} border ${borderColor} rounded-lg focus:outline-none focus:border-cyan-500`}
                                />
                            </div>

                            <button
                                onClick={async () => {
                                    try {
                                        const result = await (window as any).ipcRenderer?.invoke('browse-directory');
                                        if (result?.success && result?.path) {
                                            setLocalPath(result.path);
                                        }
                                    } catch (e) {
                                        console.error('Browse error:', e);
                                    }
                                }}
                                disabled={isScanning}
                                className={`px-4 py-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300'} disabled:opacity-50 rounded-lg font-medium flex items-center gap-2`}
                            >
                                <FolderOpen className="w-4 h-4" />
                                Browse
                            </button>

                            {isScanning ? (
                                <button
                                    onClick={handleAbort}
                                    className="px-4 py-2 bg-red-600 hover:bg-red-500 rounded-lg font-medium flex items-center gap-2 text-white"
                                >
                                    <XCircle className="w-4 h-4" />
                                    Abort
                                </button>
                            ) : (
                                <button
                                    onClick={handleLocalScan}
                                    disabled={!localPath}
                                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg font-medium flex items-center gap-2 text-white"
                                >
                                    <Search className="w-4 h-4" />
                                    Scan
                                </button>
                            )}
                        </div>

                        <p className={`text-sm ${textSecondary} flex items-center gap-1`}>
                            <Info className="w-4 h-4" />
                            Select a directory to scan for secrets, API keys, and security vulnerabilities.
                        </p>

                        {progress && 'phase' in progress && (
                            <div className="mt-4">
                                <div className="flex items-center justify-between text-sm mb-2">
                                    <span className={textSecondary}>
                                        {progress.phase === 'discovering' && 'Discovering files...'}
                                        {progress.phase === 'scanning' && `Scanning files (${progress.filesScanned}/${progress.filesDiscovered})`}
                                        {progress.phase === 'analyzing' && 'Analyzing results...'}
                                        {progress.phase === 'complete' && 'Scan complete'}
                                    </span>
                                    <span className="text-cyan-500">{progress.findingsCount} findings</span>
                                </div>
                                <div className={`h-2 ${darkMode ? 'bg-gray-700' : 'bg-gray-200'} rounded-full overflow-hidden`}>
                                    <div
                                        className="h-full bg-cyan-500 transition-all duration-300"
                                        style={{ width: `${progress.percentage}%` }}
                                    />
                                </div>
                            </div>
                        )}

                        {/* Local Results */}
                        {localResult && (
                            <div className="space-y-4 mt-6">
                                <div className={`${bgCard} rounded-lg p-4 border ${borderColor}`}>
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <h2 className="text-lg font-semibold">Scan Results</h2>
                                            <p className={`text-sm ${textSecondary}`}>
                                                {localResult.filesScanned} files scanned • {localResult.linesScanned.toLocaleString()} lines • {(localResult.duration / 1000).toFixed(2)}s
                                            </p>
                                        </div>

                                        <div className="flex items-center gap-2">
                                            <select
                                                value={severityFilter}
                                                onChange={(e) => setSeverityFilter(e.target.value as any)}
                                                className={`px-3 py-1.5 ${bgInput} border ${borderColor} rounded-lg text-sm`}
                                            >
                                                <option value="all">All Severities</option>
                                                <option value="critical">Critical</option>
                                                <option value="high">High</option>
                                                <option value="medium">Medium</option>
                                                <option value="low">Low</option>
                                                <option value="info">Info</option>
                                            </select>

                                            <div className="flex gap-1">
                                                <button
                                                    onClick={() => downloadReport('pdf')}
                                                    className={`px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm flex items-center gap-1 font-medium`}
                                                    title="Download PDF Report"
                                                >
                                                    <Download className="w-4 h-4" /> PDF
                                                </button>
                                                <button
                                                    onClick={() => downloadReport('html')}
                                                    className={`px-3 py-1.5 ${bgInput} hover:bg-opacity-80 rounded-lg text-sm flex items-center gap-1`}
                                                    title="Download HTML Report"
                                                >
                                                    <Download className="w-4 h-4" /> HTML
                                                </button>
                                                <button
                                                    onClick={() => downloadReport('csv')}
                                                    className={`px-3 py-1.5 ${bgInput} hover:bg-opacity-80 rounded-lg text-sm flex items-center gap-1`}
                                                    title="Download CSV"
                                                >
                                                    <Download className="w-4 h-4" /> CSV
                                                </button>
                                            </div>
                                        </div>
                                    </div>

                                    {renderSummary(localResult, null)}

                                    <div className="flex items-center gap-4 text-sm">
                                        <div className="flex items-center gap-2">
                                            <ShieldAlert className="w-4 h-4 text-red-400" />
                                            <span>Risk Score: </span>
                                            <span className={`font-bold ${localResult.summary.riskScore >= 75 ? 'text-red-500' :
                                                localResult.summary.riskScore >= 50 ? 'text-orange-500' :
                                                    localResult.summary.riskScore >= 25 ? 'text-yellow-500' :
                                                        'text-emerald-500'
                                                }`}>
                                                {localResult.summary.riskScore}/100
                                            </span>
                                        </div>
                                    </div>
                                </div>

                                <div className="space-y-3">
                                    {filterFindings(localResult.findings).map(finding =>
                                        renderSASTFinding(finding as SASTFinding)
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* GitHub Tab */}
                {activeTab === 'github' && (
                    <div className="space-y-4">
                        <div className="grid md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label className={`block text-sm ${textSecondary} mb-1`}>Search Query</label>
                                <input
                                    type="text"
                                    value={githubQuery}
                                    onChange={(e) => { setGithubQuery(e.target.value); setSelectedDork(''); }}
                                    placeholder='e.g., "AKIA" or "password=" extension:env'
                                    className={`w-full px-4 py-2 ${bgInput} border ${borderColor} rounded-lg focus:outline-none focus:border-cyan-500`}
                                />
                            </div>

                            <div>
                                <label className={`block text-sm ${textSecondary} mb-1`}>Or Select Preset</label>
                                <select
                                    value={selectedDork}
                                    onChange={(e) => { setSelectedDork(e.target.value); setGithubQuery(''); }}
                                    className={`w-full px-4 py-2 ${bgInput} border ${borderColor} rounded-lg focus:outline-none focus:border-cyan-500`}
                                >
                                    <option value="">Custom Query</option>
                                    {Object.keys(SECRET_DORKS).map(category => (
                                        <option key={category} value={category}>{category}</option>
                                    ))}
                                </select>
                            </div>
                        </div>

                        <div className="mb-4">
                            <label className={`block text-sm ${textSecondary} mb-1`}>
                                GitHub Token <span className="text-red-500">*</span> (required for code search)
                            </label>
                            <input
                                type="password"
                                value={githubToken}
                                onChange={(e) => setGithubToken(e.target.value)}
                                placeholder="ghp_xxxxxxxxxxxx"
                                className={`w-full px-4 py-2 ${bgInput} border ${borderColor} rounded-lg focus:outline-none focus:border-cyan-500`}
                            />
                            <p className={`text-xs ${textMuted} mt-1`}>
                                GitHub's Code Search API requires a personal access token. Create one at <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer" className="text-cyan-500 hover:underline">github.com/settings/tokens</a>
                            </p>
                        </div>

                        {/* Direct Repo Scan */}
                        <div className="mb-4">
                            <label className={`block text-sm ${textSecondary} mb-1`}>
                                Scan Specific Repository (optional)
                            </label>
                            <input
                                type="text"
                                value={directRepoScan}
                                onChange={(e) => setDirectRepoScan(e.target.value)}
                                placeholder="owner/repo (e.g., facebook/react)"
                                className={`w-full px-4 py-2 ${bgInput} border ${borderColor} rounded-lg focus:outline-none focus:border-cyan-500`}
                            />
                            <p className={`text-xs ${textMuted} mt-1`}>
                                Enter a repo to scan directly instead of searching across all of GitHub
                            </p>
                        </div>

                        {/* Scan Options */}
                        <div className="mb-4 flex flex-wrap gap-4 items-center">
                            <label className={`flex items-center gap-2 text-sm ${textSecondary} cursor-pointer`}>
                                <input
                                    type="checkbox"
                                    checked={activeReposOnly}
                                    onChange={(e) => setActiveReposOnly(e.target.checked)}
                                    className="rounded accent-cyan-500"
                                />
                                Active repos only
                            </label>

                            {activeReposOnly && (
                                <div className="flex items-center gap-2">
                                    <span className={`text-sm ${textSecondary}`}>Last</span>
                                    <select
                                        value={maxRepoAgeDays}
                                        onChange={(e) => setMaxRepoAgeDays(Number(e.target.value))}
                                        className={`px-2 py-1 ${bgInput} border ${borderColor} rounded text-sm`}
                                    >
                                        <option value={30}>30 days</option>
                                        <option value={90}>90 days</option>
                                        <option value={180}>6 months</option>
                                        <option value={365}>1 year</option>
                                        <option value={730}>2 years</option>
                                    </select>
                                </div>
                            )}

                            <span className={`text-xs ${textMuted}`}>
                                {activeReposOnly
                                    ? `Skips repos not updated in ${maxRepoAgeDays} days`
                                    : 'Shows all repos regardless of activity'}
                            </span>
                        </div>

                        <div className="flex justify-between items-center">
                            <p className="text-sm text-yellow-500 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4" />
                                Use responsibly. Don't abuse found credentials.
                            </p>

                            {isScanning ? (
                                <button
                                    onClick={handleAbort}
                                    className="px-4 py-2 bg-red-600 hover:bg-red-500 rounded-lg font-medium flex items-center gap-2 text-white"
                                >
                                    <XCircle className="w-4 h-4" />
                                    Abort
                                </button>
                            ) : (
                                <button
                                    onClick={handleGitHubScan}
                                    disabled={(!githubQuery && !selectedDork && !directRepoScan.trim()) || !githubToken}
                                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg font-medium flex items-center gap-2 text-white"
                                >
                                    <Search className="w-4 h-4" />
                                    {directRepoScan.trim() ? 'Scan Repository' : 'Search GitHub'}
                                </button>
                            )}
                        </div>

                        {progress && 'pagesSearched' in progress && (
                            <div className={`mt-4 text-sm ${textSecondary}`}>
                                <div className="flex items-center gap-4">
                                    <span>Pages: {progress.pagesSearched}</span>
                                    <span>Results: {progress.resultsFound}</span>
                                    <span className="text-emerald-500 font-medium">Secrets Found: {liveFindings.length}</span>
                                    {progress.currentQuery && (
                                        <span className="text-cyan-500 truncate max-w-xs">Query: {progress.currentQuery}</span>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Live Findings While Scanning */}
                        {isScanning && liveFindings.length > 0 && (
                            <div className="space-y-4 mt-6">
                                <div className="flex items-center justify-between">
                                    <h2 className="text-lg font-semibold flex items-center gap-2">
                                        <Loader2 className="w-5 h-5 animate-spin text-cyan-500" />
                                        Found {liveFindings.length} secrets (scanning...)
                                    </h2>
                                </div>

                                <div className="space-y-3 max-h-[500px] overflow-y-auto">
                                    {liveFindings.slice(0, 50).map(finding =>
                                        renderGitHubFinding(finding)
                                    )}
                                    {liveFindings.length > 50 && (
                                        <p className={`text-sm ${textSecondary} text-center py-2`}>
                                            +{liveFindings.length - 50} more findings...
                                        </p>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* GitHub Results (Final) */}
                        {githubResult && !isScanning && (
                            <div className="space-y-4 mt-6">
                                <div className={`${bgCard} rounded-lg p-4 border ${borderColor}`}>
                                    {/* Header Row */}
                                    <div className="flex items-start justify-between mb-4">
                                        <div>
                                            <h2 className="text-lg font-semibold">GitHub Search Results</h2>
                                            <p className={`text-sm ${textSecondary} mt-1`}>
                                                {githubResult.repositoriesSearched.toLocaleString()} repos
                                                <span className="mx-2">•</span>
                                                {(githubResult.duration / 1000).toFixed(1)}s
                                                <span className="mx-2">•</span>
                                                <span className="text-emerald-400 font-medium">
                                                    {(githubResult.findings.length || liveFindings.length).toLocaleString()} secrets
                                                </span>
                                            </p>
                                        </div>

                                        {/* Export Buttons */}
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => downloadReport('html')}
                                                className={`px-3 py-1.5 ${bgInput} border ${borderColor} hover:border-cyan-500 rounded-lg text-sm flex items-center gap-1.5 transition-colors`}
                                            >
                                                <Download className="w-4 h-4" /> HTML
                                            </button>
                                            <button
                                                onClick={() => downloadReport('csv')}
                                                className={`px-3 py-1.5 ${bgInput} border ${borderColor} hover:border-cyan-500 rounded-lg text-sm flex items-center gap-1.5 transition-colors`}
                                            >
                                                <Download className="w-4 h-4" /> CSV
                                            </button>
                                        </div>
                                    </div>

                                    {/* Filters Row */}
                                    <div className={`flex items-center gap-4 py-3 px-3 rounded-lg ${darkMode ? 'bg-gray-900/50' : 'bg-gray-100'}`}>
                                        <span className={`text-xs font-medium uppercase tracking-wide ${textMuted}`}>Filters:</span>

                                        <select
                                            value={severityFilter}
                                            onChange={(e) => setSeverityFilter(e.target.value as any)}
                                            className={`px-2.5 py-1 ${bgInput} border ${borderColor} rounded text-sm focus:outline-none focus:border-cyan-500`}
                                        >
                                            <option value="all">All Severities</option>
                                            <option value="critical">Critical</option>
                                            <option value="high">High</option>
                                            <option value="medium">Medium</option>
                                        </select>

                                        <div className={`h-4 w-px ${darkMode ? 'bg-gray-700' : 'bg-gray-300'}`} />

                                        <label className={`flex items-center gap-1.5 text-sm cursor-pointer hover:text-cyan-400 transition-colors ${hideGeneric ? 'text-cyan-400' : textSecondary}`}>
                                            <input
                                                type="checkbox"
                                                checked={hideGeneric}
                                                onChange={(e) => setHideGeneric(e.target.checked)}
                                                className="rounded accent-cyan-500 w-3.5 h-3.5"
                                            />
                                            Hide Generic
                                        </label>

                                        <div className={`h-4 w-px ${darkMode ? 'bg-gray-700' : 'bg-gray-300'}`} />

                                        <label className={`flex items-center gap-1.5 text-sm cursor-pointer hover:text-emerald-400 transition-colors ${onlyShowWithBalance ? 'text-emerald-400' : textSecondary}`}>
                                            <input
                                                type="checkbox"
                                                checked={onlyShowWithBalance}
                                                onChange={(e) => handleBalanceFilterToggle(e.target.checked)}
                                                disabled={isFilteringByBalance}
                                                className="rounded accent-emerald-500 w-3.5 h-3.5"
                                            />
                                            <DollarSign className="w-3.5 h-3.5" />
                                            {isFilteringByBalance ? (
                                                <span className="flex items-center gap-1">
                                                    <Loader2 className="w-3 h-3 animate-spin" />
                                                    {balanceFilterProgress?.checked || 0}/{balanceFilterProgress?.total || 0}
                                                </span>
                                            ) : onlyShowWithBalance && fundedFindingIds.size > 0 ? (
                                                <span>Funded ({fundedFindingIds.size})</span>
                                            ) : (
                                                <span>Only Funded</span>
                                            )}
                                        </label>
                                    </div>

                                    {/* Balance Filter Progress Banner */}
                                    {isFilteringByBalance && balanceFilterProgress && (
                                        <div className="mb-4 p-3 bg-emerald-500/20 border border-emerald-500/50 rounded-lg">
                                            <div className="flex items-center gap-3">
                                                <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
                                                <div className="flex-1">
                                                    <p className="text-sm text-emerald-300">
                                                        Scanning wallets for balances... {balanceFilterProgress.checked} / {balanceFilterProgress.total}
                                                    </p>
                                                    <p className="text-xs text-emerald-400/70">
                                                        Found {balanceFilterProgress.funded} with funds so far
                                                    </p>
                                                    <div className="mt-1 h-1 bg-emerald-900 rounded-full overflow-hidden">
                                                        <div
                                                            className="h-full bg-emerald-500 transition-all duration-300"
                                                            style={{ width: `${(balanceFilterProgress.checked / balanceFilterProgress.total) * 100}%` }}
                                                        />
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {renderSummary(null, githubResult)}

                                    {/* Filter chips - clickable to filter */}
                                    {githubResult.summary.mostCommonSecrets.length > 0 && (
                                        <div className="flex flex-wrap gap-2 mt-4">
                                            {githubResult.summary.mostCommonSecrets.slice(0, 8).map(s => (
                                                <button
                                                    key={s.type}
                                                    onClick={() => {
                                                        // If it's a generic type, toggle hide
                                                        if (s.type === 'Potential Secret' || s.type === 'Base64 Encoded Secret') {
                                                            setHideGeneric(!hideGeneric);
                                                        }
                                                    }}
                                                    className={`px-2 py-1 ${bgInput} rounded text-sm hover:opacity-80 transition-opacity ${(s.type === 'Potential Secret' || s.type === 'Base64 Encoded Secret') && hideGeneric
                                                        ? 'opacity-50 line-through'
                                                        : ''
                                                        }`}
                                                >
                                                    {s.type}: {s.count}
                                                </button>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Filtered count info */}
                                {(() => {
                                    const allFindings = githubResult.findings.length > 0 ? githubResult.findings : liveFindings;
                                    const filteredFindings = filterFindings(allFindings);
                                    const hiddenCount = allFindings.length - filteredFindings.length;

                                    return (
                                        <>
                                            {hiddenCount > 0 && (
                                                <p className={`text-sm ${textSecondary} mb-3`}>
                                                    Showing {filteredFindings.length} of {allFindings.length} findings ({hiddenCount} hidden by filters)
                                                </p>
                                            )}
                                            <div className="space-y-3">
                                                {filteredFindings.map(finding =>
                                                    renderGitHubFinding(finding as GitHubSecretFinding)
                                                )}
                                            </div>
                                        </>
                                    );
                                })()}

                                {githubResult.findings.length === 0 && liveFindings.length === 0 && (
                                    <div className="bg-emerald-500/20 border border-emerald-500/30 rounded-lg p-6 text-center">
                                        <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-3" />
                                        <h3 className="text-lg font-semibold text-emerald-400">No Secrets Found</h3>
                                        <p className={`text-sm mt-1 ${textSecondary}`}>
                                            No leaked secrets detected for this search query.
                                        </p>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}

export default CodeScanner;

// STRIX SAST - GitHub Secret Scanner
// Scan GitHub for leaked secrets, API keys, and credentials

import {
    GitHubSearchOptions,
    GitHubSearchProgress,
    GitHubSecretFinding,
    GitHubScanResult,
    GitHubScanSummary,
    GitHubRepoScanOptions,
    SeverityLevel,
    ScanError,
} from './types';

import { ALL_SECRET_PATTERNS } from './rules/secrets';
import { SecretPattern } from './types';

// GitHub API base URL
const GITHUB_API = 'https://api.github.com';

// Enhanced search queries - more specific and effective
export const SECRET_SEARCH_QUERIES = [
    // AWS - very specific patterns
    'AKIA',
    'AKID',
    'aws_secret_access_key',

    // Crypto/Blockchain - high value targets
    '0x extension:env privateKey',
    'mnemonic extension:env',
    'infura.io/v3/',
    'alchemy.com/v2/',

    // API Keys
    'sk_live_',
    'ghp_',
    'xoxb-',

    // Private Keys
    '"-----BEGIN RSA PRIVATE KEY-----"',
    '"-----BEGIN PRIVATE KEY-----"',

    // Database
    'mongodb+srv://',
    'postgres://',
];

// Enhanced search dorks - better organized and more effective
export const SECRET_DORKS: Record<string, string[]> = {
    'Crypto Private Keys': [
        // Ethereum/EVM keys - multiple search strategies
        'PRIVATE_KEY= 0x extension:env',
        'PRIVATE_KEY extension:env NOT example NOT sample',
        'privateKey "0x" extension:js NOT test NOT mock',
        'privateKey "0x" extension:ts NOT test NOT mock',
        'private_key "0x" extension:json',
        'DEPLOYER_PRIVATE_KEY extension:env',
        'WALLET_PRIVATE_KEY extension:env',
        'OWNER_PRIVATE_KEY extension:env',
        'ETH_PRIVATE_KEY extension:env',
        'secret_key "0x" extension:env',
        // Search in config files
        'filename:hardhat.config accounts "0x"',
        'filename:.env PRIVATE_KEY 0x',
        'filename:.env.local PRIVATE_KEY',
        'filename:truffle-config privateKey',
    ],
    'Seed Phrases / Mnemonics': [
        'MNEMONIC= extension:env NOT example',
        'SEED_PHRASE extension:env',
        'mnemonic "abandon" extension:env',
        'seedPhrase extension:js NOT test NOT example',
        'recovery_phrase extension:env',
        'filename:.env MNEMONIC',
        'filename:.env.local mnemonic',
        '"abandon abandon abandon" extension:env',
        '"abandon ability able" extension:js',
    ],
    'Infura API Keys': [
        'mainnet.infura.io/v3/ extension:js',
        'mainnet.infura.io/v3/ extension:ts',
        'mainnet.infura.io/v3/ extension:env',
        'INFURA_API_KEY extension:env',
        'INFURA_KEY extension:env',
        'INFURA_PROJECT_ID extension:env',
        'infura.io/v3/ NOT documentation NOT example',
        'filename:.env INFURA',
        'infuraId extension:json',
    ],
    'Alchemy API Keys': [
        'eth-mainnet.g.alchemy.com/v2/ extension:js',
        'eth-mainnet.g.alchemy.com/v2/ extension:env',
        'polygon-mainnet.g.alchemy.com extension:js',
        'ALCHEMY_API_KEY extension:env',
        'ALCHEMY_KEY extension:env',
        'alchemyApiKey extension:json NOT example',
        'filename:.env ALCHEMY',
    ],
    'Exchange API Keys': [
        'BINANCE_API_KEY extension:env',
        'BINANCE_SECRET extension:env',
        'COINBASE_API_KEY extension:env',
        'COINBASE_SECRET extension:env',
        'KRAKEN_API_KEY extension:env',
        'KRAKEN_PRIVATE_KEY extension:env',
        'KUCOIN_API_KEY extension:env',
        'KUCOIN_SECRET extension:env',
        'BYBIT_API_KEY extension:env',
        'BYBIT_SECRET extension:env',
        'OKX_API_KEY extension:env',
        'OKEX_API_KEY extension:env',
        'GATE_API_KEY extension:env',
        'HUOBI_API_KEY extension:env',
        'HTX_API_KEY extension:env',
        'BITFINEX_API_KEY extension:env',
        'GEMINI_API_KEY extension:env',
        'filename:.env BINANCE_API',
        'filename:.env COINBASE',
        'filename:.env KUCOIN',
        'filename:.env BYBIT',
    ],
    'Etherscan & Explorer Keys': [
        'ETHERSCAN_API_KEY extension:env',
        'BSCSCAN_API_KEY extension:env',
        'POLYGONSCAN_API_KEY extension:env',
        'ARBISCAN_API_KEY extension:env',
        'SNOWTRACE_API_KEY extension:env',
        'filename:.env ETHERSCAN',
        'etherscan apiKey extension:json',
    ],
    'AWS Credentials': [
        'AKIA extension:env',
        'AKIA extension:py',
        'AKIA extension:js',
        'aws_secret_access_key extension:env',
        'AWS_SECRET_ACCESS_KEY extension:env',
        'filename:.env AWS_ACCESS',
        'filename:credentials aws_secret',
    ],
    'Private Keys (PEM)': [
        '"-----BEGIN RSA PRIVATE KEY-----" extension:pem',
        '"-----BEGIN RSA PRIVATE KEY-----" extension:key',
        '"-----BEGIN OPENSSH PRIVATE KEY-----"',
        '"-----BEGIN EC PRIVATE KEY-----"',
        '"-----BEGIN PRIVATE KEY-----" extension:pem',
        'filename:id_rsa NOT .pub',
    ],
    'Database Credentials': [
        'mongodb+srv:// extension:env NOT example',
        'mongodb+srv:// password extension:json',
        'postgres:// password extension:env',
        'mysql:// password extension:env',
        'DATABASE_URL extension:env NOT example',
        'filename:.env DATABASE_URL',
        'filename:.env MONGO',
        'DB_PASSWORD extension:env',
    ],
    'Stripe Keys': [
        'sk_live_ extension:env',
        'sk_live_ extension:js NOT test',
        'STRIPE_SECRET_KEY extension:env',
        'stripe_api_key extension:json',
        'filename:.env STRIPE_SECRET',
    ],
    'GitHub Tokens': [
        'ghp_ extension:env',
        'ghp_ extension:yaml',
        'GITHUB_TOKEN extension:env NOT actions NOT workflow',
        'GH_TOKEN extension:env',
        'filename:.env GITHUB_TOKEN',
    ],
    'Slack Tokens': [
        'xoxb- extension:env',
        'xoxp- extension:env',
        'xoxb- extension:json',
        'SLACK_TOKEN extension:env',
        'SLACK_BOT_TOKEN extension:env',
    ],
    'Firebase Config': [
        'firebase apiKey extension:json NOT example',
        'firebaseConfig extension:js NOT example',
        'FIREBASE_API_KEY extension:env',
        'filename:.env FIREBASE',
    ],
    'SendGrid / Email': [
        'SENDGRID_API_KEY extension:env',
        'SG. extension:env sendgrid',
        'MAILGUN_API_KEY extension:env',
        'SMTP_PASSWORD extension:env',
    ],
    'Twilio': [
        'TWILIO_AUTH_TOKEN extension:env',
        'TWILIO_API_SECRET extension:env',
        'twilio accountSid authToken',
    ],
    '.env Files (General)': [
        'filename:.env.production NOT example',
        'filename:.env.local SECRET',
        'filename:.env PASSWORD NOT example NOT sample',
        'filename:.env API_KEY NOT example',
        'filename:.env.development SECRET',
    ],
};

/** Shuffle array in place (Fisher–Yates) and return it. */
function shuffle<T>(arr: T[]): T[] {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

export interface GitHubScannerOptions {
    token?: string;
    rateLimit?: number;
    secretPatterns?: SecretPattern[];
    onProgress?: (progress: GitHubSearchProgress) => void;
    onFinding?: (finding: GitHubSecretFinding) => void; // Real-time finding callback
    // Activity filter - only include repos active within this many days
    maxRepoAgeDays?: number; // Default: null (no filter), set to 365 for 1 year
    // Vary results each run: shuffle queries and use random page offset so you don't always get the same repos
    varyQueries?: boolean; // Default: true
}

export class GitHubScanner {
    private token?: string;
    private rateLimit: number;
    private secretPatterns: SecretPattern[];
    private onProgress?: (progress: GitHubSearchProgress) => void;
    private onFinding?: (finding: GitHubSecretFinding) => void;
    private requestCount = 0;
    private lastRequestTime = 0;
    private aborted = false;
    private allFindings: GitHubSecretFinding[] = [];
    private maxRepoAgeDays?: number;
    private varyQueries: boolean;
    private repoMetadataCache: Map<string, { updatedAt: string; pushedAt: string; stars: number; forks: number }> = new Map();

    constructor(options: GitHubScannerOptions = {}) {
        this.token = options.token;
        this.rateLimit = options.rateLimit || 10;
        this.secretPatterns = options.secretPatterns || ALL_SECRET_PATTERNS;
        this.onProgress = options.onProgress;
        this.onFinding = options.onFinding;
        this.maxRepoAgeDays = options.maxRepoAgeDays;
        this.varyQueries = options.varyQueries !== false;
    }

    setToken(token: string): void {
        this.token = token;
        this.rateLimit = 30;
    }

    setMaxRepoAge(days: number | undefined): void {
        this.maxRepoAgeDays = days;
    }

    abort(): void {
        this.aborted = true;
    }

    /**
     * Check if a repo was active within the allowed time window
     */
    private async isRepoActive(repoFullName: string): Promise<{ active: boolean; metadata?: any }> {
        if (!this.maxRepoAgeDays) {
            return { active: true }; // No filter, all repos are "active"
        }

        // Check cache first
        if (this.repoMetadataCache.has(repoFullName)) {
            const cached = this.repoMetadataCache.get(repoFullName)!;
            const pushedDate = new Date(cached.pushedAt);
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - this.maxRepoAgeDays);
            return { active: pushedDate >= cutoffDate, metadata: cached };
        }

        try {
            const response = await this.fetchGitHub(`/repos/${repoFullName}`);
            if (!response.ok) {
                return { active: true }; // On error, don't filter out
            }

            const repoData = await response.json();
            const metadata = {
                updatedAt: repoData.updated_at,
                pushedAt: repoData.pushed_at,
                stars: repoData.stargazers_count,
                forks: repoData.forks_count,
            };

            // Cache the result
            this.repoMetadataCache.set(repoFullName, metadata);

            const pushedDate = new Date(repoData.pushed_at);
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - this.maxRepoAgeDays);

            return { active: pushedDate >= cutoffDate, metadata };
        } catch {
            return { active: true }; // On error, don't filter out
        }
    }

    /**
     * Search GitHub for secrets using predefined queries
     */
    async searchForSecrets(options: Partial<GitHubSearchOptions> = {}): Promise<GitHubScanResult> {
        this.aborted = false;
        this.allFindings = [];
        const startTime = new Date();
        const errors: ScanError[] = [];
        // Vary results: shuffle queries and use random page offset so each run doesn't pull the same repos
        const queries = options.query
            ? [options.query]
            : this.varyQueries
                ? shuffle([...SECRET_SEARCH_QUERIES]).slice(0, 14)
                : SECRET_SEARCH_QUERIES.slice(0, 10);
        const pageOffset = this.varyQueries ? Math.floor(Math.random() * 5) : 0; // 0-4 so pages 1-3, 2-4, ... 4-6
        const pageStart = 1 + pageOffset;
        const pageEnd = 3 + pageOffset;
        let repositoriesSearched = 0;
        let totalPages = 0;

        const scanId = `github_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

        this.reportProgress(0, 0, 0, queries[0]);

        for (let i = 0; i < queries.length && !this.aborted; i++) {
            const query = queries[i];

            try {
                // Search multiple pages per query (vary which pages to avoid always same results)
                for (let page = pageStart; page <= pageEnd && !this.aborted; page++) {
                    const searchResults = await this.searchCode(query, {
                        language: options.language,
                        org: options.org,
                        user: options.user,
                        repo: options.repo,
                        perPage: options.perPage || 100,
                        page,
                        sort: 'indexed', // Most recently indexed first
                    });

                    if (!searchResults.items || searchResults.items.length === 0) break;

                    repositoriesSearched += searchResults.repositories;
                    totalPages++;

                    // Analyze each result for secrets - emit findings in real-time
                    for (const result of searchResults.items) {
                        if (this.aborted) break;

                        // Check repo activity if filter is enabled
                        const repoFullName = result.repository?.full_name;
                        if (this.maxRepoAgeDays && repoFullName) {
                            const { active, metadata } = await this.isRepoActive(repoFullName);
                            if (!active) {
                                continue; // Skip inactive repos
                            }
                            // Store metadata for later use
                            if (metadata) {
                                this.repoMetadataCache.set(repoFullName, metadata);
                            }
                        }

                        const secretFindings = this.analyzeSearchResult(result);

                        for (const finding of secretFindings) {
                            this.allFindings.push(finding);
                            // Emit finding immediately
                            if (this.onFinding) {
                                this.onFinding(finding);
                            }
                        }
                    }

                    this.reportProgress(this.allFindings.length, totalPages, this.allFindings.length, query);

                    // If we got fewer results than requested, no more pages
                    if (searchResults.items.length < (options.perPage || 100)) break;
                }
            } catch (err: any) {
                if (err.message.includes('rate limit')) {
                    errors.push({
                        message: `Rate limited on query "${query}". Waiting...`,
                    });
                    await this.delay(10000); // Wait 10 seconds
                } else if (err.message.includes('403')) {
                    errors.push({
                        message: `Access denied for query "${query}". Token may lack permissions.`,
                    });
                } else if (err.message.includes('422')) {
                    // Query syntax error - skip
                    errors.push({
                        message: `Invalid query syntax: "${query}"`,
                    });
                } else {
                    errors.push({
                        message: `Error searching "${query}": ${err.message}`,
                    });
                }
            }
        }

        const endTime = new Date();
        const dedupedFindings = this.deduplicateFindings(this.allFindings);

        return {
            scanId,
            queries,
            startTime,
            endTime,
            duration: endTime.getTime() - startTime.getTime(),
            repositoriesSearched,
            findings: dedupedFindings,
            summary: this.generateSummary(dedupedFindings),
            errors: errors.length > 0 ? errors : undefined,
        };
    }

    /**
     * Search using specific dorks for a category
     */
    async searchByCategory(category: keyof typeof SECRET_DORKS): Promise<GitHubScanResult> {
        const rawDorks = SECRET_DORKS[category] || [];
        const dorks = this.varyQueries ? shuffle([...rawDorks]) : rawDorks;
        this.allFindings = [];
        const errors: ScanError[] = [];
        const startTime = new Date();
        let repositoriesSearched = 0;
        let totalPages = 0;
        const pageOffset = this.varyQueries ? Math.floor(Math.random() * 3) : 0; // 0-2 so pages 1-2, 2-3, or 3-4
        const pageStart = 1 + pageOffset;
        const pageEnd = 2 + pageOffset;

        this.aborted = false;
        this.reportProgress(0, 0, 0, dorks[0]);

        for (let i = 0; i < dorks.length && !this.aborted; i++) {
            const dork = dorks[i];

            try {
                // Search with pagination (vary pages to avoid same repos every run)
                for (let page = pageStart; page <= pageEnd && !this.aborted; page++) {
                    const searchResults = await this.searchCode(dork, {
                        perPage: 100,
                        page,
                        sort: 'indexed',
                    });

                    if (!searchResults.items || searchResults.items.length === 0) break;

                    repositoriesSearched += searchResults.repositories;
                    totalPages++;

                    for (const result of searchResults.items) {
                        if (this.aborted) break;

                        // Check repo activity if filter is enabled
                        const repoFullName = result.repository?.full_name;
                        if (this.maxRepoAgeDays && repoFullName) {
                            const { active, metadata } = await this.isRepoActive(repoFullName);
                            if (!active) {
                                continue; // Skip inactive repos
                            }
                            if (metadata) {
                                this.repoMetadataCache.set(repoFullName, metadata);
                            }
                        }

                        const secretFindings = this.analyzeSearchResult(result);

                        for (const finding of secretFindings) {
                            this.allFindings.push(finding);
                            if (this.onFinding) {
                                this.onFinding(finding);
                            }
                        }
                    }

                    this.reportProgress(this.allFindings.length, totalPages, this.allFindings.length, dork);

                    if (searchResults.items.length < 100) break;
                }
            } catch (err: any) {
                if (!err.message.includes('422')) { // Ignore query syntax errors
                    errors.push({ message: `Dork "${dork}" failed: ${err.message}` });
                }
            }

            // Small delay between queries
            await this.delay(500);
        }

        const endTime = new Date();
        const dedupedFindings = this.deduplicateFindings(this.allFindings);

        return {
            scanId: `github_cat_${Date.now()}`,
            queries: dorks,
            startTime,
            endTime,
            duration: endTime.getTime() - startTime.getTime(),
            repositoriesSearched,
            findings: dedupedFindings,
            summary: this.generateSummary(dedupedFindings),
            errors: errors.length > 0 ? errors : undefined,
        };
    }

    /**
     * Quick search with a single query
     */
    async quickSearch(query: string, maxResults: number = 100): Promise<GitHubSecretFinding[]> {
        this.aborted = false;
        this.allFindings = [];

        try {
            const searchResults = await this.searchCode(query, {
                perPage: Math.min(maxResults, 100),
                page: 1,
                sort: 'indexed',
            });

            for (const result of searchResults.items || []) {
                if (this.aborted) break;

                // Check repo activity if filter is enabled
                const repoFullName = result.repository?.full_name;
                if (this.maxRepoAgeDays && repoFullName) {
                    const { active, metadata } = await this.isRepoActive(repoFullName);
                    if (!active) {
                        continue; // Skip inactive repos
                    }
                    if (metadata) {
                        this.repoMetadataCache.set(repoFullName, metadata);
                    }
                }

                const secretFindings = this.analyzeSearchResult(result);

                for (const finding of secretFindings) {
                    this.allFindings.push(finding);
                    if (this.onFinding) {
                        this.onFinding(finding);
                    }
                }
            }
        } catch (err: any) {
            console.error('Quick search error:', err);
        }

        return this.deduplicateFindings(this.allFindings);
    }

    /**
     * Search GitHub code API
     */
    private async searchCode(
        query: string,
        options: {
            language?: string;
            org?: string;
            user?: string;
            repo?: string;
            perPage?: number;
            page?: number;
            sort?: string;
        } = {}
    ): Promise<{ items: any[]; repositories: number; total_count: number }> {
        await this.throttle();

        let searchQuery = query;
        if (options.language) searchQuery += ` language:${options.language}`;
        if (options.org) searchQuery += ` org:${options.org}`;
        if (options.user) searchQuery += ` user:${options.user}`;
        if (options.repo) searchQuery += ` repo:${options.repo}`;

        const params = new URLSearchParams({
            q: searchQuery,
            per_page: String(options.perPage || 100),
            page: String(options.page || 1),
        });

        if (options.sort) {
            params.set('sort', options.sort);
            params.set('order', 'desc');
        }

        const response = await this.fetchGitHub(`/search/code?${params}`);

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.message || `GitHub API error: ${response.status}`);
        }

        const data = await response.json();

        const repos = new Set(data.items?.map((i: any) => i.repository?.full_name) || []);

        return {
            items: data.items || [],
            repositories: repos.size,
            total_count: data.total_count || 0,
        };
    }

    /**
     * Analyze search result for secrets
     */
    private analyzeSearchResult(result: any): GitHubSecretFinding[] {
        const findings: GitHubSecretFinding[] = [];
        const textMatches = result.text_matches || [];

        // Also check the result name and path for secrets
        const textsToCheck = [
            ...textMatches.map((m: any) => m.fragment || ''),
            result.name || '',
        ];

        for (const text of textsToCheck) {
            if (!text) continue;

            // Check against all secret patterns
            for (const pattern of this.secretPatterns) {
                pattern.pattern.lastIndex = 0;

                let match: RegExpExecArray | null;
                while ((match = pattern.pattern.exec(text)) !== null) {
                    // Skip if it looks like an example/placeholder
                    const matchText = match[0].toLowerCase();
                    if (matchText.includes('example') ||
                        matchText.includes('placeholder') ||
                        matchText.includes('your_') ||
                        matchText.includes('your-') ||
                        matchText.includes('<your') ||
                        matchText.includes('xxx') ||
                        matchText.includes('changeme') ||
                        matchText.includes('todo') ||
                        matchText.includes('replace') ||
                        matchText.includes('insert') ||
                        matchText.includes('dummy') ||
                        matchText.includes('sample') ||
                        matchText.includes('test_') ||
                        matchText.includes('fake') ||
                        matchText.includes('mock') ||
                        /^[x]{8,}$/i.test(matchText) ||
                        /^[0]{16,}$/.test(matchText) ||
                        matchText === '0x0000000000000000000000000000000000000000000000000000000000000000') {
                        continue;
                    }

                    // Get cached repo metadata if available
                    const repoName = result.repository?.full_name || 'unknown';
                    const cachedMeta = this.repoMetadataCache.get(repoName);

                    findings.push({
                        id: `gh_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`,
                        secretType: pattern.name,
                        severity: pattern.severity,
                        confidence: pattern.confidence,
                        repository: {
                            fullName: repoName,
                            url: result.repository?.html_url || '',
                            owner: result.repository?.owner?.login || 'unknown',
                            name: result.repository?.name || 'unknown',
                            isPrivate: result.repository?.private || false,
                            updatedAt: cachedMeta?.updatedAt || result.repository?.updated_at,
                            pushedAt: cachedMeta?.pushedAt || result.repository?.pushed_at,
                            stars: cachedMeta?.stars ?? result.repository?.stargazers_count,
                            forks: cachedMeta?.forks ?? result.repository?.forks_count,
                        },
                        file: {
                            path: result.path || '',
                            url: result.html_url || '',
                            sha: result.sha,
                        },
                        match: {
                            snippet: text.substring(
                                Math.max(0, match.index - 50),
                                Math.min(text.length, match.index + match[0].length + 50)
                            ),
                            line: this.getLineNumber(text, match.index),
                            matchedPattern: pattern.id,
                        },
                        timestamp: new Date(),
                    });

                    // Prevent infinite loop
                    if (match.index === pattern.pattern.lastIndex) {
                        pattern.pattern.lastIndex++;
                    }
                }
            }
        }

        // Also create a finding for the raw match even if no pattern matches
        // This ensures we show something for the search result
        if (findings.length === 0 && textMatches.length > 0) {
            const firstMatch = textMatches[0];
            const repoName = result.repository?.full_name || 'unknown';
            const cachedMeta = this.repoMetadataCache.get(repoName);

            findings.push({
                id: `gh_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`,
                secretType: 'Potential Secret',
                severity: 'medium',
                confidence: 'low',
                repository: {
                    fullName: repoName,
                    url: result.repository?.html_url || '',
                    owner: result.repository?.owner?.login || 'unknown',
                    name: result.repository?.name || 'unknown',
                    isPrivate: result.repository?.private || false,
                    updatedAt: cachedMeta?.updatedAt || result.repository?.updated_at,
                    pushedAt: cachedMeta?.pushedAt || result.repository?.pushed_at,
                    stars: cachedMeta?.stars ?? result.repository?.stargazers_count,
                    forks: cachedMeta?.forks ?? result.repository?.forks_count,
                },
                file: {
                    path: result.path || '',
                    url: result.html_url || '',
                    sha: result.sha,
                },
                match: {
                    snippet: firstMatch.fragment || '',
                    matchedPattern: 'search-match',
                },
                timestamp: new Date(),
            });
        }

        return findings;
    }

    private getLineNumber(text: string, index: number): number {
        return text.substring(0, index).split('\n').length;
    }

    private async fetchGitHub(endpoint: string): Promise<Response> {
        const headers: Record<string, string> = {
            'Accept': 'application/vnd.github.v3.text-match+json',
            'User-Agent': 'STRIX-Security-Scanner',
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        this.requestCount++;
        this.lastRequestTime = Date.now();

        return fetch(`${GITHUB_API}${endpoint}`, { headers });
    }

    private async throttle(): Promise<void> {
        const minInterval = (60 * 1000) / this.rateLimit;
        const elapsed = Date.now() - this.lastRequestTime;

        if (elapsed < minInterval) {
            await this.delay(minInterval - elapsed);
        }
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private deduplicateFindings(findings: GitHubSecretFinding[]): GitHubSecretFinding[] {
        const seen = new Set<string>();
        return findings.filter(f => {
            // Dedupe by repo + file + snippet hash
            const snippetHash = f.match.snippet.substring(0, 50);
            const key = `${f.repository.fullName}:${f.file.path}:${snippetHash}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    private generateSummary(findings: GitHubSecretFinding[]): GitHubScanSummary {
        const bySeverity: Record<SeverityLevel, number> = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0
        };
        const bySecretType: Record<string, number> = {};
        const byRepo: Record<string, number> = {};

        for (const finding of findings) {
            bySeverity[finding.severity]++;
            bySecretType[finding.secretType] = (bySecretType[finding.secretType] || 0) + 1;
            byRepo[finding.repository.fullName] = (byRepo[finding.repository.fullName] || 0) + 1;
        }

        const byRepository = Object.entries(byRepo)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([repo, count]) => ({ repo, findings: count }));

        const mostCommonSecrets = Object.entries(bySecretType)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([type, count]) => ({ type, count }));

        return {
            totalFindings: findings.length,
            bySeverity,
            bySecretType,
            byRepository,
            mostCommonSecrets,
        };
    }

    private reportProgress(
        results: number,
        pages: number,
        secrets: number,
        query?: string
    ): void {
        if (!this.onProgress) return;

        this.onProgress({
            resultsFound: results,
            pagesSearched: pages,
            secretsFound: secrets,
            currentQuery: query,
        });
    }

    /**
     * Scan a specific repository for secrets
     * This searches within a single repo rather than across all of GitHub
     */
    async scanRepository(options: GitHubRepoScanOptions): Promise<GitHubScanResult> {
        this.aborted = false;
        this.allFindings = [];
        const startTime = new Date();
        const errors: ScanError[] = [];
        let totalPages = 0;

        const scanId = `github_repo_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

        // Secret-focused search queries to run within this repo
        const repoSearchQueries = [
            // High-value targets
            'extension:env',
            'filename:.env',
            'filename:config password',
            'filename:secret',
            'PRIVATE_KEY',
            'API_KEY',
            'SECRET_KEY',
            'password',
            'token',
            'credential',
            'BEGIN RSA',
            'BEGIN PRIVATE KEY',
            'mongodb+srv',
            'postgres://',
            'mysql://',
            '0x', // Ethereum keys
            'mnemonic',
            'seed',
            'ghp_',
            'sk_live',
            'sk_test',
        ];

        this.reportProgress(0, 0, 0, `Scanning ${options.repoFullName}...`);

        // Get repo metadata first
        try {
            const repoResponse = await this.fetchGitHub(`/repos/${options.repoFullName}`);
            if (repoResponse.ok) {
                const repoData = await repoResponse.json();
                this.repoMetadataCache.set(options.repoFullName, {
                    updatedAt: repoData.updated_at,
                    pushedAt: repoData.pushed_at,
                    stars: repoData.stargazers_count,
                    forks: repoData.forks_count,
                });
            }
        } catch (e) {
            // Non-fatal - continue without metadata
        }

        for (let i = 0; i < repoSearchQueries.length && !this.aborted; i++) {
            const query = repoSearchQueries[i];

            try {
                // Search within this specific repo
                for (let page = 1; page <= 5 && !this.aborted; page++) {
                    const searchResults = await this.searchCode(`${query} repo:${options.repoFullName}`, {
                        perPage: 100,
                        page,
                        sort: 'indexed',
                    });

                    if (!searchResults.items || searchResults.items.length === 0) break;

                    totalPages++;

                    for (const result of searchResults.items) {
                        if (this.aborted) break;

                        // Check path filters if specified
                        if (options.excludePaths && options.excludePaths.length > 0) {
                            const path = result.path || '';
                            const shouldExclude = options.excludePaths.some(pattern => {
                                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                                return regex.test(path);
                            });
                            if (shouldExclude) continue;
                        }

                        if (options.includePaths && options.includePaths.length > 0) {
                            const path = result.path || '';
                            const shouldInclude = options.includePaths.some(pattern => {
                                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                                return regex.test(path);
                            });
                            if (!shouldInclude) continue;
                        }

                        const secretFindings = this.analyzeSearchResult(result);

                        for (const finding of secretFindings) {
                            this.allFindings.push(finding);
                            if (this.onFinding) {
                                this.onFinding(finding);
                            }
                        }
                    }

                    this.reportProgress(this.allFindings.length, totalPages, this.allFindings.length, `${options.repoFullName}: ${query}`);

                    if (searchResults.items.length < 100) break;
                }
            } catch (err: any) {
                if (err.message.includes('rate limit')) {
                    await this.delay(10000);
                } else if (!err.message.includes('422')) {
                    errors.push({ message: `Query "${query}" in ${options.repoFullName}: ${err.message}` });
                }
            }

            // Small delay between queries
            await this.delay(300);
        }

        const endTime = new Date();
        const dedupedFindings = this.deduplicateFindings(this.allFindings);

        return {
            scanId,
            queries: [`repo:${options.repoFullName}`],
            startTime,
            endTime,
            duration: endTime.getTime() - startTime.getTime(),
            repositoriesSearched: 1,
            findings: dedupedFindings,
            summary: this.generateSummary(dedupedFindings),
            errors: errors.length > 0 ? errors : undefined,
        };
    }
}

export async function searchGitHubSecrets(
    query?: string,
    token?: string
): Promise<GitHubScanResult> {
    const scanner = new GitHubScanner({ token });
    return scanner.searchForSecrets({ query });
}

export async function scanRepository(
    repoFullName: string,
    token?: string,
    options?: Partial<GitHubRepoScanOptions>
): Promise<GitHubScanResult> {
    const scanner = new GitHubScanner({ token });
    return scanner.scanRepository({ repoFullName, ...options });
}

export async function searchByCategory(
    category: keyof typeof SECRET_DORKS,
    token?: string
): Promise<GitHubScanResult> {
    const scanner = new GitHubScanner({ token });
    return scanner.searchByCategory(category);
}

export default GitHubScanner;

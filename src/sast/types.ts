// STRIX SAST (Static Application Security Testing) Types
// Code scanning and secret detection type definitions

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ConfidenceLevel = 'high' | 'medium' | 'low';

export interface SourceLocation {
    file: string;
    line: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
    snippet: string;
    context?: string[]; // Surrounding lines for context
}

export interface SASTFinding {
    id: string;
    ruleId: string;
    title: string;
    description: string;
    severity: SeverityLevel;
    confidence: ConfidenceLevel;
    category: VulnerabilityCategory;
    location: SourceLocation;
    cwe?: string[];
    owasp?: string[];
    remediation?: string;
    references?: string[];
    metadata?: Record<string, any>;
    falsePositive?: boolean;
    timestamp: Date;
}

export type VulnerabilityCategory =
    | 'hardcoded-secret'
    | 'injection'
    | 'xss'
    | 'path-traversal'
    | 'insecure-crypto'
    | 'insecure-deserialization'
    | 'authentication'
    | 'authorization'
    | 'sensitive-data-exposure'
    | 'security-misconfiguration'
    | 'vulnerable-dependency'
    | 'code-quality'
    | 'other';

export interface SecretPattern {
    id: string;
    name: string;
    description: string;
    pattern: RegExp;
    severity: SeverityLevel;
    confidence: ConfidenceLevel;
    keywords?: string[]; // Quick pre-filter keywords
    validator?: (match: string) => boolean; // Optional validation function
    falsePositivePatterns?: RegExp[]; // Patterns that indicate false positive
}

export interface VulnerabilityRule {
    id: string;
    name: string;
    description: string;
    category: VulnerabilityCategory;
    severity: SeverityLevel;
    languages: string[];
    patterns: RulePattern[];
    cwe?: string[];
    owasp?: string[];
    remediation: string;
    references?: string[];
}

export interface RulePattern {
    type: 'regex' | 'ast' | 'semantic';
    pattern: RegExp | string;
    message: string;
    negative?: RegExp; // Pattern that should NOT match (for reducing false positives)
}

export interface ScanOptions {
    targetPath: string;
    recursive?: boolean;
    includePatterns?: string[];
    excludePatterns?: string[];
    maxFileSize?: number; // bytes
    maxFiles?: number;
    enabledCategories?: VulnerabilityCategory[];
    disabledRules?: string[];
    customRules?: VulnerabilityRule[];
    secretPatterns?: SecretPattern[];
    onProgress?: (progress: ScanProgress) => void;
}

export interface ScanProgress {
    phase: 'discovering' | 'scanning' | 'analyzing' | 'complete';
    filesDiscovered: number;
    filesScanned: number;
    currentFile?: string;
    findingsCount: number;
    percentage: number;
}

export interface ScanResult {
    scanId: string;
    targetPath: string;
    startTime: Date;
    endTime: Date;
    duration: number;
    filesScanned: number;
    linesScanned: number;
    findings: SASTFinding[];
    summary: ScanSummary;
    errors?: ScanError[];
}

export interface ScanSummary {
    totalFindings: number;
    bySeverity: Record<SeverityLevel, number>;
    byCategory: Record<VulnerabilityCategory, number>;
    byConfidence: Record<ConfidenceLevel, number>;
    topFiles: Array<{ file: string; findings: number }>;
    riskScore: number; // 0-100
}

export interface ScanError {
    file?: string;
    message: string;
    stack?: string;
}

// GitHub Scanner Types
export interface GitHubSearchOptions {
    query: string;
    searchType: 'code' | 'repositories' | 'commits';
    language?: string;
    org?: string;
    user?: string;
    repo?: string;
    perPage?: number;
    maxResults?: number;
    sortBy?: 'indexed' | 'best-match';
    onProgress?: (progress: GitHubSearchProgress) => void;
    
    // Activity filter - only show results from recently active repos
    repoActivityFilter?: {
        enabled: boolean;
        maxAgeDays?: number; // Default 365 (1 year)
    };
}

// Direct repo scan options
export interface GitHubRepoScanOptions {
    repoFullName: string; // e.g., "owner/repo"
    branch?: string; // Default to default branch
    includePaths?: string[]; // Glob patterns to include
    excludePaths?: string[]; // Glob patterns to exclude
    maxFiles?: number; // Limit files to scan
    onProgress?: (progress: GitHubSearchProgress) => void;
}

export interface GitHubSearchProgress {
    resultsFound: number;
    pagesSearched: number;
    secretsFound: number;
    currentQuery?: string;
}

export interface GitHubSecretFinding {
    id: string;
    secretType: string;
    severity: SeverityLevel;
    confidence: ConfidenceLevel;
    repository: {
        fullName: string;
        url: string;
        owner: string;
        name: string;
        isPrivate: boolean;
        // Activity metadata
        updatedAt?: string;
        pushedAt?: string;
        stars?: number;
        forks?: number;
    };
    file: {
        path: string;
        url: string;
        sha?: string;
    };
    match: {
        snippet: string;
        line?: number;
        matchedPattern: string;
    };
    commitInfo?: {
        sha: string;
        author: string;
        date: string;
        message: string;
    };
    timestamp: Date;
}

export interface GitHubScanResult {
    scanId: string;
    queries: string[];
    startTime: Date;
    endTime: Date;
    duration: number;
    repositoriesSearched: number;
    findings: GitHubSecretFinding[];
    summary: GitHubScanSummary;
    rateLimitRemaining?: number;
    errors?: ScanError[];
}

export interface GitHubScanSummary {
    totalFindings: number;
    bySeverity: Record<SeverityLevel, number>;
    bySecretType: Record<string, number>;
    byRepository: Array<{ repo: string; findings: number }>;
    mostCommonSecrets: Array<{ type: string; count: number }>;
}

// File type detection
export interface FileInfo {
    path: string;
    relativePath: string;
    name: string;
    extension: string;
    language: string;
    size: number;
    isBinary: boolean;
}

export const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
    javascript: ['.js', '.jsx', '.mjs', '.cjs'],
    typescript: ['.ts', '.tsx', '.mts', '.cts'],
    python: ['.py', '.pyw', '.pyi'],
    java: ['.java'],
    csharp: ['.cs'],
    cpp: ['.cpp', '.cc', '.cxx', '.hpp', '.h'],
    go: ['.go'],
    rust: ['.rs'],
    ruby: ['.rb', '.erb'],
    php: ['.php', '.phtml'],
    swift: ['.swift'],
    kotlin: ['.kt', '.kts'],
    scala: ['.scala'],
    shell: ['.sh', '.bash', '.zsh'],
    powershell: ['.ps1', '.psm1', '.psd1'],
    sql: ['.sql'],
    html: ['.html', '.htm'],
    css: ['.css', '.scss', '.sass', '.less'],
    yaml: ['.yml', '.yaml'],
    json: ['.json'],
    xml: ['.xml'],
    markdown: ['.md', '.markdown'],
    dockerfile: ['Dockerfile'],
    terraform: ['.tf', '.tfvars'],
    solidity: ['.sol'],
};

export const BINARY_EXTENSIONS = new Set([
    '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.class', '.pyc', '.pyo',
]);

export const DEFAULT_EXCLUDE_PATTERNS = [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/build/**',
    '**/coverage/**',
    '**/.next/**',
    '**/__pycache__/**',
    '**/venv/**',
    '**/env/**',
    '**/.venv/**',
    '**/vendor/**',
    '**/target/**',
    '**/*.min.js',
    '**/*.min.css',
    '**/*.map',
    '**/package-lock.json',
    '**/yarn.lock',
    '**/pnpm-lock.yaml',
];

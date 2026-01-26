// STRIX SAST - Core Scanner Engine
// Static Application Security Testing implementation

import {
    SASTFinding,
    ScanOptions,
    ScanResult,
    ScanProgress,
    ScanSummary,
    ScanError,
    SecretPattern,
    VulnerabilityRule,
    FileInfo,
    SourceLocation,
    SeverityLevel,
    VulnerabilityCategory,
    ConfidenceLevel,
    LANGUAGE_EXTENSIONS,
    BINARY_EXTENSIONS,
    DEFAULT_EXCLUDE_PATTERNS,
} from './types';

import { ALL_SECRET_PATTERNS } from './rules/secrets';
import { ALL_VULNERABILITY_RULES } from './rules/vulnerabilities';

// Check if running in Node.js (Electron) or browser
const isNode = typeof process !== 'undefined' && process.versions?.node;

// Check if we have Electron IPC available
const hasElectronIPC = typeof window !== 'undefined' && 
    'ipcRenderer' in window && 
    typeof (window as any).ipcRenderer?.invoke === 'function';

// Dynamic imports for Node.js file system
let fs: any = null;
let path: any = null;

if (isNode && !hasElectronIPC) {
    // Will be loaded when scanner is initialized (only in main process)
}

export class SASTScanner {
    private secretPatterns: SecretPattern[];
    private vulnerabilityRules: VulnerabilityRule[];
    private options: ScanOptions;
    private findings: SASTFinding[] = [];
    private errors: ScanError[] = [];
    private filesScanned = 0;
    private linesScanned = 0;
    private aborted = false;

    constructor(options: Partial<ScanOptions> = {}) {
        this.options = {
            targetPath: options.targetPath || '',
            recursive: options.recursive ?? true,
            includePatterns: options.includePatterns || ['*'],
            excludePatterns: options.excludePatterns || DEFAULT_EXCLUDE_PATTERNS,
            maxFileSize: options.maxFileSize || 1024 * 1024, // 1MB default
            maxFiles: options.maxFiles || 10000,
            enabledCategories: options.enabledCategories,
            disabledRules: options.disabledRules || [],
            customRules: options.customRules || [],
            secretPatterns: options.secretPatterns || [],
            onProgress: options.onProgress,
        };

        // Initialize rules
        this.secretPatterns = [...ALL_SECRET_PATTERNS, ...(options.secretPatterns || [])];
        this.vulnerabilityRules = [
            ...ALL_VULNERABILITY_RULES.filter(r => !this.options.disabledRules?.includes(r.id)),
            ...(options.customRules || []),
        ];

        // Filter by enabled categories if specified
        if (this.options.enabledCategories?.length) {
            this.vulnerabilityRules = this.vulnerabilityRules.filter(
                r => this.options.enabledCategories!.includes(r.category)
            );
        }
    }

    /**
     * Initialize Node.js modules (must be called in Electron main or renderer with nodeIntegration)
     */
    async initNodeModules(): Promise<void> {
        if (isNode && !fs) {
            fs = await import('fs');
            path = await import('path');
        }
    }

    /**
     * Scan directory via Electron IPC (for renderer process)
     */
    async scanDirectoryViaIPC(targetPath: string): Promise<ScanResult> {
        console.log('[SASTScanner] scanDirectoryViaIPC called for:', targetPath);
        
        this.options.targetPath = targetPath;
        this.findings = [];
        this.errors = [];
        this.filesScanned = 0;
        this.linesScanned = 0;
        this.aborted = false;

        const startTime = new Date();
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

        this.reportProgress('discovering', 0, 0, 0);

        try {
            // Get files from main process via IPC
            console.log('[SASTScanner] Invoking IPC sast-scan-directory...');
            const response = await (window as any).ipcRenderer.invoke('sast-scan-directory', targetPath);
            console.log('[SASTScanner] IPC response:', response?.success, 'files:', response?.files?.length);
            
            if (!response.success) {
                throw new Error(response.error || 'Failed to scan directory');
            }

            const files = response.files || [];
            this.reportProgress('scanning', files.length, 0, 0);

            // Scan each file's content
            for (let i = 0; i < files.length && !this.aborted; i++) {
                const file = files[i];
                this.filesScanned++;
                
                try {
                    // Skip files that are likely to cause false positives
                    if (this.shouldSkipFile(file.relativePath, file.content)) {
                        continue;
                    }
                    
                    const lines = file.content.split('\n');
                    this.linesScanned += lines.length;
                    
                    // Create file info
                    const fileInfo: FileInfo = {
                        path: file.path,
                        relativePath: file.relativePath,
                        name: file.relativePath.split('/').pop() || file.relativePath,
                        size: file.size,
                        extension: file.extension,
                        language: this.detectLanguage(file.extension),
                        isBinary: false,
                    };

                    // Scan for secrets
                    for (const pattern of this.secretPatterns) {
                        const matches = file.content.matchAll(new RegExp(pattern.pattern.source, pattern.pattern.flags));
                        for (const match of matches) {
                            const value = match[0];
                            
                            // Skip false positives
                            if (this.isFalsePositive(value, pattern.id)) continue;

                            const lineNumber = this.getLineNumber(file.content, match.index || 0);
                            const column = this.getColumn(file.content, match.index || 0);

                            const contextStr = this.getContext(file.content, match.index || 0);
                            const lines = file.content.split('\n');
                            const snippetLine = lines[lineNumber - 1] || '';
                            
                            this.findings.push({
                                id: `${scanId}_${this.findings.length}`,
                                ruleId: pattern.id,
                                title: pattern.name,
                                description: pattern.description,
                                severity: pattern.severity,
                                confidence: pattern.confidence,
                                category: 'hardcoded-secret',
                                location: {
                                    file: fileInfo.relativePath,
                                    line: lineNumber,
                                    column,
                                    endLine: lineNumber,
                                    endColumn: column + value.length,
                                    snippet: this.redactSecret(snippetLine),
                                    context: contextStr.split('\n'),
                                },
                                cwe: ['CWE-798', 'CWE-259'],
                                owasp: ['A07:2021'],
                                remediation: 'Remove hardcoded secret and use environment variables or secure vault.',
                                metadata: {
                                    secretType: pattern.name,
                                    matchedValue: this.redactSecret(value),
                                },
                                timestamp: new Date(),
                            });
                        }
                    }

                    // Scan for vulnerabilities
                    for (const rule of this.vulnerabilityRules) {
                        if (!this.shouldApplyRule(rule, fileInfo)) continue;
                        
                        // Iterate through all patterns in the rule
                        for (const rulePattern of rule.patterns) {
                            if (rulePattern.type !== 'regex') continue;
                            
                            const pattern = rulePattern.pattern instanceof RegExp 
                                ? rulePattern.pattern 
                                : new RegExp(rulePattern.pattern, 'gi');
                            
                            const matches = file.content.matchAll(new RegExp(pattern.source, pattern.flags || 'gi'));
                            for (const match of matches) {
                                // Skip if negative pattern matches (false positive)
                                if (rulePattern.negative?.test(match[0])) continue;
                                
                                const lineNumber = this.getLineNumber(file.content, match.index || 0);
                                const column = this.getColumn(file.content, match.index || 0);

                                const vulnContextStr = this.getContext(file.content, match.index || 0);
                                const vulnLines = file.content.split('\n');
                                const vulnSnippetLine = vulnLines[lineNumber - 1] || '';
                                
                                this.findings.push({
                                    id: `${scanId}_${this.findings.length}`,
                                    ruleId: rule.id,
                                    title: rule.name,
                                    description: rulePattern.message || rule.description,
                                    severity: rule.severity,
                                    confidence: 'medium',
                                    category: rule.category,
                                    location: {
                                        file: fileInfo.relativePath,
                                        line: lineNumber,
                                        column,
                                        endLine: lineNumber,
                                        endColumn: column + match[0].length,
                                        snippet: vulnSnippetLine,
                                        context: vulnContextStr.split('\n'),
                                    },
                                    cwe: rule.cwe,
                                    owasp: rule.owasp,
                                    remediation: rule.remediation,
                                    references: rule.references,
                                    metadata: {
                                        matchedText: match[0],
                                    },
                                    timestamp: new Date(),
                                });
                            }
                        }
                    }
                } catch (err: any) {
                    this.errors.push({
                        file: file.path,
                        message: err.message,
                        stack: err.stack,
                    });
                }

                // Report progress
                this.reportProgress('scanning', files.length, i + 1, this.findings.length);
            }

            this.reportProgress('complete', files.length, files.length, this.findings.length);

            const endTime = new Date();
            const summary = this.generateSummary();

            return {
                scanId,
                targetPath,
                startTime,
                endTime,
                duration: endTime.getTime() - startTime.getTime(),
                findings: this.findings,
                errors: this.errors,
                summary,
                filesScanned: this.filesScanned,
                linesScanned: this.linesScanned,
            };
        } catch (err: any) {
            throw new Error(`Scan failed: ${err.message}`);
        }
    }

    /**
     * Helper: Check if a value is a false positive
     */
    private isFalsePositive(value: string, patternId: string): boolean {
        // Normalize value for checking
        const normalizedValue = value.toLowerCase().trim();
        
        // Common false positive patterns
        const falsePositivePatterns = [
            /^(example|test|sample|dummy|fake|placeholder|xxx|your[-_]?)/i,
            /^(0{8,}|1{8,}|a{8,}|x{8,}|y{8,}|z{8,})/i,
            /^\$\{.*\}$/,              // Template variables ${...}
            /^<.*>$/,                   // Placeholder syntax <...>
            /^\{\{.*\}\}$/,             // Mustache templates {{...}}
            /^%[A-Z_]+%$/,              // Environment variable placeholders %VAR%
            /process\.env\./,           // Node.js environment references
            /^(insert|add|enter|put)[-_]?(here|your|api|key|token|secret)/i,
            /^(my|your|the)[-_]?(api|secret|private)[-_]?(key|token)/i,
            /^sk[-_]?(test|live|demo)[-_]/i,  // Stripe test keys
            /^pk[-_]?(test|live|demo)[-_]/i,  // Stripe publishable test keys
        ];
        
        // Check if value matches any false positive pattern
        if (falsePositivePatterns.some(fp => fp.test(value))) {
            return true;
        }
        
        // Skip if value is all same character repeated
        if (/^(.)\1{7,}$/.test(normalizedValue)) {
            return true;
        }
        
        // Skip common placeholder values
        const placeholderValues = [
            'your-api-key', 'your_api_key', 'api-key-here', 'api_key_here',
            'your-secret-key', 'your_secret_key', 'secret-key-here',
            'enter-your-key', 'insert-key-here', 'replace-with-your-key',
            'your-token', 'your_token', 'token-here', 'insert-token',
            'changeme', 'change-me', 'change_me', 'password123', 'secret123',
            'abcdefghijklmnopqrstuvwxyz', '1234567890123456789012345678901234567890',
            'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'demo', 'development', 'testing',
        ];
        
        if (placeholderValues.some(p => normalizedValue.includes(p))) {
            return true;
        }
        
        // Skip extremely short values (likely not real secrets)
        if (value.length < 8) {
            return true;
        }
        
        // Skip values that are mostly numbers in sequence
        const digitSequence = normalizedValue.replace(/[^0-9]/g, '');
        if (digitSequence.length > 10) {
            const isSequential = /0123456789|1234567890|9876543210/.test(digitSequence);
            if (isSequential) return true;
        }
        
        return false;
    }

    /**
     * Helper: Get line number from character index
     */
    private getLineNumber(content: string, index: number): number {
        return content.substring(0, index).split('\n').length;
    }

    /**
     * Helper: Get column number from character index
     */
    private getColumn(content: string, index: number): number {
        const lastNewline = content.lastIndexOf('\n', index - 1);
        return index - lastNewline;
    }

    /**
     * Helper: Redact secret value for display
     */
    private redactSecret(value: string): string {
        if (value.length <= 8) return '*'.repeat(value.length);
        return value.substring(0, 4) + '*'.repeat(value.length - 8) + value.substring(value.length - 4);
    }

    /**
     * Helper: Get context around a match
     */
    private getContext(content: string, index: number, contextLines: number = 2): string {
        const lines = content.split('\n');
        const lineNum = this.getLineNumber(content, index);
        const start = Math.max(0, lineNum - contextLines - 1);
        const end = Math.min(lines.length, lineNum + contextLines);
        return lines.slice(start, end).join('\n');
    }

    /**
     * Helper: Check if rule should apply to file
     */
    private shouldApplyRule(rule: VulnerabilityRule, file: FileInfo): boolean {
        // If rule specifies languages, check if file language matches
        if (rule.languages && rule.languages.length > 0) {
            return rule.languages.includes(file.language);
        }
        return true;
    }

    /**
     * Helper: Check if file should be skipped (likely false positives)
     */
    private shouldSkipFile(relativePath: string, content: string): boolean {
        const normalizedPath = relativePath.toLowerCase().replace(/\\/g, '/');
        
        // Skip common directories that contain third-party code
        const skipDirs = [
            'node_modules/',
            'vendor/',
            '.git/',
            'dist/',
            'build/',
            '.next/',
            '__pycache__/',
            '.venv/',
            'venv/',
            'bower_components/',
            '.bundle/',
            'target/',
            'out/',
            'bin/',
            'obj/',
            '.nuget/',
            'packages/',
            '.gradle/',
        ];
        
        if (skipDirs.some(dir => normalizedPath.includes(dir))) {
            return true;
        }
        
        // Skip minified files
        if (/\.min\.(js|css)$/.test(normalizedPath)) {
            return true;
        }
        
        // Skip bundle files
        if (/\.(bundle|chunk)\.(js|css)$/.test(normalizedPath)) {
            return true;
        }
        
        // Skip source maps
        if (/\.map$/.test(normalizedPath)) {
            return true;
        }
        
        // Skip lock files
        if (/\.(lock|lockb)$/.test(normalizedPath) || /lock\.json$/.test(normalizedPath)) {
            return true;
        }
        
        // Skip browser extension manifest files (they often have fake/example keys)
        if (normalizedPath.includes('extensions/') && normalizedPath.endsWith('manifest.json')) {
            return true;
        }
        
        // Skip files that are likely minified (very long lines)
        const lines = content.split('\n');
        const avgLineLength = content.length / Math.max(lines.length, 1);
        if (avgLineLength > 500 && lines.length < 50) {
            // File has very long lines but few of them - likely minified
            return true;
        }
        
        // Skip files with extremely long single lines (minified code)
        if (lines.some(line => line.length > 5000)) {
            return true;
        }
        
        return false;
    }

    /**
     * Abort the current scan
     */
    abort(): void {
        this.aborted = true;
    }

    /**
     * Scan a directory for security issues
     */
    async scanDirectory(targetPath: string): Promise<ScanResult> {
        console.log('[SASTScanner] scanDirectory called');
        console.log('[SASTScanner] hasElectronIPC:', hasElectronIPC);
        
        // Use Electron IPC if available (renderer process)
        if (hasElectronIPC) {
            console.log('[SASTScanner] Using IPC method');
            return this.scanDirectoryViaIPC(targetPath);
        }
        
        console.log('[SASTScanner] Using Node.js method');
        
        await this.initNodeModules();
        
        if (!fs || !path) {
            throw new Error('File system access not available. This scanner requires Node.js/Electron.');
        }

        this.options.targetPath = targetPath;
        this.findings = [];
        this.errors = [];
        this.filesScanned = 0;
        this.linesScanned = 0;
        this.aborted = false;

        const startTime = new Date();
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        this.reportProgress('discovering', 0, 0, 0);

        try {
            // Discover files
            const files = await this.discoverFiles(targetPath);
            this.reportProgress('scanning', files.length, 0, 0);

            // Scan each file
            for (let i = 0; i < files.length && !this.aborted; i++) {
                const file = files[i];
                try {
                    await this.scanFile(file);
                } catch (err: any) {
                    this.errors.push({
                        file: file.path,
                        message: err.message,
                        stack: err.stack,
                    });
                }

                this.filesScanned++;
                this.reportProgress('scanning', files.length, this.filesScanned, this.findings.length);
            }

            this.reportProgress('analyzing', files.length, this.filesScanned, this.findings.length);

            // Deduplicate findings
            this.findings = this.deduplicateFindings(this.findings);

        } catch (err: any) {
            this.errors.push({
                message: `Scan failed: ${err.message}`,
                stack: err.stack,
            });
        }

        const endTime = new Date();
        this.reportProgress('complete', this.filesScanned, this.filesScanned, this.findings.length);

        return {
            scanId,
            targetPath,
            startTime,
            endTime,
            duration: endTime.getTime() - startTime.getTime(),
            filesScanned: this.filesScanned,
            linesScanned: this.linesScanned,
            findings: this.findings,
            summary: this.generateSummary(),
            errors: this.errors.length > 0 ? this.errors : undefined,
        };
    }

    /**
     * Scan a single file's content (can be used without filesystem access)
     */
    scanContent(content: string, filename: string): SASTFinding[] {
        const findings: SASTFinding[] = [];
        const lines = content.split('\n');
        const language = this.detectLanguage(filename);

        // Scan for secrets
        for (const pattern of this.secretPatterns) {
            const secretFindings = this.scanForSecret(content, lines, filename, pattern);
            findings.push(...secretFindings);
        }

        // Scan for vulnerabilities
        for (const rule of this.vulnerabilityRules) {
            // Skip if rule doesn't apply to this language
            if (rule.languages.length > 0 && !rule.languages.includes(language)) {
                continue;
            }

            const vulnFindings = this.scanForVulnerability(content, lines, filename, rule);
            findings.push(...vulnFindings);
        }

        return findings;
    }

    /**
     * Discover all files to scan
     */
    private async discoverFiles(dirPath: string): Promise<FileInfo[]> {
        const files: FileInfo[] = [];
        
        const walkDir = async (currentPath: string): Promise<void> => {
            if (this.aborted || files.length >= this.options.maxFiles!) return;

            const entries = await fs.promises.readdir(currentPath, { withFileTypes: true });

            for (const entry of entries) {
                if (this.aborted || files.length >= this.options.maxFiles!) break;

                const fullPath = path.join(currentPath, entry.name);
                const relativePath = path.relative(this.options.targetPath, fullPath);

                // Check exclude patterns
                if (this.matchesPattern(relativePath, this.options.excludePatterns!)) {
                    continue;
                }

                if (entry.isDirectory() && this.options.recursive) {
                    await walkDir(fullPath);
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name).toLowerCase();
                    
                    // Skip binary files
                    if (BINARY_EXTENSIONS.has(ext)) continue;

                    // Check file size
                    try {
                        const stats = await fs.promises.stat(fullPath);
                        if (stats.size > this.options.maxFileSize!) continue;
                        if (stats.size === 0) continue;

                        files.push({
                            path: fullPath,
                            relativePath,
                            name: entry.name,
                            extension: ext,
                            language: this.detectLanguage(entry.name),
                            size: stats.size,
                            isBinary: false,
                        });
                    } catch {
                        // Skip files we can't stat
                    }
                }
            }
        };

        await walkDir(dirPath);
        return files;
    }

    /**
     * Scan a single file
     */
    private async scanFile(file: FileInfo): Promise<void> {
        const content = await fs.promises.readFile(file.path, 'utf-8');
        
        // Check if file appears to be binary
        if (this.isBinaryContent(content)) return;

        const lines = content.split('\n');
        this.linesScanned += lines.length;

        // Scan for secrets
        for (const pattern of this.secretPatterns) {
            const findings = this.scanForSecret(content, lines, file.relativePath, pattern);
            this.findings.push(...findings);
        }

        // Scan for vulnerabilities
        for (const rule of this.vulnerabilityRules) {
            // Skip if rule doesn't apply to this language
            if (rule.languages.length > 0 && !rule.languages.includes(file.language)) {
                continue;
            }

            const findings = this.scanForVulnerability(content, lines, file.relativePath, rule);
            this.findings.push(...findings);
        }
    }

    /**
     * Scan content for a specific secret pattern
     */
    private scanForSecret(
        content: string,
        lines: string[],
        filename: string,
        pattern: SecretPattern
    ): SASTFinding[] {
        const findings: SASTFinding[] = [];

        // Quick keyword check for performance
        if (pattern.keywords?.length) {
            const hasKeyword = pattern.keywords.some(kw => 
                content.toLowerCase().includes(kw.toLowerCase())
            );
            if (!hasKeyword) return findings;
        }

        // Reset regex lastIndex
        pattern.pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.pattern.exec(content)) !== null) {
            // Find line number
            const beforeMatch = content.substring(0, match.index);
            const lineNumber = beforeMatch.split('\n').length;
            const line = lines[lineNumber - 1] || '';

            // Check for false positives
            if (pattern.falsePositivePatterns?.some(fp => fp.test(line))) {
                continue;
            }

            // Validate match if validator provided
            if (pattern.validator && !pattern.validator(match[0])) {
                continue;
            }

            const location = this.createLocation(filename, lineNumber, line, lines);

            findings.push({
                id: `${pattern.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                ruleId: pattern.id,
                title: pattern.name,
                description: pattern.description,
                severity: pattern.severity,
                confidence: pattern.confidence,
                category: 'hardcoded-secret',
                location,
                cwe: ['CWE-798', 'CWE-259'],
                owasp: ['A07:2021'],
                remediation: 'Remove hardcoded secret and use environment variables or secure vault.',
                timestamp: new Date(),
            });

            // Prevent infinite loop with zero-width matches
            if (match.index === pattern.pattern.lastIndex) {
                pattern.pattern.lastIndex++;
            }
        }

        return findings;
    }

    /**
     * Scan content for a specific vulnerability pattern
     */
    private scanForVulnerability(
        content: string,
        lines: string[],
        filename: string,
        rule: VulnerabilityRule
    ): SASTFinding[] {
        const findings: SASTFinding[] = [];

        for (const rulePattern of rule.patterns) {
            if (rulePattern.type !== 'regex') continue;

            const regex = rulePattern.pattern instanceof RegExp 
                ? rulePattern.pattern 
                : new RegExp(rulePattern.pattern, 'gi');

            regex.lastIndex = 0;

            let match: RegExpExecArray | null;
            while ((match = regex.exec(content)) !== null) {
                // Find line number
                const beforeMatch = content.substring(0, match.index);
                const lineNumber = beforeMatch.split('\n').length;
                const line = lines[lineNumber - 1] || '';

                // Check negative pattern (false positive filter)
                if (rulePattern.negative?.test(line)) {
                    continue;
                }

                const location = this.createLocation(filename, lineNumber, line, lines);

                findings.push({
                    id: `${rule.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                    ruleId: rule.id,
                    title: rule.name,
                    description: rulePattern.message || rule.description,
                    severity: rule.severity,
                    confidence: 'medium',
                    category: rule.category,
                    location,
                    cwe: rule.cwe,
                    owasp: rule.owasp,
                    remediation: rule.remediation,
                    references: rule.references,
                    timestamp: new Date(),
                });

                // Prevent infinite loop
                if (match.index === regex.lastIndex) {
                    regex.lastIndex++;
                }
            }
        }

        return findings;
    }

    /**
     * Create a source location with context
     */
    private createLocation(
        filename: string,
        lineNumber: number,
        line: string,
        allLines: string[]
    ): SourceLocation {
        // Get context (2 lines before and after)
        const contextStart = Math.max(0, lineNumber - 3);
        const contextEnd = Math.min(allLines.length, lineNumber + 2);
        const context = allLines.slice(contextStart, contextEnd);

        // Mask potential secrets in the snippet
        const maskedLine = this.maskSecrets(line);

        return {
            file: filename,
            line: lineNumber,
            snippet: maskedLine,
            context: context.map(l => this.maskSecrets(l)),
        };
    }

    /**
     * Return line as-is (no masking - user wants to see full secrets for analysis)
     */
    private maskSecrets(line: string): string {
        return line;
    }

    /**
     * Detect language from filename
     */
    private detectLanguage(filename: string): string {
        const ext = filename.includes('.') 
            ? '.' + filename.split('.').pop()!.toLowerCase()
            : filename.toLowerCase();

        for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
            if (exts.includes(ext) || exts.includes(filename.toLowerCase())) {
                return lang;
            }
        }
        return 'unknown';
    }

    /**
     * Check if content appears to be binary
     */
    private isBinaryContent(content: string): boolean {
        // Check for null bytes or high ratio of non-printable characters
        const nullCount = (content.match(/\0/g) || []).length;
        if (nullCount > 0) return true;

        const nonPrintable = content.match(/[^\x20-\x7E\t\n\r]/g) || [];
        return nonPrintable.length / content.length > 0.3;
    }

    /**
     * Check if path matches any of the patterns
     */
    private matchesPattern(filePath: string, patterns: string[]): boolean {
        const normalizedPath = filePath.replace(/\\/g, '/');
        
        for (const pattern of patterns) {
            // Simple glob matching
            const regexPattern = pattern
                .replace(/\*\*/g, '{{GLOBSTAR}}')
                .replace(/\*/g, '[^/]*')
                .replace(/\?/g, '.')
                .replace(/\{\{GLOBSTAR\}\}/g, '.*');
            
            const regex = new RegExp(`^${regexPattern}$|/${regexPattern}$|^${regexPattern}/|/${regexPattern}/`);
            if (regex.test(normalizedPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Remove duplicate findings
     */
    private deduplicateFindings(findings: SASTFinding[]): SASTFinding[] {
        const seen = new Set<string>();
        return findings.filter(f => {
            const key = `${f.ruleId}:${f.location.file}:${f.location.line}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }

    /**
     * Generate scan summary
     */
    private generateSummary(): ScanSummary {
        const bySeverity: Record<SeverityLevel, number> = {
            critical: 0, high: 0, medium: 0, low: 0, info: 0
        };
        const byCategory: Record<VulnerabilityCategory, number> = {
            'hardcoded-secret': 0, injection: 0, xss: 0, 'path-traversal': 0,
            'insecure-crypto': 0, 'insecure-deserialization': 0, authentication: 0,
            authorization: 0, 'sensitive-data-exposure': 0, 'security-misconfiguration': 0,
            'vulnerable-dependency': 0, 'code-quality': 0, other: 0
        };
        const byConfidence: Record<ConfidenceLevel, number> = {
            high: 0, medium: 0, low: 0
        };
        const fileFindings: Record<string, number> = {};

        for (const finding of this.findings) {
            bySeverity[finding.severity]++;
            byCategory[finding.category]++;
            byConfidence[finding.confidence]++;
            fileFindings[finding.location.file] = (fileFindings[finding.location.file] || 0) + 1;
        }

        const topFiles = Object.entries(fileFindings)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([file, findings]) => ({ file, findings }));

        // Calculate risk score (0-100)
        const riskScore = Math.min(100, 
            (bySeverity.critical * 25) + 
            (bySeverity.high * 10) + 
            (bySeverity.medium * 3) + 
            (bySeverity.low * 1)
        );

        return {
            totalFindings: this.findings.length,
            bySeverity,
            byCategory,
            byConfidence,
            topFiles,
            riskScore,
        };
    }

    /**
     * Report scan progress
     */
    private reportProgress(
        phase: ScanProgress['phase'],
        discovered: number,
        scanned: number,
        findings: number
    ): void {
        if (!this.options.onProgress) return;

        const percentage = discovered > 0 ? Math.round((scanned / discovered) * 100) : 0;

        this.options.onProgress({
            phase,
            filesDiscovered: discovered,
            filesScanned: scanned,
            findingsCount: findings,
            percentage,
        });
    }
}

/**
 * Quick scan helper function
 */
export async function scanDirectory(
    targetPath: string,
    options?: Partial<ScanOptions>
): Promise<ScanResult> {
    const scanner = new SASTScanner({ ...options, targetPath });
    return scanner.scanDirectory(targetPath);
}

/**
 * Scan content without filesystem (for browser/uploaded content)
 */
export function scanContent(
    content: string,
    filename: string,
    options?: Partial<ScanOptions>
): SASTFinding[] {
    const scanner = new SASTScanner(options);
    return scanner.scanContent(content, filename);
}

export default SASTScanner;

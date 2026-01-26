// STRIX SAST - Vulnerability Detection Rules
// Pattern-based rules for common security vulnerabilities

import { VulnerabilityRule } from '../types';

// ============================================
// Injection Vulnerabilities
// ============================================

export const INJECTION_RULES: VulnerabilityRule[] = [
    {
        id: 'sql-injection-concatenation',
        name: 'SQL Injection via String Concatenation',
        description: 'SQL query built using string concatenation with potentially untrusted input',
        category: 'injection',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'ruby'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:query|execute|exec|raw)\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE).*?\+/gi,
                message: 'SQL query uses string concatenation - use parameterized queries instead',
            },
            {
                type: 'regex',
                pattern: /(?:query|execute|exec)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`\s*\)/gi,
                message: 'SQL query uses template literals with interpolation - use parameterized queries',
            },
            {
                type: 'regex',
                pattern: /f["'](?:SELECT|INSERT|UPDATE|DELETE).*?\{.*?\}/gi,
                message: 'Python f-string used in SQL query - use parameterized queries',
            },
        ],
        cwe: ['CWE-89'],
        owasp: ['A03:2021'],
        remediation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
        references: [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cwe.mitre.org/data/definitions/89.html',
        ],
    },
    {
        id: 'command-injection',
        name: 'OS Command Injection',
        description: 'System command executed with potentially untrusted input',
        category: 'injection',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'shell'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:[^,]+\s*\+|`[^`]*\$\{)/gi,
                message: 'Command execution with dynamic input - validate and sanitize input',
            },
            {
                type: 'regex',
                pattern: /(?:child_process|subprocess|os\.system|os\.popen|Runtime\.exec)\s*\([^)]*\+/gi,
                message: 'System command built with string concatenation',
            },
            {
                type: 'regex',
                pattern: /(?:shell_exec|system|passthru|popen|proc_open)\s*\(\s*\$/gi,
                message: 'PHP command execution with variable input',
            },
        ],
        cwe: ['CWE-78'],
        owasp: ['A03:2021'],
        remediation: 'Avoid executing system commands with user input. If necessary, use allowlists and proper escaping.',
        references: [
            'https://owasp.org/www-community/attacks/Command_Injection',
        ],
    },
    {
        id: 'ldap-injection',
        name: 'LDAP Injection',
        description: 'LDAP query constructed with potentially untrusted input',
        category: 'injection',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:ldap|search|bind).*?["'`]\([^)]*\+/gi,
                message: 'LDAP query uses string concatenation',
            },
            {
                type: 'regex',
                pattern: /\(\&?\(?\w+=[^)]*\+[^)]*\)/gi,
                message: 'LDAP filter constructed with concatenation',
            },
        ],
        cwe: ['CWE-90'],
        owasp: ['A03:2021'],
        remediation: 'Properly escape LDAP special characters and validate input.',
    },
    {
        id: 'xpath-injection',
        name: 'XPath Injection',
        description: 'XPath query constructed with potentially untrusted input',
        category: 'injection',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:xpath|selectNodes|evaluate)\s*\([^)]*\+/gi,
                message: 'XPath query uses string concatenation',
            },
        ],
        cwe: ['CWE-643'],
        owasp: ['A03:2021'],
        remediation: 'Use parameterized XPath queries or properly escape input.',
    },
];

// ============================================
// Cross-Site Scripting (XSS)
// ============================================

export const XSS_RULES: VulnerabilityRule[] = [
    {
        id: 'dom-xss-innerhtml',
        name: 'DOM XSS via innerHTML',
        description: 'innerHTML assignment with potentially untrusted content',
        category: 'xss',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
            {
                type: 'regex',
                pattern: /\.innerHTML\s*=\s*(?!["'`][^"'`]*["'`])/g,
                message: 'innerHTML assignment with dynamic content - use textContent or sanitize',
            },
            {
                type: 'regex',
                pattern: /\.outerHTML\s*=\s*(?!["'`][^"'`]*["'`])/g,
                message: 'outerHTML assignment with dynamic content',
            },
        ],
        cwe: ['CWE-79'],
        owasp: ['A03:2021'],
        remediation: 'Use textContent for text, or properly sanitize HTML content before insertion.',
    },
    {
        id: 'react-dangerously-set-innerhtml',
        name: 'React dangerouslySetInnerHTML',
        description: 'React dangerouslySetInnerHTML with potentially untrusted content',
        category: 'xss',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
            {
                type: 'regex',
                pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
                message: 'dangerouslySetInnerHTML used - ensure content is sanitized',
            },
        ],
        cwe: ['CWE-79'],
        owasp: ['A03:2021'],
        remediation: 'Sanitize HTML content with DOMPurify or similar library before using dangerouslySetInnerHTML.',
    },
    {
        id: 'dom-xss-document-write',
        name: 'DOM XSS via document.write',
        description: 'document.write/writeln with potentially untrusted content',
        category: 'xss',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
            {
                type: 'regex',
                pattern: /document\.write(?:ln)?\s*\(/g,
                message: 'document.write is dangerous and may enable XSS',
            },
        ],
        cwe: ['CWE-79'],
        owasp: ['A03:2021'],
        remediation: 'Avoid document.write entirely. Use DOM manipulation methods instead.',
    },
    {
        id: 'dom-xss-eval',
        name: 'DOM XSS via eval',
        description: 'eval() or similar function with potentially untrusted input',
        category: 'xss',
        severity: 'critical',
        languages: ['javascript', 'typescript'],
        patterns: [
            {
                type: 'regex',
                pattern: /\beval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))/g,
                message: 'eval() with dynamic input - avoid eval entirely',
            },
            {
                type: 'regex',
                pattern: /new\s+Function\s*\([^)]*\+/g,
                message: 'new Function() with dynamic input - avoid dynamic code execution',
            },
            {
                type: 'regex',
                pattern: /setTimeout\s*\(\s*["'`][^"'`]*\+/g,
                message: 'setTimeout with string containing dynamic content',
            },
            {
                type: 'regex',
                pattern: /setInterval\s*\(\s*["'`][^"'`]*\+/g,
                message: 'setInterval with string containing dynamic content',
            },
        ],
        cwe: ['CWE-95'],
        owasp: ['A03:2021'],
        remediation: 'Never use eval() or new Function() with untrusted input. Refactor to avoid dynamic code execution.',
    },
    {
        id: 'jquery-xss',
        name: 'jQuery XSS Sink',
        description: 'jQuery methods that can execute HTML/scripts',
        category: 'xss',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
            {
                type: 'regex',
                pattern: /\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*[^"'`\)]/g,
                message: 'jQuery HTML manipulation with dynamic content - sanitize input',
            },
        ],
        cwe: ['CWE-79'],
        owasp: ['A03:2021'],
        remediation: 'Use .text() for text content, or sanitize HTML before using .html() methods.',
    },
];

// ============================================
// Path Traversal
// ============================================

export const PATH_TRAVERSAL_RULES: VulnerabilityRule[] = [
    {
        id: 'path-traversal-file-read',
        name: 'Path Traversal in File Operations',
        description: 'File operation with path potentially controlled by user input',
        category: 'path-traversal',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:readFile|readFileSync|createReadStream|open)\s*\([^)]*\+/gi,
                message: 'File read with concatenated path - validate and sanitize path input',
            },
            {
                type: 'regex',
                pattern: /(?:writeFile|writeFileSync|createWriteStream)\s*\([^)]*\+/gi,
                message: 'File write with concatenated path - validate and sanitize path input',
            },
            {
                type: 'regex',
                pattern: /path\.join\s*\([^)]*(?:req\.|request\.|params\.|query\.)/gi,
                message: 'path.join with request parameter - may allow path traversal',
            },
        ],
        cwe: ['CWE-22'],
        owasp: ['A01:2021'],
        remediation: 'Validate and sanitize file paths. Use path.normalize() and verify the resolved path is within expected directory.',
    },
];

// ============================================
// Insecure Cryptography
// ============================================

export const CRYPTO_RULES: VulnerabilityRule[] = [
    {
        id: 'weak-hash-md5',
        name: 'Weak Hash Algorithm (MD5)',
        description: 'MD5 hash algorithm used - cryptographically broken',
        category: 'insecure-crypto',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'go'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:createHash|hashlib\.md5|MessageDigest\.getInstance)\s*\(\s*["']md5["']/gi,
                message: 'MD5 is cryptographically broken - use SHA-256 or better',
            },
            {
                type: 'regex',
                pattern: /\bmd5\s*\(/gi,
                message: 'MD5 hash function used - use SHA-256 or better',
            },
        ],
        cwe: ['CWE-328'],
        owasp: ['A02:2021'],
        remediation: 'Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or Argon2.',
    },
    {
        id: 'weak-hash-sha1',
        name: 'Weak Hash Algorithm (SHA1)',
        description: 'SHA1 hash algorithm used - considered weak',
        category: 'insecure-crypto',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'go'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:createHash|hashlib\.sha1|MessageDigest\.getInstance)\s*\(\s*["']sha1?["']/gi,
                message: 'SHA1 is weak - use SHA-256 or better',
            },
        ],
        cwe: ['CWE-328'],
        owasp: ['A02:2021'],
        remediation: 'Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or Argon2.',
    },
    {
        id: 'weak-cipher-des',
        name: 'Weak Cipher (DES/3DES)',
        description: 'DES or Triple DES cipher used - considered weak',
        category: 'insecure-crypto',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:createCipher|Cipher\.getInstance)\s*\(\s*["'](?:des|3des|tripledes|des-ede)/gi,
                message: 'DES/3DES is weak - use AES-256-GCM',
            },
        ],
        cwe: ['CWE-327'],
        owasp: ['A02:2021'],
        remediation: 'Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.',
    },
    {
        id: 'ecb-mode',
        name: 'Insecure Block Cipher Mode (ECB)',
        description: 'ECB mode used for block cipher - patterns in plaintext visible in ciphertext',
        category: 'insecure-crypto',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        patterns: [
            {
                type: 'regex',
                pattern: /["'](?:aes|des).*?-ecb["']/gi,
                message: 'ECB mode reveals patterns - use GCM or CBC with HMAC',
            },
            {
                type: 'regex',
                pattern: /AES\/ECB/gi,
                message: 'ECB mode reveals patterns - use AES/GCM/NoPadding',
            },
        ],
        cwe: ['CWE-327'],
        owasp: ['A02:2021'],
        remediation: 'Use GCM mode for authenticated encryption, or CBC with HMAC for encrypt-then-MAC.',
    },
    {
        id: 'hardcoded-iv',
        name: 'Hardcoded Initialization Vector',
        description: 'IV (Initialization Vector) appears to be hardcoded',
        category: 'insecure-crypto',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:iv|IV|initVector|initializationVector)\s*=\s*["'][A-Fa-f0-9]{16,}["']/gi,
                message: 'Hardcoded IV detected - IVs should be random and unique per encryption',
            },
            {
                type: 'regex',
                pattern: /(?:iv|IV)\s*=\s*Buffer\.from\s*\(\s*["'][^"']+["']/gi,
                message: 'Hardcoded IV in Buffer - IVs should be randomly generated',
            },
        ],
        cwe: ['CWE-329'],
        owasp: ['A02:2021'],
        remediation: 'Generate a random IV for each encryption operation. Store IV with ciphertext (it does not need to be secret).',
    },
    {
        id: 'insecure-random',
        name: 'Insecure Random Number Generator',
        description: 'Non-cryptographic random used where secure random is needed',
        category: 'insecure-crypto',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
            {
                type: 'regex',
                pattern: /Math\.random\s*\(\s*\).*(?:token|secret|key|password|nonce|iv|salt)/gi,
                message: 'Math.random() used for security purpose - use crypto.randomBytes()',
            },
            {
                type: 'regex',
                pattern: /(?:token|secret|key|password|nonce|iv|salt).*Math\.random\s*\(\s*\)/gi,
                message: 'Math.random() used for security purpose - use crypto.randomBytes()',
            },
        ],
        cwe: ['CWE-330'],
        owasp: ['A02:2021'],
        remediation: 'Use crypto.randomBytes() in Node.js or crypto.getRandomValues() in browser for security-sensitive random values.',
    },
];

// ============================================
// Authentication Issues
// ============================================

export const AUTH_RULES: VulnerabilityRule[] = [
    {
        id: 'hardcoded-credentials',
        name: 'Hardcoded Credentials',
        description: 'Credentials appear to be hardcoded in source code',
        category: 'authentication',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'go', 'ruby'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:admin|root|user).*(?:password|passwd|pwd)\s*[=:]\s*["'][^"']+["']/gi,
                message: 'Hardcoded username/password pair detected',
                negative: /example|placeholder|test|sample|dummy|\$\{|process\.env|getenv/i,
            },
        ],
        cwe: ['CWE-798'],
        owasp: ['A07:2021'],
        remediation: 'Store credentials in environment variables or secure vaults. Never commit credentials to source code.',
    },
    {
        id: 'jwt-none-algorithm',
        name: 'JWT None Algorithm',
        description: 'JWT verification may accept "none" algorithm',
        category: 'authentication',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
            {
                type: 'regex',
                pattern: /algorithms?\s*:\s*\[.*["']none["']/gi,
                message: 'JWT accepts "none" algorithm - attacker can forge tokens',
            },
        ],
        cwe: ['CWE-347'],
        owasp: ['A02:2021'],
        remediation: 'Never allow "none" algorithm. Explicitly specify allowed algorithms in JWT verification.',
    },
    {
        id: 'jwt-secret-hardcoded',
        name: 'Hardcoded JWT Secret',
        description: 'JWT secret appears to be hardcoded',
        category: 'authentication',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
            {
                type: 'regex',
                pattern: /jwt\.(?:sign|verify)\s*\([^)]+["'][A-Za-z0-9+/=]{10,}["']/gi,
                message: 'Hardcoded JWT secret - use environment variable',
            },
        ],
        cwe: ['CWE-798'],
        owasp: ['A02:2021'],
        remediation: 'Store JWT secrets in environment variables or secure key management systems.',
    },
];

// ============================================
// Insecure Deserialization
// ============================================

export const DESERIALIZATION_RULES: VulnerabilityRule[] = [
    {
        id: 'unsafe-eval',
        name: 'Unsafe Code Evaluation',
        description: 'Dynamic code evaluation that could execute untrusted code',
        category: 'insecure-deserialization',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python'],
        patterns: [
            {
                type: 'regex',
                pattern: /\beval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/gi,
                message: 'eval() with user input - critical vulnerability',
            },
            {
                type: 'regex',
                pattern: /exec\s*\(\s*(?:req\.|request\.|input)/gi,
                message: 'exec() with user input - critical vulnerability',
            },
        ],
        cwe: ['CWE-502'],
        owasp: ['A08:2021'],
        remediation: 'Never deserialize untrusted data. Use safe parsers like JSON.parse() for data exchange.',
    },
    {
        id: 'unsafe-pickle',
        name: 'Unsafe Pickle Deserialization',
        description: 'Python pickle with untrusted data enables arbitrary code execution',
        category: 'insecure-deserialization',
        severity: 'critical',
        languages: ['python'],
        patterns: [
            {
                type: 'regex',
                pattern: /pickle\.(?:load|loads)\s*\(/gi,
                message: 'pickle.load with untrusted data enables code execution',
            },
            {
                type: 'regex',
                pattern: /cPickle\.(?:load|loads)\s*\(/gi,
                message: 'cPickle.load with untrusted data enables code execution',
            },
        ],
        cwe: ['CWE-502'],
        owasp: ['A08:2021'],
        remediation: 'Use JSON or other safe formats for untrusted data. If pickle is required, sign data with HMAC.',
    },
    {
        id: 'unsafe-yaml',
        name: 'Unsafe YAML Loading',
        description: 'YAML loading with untrusted data may enable code execution',
        category: 'insecure-deserialization',
        severity: 'critical',
        languages: ['python', 'ruby'],
        patterns: [
            {
                type: 'regex',
                pattern: /yaml\.load\s*\([^)]*(?!Loader=yaml\.SafeLoader)/g,
                message: 'yaml.load without SafeLoader - use yaml.safe_load()',
            },
            {
                type: 'regex',
                pattern: /YAML\.load\s*\([^)]*(?!safe:\s*true)/gi,
                message: 'YAML.load without safe option - enable safe mode',
            },
        ],
        cwe: ['CWE-502'],
        owasp: ['A08:2021'],
        remediation: 'Use yaml.safe_load() in Python or safe: true option in Ruby.',
    },
];

// ============================================
// Sensitive Data Exposure
// ============================================

export const DATA_EXPOSURE_RULES: VulnerabilityRule[] = [
    {
        id: 'console-log-sensitive',
        name: 'Sensitive Data in Logs',
        description: 'Potentially sensitive data logged to console',
        category: 'sensitive-data-exposure',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
            {
                type: 'regex',
                pattern: /console\.(?:log|info|debug|warn)\s*\([^)]*(?:password|secret|token|key|credential|ssn|credit)/gi,
                message: 'Sensitive data may be logged - remove before production',
            },
            {
                type: 'regex',
                pattern: /(?:print|logging\.|logger\.)\s*\([^)]*(?:password|secret|token|key|credential)/gi,
                message: 'Sensitive data may be logged - remove or mask',
            },
        ],
        cwe: ['CWE-532'],
        owasp: ['A09:2021'],
        remediation: 'Never log sensitive data. If needed for debugging, mask or redact sensitive values.',
    },
    {
        id: 'error-message-exposure',
        name: 'Detailed Error Messages',
        description: 'Detailed error messages may expose sensitive information',
        category: 'sensitive-data-exposure',
        severity: 'low',
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:res\.send|response\.send|print|echo)\s*\(\s*(?:err|error|exception)\.(?:message|stack)/gi,
                message: 'Error details sent to client - use generic messages in production',
            },
        ],
        cwe: ['CWE-209'],
        owasp: ['A05:2021'],
        remediation: 'Return generic error messages to clients. Log detailed errors server-side only.',
    },
];

// ============================================
// Security Misconfiguration
// ============================================

export const MISCONFIG_RULES: VulnerabilityRule[] = [
    {
        id: 'cors-wildcard',
        name: 'CORS Wildcard Origin',
        description: 'CORS configured with wildcard origin',
        category: 'security-misconfiguration',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:Access-Control-Allow-Origin|cors.*origin)\s*[=:]\s*["']\*["']/gi,
                message: 'CORS wildcard allows any origin - restrict to specific domains',
            },
        ],
        cwe: ['CWE-942'],
        owasp: ['A05:2021'],
        remediation: 'Specify allowed origins explicitly instead of using wildcard.',
    },
    {
        id: 'ssl-verify-disabled',
        name: 'SSL Verification Disabled',
        description: 'SSL/TLS certificate verification disabled',
        category: 'security-misconfiguration',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'ruby'],
        patterns: [
            {
                type: 'regex',
                pattern: /rejectUnauthorized\s*:\s*false/gi,
                message: 'SSL verification disabled - vulnerable to MITM attacks',
            },
            {
                type: 'regex',
                pattern: /verify\s*=\s*False/gi,
                message: 'SSL verification disabled - vulnerable to MITM attacks',
            },
            {
                type: 'regex',
                pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/gi,
                message: 'TLS verification disabled globally',
            },
        ],
        cwe: ['CWE-295'],
        owasp: ['A07:2021'],
        remediation: 'Always verify SSL certificates in production. Fix certificate issues instead of disabling verification.',
    },
    {
        id: 'debug-mode-enabled',
        name: 'Debug Mode Enabled',
        description: 'Application appears to have debug mode enabled',
        category: 'security-misconfiguration',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        patterns: [
            {
                type: 'regex',
                pattern: /(?:DEBUG|debug)\s*[=:]\s*(?:true|True|1|["']true["'])/gi,
                message: 'Debug mode appears to be enabled - disable in production',
            },
            {
                type: 'regex',
                pattern: /app\.debug\s*=\s*True/gi,
                message: 'Flask debug mode enabled - disable in production',
            },
        ],
        cwe: ['CWE-489'],
        owasp: ['A05:2021'],
        remediation: 'Disable debug mode in production deployments.',
    },
];

// ============================================
// All Rules Combined
// ============================================

export const ALL_VULNERABILITY_RULES: VulnerabilityRule[] = [
    ...INJECTION_RULES,
    ...XSS_RULES,
    ...PATH_TRAVERSAL_RULES,
    ...CRYPTO_RULES,
    ...AUTH_RULES,
    ...DESERIALIZATION_RULES,
    ...DATA_EXPOSURE_RULES,
    ...MISCONFIG_RULES,
];

export default {
    all: ALL_VULNERABILITY_RULES,
    injection: INJECTION_RULES,
    xss: XSS_RULES,
    pathTraversal: PATH_TRAVERSAL_RULES,
    crypto: CRYPTO_RULES,
    auth: AUTH_RULES,
    deserialization: DESERIALIZATION_RULES,
    dataExposure: DATA_EXPOSURE_RULES,
    misconfiguration: MISCONFIG_RULES,
};

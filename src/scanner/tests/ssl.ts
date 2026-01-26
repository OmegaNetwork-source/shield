// STRIX SSL/TLS Analysis Module
// Comprehensive SSL/TLS security analysis with NIST 800-52 mapping

import type { UnifiedVulnerability } from '../types';

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

// ============================================================================
// SSL/TLS CONFIGURATION
// ============================================================================

// Protocol versions with security ratings
export const TLS_PROTOCOLS = {
    'SSLv2': { secure: false, severity: 'critical', reason: 'Deprecated, multiple known vulnerabilities' },
    'SSLv3': { secure: false, severity: 'critical', reason: 'POODLE vulnerability (CVE-2014-3566)' },
    'TLSv1.0': { secure: false, severity: 'high', reason: 'BEAST vulnerability, deprecated by PCI-DSS' },
    'TLSv1.1': { secure: false, severity: 'medium', reason: 'Deprecated, lacks modern cipher support' },
    'TLSv1.2': { secure: true, severity: 'info', reason: 'Secure with proper cipher configuration' },
    'TLSv1.3': { secure: true, severity: 'info', reason: 'Most secure, recommended' },
};

// Weak cipher suites to flag
export const WEAK_CIPHERS = [
    // NULL ciphers
    { pattern: /NULL/i, severity: 'critical', reason: 'No encryption' },
    // Export grade
    { pattern: /EXPORT/i, severity: 'critical', reason: 'Export-grade weak encryption' },
    // DES/3DES
    { pattern: /^DES-|_DES_|3DES|DES-CBC3/i, severity: 'high', reason: 'Weak encryption (Sweet32)' },
    // RC4
    { pattern: /RC4/i, severity: 'high', reason: 'RC4 is broken (RFC 7465)' },
    // RC2
    { pattern: /RC2/i, severity: 'high', reason: 'RC2 is cryptographically weak' },
    // MD5
    { pattern: /-MD5$/i, severity: 'medium', reason: 'MD5 is cryptographically broken' },
    // Anonymous key exchange
    { pattern: /^ADH-|^AECDH-|_anon_/i, severity: 'critical', reason: 'No authentication' },
    // Low strength
    { pattern: /_40_|_56_/i, severity: 'critical', reason: 'Insufficient key length' },
    // CBC with TLS 1.0
    { pattern: /-CBC-/i, severity: 'low', reason: 'CBC mode vulnerable with older TLS' },
];

// Strong cipher suites
export const STRONG_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
];

// NIST 800-52 Rev 2 requirements
export const NIST_800_52_REQUIREMENTS = {
    minProtocol: 'TLSv1.2',
    requiredCiphers: [
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    ],
    forbiddenProtocols: ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
    minKeySize: {
        RSA: 2048,
        ECDSA: 256,
        DSA: 2048,
    },
    forbiddenCiphers: ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon'],
};

// ============================================================================
// INTERFACES
// ============================================================================

export interface SslCertificate {
    subject: {
        CN?: string;
        O?: string;
        OU?: string;
        C?: string;
        ST?: string;
        L?: string;
    };
    issuer: {
        CN?: string;
        O?: string;
        C?: string;
    };
    validFrom: Date;
    validTo: Date;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    subjectAltName?: string[];
    keySize?: number;
    keyType?: string;
    signatureAlgorithm?: string;
    version?: number;
    isCA?: boolean;
    selfSigned?: boolean;
}

export interface SslAnalysisResult {
    url: string;
    port: number;
    protocol: string;
    certificate?: SslCertificate;
    chain?: SslCertificate[];
    supportedProtocols: string[];
    supportedCiphers: string[];
    preferredCipher?: string;
    weakCiphers: string[];
    strongCiphers: string[];
    hasHsts: boolean;
    hstsMaxAge?: number;
    hstsPreload?: boolean;
    hasHpkp: boolean;
    hasCertTransparency: boolean;
    ocspStapling: boolean;
    vulnerabilities: UnifiedVulnerability[];
    nistCompliant: boolean;
    nistIssues: string[];
    grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    score: number;
}

// ============================================================================
// SSL/TLS ANALYSIS
// ============================================================================

/**
 * Analyze SSL/TLS configuration of a URL
 * Note: Full SSL analysis requires Node.js TLS module (works in Electron main process)
 * In browser, we can only do limited analysis via headers
 */
export async function analyzeSsl(url: string): Promise<SslAnalysisResult> {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';

    const result: SslAnalysisResult = {
        url,
        port: parseInt(parsedUrl.port) || (isHttps ? 443 : 80),
        protocol: isHttps ? 'TLSv1.2+' : 'none',
        supportedProtocols: [],
        supportedCiphers: [],
        weakCiphers: [],
        strongCiphers: [],
        hasHsts: false,
        hasHpkp: false,
        hasCertTransparency: false,
        ocspStapling: false,
        vulnerabilities: [],
        nistCompliant: true,
        nistIssues: [],
        grade: 'A',
        score: 100
    };

    if (!isHttps) {
        result.vulnerabilities.push({
            id: 'ssl-no-https',
            category: 'crypto',
            severity: 'high',
            title: 'No HTTPS',
            description: 'Site does not use HTTPS encryption',
            url,
            location: 'Protocol',
            recommendation: 'Enable HTTPS with a valid certificate',
            cwe: 'CWE-319',
            owasp: 'A02:2021',
            nistControl: 'SC-8, SC-12'
        });
        result.nistCompliant = false;
        result.nistIssues.push('No TLS encryption');
        result.grade = 'F';
        result.score = 0;
        return result;
    }

    // Fetch the URL to get headers
    try {
        let headers: Record<string, string> = {};

        if (isElectron) {
            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url,
                method: 'HEAD',
                timeout: 10000
            });
            headers = response.headers || {};
        } else {
            const response = await fetch(url, { method: 'HEAD' });
            response.headers.forEach((v, k) => headers[k.toLowerCase()] = v);
        }

        // Analyze HSTS
        const hsts = headers['strict-transport-security'];
        if (hsts) {
            result.hasHsts = true;
            const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
            if (maxAgeMatch) {
                result.hstsMaxAge = parseInt(maxAgeMatch[1]);

                // Check HSTS max-age (should be at least 1 year = 31536000)
                if (result.hstsMaxAge < 31536000) {
                    result.vulnerabilities.push({
                        id: 'ssl-hsts-short',
                        category: 'crypto',
                        severity: 'low',
                        title: 'HSTS Max-Age Too Short',
                        description: `HSTS max-age is ${result.hstsMaxAge}s (recommended: 31536000s)`,
                        url,
                        location: 'HSTS Header',
                        recommendation: 'Set HSTS max-age to at least 1 year (31536000 seconds)',
                        cwe: 'CWE-319',
                        owasp: 'A02:2021'
                    });
                    result.score -= 5;
                }
            }
            result.hstsPreload = /preload/i.test(hsts);
        } else {
            result.vulnerabilities.push({
                id: 'ssl-no-hsts',
                category: 'crypto',
                severity: 'medium',
                title: 'Missing HSTS Header',
                description: 'HTTP Strict Transport Security is not enabled',
                url,
                location: 'HTTP Headers',
                recommendation: 'Enable HSTS with: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                cwe: 'CWE-319',
                owasp: 'A02:2021',
                nistControl: 'SC-8'
            });
            result.nistIssues.push('Missing HSTS header');
            result.score -= 15;
        }

        // Check for Certificate Transparency
        const expectCt = headers['expect-ct'];
        if (expectCt) {
            result.hasCertTransparency = true;
        }

        // Check for deprecated HPKP (should NOT be present)
        const hpkp = headers['public-key-pins'];
        if (hpkp) {
            result.hasHpkp = true;
            result.vulnerabilities.push({
                id: 'ssl-hpkp-deprecated',
                category: 'crypto',
                severity: 'low',
                title: 'Deprecated HPKP Header',
                description: 'HTTP Public Key Pinning is deprecated and should be removed',
                url,
                location: 'HTTP Headers',
                recommendation: 'Remove HPKP header; use Certificate Transparency instead',
                cwe: 'CWE-295'
            });
        }

    } catch (error) {
        result.vulnerabilities.push({
            id: 'ssl-connection-failed',
            category: 'crypto',
            severity: 'high',
            title: 'SSL Connection Failed',
            description: `Could not establish SSL connection: ${error instanceof Error ? error.message : 'Unknown error'}`,
            url,
            location: 'SSL/TLS',
            recommendation: 'Verify SSL certificate and configuration'
        });
        result.grade = 'F';
        result.score = 0;
        return result;
    }

    // Calculate final grade
    result.grade = calculateGrade(result.score);
    result.nistCompliant = result.nistIssues.length === 0;

    return result;
}

/**
 * Analyze certificate details (Electron main process only)
 */
export function analyzeCertificate(cert: SslCertificate): UnifiedVulnerability[] {
    const vulnerabilities: UnifiedVulnerability[] = [];
    const now = new Date();

    // Check expiration
    if (cert.validTo < now) {
        vulnerabilities.push({
            id: 'ssl-cert-expired',
            category: 'crypto',
            severity: 'critical',
            title: 'SSL Certificate Expired',
            description: `Certificate expired on ${cert.validTo.toISOString()}`,
            location: 'Certificate',
            recommendation: 'Renew the SSL certificate immediately',
            cwe: 'CWE-295',
            owasp: 'A02:2021',
            nistControl: 'SC-12, SC-17'
        });
    } else {
        // Check if expiring soon (30 days)
        const daysUntilExpiry = Math.floor((cert.validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        if (daysUntilExpiry < 30) {
            vulnerabilities.push({
                id: 'ssl-cert-expiring',
                category: 'crypto',
                severity: 'medium',
                title: 'SSL Certificate Expiring Soon',
                description: `Certificate expires in ${daysUntilExpiry} days`,
                location: 'Certificate',
                recommendation: 'Renew the SSL certificate before expiration',
                cwe: 'CWE-295'
            });
        }
    }

    // Check if not yet valid
    if (cert.validFrom > now) {
        vulnerabilities.push({
            id: 'ssl-cert-not-valid',
            category: 'crypto',
            severity: 'critical',
            title: 'SSL Certificate Not Yet Valid',
            description: `Certificate valid from ${cert.validFrom.toISOString()}`,
            location: 'Certificate',
            recommendation: 'Check server time or certificate dates',
            cwe: 'CWE-295'
        });
    }

    // Check if self-signed
    if (cert.selfSigned) {
        vulnerabilities.push({
            id: 'ssl-self-signed',
            category: 'crypto',
            severity: 'high',
            title: 'Self-Signed Certificate',
            description: 'Certificate is self-signed and not trusted by default',
            location: 'Certificate',
            recommendation: 'Use a certificate from a trusted Certificate Authority',
            cwe: 'CWE-295',
            owasp: 'A02:2021',
            nistControl: 'SC-12'
        });
    }

    // Check key size
    if (cert.keySize) {
        const minSize = cert.keyType === 'ECDSA' ? 256 : 2048;
        if (cert.keySize < minSize) {
            vulnerabilities.push({
                id: 'ssl-weak-key',
                category: 'crypto',
                severity: 'high',
                title: 'Weak Certificate Key',
                description: `${cert.keyType} key size ${cert.keySize} is below minimum ${minSize}`,
                location: 'Certificate',
                recommendation: `Use ${cert.keyType} key with at least ${minSize} bits`,
                cwe: 'CWE-326',
                owasp: 'A02:2021',
                nistControl: 'SC-12, SC-13'
            });
        }
    }

    // Check signature algorithm
    if (cert.signatureAlgorithm) {
        const weakAlgos = ['md5', 'sha1', 'md2', 'md4'];
        const algoLower = cert.signatureAlgorithm.toLowerCase();
        if (weakAlgos.some(w => algoLower.includes(w))) {
            vulnerabilities.push({
                id: 'ssl-weak-signature',
                category: 'crypto',
                severity: cert.signatureAlgorithm.includes('md5') ? 'critical' : 'high',
                title: 'Weak Signature Algorithm',
                description: `Certificate uses weak signature algorithm: ${cert.signatureAlgorithm}`,
                location: 'Certificate',
                recommendation: 'Use SHA-256 or stronger signature algorithm',
                cwe: 'CWE-328',
                owasp: 'A02:2021',
                nistControl: 'SC-12, SC-13'
            });
        }
    }

    return vulnerabilities;
}

/**
 * Check if cipher suite is weak
 */
export function isWeakCipher(cipher: string): { weak: boolean; severity?: string; reason?: string } {
    for (const { pattern, severity, reason } of WEAK_CIPHERS) {
        if (pattern.test(cipher)) {
            return { weak: true, severity, reason };
        }
    }
    return { weak: false };
}

/**
 * Check NIST 800-52 compliance
 */
export function checkNistCompliance(result: SslAnalysisResult): string[] {
    const issues: string[] = [];

    // Check protocols
    for (const proto of result.supportedProtocols) {
        if (NIST_800_52_REQUIREMENTS.forbiddenProtocols.includes(proto)) {
            issues.push(`Forbidden protocol: ${proto}`);
        }
    }

    // Check if minimum protocol is supported
    if (!result.supportedProtocols.includes('TLSv1.2') &&
        !result.supportedProtocols.includes('TLSv1.3')) {
        issues.push('Must support TLS 1.2 or higher');
    }

    // Check ciphers
    for (const cipher of result.supportedCiphers) {
        for (const forbidden of NIST_800_52_REQUIREMENTS.forbiddenCiphers) {
            if (cipher.toUpperCase().includes(forbidden.toUpperCase())) {
                issues.push(`Forbidden cipher: ${cipher}`);
            }
        }
    }

    // Check HSTS
    if (!result.hasHsts) {
        issues.push('HSTS not enabled');
    }

    return issues;
}

/**
 * Calculate SSL grade from score
 */
function calculateGrade(score: number): 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 95) return 'A+';
    if (score >= 80) return 'A';
    if (score >= 65) return 'B';
    if (score >= 50) return 'C';
    if (score >= 35) return 'D';
    return 'F';
}

/**
 * Get SSL grade description
 */
export function getGradeDescription(grade: string): string {
    switch (grade) {
        case 'A+': return 'Exceptional - All security features properly configured';
        case 'A': return 'Good - Minor improvements possible';
        case 'B': return 'Fair - Some security issues to address';
        case 'C': return 'Poor - Significant security issues';
        case 'D': return 'Bad - Critical security issues';
        case 'F': return 'Fail - Severe security vulnerabilities';
        default: return 'Unknown';
    }
}

export default {
    analyzeSsl,
    analyzeCertificate,
    isWeakCipher,
    checkNistCompliance,
    getGradeDescription,
    TLS_PROTOCOLS,
    WEAK_CIPHERS,
    STRONG_CIPHERS,
    NIST_800_52_REQUIREMENTS
};

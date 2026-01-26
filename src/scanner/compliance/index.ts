// STRIX Compliance Mapping Module
// Maps vulnerabilities to NIST 800-53, DISA STIG, CWE, and OWASP controls

import type { UnifiedVulnerability } from '../types';

// ============================================================================
// NIST 800-53 Rev 5 CONTROL FAMILIES
// ============================================================================

export const NIST_CONTROL_FAMILIES = {
    AC: 'Access Control',
    AT: 'Awareness and Training',
    AU: 'Audit and Accountability',
    CA: 'Assessment, Authorization, and Monitoring',
    CM: 'Configuration Management',
    CP: 'Contingency Planning',
    IA: 'Identification and Authentication',
    IR: 'Incident Response',
    MA: 'Maintenance',
    MP: 'Media Protection',
    PE: 'Physical and Environmental Protection',
    PL: 'Planning',
    PM: 'Program Management',
    PS: 'Personnel Security',
    PT: 'PII Processing and Transparency',
    RA: 'Risk Assessment',
    SA: 'System and Services Acquisition',
    SC: 'System and Communications Protection',
    SI: 'System and Information Integrity',
    SR: 'Supply Chain Risk Management',
};

// NIST 800-53 control descriptions (subset for web vulnerabilities)
export const NIST_CONTROLS: Record<string, { title: string; description: string; family: string }> = {
    'AC-3': { title: 'Access Enforcement', description: 'Enforce approved authorizations for logical access', family: 'AC' },
    'AC-4': { title: 'Information Flow Enforcement', description: 'Enforce approved authorizations for controlling information flow', family: 'AC' },
    'AC-6': { title: 'Least Privilege', description: 'Employ principle of least privilege', family: 'AC' },
    'AC-7': { title: 'Unsuccessful Logon Attempts', description: 'Limit unsuccessful logon attempts', family: 'AC' },
    'AC-17': { title: 'Remote Access', description: 'Establish usage restrictions for remote access', family: 'AC' },
    'AU-2': { title: 'Event Logging', description: 'Identify and select events for logging', family: 'AU' },
    'AU-3': { title: 'Content of Audit Records', description: 'Include required content in audit records', family: 'AU' },
    'AU-9': { title: 'Protection of Audit Information', description: 'Protect audit information from unauthorized access', family: 'AU' },
    'CM-6': { title: 'Configuration Settings', description: 'Establish and document configuration settings', family: 'CM' },
    'CM-7': { title: 'Least Functionality', description: 'Configure to provide only essential capabilities', family: 'CM' },
    'IA-2': { title: 'Identification and Authentication', description: 'Uniquely identify and authenticate users', family: 'IA' },
    'IA-5': { title: 'Authenticator Management', description: 'Manage system authenticators', family: 'IA' },
    'IA-6': { title: 'Authentication Feedback', description: 'Obscure authentication information during process', family: 'IA' },
    'IA-8': { title: 'Identification and Authentication (Non-Org Users)', description: 'Identify and authenticate non-organizational users', family: 'IA' },
    'RA-5': { title: 'Vulnerability Monitoring and Scanning', description: 'Monitor and scan for vulnerabilities', family: 'RA' },
    'SC-5': { title: 'Denial of Service Protection', description: 'Protect against denial of service attacks', family: 'SC' },
    'SC-7': { title: 'Boundary Protection', description: 'Monitor and control communications at boundaries', family: 'SC' },
    'SC-8': { title: 'Transmission Confidentiality and Integrity', description: 'Protect transmitted information', family: 'SC' },
    'SC-12': { title: 'Cryptographic Key Establishment and Management', description: 'Establish and manage cryptographic keys', family: 'SC' },
    'SC-13': { title: 'Cryptographic Protection', description: 'Implement cryptographic protection', family: 'SC' },
    'SC-17': { title: 'Public Key Infrastructure Certificates', description: 'Issue public key certificates', family: 'SC' },
    'SC-18': { title: 'Mobile Code', description: 'Define and enforce mobile code restrictions', family: 'SC' },
    'SC-23': { title: 'Session Authenticity', description: 'Protect session authenticity', family: 'SC' },
    'SC-28': { title: 'Protection of Information at Rest', description: 'Protect stored information', family: 'SC' },
    'SI-2': { title: 'Flaw Remediation', description: 'Identify and remediate flaws', family: 'SI' },
    'SI-3': { title: 'Malicious Code Protection', description: 'Protect against malicious code', family: 'SI' },
    'SI-4': { title: 'System Monitoring', description: 'Monitor the system for attacks', family: 'SI' },
    'SI-10': { title: 'Information Input Validation', description: 'Check validity of information inputs', family: 'SI' },
    'SI-11': { title: 'Error Handling', description: 'Generate error messages without revealing sensitive info', family: 'SI' },
    'SI-16': { title: 'Memory Protection', description: 'Protect system memory', family: 'SI' },
};

// ============================================================================
// CWE TO NIST MAPPING
// ============================================================================

export const CWE_TO_NIST: Record<string, string[]> = {
    // Injection
    'CWE-78': ['SI-10', 'SC-18'],      // OS Command Injection
    'CWE-79': ['SI-10', 'SC-18'],      // XSS
    'CWE-89': ['SI-10'],               // SQL Injection
    'CWE-91': ['SI-10'],               // XML Injection
    'CWE-94': ['SI-10', 'SC-18'],      // Code Injection
    'CWE-917': ['SI-10'],              // Expression Language Injection

    // Authentication/Session
    'CWE-287': ['IA-2', 'IA-5'],       // Improper Authentication
    'CWE-306': ['IA-2'],               // Missing Authentication
    'CWE-307': ['AC-7'],               // Brute Force
    'CWE-384': ['SC-23'],              // Session Fixation
    'CWE-613': ['SC-23'],              // Session Expiration
    'CWE-614': ['SC-23'],              // Sensitive Cookie in HTTPS

    // Access Control
    'CWE-22': ['AC-3', 'AC-6'],        // Path Traversal
    'CWE-284': ['AC-3'],               // Improper Access Control
    'CWE-285': ['AC-3'],               // Improper Authorization
    'CWE-639': ['AC-3', 'AC-6'],       // IDOR
    'CWE-862': ['AC-3'],               // Missing Authorization
    'CWE-863': ['AC-3'],               // Incorrect Authorization

    // Cryptography
    'CWE-295': ['SC-8', 'SC-12'],      // Improper Certificate Validation
    'CWE-310': ['SC-13'],              // Cryptographic Issues
    'CWE-319': ['SC-8'],               // Cleartext Transmission
    'CWE-326': ['SC-13'],              // Inadequate Encryption
    'CWE-327': ['SC-13'],              // Broken Crypto
    'CWE-328': ['SC-13'],              // Weak Hash
    'CWE-330': ['SC-13'],              // Weak Random

    // Information Disclosure
    'CWE-200': ['SI-11', 'AU-9'],      // Information Exposure
    'CWE-209': ['SI-11'],              // Error Message Info Leak
    'CWE-532': ['AU-9'],               // Log Exposure
    'CWE-538': ['CM-7'],               // File Exposure

    // SSRF/Redirect
    'CWE-601': ['AC-4', 'SC-7'],       // Open Redirect
    'CWE-918': ['AC-4', 'SC-7'],       // SSRF

    // Config/Security
    'CWE-16': ['CM-6'],                // Configuration
    'CWE-693': ['CM-7'],               // Protection Mechanism Failure
    'CWE-942': ['SC-7'],               // CORS Misconfiguration
    'CWE-1021': ['SC-18'],             // Clickjacking

    // Components
    'CWE-1104': ['SI-2', 'RA-5'],      // Vulnerable Components

    // XXE
    'CWE-611': ['SI-10', 'CM-7'],      // XXE
};

// ============================================================================
// OWASP TOP 10 2021
// ============================================================================

export const OWASP_TOP_10_2021 = {
    'A01:2021': {
        name: 'Broken Access Control',
        description: 'Access control enforces policy such that users cannot act outside their intended permissions',
        cwes: ['CWE-22', 'CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863', 'CWE-601'],
        nist: ['AC-3', 'AC-4', 'AC-6']
    },
    'A02:2021': {
        name: 'Cryptographic Failures',
        description: 'Failures related to cryptography which often lead to sensitive data exposure',
        cwes: ['CWE-295', 'CWE-310', 'CWE-319', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-330'],
        nist: ['SC-8', 'SC-12', 'SC-13', 'SC-17']
    },
    'A03:2021': {
        name: 'Injection',
        description: 'User-supplied data is not validated, filtered, or sanitized by the application',
        cwes: ['CWE-78', 'CWE-79', 'CWE-89', 'CWE-91', 'CWE-94', 'CWE-917'],
        nist: ['SI-10', 'SC-18']
    },
    'A04:2021': {
        name: 'Insecure Design',
        description: 'Missing or ineffective control design',
        cwes: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
        nist: ['SA-8', 'SA-17', 'PL-8']
    },
    'A05:2021': {
        name: 'Security Misconfiguration',
        description: 'Missing appropriate security hardening or improperly configured permissions',
        cwes: ['CWE-16', 'CWE-200', 'CWE-611', 'CWE-942', 'CWE-1021'],
        nist: ['CM-6', 'CM-7', 'SC-7']
    },
    'A06:2021': {
        name: 'Vulnerable and Outdated Components',
        description: 'Components with known vulnerabilities',
        cwes: ['CWE-1104'],
        nist: ['SI-2', 'RA-5', 'CM-8']
    },
    'A07:2021': {
        name: 'Identification and Authentication Failures',
        description: 'Confirmation of identity, authentication, and session management',
        cwes: ['CWE-287', 'CWE-306', 'CWE-307', 'CWE-384', 'CWE-613', 'CWE-614'],
        nist: ['IA-2', 'IA-5', 'AC-7', 'SC-23']
    },
    'A08:2021': {
        name: 'Software and Data Integrity Failures',
        description: 'Code and infrastructure that does not protect against integrity violations',
        cwes: ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494'],
        nist: ['SI-7', 'SC-28', 'SA-12']
    },
    'A09:2021': {
        name: 'Security Logging and Monitoring Failures',
        description: 'Without logging and monitoring, breaches cannot be detected',
        cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
        nist: ['AU-2', 'AU-3', 'AU-9', 'SI-4']
    },
    'A10:2021': {
        name: 'Server-Side Request Forgery',
        description: 'SSRF flaws occur when a web application fetches a remote resource without validating user-supplied URL',
        cwes: ['CWE-918'],
        nist: ['AC-4', 'SC-7']
    },
};

// ============================================================================
// DISA STIG MAPPINGS (Web Server and Application)
// ============================================================================

export const STIG_WEB_APP_CONTROLS: Record<string, {
    title: string;
    stigId: string;
    severity: 'CAT I' | 'CAT II' | 'CAT III';
    cwes: string[];
    description: string;
    check: string;
    fix: string;
}> = {
    'V-222602': {
        stigId: 'SRG-APP-000439',
        title: 'SSL/TLS must be used',
        severity: 'CAT I',
        cwes: ['CWE-319'],
        description: 'The application must protect the confidentiality and integrity of transmitted information.',
        check: 'Verify HTTPS is enforced and HTTP traffic is redirected.',
        fix: 'Configure the application to use TLS 1.2 or higher for all connections.'
    },
    'V-222603': {
        stigId: 'SRG-APP-000440',
        title: 'HSTS must be enabled',
        severity: 'CAT II',
        cwes: ['CWE-319'],
        description: 'HTTP Strict Transport Security header must be used.',
        check: 'Verify Strict-Transport-Security header is present with appropriate max-age.',
        fix: 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'V-222604': {
        stigId: 'SRG-APP-000441',
        title: 'Input validation required',
        severity: 'CAT I',
        cwes: ['CWE-79', 'CWE-89', 'CWE-78'],
        description: 'The application must validate all input.',
        check: 'Test for injection vulnerabilities (SQLi, XSS, Command Injection).',
        fix: 'Implement input validation, output encoding, and parameterized queries.'
    },
    'V-222607': {
        stigId: 'SRG-APP-000266',
        title: 'Session timeout required',
        severity: 'CAT II',
        cwes: ['CWE-613'],
        description: 'The application must terminate user sessions after inactivity.',
        check: 'Verify session timeout is implemented (typically 15-30 minutes).',
        fix: 'Configure session timeout to 15 minutes for high-value applications.'
    },
    'V-222610': {
        stigId: 'SRG-APP-000176',
        title: 'Error messages must not reveal sensitive info',
        severity: 'CAT II',
        cwes: ['CWE-209'],
        description: 'Error messages must be generic and not reveal system information.',
        check: 'Review error messages for sensitive information disclosure.',
        fix: 'Implement custom error pages that do not reveal stack traces or system details.'
    },
    'V-222612': {
        stigId: 'SRG-APP-000251',
        title: 'Cookies must have Secure flag',
        severity: 'CAT II',
        cwes: ['CWE-614'],
        description: 'Session cookies must have the Secure flag set.',
        check: 'Verify all session cookies have Secure flag.',
        fix: 'Set Secure flag on all cookies: Set-Cookie: name=value; Secure'
    },
    'V-222613': {
        stigId: 'SRG-APP-000439',
        title: 'Cookies must have HttpOnly flag',
        severity: 'CAT II',
        cwes: ['CWE-1004'],
        description: 'Session cookies must have the HttpOnly flag set.',
        check: 'Verify all session cookies have HttpOnly flag.',
        fix: 'Set HttpOnly flag on all cookies: Set-Cookie: name=value; HttpOnly'
    },
    'V-222620': {
        stigId: 'SRG-APP-000516',
        title: 'X-Frame-Options required',
        severity: 'CAT II',
        cwes: ['CWE-1021'],
        description: 'The application must protect against clickjacking.',
        check: 'Verify X-Frame-Options or CSP frame-ancestors is set.',
        fix: 'Add X-Frame-Options: DENY or SAMEORIGIN header.'
    },
    'V-222625': {
        stigId: 'SRG-APP-000266',
        title: 'Access control enforcement',
        severity: 'CAT I',
        cwes: ['CWE-284', 'CWE-639'],
        description: 'The application must enforce access control.',
        check: 'Test for IDOR and authorization bypass vulnerabilities.',
        fix: 'Implement proper authorization checks for all sensitive operations.'
    },
    'V-222630': {
        stigId: 'SRG-APP-000175',
        title: 'CSP header required',
        severity: 'CAT II',
        cwes: ['CWE-79'],
        description: 'Content Security Policy must be implemented.',
        check: 'Verify Content-Security-Policy header is present and properly configured.',
        fix: 'Implement CSP header that restricts script sources and prevents inline execution.'
    },
};

// ============================================================================
// COMPLIANCE FUNCTIONS
// ============================================================================

export interface ComplianceMapping {
    owasp?: string;
    owaspName?: string;
    nist?: string[];
    nistDetails?: Array<{ control: string; title: string }>;
    cwe?: string;
    cweDescription?: string;
    stig?: string[];
    stigDetails?: Array<{ id: string; title: string; severity: string }>;
}

/**
 * Get compliance mappings for a vulnerability
 */
export function getComplianceMapping(vuln: UnifiedVulnerability): ComplianceMapping {
    const mapping: ComplianceMapping = {};

    // Map from CWE
    if (vuln.cwe) {
        mapping.cwe = vuln.cwe;

        // Get NIST controls
        const cweNum = vuln.cwe.replace('CWE-', '');
        const nistControls = CWE_TO_NIST[vuln.cwe] || CWE_TO_NIST[`CWE-${cweNum}`];
        if (nistControls) {
            mapping.nist = nistControls;
            mapping.nistDetails = nistControls.map(ctrl => ({
                control: ctrl,
                title: NIST_CONTROLS[ctrl]?.title || ctrl
            }));
        }
    }

    // Map from OWASP
    if (vuln.owasp) {
        mapping.owasp = vuln.owasp;
        const owaspEntry = OWASP_TOP_10_2021[vuln.owasp as keyof typeof OWASP_TOP_10_2021];
        if (owaspEntry) {
            mapping.owaspName = owaspEntry.name;
            // Add NIST from OWASP if not already set
            if (!mapping.nist) {
                mapping.nist = owaspEntry.nist;
                mapping.nistDetails = owaspEntry.nist.map(ctrl => ({
                    control: ctrl,
                    title: NIST_CONTROLS[ctrl]?.title || ctrl
                }));
            }
        }
    }

    // Map to STIG
    const stigMatches: string[] = [];
    for (const [stigId, stig] of Object.entries(STIG_WEB_APP_CONTROLS)) {
        if (vuln.cwe && stig.cwes.includes(vuln.cwe)) {
            stigMatches.push(stigId);
        }
    }
    if (stigMatches.length > 0) {
        mapping.stig = stigMatches;
        mapping.stigDetails = stigMatches.map(id => ({
            id,
            title: STIG_WEB_APP_CONTROLS[id].title,
            severity: STIG_WEB_APP_CONTROLS[id].severity
        }));
    }

    return mapping;
}

/**
 * Enrich vulnerability with compliance data
 */
export function enrichWithCompliance(vuln: UnifiedVulnerability): UnifiedVulnerability & { compliance: ComplianceMapping } {
    const compliance = getComplianceMapping(vuln);

    // Add NIST to vuln if not present
    if (!vuln.nistControl && compliance.nist) {
        vuln.nistControl = compliance.nist.join(', ');
    }

    return {
        ...vuln,
        compliance
    };
}

/**
 * Generate compliance summary for scan results
 */
export function generateComplianceSummary(vulnerabilities: UnifiedVulnerability[]): {
    owaspCoverage: Record<string, number>;
    nistControls: Record<string, number>;
    stigFindings: Record<string, { count: number; severity: string }>;
    cweDistribution: Record<string, number>;
} {
    const owaspCoverage: Record<string, number> = {};
    const nistControls: Record<string, number> = {};
    const stigFindings: Record<string, { count: number; severity: string }> = {};
    const cweDistribution: Record<string, number> = {};

    for (const vuln of vulnerabilities) {
        const mapping = getComplianceMapping(vuln);

        // OWASP
        if (mapping.owasp) {
            owaspCoverage[mapping.owasp] = (owaspCoverage[mapping.owasp] || 0) + 1;
        }

        // NIST
        if (mapping.nist) {
            for (const ctrl of mapping.nist) {
                nistControls[ctrl] = (nistControls[ctrl] || 0) + 1;
            }
        }

        // STIG
        if (mapping.stigDetails) {
            for (const stig of mapping.stigDetails) {
                if (!stigFindings[stig.id]) {
                    stigFindings[stig.id] = { count: 0, severity: stig.severity };
                }
                stigFindings[stig.id].count++;
            }
        }

        // CWE
        if (mapping.cwe) {
            cweDistribution[mapping.cwe] = (cweDistribution[mapping.cwe] || 0) + 1;
        }
    }

    return { owaspCoverage, nistControls, stigFindings, cweDistribution };
}

/**
 * Check if scan meets compliance requirements
 */
export function checkCompliance(vulnerabilities: UnifiedVulnerability[], standard: 'nist' | 'stig' | 'owasp'): {
    compliant: boolean;
    issues: string[];
    score: number;
} {
    const issues: string[] = [];
    let score = 100;

    for (const vuln of vulnerabilities) {
        const mapping = getComplianceMapping(vuln);

        if (standard === 'nist' && mapping.nist) {
            for (const ctrl of mapping.nist) {
                issues.push(`${ctrl} (${NIST_CONTROLS[ctrl]?.title}): ${vuln.title}`);
                score -= vuln.severity === 'critical' ? 20 : vuln.severity === 'high' ? 10 : 5;
            }
        }

        if (standard === 'stig' && mapping.stigDetails) {
            for (const stig of mapping.stigDetails) {
                issues.push(`${stig.id} (${stig.severity}): ${vuln.title}`);
                score -= stig.severity === 'CAT I' ? 25 : stig.severity === 'CAT II' ? 10 : 5;
            }
        }

        if (standard === 'owasp' && mapping.owasp) {
            issues.push(`${mapping.owasp} (${mapping.owaspName}): ${vuln.title}`);
            score -= vuln.severity === 'critical' ? 15 : vuln.severity === 'high' ? 10 : 5;
        }
    }

    score = Math.max(0, score);

    return {
        compliant: score >= 70,
        issues,
        score
    };
}

export default {
    getComplianceMapping,
    enrichWithCompliance,
    generateComplianceSummary,
    checkCompliance,
    NIST_CONTROLS,
    NIST_CONTROL_FAMILIES,
    CWE_TO_NIST,
    OWASP_TOP_10_2021,
    STIG_WEB_APP_CONTROLS
};

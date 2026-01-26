// STRIX Evidence Collection Module
// Collects and stores proof for vulnerability findings

import type { UnifiedVulnerability } from './types';

// ============================================================================
// INTERFACES
// ============================================================================

export interface HttpRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    timestamp: Date;
}

export interface HttpResponse {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: string;
    bodyTruncated: boolean;
    responseTime: number;
    timestamp: Date;
}

export interface Evidence {
    id: string;
    vulnerabilityId: string;
    type: 'request-response' | 'screenshot' | 'payload' | 'code-snippet' | 'configuration';
    timestamp: Date;

    // Request/Response evidence
    request?: HttpRequest;
    response?: HttpResponse;

    // Payload evidence
    payload?: string;
    payloadType?: string;

    // Code evidence
    codeSnippet?: string;
    codeLocation?: string;
    lineNumbers?: { start: number; end: number };

    // Screenshot (base64)
    screenshot?: string;
    screenshotFormat?: 'png' | 'jpeg';

    // Reproduction steps
    reproductionSteps?: string[];

    // Additional metadata
    description?: string;
    confidence: 'confirmed' | 'likely' | 'possible';
    falsePositiveRisk: 'low' | 'medium' | 'high';
}

export interface EvidenceBundle {
    scanId: string;
    targetUrl: string;
    scanDate: Date;
    scanner: string;
    version: string;
    evidenceItems: Evidence[];
    summary: {
        totalFindings: number;
        confirmed: number;
        likely: number;
        possible: number;
    };
}

// ============================================================================
// EVIDENCE COLLECTOR
// ============================================================================

export class EvidenceCollector {
    private evidence: Evidence[] = [];
    private scanId: string;
    private maxBodySize: number = 50000; // 50KB max for response bodies

    constructor(scanId?: string) {
        this.scanId = scanId || this.generateId();
    }

    /**
     * Generate unique ID
     */
    private generateId(): string {
        return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
    }

    /**
     * Record HTTP request/response as evidence
     */
    recordHttpEvidence(
        vulnerabilityId: string,
        request: {
            method: string;
            url: string;
            headers?: Record<string, string>;
            body?: string;
        },
        response: {
            status: number;
            statusText?: string;
            headers?: Record<string, string>;
            body?: string;
            responseTime?: number;
        },
        options: {
            description?: string;
            confidence?: Evidence['confidence'];
            falsePositiveRisk?: Evidence['falsePositiveRisk'];
            payload?: string;
        } = {}
    ): Evidence {
        const now = new Date();

        // Truncate response body if too large
        let responseBody = response.body || '';
        let bodyTruncated = false;
        if (responseBody.length > this.maxBodySize) {
            responseBody = responseBody.substring(0, this.maxBodySize) + '\n\n[... TRUNCATED ...]';
            bodyTruncated = true;
        }

        const evidence: Evidence = {
            id: this.generateId(),
            vulnerabilityId,
            type: 'request-response',
            timestamp: now,
            request: {
                method: request.method,
                url: request.url,
                headers: this.sanitizeHeaders(request.headers || {}),
                body: request.body,
                timestamp: now
            },
            response: {
                status: response.status,
                statusText: response.statusText || '',
                headers: response.headers || {},
                body: responseBody,
                bodyTruncated,
                responseTime: response.responseTime || 0,
                timestamp: now
            },
            payload: options.payload,
            payloadType: options.payload ? this.detectPayloadType(options.payload) : undefined,
            description: options.description,
            confidence: options.confidence || 'likely',
            falsePositiveRisk: options.falsePositiveRisk || 'medium'
        };

        this.evidence.push(evidence);
        return evidence;
    }

    /**
     * Record payload evidence
     */
    recordPayloadEvidence(
        vulnerabilityId: string,
        payload: string,
        options: {
            type?: string;
            description?: string;
            response?: string;
            confidence?: Evidence['confidence'];
        } = {}
    ): Evidence {
        const evidence: Evidence = {
            id: this.generateId(),
            vulnerabilityId,
            type: 'payload',
            timestamp: new Date(),
            payload,
            payloadType: options.type || this.detectPayloadType(payload),
            description: options.description,
            confidence: options.confidence || 'likely',
            falsePositiveRisk: 'medium'
        };

        this.evidence.push(evidence);
        return evidence;
    }

    /**
     * Record code snippet as evidence
     */
    recordCodeEvidence(
        vulnerabilityId: string,
        code: string,
        location: string,
        options: {
            lineNumbers?: { start: number; end: number };
            description?: string;
            confidence?: Evidence['confidence'];
        } = {}
    ): Evidence {
        const evidence: Evidence = {
            id: this.generateId(),
            vulnerabilityId,
            type: 'code-snippet',
            timestamp: new Date(),
            codeSnippet: code,
            codeLocation: location,
            lineNumbers: options.lineNumbers,
            description: options.description,
            confidence: options.confidence || 'likely',
            falsePositiveRisk: 'low'
        };

        this.evidence.push(evidence);
        return evidence;
    }

    /**
     * Record reproduction steps
     */
    recordReproductionSteps(
        vulnerabilityId: string,
        steps: string[],
        options: {
            description?: string;
        } = {}
    ): Evidence {
        const evidence: Evidence = {
            id: this.generateId(),
            vulnerabilityId,
            type: 'request-response',
            timestamp: new Date(),
            reproductionSteps: steps,
            description: options.description,
            confidence: 'confirmed',
            falsePositiveRisk: 'low'
        };

        this.evidence.push(evidence);
        return evidence;
    }

    /**
     * Add reproduction steps to a vulnerability
     */
    generateReproductionSteps(vuln: UnifiedVulnerability): string[] {
        const steps: string[] = [];

        steps.push(`1. Navigate to: ${vuln.url}`);

        if (vuln.location) {
            steps.push(`2. Locate the vulnerable parameter/location: ${vuln.location}`);
        }

        if (vuln.evidence) {
            steps.push(`3. The following evidence was found:\n   ${vuln.evidence}`);
        }

        // Add category-specific steps
        switch (vuln.category) {
            case 'injection':
                steps.push('4. Inject the payload into the identified parameter');
                steps.push('5. Observe the response for signs of successful injection');
                break;
            case 'xss':
                steps.push('4. Enter XSS payload into the vulnerable input');
                steps.push('5. Observe if the payload is reflected without sanitization');
                break;
            case 'crypto':
                steps.push('4. Check SSL/TLS configuration using browser developer tools or ssllabs.com');
                break;
            case 'authentication':
                steps.push('4. Attempt to access the resource without authentication');
                steps.push('5. Verify if authentication is properly enforced');
                break;
            default:
                steps.push('4. Follow the description to reproduce the vulnerability');
        }

        steps.push(`\nRecommended Fix: ${vuln.recommendation || 'See vulnerability details'}`);

        return steps;
    }

    /**
     * Get all evidence for a vulnerability
     */
    getEvidenceForVulnerability(vulnerabilityId: string): Evidence[] {
        return this.evidence.filter(e => e.vulnerabilityId === vulnerabilityId);
    }

    /**
     * Get all collected evidence
     */
    getAllEvidence(): Evidence[] {
        return [...this.evidence];
    }

    /**
     * Generate evidence bundle for export
     */
    generateBundle(targetUrl: string, vulnerabilities: UnifiedVulnerability[]): EvidenceBundle {
        // Count confidence levels
        const confirmed = this.evidence.filter(e => e.confidence === 'confirmed').length;
        const likely = this.evidence.filter(e => e.confidence === 'likely').length;
        const possible = this.evidence.filter(e => e.confidence === 'possible').length;

        return {
            scanId: this.scanId,
            targetUrl,
            scanDate: new Date(),
            scanner: 'STRIX',
            version: '1.0.0',
            evidenceItems: this.evidence,
            summary: {
                totalFindings: vulnerabilities.length,
                confirmed,
                likely,
                possible
            }
        };
    }

    /**
     * Export evidence as formatted text
     */
    exportAsText(vuln: UnifiedVulnerability): string {
        const evidence = this.getEvidenceForVulnerability(vuln.id);
        let output = '';

        output += `================================================================================\n`;
        output += `VULNERABILITY EVIDENCE\n`;
        output += `================================================================================\n\n`;
        output += `Finding: ${vuln.title}\n`;
        output += `Severity: ${vuln.severity.toUpperCase()}\n`;
        output += `URL: ${vuln.url}\n`;
        output += `Location: ${vuln.location || 'N/A'}\n`;
        output += `CWE: ${vuln.cwe || 'N/A'}\n`;
        output += `OWASP: ${vuln.owasp || 'N/A'}\n`;
        output += `\n`;
        output += `Description:\n${vuln.description}\n\n`;

        if (evidence.length > 0) {
            output += `--------------------------------------------------------------------------------\n`;
            output += `EVIDENCE (${evidence.length} items)\n`;
            output += `--------------------------------------------------------------------------------\n\n`;

            for (const item of evidence) {
                if (item.request && item.response) {
                    output += `--- HTTP Request ---\n`;
                    output += `${item.request.method} ${item.request.url}\n`;
                    for (const [key, value] of Object.entries(item.request.headers)) {
                        output += `${key}: ${value}\n`;
                    }
                    if (item.request.body) {
                        output += `\n${item.request.body}\n`;
                    }
                    output += `\n`;

                    output += `--- HTTP Response ---\n`;
                    output += `HTTP ${item.response.status} ${item.response.statusText}\n`;
                    for (const [key, value] of Object.entries(item.response.headers)) {
                        output += `${key}: ${value}\n`;
                    }
                    output += `\n`;
                    if (item.response.body) {
                        output += `${item.response.body.substring(0, 2000)}`;
                        if (item.response.bodyTruncated) {
                            output += `\n[... Response truncated ...]\n`;
                        }
                    }
                    output += `\n\n`;
                }

                if (item.payload) {
                    output += `--- Payload ---\n`;
                    output += `Type: ${item.payloadType || 'unknown'}\n`;
                    output += `${item.payload}\n\n`;
                }

                if (item.codeSnippet) {
                    output += `--- Code Snippet ---\n`;
                    output += `Location: ${item.codeLocation}\n`;
                    if (item.lineNumbers) {
                        output += `Lines: ${item.lineNumbers.start}-${item.lineNumbers.end}\n`;
                    }
                    output += `\n${item.codeSnippet}\n\n`;
                }
            }
        }

        output += `--------------------------------------------------------------------------------\n`;
        output += `REPRODUCTION STEPS\n`;
        output += `--------------------------------------------------------------------------------\n\n`;
        const steps = this.generateReproductionSteps(vuln);
        output += steps.join('\n') + '\n\n';

        output += `--------------------------------------------------------------------------------\n`;
        output += `RECOMMENDATION\n`;
        output += `--------------------------------------------------------------------------------\n\n`;
        output += vuln.recommendation || 'See vulnerability details for remediation guidance.';
        output += '\n\n';

        return output;
    }

    /**
     * Sanitize headers to remove sensitive values
     */
    private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
        const sanitized = { ...headers };
        const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];

        for (const header of sensitiveHeaders) {
            if (sanitized[header]) {
                sanitized[header] = '[REDACTED]';
            }
            if (sanitized[header.toLowerCase()]) {
                sanitized[header.toLowerCase()] = '[REDACTED]';
            }
        }

        return sanitized;
    }

    /**
     * Detect payload type
     */
    private detectPayloadType(payload: string): string {
        if (/<script|onerror|onload|javascript:/i.test(payload)) return 'XSS';
        if (/['"].*OR.*['"]|UNION.*SELECT|--\s*$/i.test(payload)) return 'SQLi';
        if (/;.*\||`|\\$\(/i.test(payload)) return 'Command Injection';
        if (/\.\.\/|\.\.\\|etc\/passwd/i.test(payload)) return 'Path Traversal';
        if (/file:\/\/|gopher:\/\/|dict:\/\//i.test(payload)) return 'SSRF';
        if (/<!ENTITY|SYSTEM.*file:/i.test(payload)) return 'XXE';
        return 'Unknown';
    }

    /**
     * Clear all evidence
     */
    clear(): void {
        this.evidence = [];
    }
}

/**
 * Create a new evidence collector
 */
export function createEvidenceCollector(scanId?: string): EvidenceCollector {
    return new EvidenceCollector(scanId);
}

export default {
    EvidenceCollector,
    createEvidenceCollector
};

// STRIX Report Generation Module
// Generates HTML, JSON, CSV, PDF, and STIG CKL format reports
// Includes specialized reports for Web, Blockchain, Code, and Directory scans

import type { UnifiedVulnerability, ScanResult } from '../types';
import { getComplianceMapping, generateComplianceSummary } from '../compliance';
import { EvidenceCollector } from '../evidence';

// Re-export base report utilities
export * from './report-base';

// Re-export PDF report functions (Web Security)
export * from './pdf-report';

// Re-export Blockchain Security Report
export * from './blockchain-report';

// Re-export Code Security Report
export * from './code-report';

// Re-export Directory Security Report
export * from './directory-report';

// ============================================================================
// INTERFACES
// ============================================================================

export interface ReportOptions {
    title?: string;
    includeEvidence?: boolean;
    includeCompliance?: boolean;
    includeRemediation?: boolean;
    redactSensitive?: boolean;
    format: 'html' | 'json' | 'csv' | 'ckl' | 'executive' | 'pdf';
    // PDF-specific options
    scannerUser?: string;
    organization?: string;
    classification?: 'UNCLASSIFIED' | 'CUI' | 'CONFIDENTIAL' | 'SECRET' | 'TOP SECRET';
    includeExploitation?: boolean;
    includeTechnicalDetails?: boolean;
}

export interface ExecutiveSummary {
    overallRisk: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
    riskScore: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    infoFindings: number;
    topRisks: string[];
    recommendations: string[];
    complianceStatus: {
        nist: { compliant: boolean; score: number };
        owasp: { compliant: boolean; score: number };
        stig: { compliant: boolean; score: number };
    };
}

// ============================================================================
// HTML REPORT GENERATOR
// ============================================================================

export function generateHtmlReport(
    scanResult: ScanResult,
    options: Partial<ReportOptions> = {}
): string {
    const title = options.title || 'STRIX Security Assessment Report';
    const vulns = scanResult.vulnerabilities;
    
    // Calculate statistics
    const stats = {
        critical: vulns.filter(v => v.severity === 'critical').length,
        high: vulns.filter(v => v.severity === 'high').length,
        medium: vulns.filter(v => v.severity === 'medium').length,
        low: vulns.filter(v => v.severity === 'low').length,
        info: vulns.filter(v => v.severity === 'info').length,
    };
    
    const riskScore = calculateRiskScore(vulns);
    const compliance = generateComplianceSummary(vulns);
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f8fafc;
            --border: #334155;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 2rem; }
        header {
            background: linear-gradient(135deg, #0891b2, #0d9488);
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 12px;
        }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { opacity: 0.9; }
        .meta { display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.9rem; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border-left: 4px solid;
        }
        .stat-card.critical { border-color: var(--critical); }
        .stat-card.high { border-color: var(--high); }
        .stat-card.medium { border-color: var(--medium); }
        .stat-card.low { border-color: var(--low); }
        .stat-card.info { border-color: var(--info); }
        .stat-value { font-size: 2.5rem; font-weight: bold; }
        .stat-label { font-size: 0.8rem; text-transform: uppercase; opacity: 0.7; }
        
        .risk-score {
            background: var(--card);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 2rem;
        }
        .risk-meter {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: conic-gradient(
                var(--critical) 0deg ${360 - riskScore * 3.6}deg,
                #22c55e ${360 - riskScore * 3.6}deg 360deg
            );
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .risk-meter-inner {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: var(--card);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .risk-value { font-size: 2rem; font-weight: bold; }
        .risk-label { font-size: 0.8rem; opacity: 0.7; }
        
        .section { margin-bottom: 2rem; }
        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border);
        }
        
        .vuln-card {
            background: var(--card);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        .vuln-card.critical { border-color: var(--critical); }
        .vuln-card.high { border-color: var(--high); }
        .vuln-card.medium { border-color: var(--medium); }
        .vuln-card.low { border-color: var(--low); }
        .vuln-card.info { border-color: var(--info); }
        
        .vuln-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem; }
        .vuln-title { font-size: 1.1rem; font-weight: 600; }
        .vuln-severity {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .vuln-severity.critical { background: var(--critical); }
        .vuln-severity.high { background: var(--high); }
        .vuln-severity.medium { background: var(--medium); }
        .vuln-severity.low { background: var(--low); }
        .vuln-severity.info { background: var(--info); }
        
        .vuln-meta { display: flex; gap: 1rem; margin-bottom: 1rem; font-size: 0.85rem; opacity: 0.8; }
        .vuln-description { margin-bottom: 1rem; }
        .vuln-evidence {
            background: rgba(0,0,0,0.2);
            padding: 1rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            margin-bottom: 1rem;
        }
        .vuln-remediation {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            padding: 1rem;
            border-radius: 4px;
        }
        .vuln-remediation-title { color: #22c55e; font-weight: 600; margin-bottom: 0.5rem; }
        
        .compliance-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .compliance-card {
            background: var(--card);
            border-radius: 8px;
            padding: 1.5rem;
        }
        .compliance-title { font-size: 0.9rem; opacity: 0.7; margin-bottom: 0.5rem; }
        .compliance-items { font-size: 0.85rem; }
        
        footer {
            text-align: center;
            padding: 2rem;
            opacity: 0.7;
            font-size: 0.85rem;
        }
        
        @media print {
            body { background: white; color: black; }
            .vuln-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>${escapeHtml(title)}</h1>
            <p class="subtitle">Security Vulnerability Assessment</p>
            <div class="meta">
                <span>Target: ${escapeHtml(scanResult.target)}</span>
                <span>Scan Date: ${new Date(scanResult.startTime).toLocaleDateString()}</span>
                <span>Duration: ${Math.round((scanResult.duration || 0) / 1000)}s</span>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="stat-value">${stats.critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">${stats.high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">${stats.medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">${stats.low}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value">${stats.info}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <div class="risk-score">
            <div class="risk-meter">
                <div class="risk-meter-inner">
                    <div class="risk-value">${riskScore}</div>
                    <div class="risk-label">Risk Score</div>
                </div>
            </div>
            <div>
                <h3>Overall Risk Assessment</h3>
                <p>Based on ${vulns.length} findings, the target has a risk score of ${riskScore}/100.</p>
                <p style="margin-top: 0.5rem; opacity: 0.8;">
                    ${riskScore >= 70 ? 'Critical attention required - multiple high-severity issues found.' :
                      riskScore >= 40 ? 'Moderate risk - address high and medium severity issues.' :
                      riskScore >= 20 ? 'Low risk - minor issues to address.' :
                      'Minimal risk - good security posture.'}
                </p>
            </div>
        </div>
        
        ${options.includeCompliance !== false ? `
        <section class="section">
            <h2 class="section-title">Compliance Mapping</h2>
            <div class="compliance-grid">
                <div class="compliance-card">
                    <div class="compliance-title">OWASP Top 10</div>
                    <div class="compliance-items">
                        ${Object.entries(compliance.owaspCoverage).map(([id, count]) => 
                            `<div>${id}: ${count} finding(s)</div>`
                        ).join('') || 'No OWASP mappings'}
                    </div>
                </div>
                <div class="compliance-card">
                    <div class="compliance-title">NIST 800-53 Controls</div>
                    <div class="compliance-items">
                        ${Object.entries(compliance.nistControls).slice(0, 5).map(([id, count]) => 
                            `<div>${id}: ${count} finding(s)</div>`
                        ).join('') || 'No NIST mappings'}
                    </div>
                </div>
                <div class="compliance-card">
                    <div class="compliance-title">DISA STIG Findings</div>
                    <div class="compliance-items">
                        ${Object.entries(compliance.stigFindings).slice(0, 5).map(([id, data]) => 
                            `<div>${id} (${data.severity}): ${data.count}</div>`
                        ).join('') || 'No STIG mappings'}
                    </div>
                </div>
            </div>
        </section>
        ` : ''}
        
        <section class="section">
            <h2 class="section-title">Vulnerability Details</h2>
            ${vulns.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))
                .map(vuln => {
                    const complianceMap = options.includeCompliance !== false ? getComplianceMapping(vuln) : null;
                    return `
                    <div class="vuln-card ${vuln.severity}">
                        <div class="vuln-header">
                            <div class="vuln-title">${escapeHtml(vuln.title)}</div>
                            <span class="vuln-severity ${vuln.severity}">${vuln.severity}</span>
                        </div>
                        <div class="vuln-meta">
                            <span>URL: ${escapeHtml(vuln.url || '')}</span>
                            ${vuln.cwe ? `<span>CWE: ${vuln.cwe}</span>` : ''}
                            ${vuln.owasp ? `<span>OWASP: ${vuln.owasp}</span>` : ''}
                            ${complianceMap?.nist ? `<span>NIST: ${complianceMap.nist.join(', ')}</span>` : ''}
                        </div>
                        <div class="vuln-description">${escapeHtml(vuln.description)}</div>
                        ${vuln.evidence ? `
                        <div class="vuln-evidence">${escapeHtml(vuln.evidence)}</div>
                        ` : ''}
                        ${options.includeRemediation !== false && vuln.recommendation ? `
                        <div class="vuln-remediation">
                            <div class="vuln-remediation-title">Recommendation</div>
                            <div>${escapeHtml(vuln.recommendation)}</div>
                        </div>
                        ` : ''}
                    </div>
                    `;
                }).join('')}
        </section>
        
        <footer>
            <p>Generated by STRIX Security Scanner</p>
            <p>Report generated: ${new Date().toISOString()}</p>
        </footer>
    </div>
</body>
</html>`;
}

// ============================================================================
// JSON REPORT GENERATOR
// ============================================================================

export function generateJsonReport(scanResult: ScanResult, options: Partial<ReportOptions> = {}): string {
    const compliance = generateComplianceSummary(scanResult.vulnerabilities);
    
    const report = {
        metadata: {
            scanner: 'STRIX',
            version: '1.0.0',
            generatedAt: new Date().toISOString(),
            title: options.title || 'Security Assessment Report'
        },
        target: {
            url: scanResult.target,
            scanDate: new Date(scanResult.startTime).toISOString(),
            duration: scanResult.duration || 0
        },
        summary: {
            totalVulnerabilities: scanResult.vulnerabilities.length,
            bySeverity: {
                critical: scanResult.vulnerabilities.filter(v => v.severity === 'critical').length,
                high: scanResult.vulnerabilities.filter(v => v.severity === 'high').length,
                medium: scanResult.vulnerabilities.filter(v => v.severity === 'medium').length,
                low: scanResult.vulnerabilities.filter(v => v.severity === 'low').length,
                info: scanResult.vulnerabilities.filter(v => v.severity === 'info').length,
            },
            riskScore: calculateRiskScore(scanResult.vulnerabilities)
        },
        compliance: options.includeCompliance !== false ? compliance : undefined,
        vulnerabilities: scanResult.vulnerabilities.map(vuln => ({
            ...vuln,
            compliance: options.includeCompliance !== false ? getComplianceMapping(vuln) : undefined
        })),
        web3Detection: scanResult.web3Detection
    };
    
    return JSON.stringify(report, null, 2);
}

// ============================================================================
// CSV REPORT GENERATOR
// ============================================================================

export function generateCsvReport(scanResult: ScanResult): string {
    const headers = [
        'ID',
        'Severity',
        'Title',
        'Category',
        'URL',
        'Location',
        'Description',
        'Evidence',
        'CWE',
        'OWASP',
        'NIST Controls',
        'Recommendation'
    ];
    
    const rows = scanResult.vulnerabilities.map(vuln => {
        const compliance = getComplianceMapping(vuln);
        return [
            vuln.id,
            vuln.severity,
            vuln.title,
            vuln.category,
            vuln.url || '',
            vuln.location || '',
            vuln.description.replace(/"/g, '""'),
            (vuln.evidence || '').replace(/"/g, '""'),
            vuln.cwe || '',
            vuln.owasp || '',
            compliance.nist?.join('; ') || '',
            (vuln.recommendation || '').replace(/"/g, '""')
        ].map(v => `"${v}"`).join(',');
    });
    
    return [headers.join(','), ...rows].join('\n');
}

// ============================================================================
// STIG CKL (Checklist) FORMAT
// ============================================================================

export function generateStigCkl(scanResult: ScanResult, stigId: string = 'Web_Application_STIG'): string {
    const vulns = scanResult.vulnerabilities;
    const now = new Date().toISOString();
    
    // Build checklist items
    let checklistItems = '';
    
    // Map vulnerabilities to STIG checks
    const stigVulns = vulns.filter(v => {
        const compliance = getComplianceMapping(v);
        return compliance.stig && compliance.stig.length > 0;
    });
    
    for (const vuln of stigVulns) {
        const compliance = getComplianceMapping(vuln);
        for (const stigCheck of compliance.stig || []) {
            checklistItems += `
        <VULN>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${stigCheck}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${vuln.severity === 'critical' || vuln.severity === 'high' ? 'high' : vuln.severity}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${escapeXml(vuln.title)}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Discussion</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${escapeXml(vuln.description)}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Check_Content</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${escapeXml(vuln.evidence || 'See vulnerability details')}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STIG_DATA>
                <VULN_ATTRIBUTE>Fix_Text</VULN_ATTRIBUTE>
                <ATTRIBUTE_DATA>${escapeXml(vuln.recommendation || 'See remediation guidance')}</ATTRIBUTE_DATA>
            </STIG_DATA>
            <STATUS>Open</STATUS>
            <FINDING_DETAILS>${escapeXml(vuln.evidence || '')}</FINDING_DETAILS>
            <COMMENTS>Found by STRIX Security Scanner</COMMENTS>
        </VULN>`;
        }
    }
    
    return `<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
    <ASSET>
        <ROLE>None</ROLE>
        <ASSET_TYPE>Web Application</ASSET_TYPE>
        <HOST_NAME>${escapeXml(new URL(scanResult.target).hostname)}</HOST_NAME>
        <HOST_IP></HOST_IP>
        <HOST_MAC></HOST_MAC>
        <HOST_FQDN>${escapeXml(new URL(scanResult.target).hostname)}</HOST_FQDN>
        <TARGET_COMMENT>${escapeXml(scanResult.target)}</TARGET_COMMENT>
        <TECH_AREA></TECH_AREA>
        <TARGET_KEY></TARGET_KEY>
        <WEB_OR_DATABASE>true</WEB_OR_DATABASE>
        <WEB_DB_SITE>${escapeXml(scanResult.target)}</WEB_DB_SITE>
        <WEB_DB_INSTANCE></WEB_DB_INSTANCE>
    </ASSET>
    <STIGS>
        <iSTIG>
            <STIG_INFO>
                <SI_DATA>
                    <SID_NAME>version</SID_NAME>
                    <SID_DATA>1</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>classification</SID_NAME>
                    <SID_DATA>UNCLASSIFIED</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>stigid</SID_NAME>
                    <SID_DATA>${stigId}</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>description</SID_NAME>
                    <SID_DATA>STRIX Security Scan Results</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>title</SID_NAME>
                    <SID_DATA>Web Application Security Assessment</SID_DATA>
                </SI_DATA>
                <SI_DATA>
                    <SID_NAME>releaseinfo</SID_NAME>
                    <SID_DATA>Generated: ${now}</SID_DATA>
                </SI_DATA>
            </STIG_INFO>
            ${checklistItems}
        </iSTIG>
    </STIGS>
</CHECKLIST>`;
}

// ============================================================================
// EXECUTIVE SUMMARY
// ============================================================================

export function generateExecutiveSummary(scanResult: ScanResult): ExecutiveSummary {
    const vulns = scanResult.vulnerabilities;
    
    const criticalFindings = vulns.filter(v => v.severity === 'critical').length;
    const highFindings = vulns.filter(v => v.severity === 'high').length;
    const mediumFindings = vulns.filter(v => v.severity === 'medium').length;
    const lowFindings = vulns.filter(v => v.severity === 'low').length;
    const infoFindings = vulns.filter(v => v.severity === 'info').length;
    
    const riskScore = calculateRiskScore(vulns);
    
    // Determine overall risk
    let overallRisk: ExecutiveSummary['overallRisk'];
    if (criticalFindings > 0 || riskScore >= 70) overallRisk = 'critical';
    else if (highFindings > 2 || riskScore >= 50) overallRisk = 'high';
    else if (mediumFindings > 3 || riskScore >= 30) overallRisk = 'medium';
    else if (lowFindings > 0 || riskScore >= 10) overallRisk = 'low';
    else overallRisk = 'minimal';
    
    // Top risks
    const topRisks = vulns
        .filter(v => v.severity === 'critical' || v.severity === 'high')
        .slice(0, 5)
        .map(v => v.title);
    
    // Key recommendations
    const recommendations = [
        ...new Set(vulns
            .filter(v => v.severity === 'critical' || v.severity === 'high')
            .map(v => v.recommendation)
            .filter(Boolean) as string[])
    ].slice(0, 5);
    
    return {
        overallRisk,
        riskScore,
        criticalFindings,
        highFindings,
        mediumFindings,
        lowFindings,
        infoFindings,
        topRisks,
        recommendations,
        complianceStatus: {
            nist: { compliant: riskScore < 30, score: 100 - riskScore },
            owasp: { compliant: criticalFindings === 0 && highFindings < 3, score: 100 - riskScore },
            stig: { compliant: criticalFindings === 0, score: 100 - (criticalFindings * 25 + highFindings * 10) }
        }
    };
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function calculateRiskScore(vulns: UnifiedVulnerability[]): number {
    let score = 0;
    for (const vuln of vulns) {
        switch (vuln.severity) {
            case 'critical': score += 25; break;
            case 'high': score += 15; break;
            case 'medium': score += 8; break;
            case 'low': score += 3; break;
            case 'info': score += 1; break;
        }
    }
    return Math.min(100, score);
}

function severityOrder(severity: string): number {
    switch (severity) {
        case 'critical': return 0;
        case 'high': return 1;
        case 'medium': return 2;
        case 'low': return 3;
        case 'info': return 4;
        default: return 5;
    }
}

function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function escapeXml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

/**
 * Generate report in specified format
 */
export function generateReport(
    scanResult: ScanResult,
    options: ReportOptions
): string {
    switch (options.format) {
        case 'html':
            return generateHtmlReport(scanResult, options);
        case 'json':
            return generateJsonReport(scanResult, options);
        case 'csv':
            return generateCsvReport(scanResult);
        case 'ckl':
            return generateStigCkl(scanResult);
        case 'executive':
            return JSON.stringify(generateExecutiveSummary(scanResult), null, 2);
        case 'pdf':
            // PDF returns a jsPDF object, so we convert to base64 data URI for string return
            const { generatePdfReport } = require('./pdf-report');
            const doc = generatePdfReport(scanResult, {
                title: options.title,
                scannerUser: options.scannerUser,
                organization: options.organization,
                classification: options.classification,
                includeEvidence: options.includeEvidence,
                includeExploitation: options.includeExploitation,
                includeRemediation: options.includeRemediation,
                includeTechnicalDetails: options.includeTechnicalDetails,
                includeCompliance: options.includeCompliance,
                redactSensitive: options.redactSensitive
            });
            return doc.output('datauristring');
        default:
            throw new Error(`Unknown report format: ${options.format}`);
    }
}

// Import PDF functions for default export
import { generatePdfReport, downloadPdfReport, generatePdfBlob } from './pdf-report';
import { generateBlockchainReport, downloadBlockchainReport } from './blockchain-report';
import { generateCodeReport, downloadCodeReport } from './code-report';
import { generateDirectoryReport, downloadDirectoryReport } from './directory-report';
import reportBase from './report-base';

export default {
    // Legacy/HTML reports
    generateReport,
    generateHtmlReport,
    generateJsonReport,
    generateCsvReport,
    generateStigCkl,
    generateExecutiveSummary,
    
    // Web Security PDF Report
    generatePdfReport,
    downloadPdfReport,
    generatePdfBlob,
    
    // Blockchain Security Report
    generateBlockchainReport,
    downloadBlockchainReport,
    
    // Code Security Report
    generateCodeReport,
    downloadCodeReport,
    
    // Directory Security Report
    generateDirectoryReport,
    downloadDirectoryReport,
    
    // Base utilities
    base: reportBase
};

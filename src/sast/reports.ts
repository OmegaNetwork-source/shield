// STRIX SAST - Report Generation
// Generate reports from SAST and GitHub scan results

import {
    ScanResult,
    GitHubScanResult,
    SASTFinding,
    GitHubSecretFinding,
    SeverityLevel,
} from './types';

// Severity colors for HTML/PDF
const SEVERITY_COLORS: Record<SeverityLevel, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#ca8a04',
    low: '#2563eb',
    info: '#6b7280',
};

const SEVERITY_BG_COLORS: Record<SeverityLevel, string> = {
    critical: '#fef2f2',
    high: '#fff7ed',
    medium: '#fefce8',
    low: '#eff6ff',
    info: '#f9fafb',
};

/**
 * Generate HTML report from SAST scan
 */
export function generateHtmlReport(result: ScanResult): string {
    const { summary, findings } = result;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIX SAST Report - ${new Date(result.startTime).toLocaleDateString()}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 0.5rem; }
        .header p { color: #94a3b8; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .summary-card { background: #1e293b; border-radius: 12px; padding: 1.5rem; text-align: center; }
        .summary-card h3 { font-size: 2rem; color: #38bdf8; }
        .summary-card p { color: #94a3b8; font-size: 0.875rem; }
        .severity-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.5rem; margin-bottom: 2rem; }
        .severity-badge { padding: 1rem; border-radius: 8px; text-align: center; }
        .severity-badge.critical { background: ${SEVERITY_BG_COLORS.critical}; color: ${SEVERITY_COLORS.critical}; }
        .severity-badge.high { background: ${SEVERITY_BG_COLORS.high}; color: ${SEVERITY_COLORS.high}; }
        .severity-badge.medium { background: ${SEVERITY_BG_COLORS.medium}; color: ${SEVERITY_COLORS.medium}; }
        .severity-badge.low { background: ${SEVERITY_BG_COLORS.low}; color: ${SEVERITY_COLORS.low}; }
        .severity-badge.info { background: ${SEVERITY_BG_COLORS.info}; color: ${SEVERITY_COLORS.info}; }
        .severity-badge span { font-size: 1.5rem; font-weight: bold; display: block; }
        .findings { margin-top: 2rem; }
        .finding { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; }
        .finding.critical { border-color: ${SEVERITY_COLORS.critical}; }
        .finding.high { border-color: ${SEVERITY_COLORS.high}; }
        .finding.medium { border-color: ${SEVERITY_COLORS.medium}; }
        .finding.low { border-color: ${SEVERITY_COLORS.low}; }
        .finding.info { border-color: ${SEVERITY_COLORS.info}; }
        .finding-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem; }
        .finding-title { font-weight: 600; font-size: 1.125rem; }
        .finding-badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .finding-location { font-family: monospace; background: #0f172a; padding: 0.5rem; border-radius: 4px; font-size: 0.875rem; color: #94a3b8; margin: 0.5rem 0; }
        .finding-snippet { font-family: monospace; background: #0f172a; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.875rem; white-space: pre-wrap; }
        .finding-meta { display: flex; gap: 1rem; margin-top: 1rem; font-size: 0.875rem; color: #94a3b8; }
        .finding-meta span { display: flex; align-items: center; gap: 0.25rem; }
        .remediation { background: #0f172a; padding: 1rem; border-radius: 8px; margin-top: 1rem; }
        .remediation h4 { color: #38bdf8; margin-bottom: 0.5rem; }
        .risk-score { font-size: 3rem; font-weight: bold; }
        .risk-score.low { color: #22c55e; }
        .risk-score.medium { color: #eab308; }
        .risk-score.high { color: #f97316; }
        .risk-score.critical { color: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦉 STRIX SAST Report</h1>
            <p>Static Application Security Testing Results</p>
            <p>Scanned: ${result.targetPath}</p>
            <p>Date: ${new Date(result.startTime).toLocaleString()}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>${summary.totalFindings}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card">
                <h3>${result.filesScanned}</h3>
                <p>Files Scanned</p>
            </div>
            <div class="summary-card">
                <h3>${result.linesScanned.toLocaleString()}</h3>
                <p>Lines Analyzed</p>
            </div>
            <div class="summary-card">
                <h3 class="risk-score ${getRiskClass(summary.riskScore)}">${summary.riskScore}</h3>
                <p>Risk Score</p>
            </div>
        </div>

        <div class="severity-grid">
            <div class="severity-badge critical">
                <span>${summary.bySeverity.critical}</span>
                Critical
            </div>
            <div class="severity-badge high">
                <span>${summary.bySeverity.high}</span>
                High
            </div>
            <div class="severity-badge medium">
                <span>${summary.bySeverity.medium}</span>
                Medium
            </div>
            <div class="severity-badge low">
                <span>${summary.bySeverity.low}</span>
                Low
            </div>
            <div class="severity-badge info">
                <span>${summary.bySeverity.info}</span>
                Info
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 1rem;">Findings</h2>
            ${findings.map(f => renderFinding(f)).join('')}
        </div>

        <footer style="text-align: center; margin-top: 3rem; color: #64748b; font-size: 0.875rem;">
            <p>Generated by STRIX Security Scanner</p>
            <p>Duration: ${(result.duration / 1000).toFixed(2)}s</p>
        </footer>
    </div>
</body>
</html>`;
}

function renderFinding(finding: SASTFinding): string {
    return `
    <div class="finding ${finding.severity}">
        <div class="finding-header">
            <div>
                <div class="finding-title">${escapeHtml(finding.title)}</div>
                <div class="finding-location">${escapeHtml(finding.location.file)}:${finding.location.line}</div>
            </div>
            <span class="finding-badge" style="background: ${SEVERITY_BG_COLORS[finding.severity]}; color: ${SEVERITY_COLORS[finding.severity]}">
                ${finding.severity}
            </span>
        </div>
        <p>${escapeHtml(finding.description)}</p>
        <div class="finding-snippet">${escapeHtml(finding.location.snippet)}</div>
        <div class="finding-meta">
            <span>📁 ${finding.category}</span>
            ${finding.cwe?.length ? `<span>🔗 ${finding.cwe.join(', ')}</span>` : ''}
            ${finding.owasp?.length ? `<span>🛡️ ${finding.owasp.join(', ')}</span>` : ''}
        </div>
        ${finding.remediation ? `
        <div class="remediation">
            <h4>Remediation</h4>
            <p>${escapeHtml(finding.remediation)}</p>
        </div>
        ` : ''}
    </div>`;
}

/**
 * Generate HTML report from GitHub scan
 */
export function generateGitHubHtmlReport(result: GitHubScanResult): string {
    const { summary, findings } = result;
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIX GitHub Secrets Report - ${new Date(result.startTime).toLocaleDateString()}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; margin-bottom: 3rem; }
        .header h1 { font-size: 2.5rem; color: #38bdf8; margin-bottom: 0.5rem; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .summary-card { background: #1e293b; border-radius: 12px; padding: 1.5rem; text-align: center; }
        .summary-card h3 { font-size: 2rem; color: #38bdf8; }
        .summary-card p { color: #94a3b8; font-size: 0.875rem; }
        .finding { background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; }
        .finding.critical { border-color: ${SEVERITY_COLORS.critical}; }
        .finding.high { border-color: ${SEVERITY_COLORS.high}; }
        .finding.medium { border-color: ${SEVERITY_COLORS.medium}; }
        .finding-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem; }
        .finding-title { font-weight: 600; font-size: 1.125rem; }
        .finding-badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
        .repo-link { color: #38bdf8; text-decoration: none; }
        .repo-link:hover { text-decoration: underline; }
        .finding-snippet { font-family: monospace; background: #0f172a; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.875rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GitHub Secrets Scan Report</h1>
            <p>Leaked credentials and secrets found on GitHub</p>
            <p>Date: ${new Date(result.startTime).toLocaleString()}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>${summary.totalFindings}</h3>
                <p>Secrets Found</p>
            </div>
            <div class="summary-card">
                <h3>${result.repositoriesSearched}</h3>
                <p>Repositories Searched</p>
            </div>
            <div class="summary-card">
                <h3>${summary.bySeverity.critical}</h3>
                <p>Critical Findings</p>
            </div>
        </div>

        <h2 style="margin-bottom: 1rem;">Findings</h2>
        ${findings.map(f => renderGitHubFinding(f)).join('')}

        <footer style="text-align: center; margin-top: 3rem; color: #64748b; font-size: 0.875rem;">
            <p>Generated by STRIX Security Scanner</p>
            <p>Duration: ${(result.duration / 1000).toFixed(2)}s</p>
        </footer>
    </div>
</body>
</html>`;
}

function renderGitHubFinding(finding: GitHubSecretFinding): string {
    return `
    <div class="finding ${finding.severity}">
        <div class="finding-header">
            <div>
                <div class="finding-title">${escapeHtml(finding.secretType)}</div>
                <a class="repo-link" href="${finding.repository.url}" target="_blank">
                    ${escapeHtml(finding.repository.fullName)}
                </a>
            </div>
            <span class="finding-badge" style="background: ${SEVERITY_BG_COLORS[finding.severity]}; color: ${SEVERITY_COLORS[finding.severity]}">
                ${finding.severity}
            </span>
        </div>
        <p>File: <a class="repo-link" href="${finding.file.url}" target="_blank">${escapeHtml(finding.file.path)}</a></p>
        <div class="finding-snippet">${escapeHtml(finding.match.snippet)}</div>
    </div>`;
}

/**
 * Generate JSON report
 */
export function generateJsonReport(result: ScanResult | GitHubScanResult): string {
    return JSON.stringify(result, null, 2);
}

/**
 * Generate CSV report from SAST scan
 */
export function generateCsvReport(result: ScanResult): string {
    const headers = [
        'Severity',
        'Title',
        'Category',
        'File',
        'Line',
        'Description',
        'CWE',
        'OWASP',
        'Remediation',
    ];

    const rows = result.findings.map(f => [
        f.severity,
        escapeCsv(f.title),
        f.category,
        escapeCsv(f.location.file),
        f.location.line.toString(),
        escapeCsv(f.description),
        f.cwe?.join('; ') || '',
        f.owasp?.join('; ') || '',
        escapeCsv(f.remediation || ''),
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

/**
 * Generate GitHub CSV report
 */
export function generateGitHubCsvReport(result: GitHubScanResult): string {
    const headers = [
        'Severity',
        'Secret Type',
        'Repository',
        'File Path',
        'Confidence',
        'Snippet',
    ];

    const rows = result.findings.map(f => [
        f.severity,
        escapeCsv(f.secretType),
        escapeCsv(f.repository.fullName),
        escapeCsv(f.file.path),
        f.confidence,
        escapeCsv(f.match.snippet),
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

/**
 * Generate SARIF report (Static Analysis Results Interchange Format)
 */
export function generateSarifReport(result: ScanResult): object {
    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'STRIX SAST',
                        version: '1.0.0',
                        informationUri: 'https://strix.security',
                        rules: getUniqueRules(result.findings),
                    },
                },
                results: result.findings.map(f => ({
                    ruleId: f.ruleId,
                    level: mapSeverityToSarif(f.severity),
                    message: {
                        text: f.description,
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: f.location.file,
                                },
                                region: {
                                    startLine: f.location.line,
                                    startColumn: f.location.column || 1,
                                    snippet: {
                                        text: f.location.snippet,
                                    },
                                },
                            },
                        },
                    ],
                })),
            },
        ],
    };
}

// Helper functions
function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeCsv(str: string): string {
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

function getRiskClass(score: number): string {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
}

function mapSeverityToSarif(severity: SeverityLevel): string {
    const map: Record<SeverityLevel, string> = {
        critical: 'error',
        high: 'error',
        medium: 'warning',
        low: 'note',
        info: 'note',
    };
    return map[severity];
}

function getUniqueRules(findings: SASTFinding[]): object[] {
    const seen = new Set<string>();
    const rules: object[] = [];

    for (const finding of findings) {
        if (seen.has(finding.ruleId)) continue;
        seen.add(finding.ruleId);

        rules.push({
            id: finding.ruleId,
            name: finding.title,
            shortDescription: { text: finding.title },
            fullDescription: { text: finding.description },
            defaultConfiguration: {
                level: mapSeverityToSarif(finding.severity),
            },
            help: {
                text: finding.remediation || '',
                markdown: finding.remediation || '',
            },
        });
    }

    return rules;
}

export default {
    generateHtmlReport,
    generateGitHubHtmlReport,
    generateJsonReport,
    generateCsvReport,
    generateGitHubCsvReport,
    generateSarifReport,
};

// STRIX Code Security Report Generator
// Generates comprehensive PDF reports for source code security analysis

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
    COLORS,
    BaseReportOptions,
    drawReportHeader,
    drawSectionHeader,
    drawRiskGauge,
    drawSeveritySummary,
    addNewPage,
    addAllPageFooters,
    getSeverityColor,
    formatDate,
    sanitizeText,
    generateReportId,
    calculateRiskScore,
    getRiskLevel
} from './report-base';

// ============================================================================
// INTERFACES
// ============================================================================

export interface CodeFinding {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    category: string;
    filePath: string;
    lineNumber?: number;
    columnNumber?: number;
    codeSnippet?: string;
    cwe?: string;
    owasp?: string;
    recommendation: string;
    references?: string[];
    language?: string;
    rule?: string;
}

export interface FileAnalysis {
    path: string;
    language: string;
    lines: number;
    findings: number;
    complexity?: number;
    coverage?: number;
}

export interface DependencyVuln {
    package: string;
    version: string;
    severity: string;
    cve?: string;
    title: string;
    fixedIn?: string;
}

export interface CodeScanResult {
    projectName: string;
    scanDate: Date;
    duration: number;
    files: FileAnalysis[];
    findings: CodeFinding[];
    dependencies?: DependencyVuln[];
    languages: { [key: string]: number };
    totalLines: number;
    metrics?: {
        complexity: number;
        duplications: number;
        testCoverage?: number;
        technicalDebt?: string;
    };
    secretsFound?: number;
    hardcodedCredentials?: string[];
}

export interface CodeReportOptions extends BaseReportOptions {
    projectName?: string;
    repositoryUrl?: string;
    branch?: string;
    commitHash?: string;
    includeDependencies?: boolean;
    includeMetrics?: boolean;
    includeSecrets?: boolean;
}

// ============================================================================
// CODE SECURITY REPORT GENERATOR
// ============================================================================

export function generateCodeReport(
    scanResult: CodeScanResult,
    options: CodeReportOptions = {}
): jsPDF {
    const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4'
    });
    
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;
    
    const title = options.title || 'Source Code Security Analysis';
    const projectName = options.projectName || scanResult.projectName || 'Code Project';
    const reportId = options.reportId || generateReportId();
    
    let currentY = margin;
    
    // ========================================================================
    // COVER PAGE
    // ========================================================================
    
    currentY = drawReportHeader(doc, title, projectName, {
        ...options,
        reportId
    });
    
    currentY += 10;
    
    // Risk Score
    const riskScore = calculateRiskScore(scanResult.findings);
    const riskInfo = getRiskLevel(riskScore);
    
    drawRiskGauge(doc, pageWidth / 2 - 30, currentY, riskScore, 60);
    currentY += 75;
    
    // Severity Summary
    const counts = {
        critical: scanResult.findings.filter(f => f.severity === 'critical').length,
        high: scanResult.findings.filter(f => f.severity === 'high').length,
        medium: scanResult.findings.filter(f => f.severity === 'medium').length,
        low: scanResult.findings.filter(f => f.severity === 'low').length,
        info: scanResult.findings.filter(f => f.severity === 'info').length,
    };
    
    currentY = drawSeveritySummary(doc, margin + 10, currentY, counts, 32);
    currentY += 15;
    
    // Scan summary box
    doc.setFillColor(...COLORS.darkAlt);
    doc.roundedRect(margin, currentY, contentWidth, 55, 3, 3, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Scan Summary', margin + 5, currentY + 8);
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    
    const summaryItems = [
        ['Files Analyzed:', scanResult.files.length.toString()],
        ['Total Lines of Code:', scanResult.totalLines.toLocaleString()],
        ['Security Findings:', scanResult.findings.length.toString()],
        ['Languages:', Object.keys(scanResult.languages).join(', ')],
        ['Scan Duration:', `${Math.round(scanResult.duration / 1000)}s`],
        ['Scan Date:', formatDate(scanResult.scanDate)],
    ];
    
    if (options.branch) {
        summaryItems.push(['Branch:', options.branch]);
    }
    if (options.commitHash) {
        summaryItems.push(['Commit:', options.commitHash.substring(0, 8)]);
    }
    
    let summaryY = currentY + 16;
    const col1X = margin + 5;
    const col2X = margin + contentWidth / 2;
    
    for (let i = 0; i < summaryItems.length; i++) {
        const [label, value] = summaryItems[i];
        const x = i % 2 === 0 ? col1X : col2X;
        const y = summaryY + Math.floor(i / 2) * 7;
        
        doc.setTextColor(...COLORS.textLight);
        doc.text(label, x, y);
        doc.setTextColor(...COLORS.white);
        doc.text(value, x + 40, y);
    }
    
    // ========================================================================
    // EXECUTIVE SUMMARY
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Executive Summary', currentY, 1);
    
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    
    const execSummary = `A comprehensive static code analysis was performed on ${projectName}. The analysis covered ${scanResult.files.length} files totaling ${scanResult.totalLines.toLocaleString()} lines of code across ${Object.keys(scanResult.languages).length} programming language(s). The scan identified ${scanResult.findings.length} security findings with an overall risk score of ${riskScore}/100 (${riskInfo.level}).`;
    
    const summaryLines = doc.splitTextToSize(execSummary, contentWidth);
    doc.text(summaryLines, margin, currentY);
    currentY += summaryLines.length * 5 + 10;
    
    // Language breakdown
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('Language Distribution', margin, currentY);
    currentY += 8;
    
    const langData = Object.entries(scanResult.languages)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([lang, lines]) => [
            lang,
            lines.toLocaleString(),
            `${((lines / scanResult.totalLines) * 100).toFixed(1)}%`
        ]);
    
    autoTable(doc, {
        startY: currentY,
        head: [['Language', 'Lines', 'Percentage']],
        body: langData,
        theme: 'striped',
        headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
        styles: { fontSize: 9 },
        columnStyles: {
            0: { cellWidth: 50 },
            1: { cellWidth: 40, halign: 'right' },
            2: { cellWidth: 40, halign: 'right' }
        },
        margin: { left: margin, right: margin }
    });
    
    currentY = doc.lastAutoTable.finalY + 15;
    
    // Finding categories
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Findings by Category', margin, currentY);
    currentY += 8;
    
    const categoryGroups: { [key: string]: number } = {};
    for (const finding of scanResult.findings) {
        categoryGroups[finding.category] = (categoryGroups[finding.category] || 0) + 1;
    }
    
    const categoryData = Object.entries(categoryGroups)
        .sort((a, b) => b[1] - a[1])
        .map(([cat, count]) => [cat, count.toString()]);
    
    if (categoryData.length > 0) {
        autoTable(doc, {
            startY: currentY,
            head: [['Category', 'Count']],
            body: categoryData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 9 },
            margin: { left: margin, right: margin }
        });
        currentY = doc.lastAutoTable.finalY + 10;
    }
    
    // ========================================================================
    // DEPENDENCY VULNERABILITIES
    // ========================================================================
    
    if (options.includeDependencies !== false && scanResult.dependencies && scanResult.dependencies.length > 0) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Dependency Vulnerabilities', currentY, 2);
        
        doc.setTextColor(...COLORS.text);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.text(`Found ${scanResult.dependencies.length} vulnerable dependencies:`, margin, currentY);
        currentY += 8;
        
        const depData = scanResult.dependencies.slice(0, 20).map(dep => [
            dep.package,
            dep.version,
            dep.severity.toUpperCase(),
            dep.cve || 'N/A',
            dep.fixedIn || 'N/A'
        ]);
        
        autoTable(doc, {
            startY: currentY,
            head: [['Package', 'Version', 'Severity', 'CVE', 'Fixed In']],
            body: depData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 8 },
            didParseCell: (data) => {
                if (data.column.index === 2 && data.section === 'body') {
                    const sev = data.cell.raw?.toString().toLowerCase();
                    if (sev) {
                        data.cell.styles.textColor = getSeverityColor(sev);
                        data.cell.styles.fontStyle = 'bold';
                    }
                }
            },
            margin: { left: margin, right: margin }
        });
        
        currentY = doc.lastAutoTable.finalY + 10;
    }
    
    // ========================================================================
    // DETAILED FINDINGS
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Detailed Findings', currentY, 3);
    
    // Summary table first
    const findingsTableData = scanResult.findings
        .sort((a, b) => {
            const order = ['critical', 'high', 'medium', 'low', 'info'];
            return order.indexOf(a.severity) - order.indexOf(b.severity);
        })
        .slice(0, 30)
        .map((f, i) => [
            (i + 1).toString(),
            f.severity.toUpperCase(),
            sanitizeText(f.title).substring(0, 40),
            f.filePath.split('/').pop() || f.filePath,
            f.lineNumber?.toString() || '-',
            f.cwe || '-'
        ]);
    
    autoTable(doc, {
        startY: currentY,
        head: [['#', 'Severity', 'Title', 'File', 'Line', 'CWE']],
        body: findingsTableData,
        theme: 'striped',
        headStyles: { fillColor: COLORS.primary, textColor: COLORS.white, fontSize: 8 },
        styles: { fontSize: 7, cellPadding: 2 },
        columnStyles: {
            0: { cellWidth: 8 },
            1: { cellWidth: 18 },
            2: { cellWidth: 55 },
            3: { cellWidth: 35 },
            4: { cellWidth: 12 },
            5: { cellWidth: 20 }
        },
        didParseCell: (data) => {
            if (data.column.index === 1 && data.section === 'body') {
                const sev = data.cell.raw?.toString().toLowerCase();
                if (sev) {
                    data.cell.styles.textColor = getSeverityColor(sev);
                    data.cell.styles.fontStyle = 'bold';
                }
            }
        },
        margin: { left: margin, right: margin }
    });
    
    currentY = doc.lastAutoTable.finalY + 15;
    
    // Detailed findings
    const sortedFindings = [...scanResult.findings].sort((a, b) => {
        const order = ['critical', 'high', 'medium', 'low', 'info'];
        return order.indexOf(a.severity) - order.indexOf(b.severity);
    });
    
    for (let i = 0; i < Math.min(sortedFindings.length, 15); i++) {
        const finding = sortedFindings[i];
        
        if (currentY > pageHeight - 70) {
            currentY = addNewPage(doc, options.classification);
        }
        
        // Finding header
        const severityColor = getSeverityColor(finding.severity);
        doc.setFillColor(...severityColor);
        doc.roundedRect(margin, currentY, contentWidth, 8, 1, 1, 'F');
        
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text(`${finding.id}: ${sanitizeText(finding.title)}`, margin + 3, currentY + 5.5);
        doc.text(finding.severity.toUpperCase(), pageWidth - margin - 20, currentY + 5.5);
        
        currentY += 12;
        
        // Details
        const boxStartY = currentY;
        doc.setDrawColor(...severityColor);
        doc.setLineWidth(0.3);
        
        // File location
        doc.setTextColor(...COLORS.textLight);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        let locText = `File: ${finding.filePath}`;
        if (finding.lineNumber) locText += `:${finding.lineNumber}`;
        if (finding.cwe) locText += ` | CWE: ${finding.cwe}`;
        if (finding.owasp) locText += ` | OWASP: ${finding.owasp}`;
        doc.text(locText, margin + 3, currentY);
        currentY += 5;
        
        // Description
        doc.setTextColor(...COLORS.text);
        doc.setFontSize(9);
        const descLines = doc.splitTextToSize(sanitizeText(finding.description), contentWidth - 10);
        doc.text(descLines.slice(0, 3), margin + 3, currentY);
        currentY += Math.min(descLines.length, 3) * 4 + 4;
        
        // Code snippet
        if (finding.codeSnippet) {
            doc.setFillColor(...COLORS.lightBg);
            doc.setFont('courier', 'normal');
            doc.setFontSize(7);
            
            const codeText = sanitizeText(finding.codeSnippet).substring(0, 200);
            const codeLines = doc.splitTextToSize(codeText, contentWidth - 10);
            
            doc.rect(margin + 3, currentY - 2, contentWidth - 6, Math.min(codeLines.length * 3 + 4, 20), 'F');
            doc.text(codeLines.slice(0, 5), margin + 5, currentY + 2);
            currentY += Math.min(codeLines.length * 3, 15) + 6;
            
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
        }
        
        // Recommendation
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...COLORS.success);
        doc.text('Fix:', margin + 3, currentY);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        const recLines = doc.splitTextToSize(sanitizeText(finding.recommendation), contentWidth - 20);
        doc.text(recLines.slice(0, 2), margin + 15, currentY);
        currentY += Math.min(recLines.length, 2) * 4 + 4;
        
        // Draw border
        doc.roundedRect(margin, boxStartY - 4, contentWidth, currentY - boxStartY + 4, 1, 1, 'S');
        currentY += 8;
    }
    
    // ========================================================================
    // CODE METRICS (if enabled)
    // ========================================================================
    
    if (options.includeMetrics !== false && scanResult.metrics) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Code Quality Metrics', currentY, 4);
        
        const metricsData = [
            ['Total Lines of Code', scanResult.totalLines.toLocaleString()],
            ['Files Analyzed', scanResult.files.length.toString()],
            ['Cyclomatic Complexity', scanResult.metrics.complexity?.toString() || 'N/A'],
            ['Code Duplications', `${scanResult.metrics.duplications || 0}%`],
        ];
        
        if (scanResult.metrics.testCoverage !== undefined) {
            metricsData.push(['Test Coverage', `${scanResult.metrics.testCoverage}%`]);
        }
        if (scanResult.metrics.technicalDebt) {
            metricsData.push(['Technical Debt', scanResult.metrics.technicalDebt]);
        }
        
        autoTable(doc, {
            startY: currentY,
            head: [['Metric', 'Value']],
            body: metricsData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 10 },
            columnStyles: {
                0: { cellWidth: 60, fontStyle: 'bold' },
                1: { cellWidth: 60 }
            },
            margin: { left: margin, right: margin }
        });
        
        currentY = doc.lastAutoTable.finalY + 15;
        
        // Files with most issues
        const filesBySeverity = [...scanResult.files]
            .filter(f => f.findings > 0)
            .sort((a, b) => b.findings - a.findings)
            .slice(0, 10);
        
        if (filesBySeverity.length > 0) {
            doc.setFontSize(11);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Files with Most Security Issues', margin, currentY);
            currentY += 8;
            
            const filesData = filesBySeverity.map(f => [
                f.path.length > 50 ? '...' + f.path.substring(f.path.length - 47) : f.path,
                f.language,
                f.lines.toLocaleString(),
                f.findings.toString()
            ]);
            
            autoTable(doc, {
                startY: currentY,
                head: [['File', 'Language', 'Lines', 'Issues']],
                body: filesData,
                theme: 'striped',
                headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
                styles: { fontSize: 8 },
                margin: { left: margin, right: margin }
            });
        }
    }
    
    // ========================================================================
    // RECOMMENDATIONS
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Recommendations', currentY, 5);
    
    const priorityRecs = [
        { priority: 'Critical - Fix Immediately', findings: sortedFindings.filter(f => f.severity === 'critical'), color: COLORS.critical },
        { priority: 'High - Fix Before Release', findings: sortedFindings.filter(f => f.severity === 'high'), color: COLORS.high },
        { priority: 'Medium - Plan to Fix', findings: sortedFindings.filter(f => f.severity === 'medium'), color: COLORS.medium },
    ];
    
    for (const rec of priorityRecs) {
        if (rec.findings.length > 0) {
            doc.setFillColor(...rec.color);
            doc.circle(margin + 3, currentY - 1, 2, 'F');
            
            doc.setTextColor(...rec.color);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(`${rec.priority} (${rec.findings.length} issues)`, margin + 8, currentY);
            currentY += 6;
            
            doc.setTextColor(...COLORS.text);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            
            const uniqueRecs = [...new Set(rec.findings.map(f => f.recommendation))];
            for (const recText of uniqueRecs.slice(0, 3)) {
                const recLines = doc.splitTextToSize(`- ${sanitizeText(recText)}`, contentWidth - 15);
                doc.text(recLines.slice(0, 2), margin + 8, currentY);
                currentY += Math.min(recLines.length, 2) * 4 + 2;
            }
            
            currentY += 5;
        }
    }
    
    // Add footers
    addAllPageFooters(doc, options.classification);
    
    return doc;
}

/**
 * Download code report as PDF
 */
export function downloadCodeReport(
    scanResult: CodeScanResult,
    options: CodeReportOptions = {},
    filename?: string
): void {
    const doc = generateCodeReport(scanResult, options);
    const defaultFilename = `STRIX_Code_Analysis_${options.projectName || 'Report'}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
}

export default {
    generateCodeReport,
    downloadCodeReport
};

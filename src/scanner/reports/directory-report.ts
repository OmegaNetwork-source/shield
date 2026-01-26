// STRIX Directory Security Report Generator
// Generates comprehensive PDF reports for local directory/filesystem security scans

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

export interface SecretFinding {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    type: string;
    title: string;
    filePath: string;
    lineNumber?: number;
    value?: string;          // Redacted or partial value
    fullValue?: string;      // Full value (for non-redacted reports)
    context?: string;
    serviceName?: string;
    recommendation: string;
    confidence: 'high' | 'medium' | 'low';
}

export interface PermissionIssue {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    path: string;
    type: 'file' | 'directory';
    issue: string;
    currentPermissions?: string;
    recommendedPermissions?: string;
    recommendation: string;
}

export interface SensitiveFile {
    path: string;
    type: string;
    size: number;
    risk: string;
    recommendation: string;
}

export interface ConfigIssue {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    filePath: string;
    setting: string;
    currentValue?: string;
    issue: string;
    recommendation: string;
}

export interface DirectoryScanResult {
    scanPath: string;
    scanDate: Date;
    duration: number;
    
    // Statistics
    totalFiles: number;
    totalDirectories: number;
    totalSize: number;
    
    // Findings
    secrets: SecretFinding[];
    permissionIssues: PermissionIssue[];
    sensitiveFiles: SensitiveFile[];
    configIssues: ConfigIssue[];
    
    // File type breakdown
    fileTypes: { [ext: string]: number };
    
    // Scanned paths
    excludedPaths?: string[];
    
    // Additional metadata
    systemInfo?: {
        hostname: string;
        platform: string;
        user: string;
    };
}

export interface DirectoryReportOptions extends BaseReportOptions {
    systemName?: string;
    includeSecrets?: boolean;
    includePermissions?: boolean;
    includeSensitiveFiles?: boolean;
    includeConfigs?: boolean;
    redactSecretValues?: boolean;
}

// ============================================================================
// DIRECTORY SECURITY REPORT GENERATOR
// ============================================================================

export function generateDirectoryReport(
    scanResult: DirectoryScanResult,
    options: DirectoryReportOptions = {}
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
    
    const title = options.title || 'Filesystem Security Assessment';
    const systemName = options.systemName || scanResult.systemInfo?.hostname || 'Local System';
    const reportId = options.reportId || generateReportId();
    const redactSecrets = options.redactSecretValues !== false;
    
    let currentY = margin;
    
    // Combine all findings for risk calculation
    const allFindings = [
        ...scanResult.secrets,
        ...scanResult.permissionIssues,
        ...scanResult.configIssues
    ];
    
    // ========================================================================
    // COVER PAGE
    // ========================================================================
    
    currentY = drawReportHeader(doc, title, `${systemName} - ${scanResult.scanPath}`, {
        ...options,
        reportId
    });
    
    currentY += 10;
    
    // Risk Score
    const riskScore = calculateRiskScore(allFindings);
    const riskInfo = getRiskLevel(riskScore);
    
    drawRiskGauge(doc, pageWidth / 2 - 30, currentY, riskScore, 60);
    currentY += 75;
    
    // Severity Summary
    const counts = {
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        medium: allFindings.filter(f => f.severity === 'medium').length,
        low: allFindings.filter(f => f.severity === 'low').length,
        info: allFindings.filter(f => f.severity === 'info').length,
    };
    
    currentY = drawSeveritySummary(doc, margin + 10, currentY, counts, 32);
    currentY += 15;
    
    // Scan summary box
    doc.setFillColor(...COLORS.darkAlt);
    doc.roundedRect(margin, currentY, contentWidth, 60, 3, 3, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Scan Summary', margin + 5, currentY + 8);
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    
    const formatSize = (bytes: number): string => {
        if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`;
        if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
        if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        return `${bytes} bytes`;
    };
    
    const summaryItems = [
        ['Scan Path:', scanResult.scanPath.length > 40 ? '...' + scanResult.scanPath.slice(-37) : scanResult.scanPath],
        ['Total Files:', scanResult.totalFiles.toLocaleString()],
        ['Total Directories:', scanResult.totalDirectories.toLocaleString()],
        ['Total Size:', formatSize(scanResult.totalSize)],
        ['Secrets Found:', scanResult.secrets.length.toString()],
        ['Permission Issues:', scanResult.permissionIssues.length.toString()],
        ['Config Issues:', scanResult.configIssues.length.toString()],
        ['Scan Duration:', `${Math.round(scanResult.duration / 1000)}s`],
    ];
    
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
    
    const execSummary = `A comprehensive filesystem security scan was performed on ${systemName}. The scan analyzed ${scanResult.totalFiles.toLocaleString()} files and ${scanResult.totalDirectories.toLocaleString()} directories (${formatSize(scanResult.totalSize)} total). The assessment identified ${allFindings.length} security findings with an overall risk score of ${riskScore}/100 (${riskInfo.level}).`;
    
    const summaryLines = doc.splitTextToSize(execSummary, contentWidth);
    doc.text(summaryLines, margin, currentY);
    currentY += summaryLines.length * 5 + 10;
    
    // Key findings summary
    const keyFindings = [
        { label: 'Exposed Secrets/Credentials', count: scanResult.secrets.length, color: COLORS.critical },
        { label: 'Permission Vulnerabilities', count: scanResult.permissionIssues.length, color: COLORS.high },
        { label: 'Sensitive Files Exposed', count: scanResult.sensitiveFiles.length, color: COLORS.medium },
        { label: 'Configuration Issues', count: scanResult.configIssues.length, color: COLORS.low },
    ];
    
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('Findings Overview', margin, currentY);
    currentY += 8;
    
    for (const kf of keyFindings) {
        doc.setFillColor(...kf.color);
        doc.circle(margin + 3, currentY - 1, 2, 'F');
        
        doc.setTextColor(...COLORS.text);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.text(`${kf.label}: `, margin + 8, currentY);
        
        doc.setTextColor(...kf.color);
        doc.setFont('helvetica', 'bold');
        doc.text(kf.count.toString(), margin + 60, currentY);
        
        currentY += 7;
    }
    
    currentY += 10;
    
    // File type breakdown
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('File Type Distribution', margin, currentY);
    currentY += 8;
    
    const fileTypeData = Object.entries(scanResult.fileTypes)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ext, count]) => [ext || 'No extension', count.toLocaleString()]);
    
    if (fileTypeData.length > 0) {
        autoTable(doc, {
            startY: currentY,
            head: [['File Type', 'Count']],
            body: fileTypeData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 9 },
            columnStyles: {
                0: { cellWidth: 50 },
                1: { cellWidth: 40, halign: 'right' }
            },
            margin: { left: margin, right: margin }
        });
        currentY = doc.lastAutoTable.finalY + 10;
    }
    
    // ========================================================================
    // SECRETS AND CREDENTIALS
    // ========================================================================
    
    if (options.includeSecrets !== false && scanResult.secrets.length > 0) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Exposed Secrets & Credentials', currentY, 2);
        
        doc.setFillColor(...COLORS.critical);
        doc.setTextColor(...COLORS.critical);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        
        const warningText = 'WARNING: The following secrets were found exposed in the filesystem. Immediate rotation is recommended.';
        const warnLines = doc.splitTextToSize(warningText, contentWidth);
        doc.text(warnLines, margin, currentY);
        currentY += warnLines.length * 4 + 8;
        
        // Group secrets by type
        const secretsByType: { [key: string]: SecretFinding[] } = {};
        for (const secret of scanResult.secrets) {
            const type = secret.serviceName || secret.type;
            if (!secretsByType[type]) secretsByType[type] = [];
            secretsByType[type].push(secret);
        }
        
        for (const [type, secrets] of Object.entries(secretsByType)) {
            if (currentY > pageHeight - 60) {
                currentY = addNewPage(doc, options.classification);
            }
            
            // Type header
            doc.setFillColor(...COLORS.high);
            doc.roundedRect(margin, currentY, contentWidth, 7, 1, 1, 'F');
            doc.setTextColor(...COLORS.white);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(`${type} (${secrets.length} found)`, margin + 3, currentY + 5);
            currentY += 10;
            
            // List secrets
            for (const secret of secrets.slice(0, 5)) {
                doc.setFillColor(...COLORS.lightBg);
                doc.roundedRect(margin + 3, currentY, contentWidth - 6, 20, 1, 1, 'F');
                
                doc.setTextColor(...COLORS.dark);
                doc.setFontSize(8);
                doc.setFont('helvetica', 'bold');
                doc.text(sanitizeText(secret.title), margin + 5, currentY + 5);
                
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.text);
                doc.text(`File: ${secret.filePath.length > 60 ? '...' + secret.filePath.slice(-57) : secret.filePath}`, margin + 5, currentY + 10);
                
                if (secret.value && !redactSecrets) {
                    doc.setTextColor(...COLORS.critical);
                    doc.text(`Value: ${secret.value.substring(0, 40)}...`, margin + 5, currentY + 15);
                } else if (secret.lineNumber) {
                    doc.text(`Line: ${secret.lineNumber}`, margin + 5, currentY + 15);
                }
                
                currentY += 23;
            }
            
            if (secrets.length > 5) {
                doc.setTextColor(...COLORS.textLight);
                doc.setFontSize(8);
                doc.text(`... and ${secrets.length - 5} more ${type} secrets`, margin + 5, currentY);
                currentY += 5;
            }
            
            currentY += 5;
        }
    }
    
    // ========================================================================
    // PERMISSION ISSUES
    // ========================================================================
    
    if (options.includePermissions !== false && scanResult.permissionIssues.length > 0) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Permission Vulnerabilities', currentY, 3);
        
        const permData = scanResult.permissionIssues.slice(0, 20).map(p => [
            p.severity.toUpperCase(),
            p.type === 'directory' ? 'Dir' : 'File',
            p.path.length > 35 ? '...' + p.path.slice(-32) : p.path,
            sanitizeText(p.issue).substring(0, 30),
            p.currentPermissions || '-'
        ]);
        
        autoTable(doc, {
            startY: currentY,
            head: [['Severity', 'Type', 'Path', 'Issue', 'Perms']],
            body: permData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 7 },
            columnStyles: {
                0: { cellWidth: 18 },
                1: { cellWidth: 12 },
                2: { cellWidth: 50 },
                3: { cellWidth: 45 },
                4: { cellWidth: 20 }
            },
            didParseCell: (data) => {
                if (data.column.index === 0 && data.section === 'body') {
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
    // SENSITIVE FILES
    // ========================================================================
    
    if (options.includeSensitiveFiles !== false && scanResult.sensitiveFiles.length > 0) {
        if (currentY > pageHeight - 80) {
            currentY = addNewPage(doc, options.classification);
        }
        
        currentY = drawSectionHeader(doc, 'Sensitive Files Detected', currentY, 4);
        
        const sensitiveData = scanResult.sensitiveFiles.slice(0, 15).map(f => [
            f.type,
            f.path.length > 50 ? '...' + f.path.slice(-47) : f.path,
            formatSize(f.size),
            f.risk
        ]);
        
        autoTable(doc, {
            startY: currentY,
            head: [['Type', 'Path', 'Size', 'Risk']],
            body: sensitiveData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 8 },
            margin: { left: margin, right: margin }
        });
        
        currentY = doc.lastAutoTable.finalY + 10;
    }
    
    // ========================================================================
    // CONFIGURATION ISSUES
    // ========================================================================
    
    if (options.includeConfigs !== false && scanResult.configIssues.length > 0) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Configuration Issues', currentY, 5);
        
        for (const issue of scanResult.configIssues.slice(0, 10)) {
            if (currentY > pageHeight - 50) {
                currentY = addNewPage(doc, options.classification);
            }
            
            const severityColor = getSeverityColor(issue.severity);
            doc.setFillColor(...severityColor);
            doc.roundedRect(margin, currentY, contentWidth, 7, 1, 1, 'F');
            
            doc.setTextColor(...COLORS.white);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(`${issue.setting} (${issue.severity.toUpperCase()})`, margin + 3, currentY + 5);
            currentY += 10;
            
            doc.setDrawColor(...severityColor);
            const boxStart = currentY;
            
            doc.setTextColor(...COLORS.textLight);
            doc.setFontSize(8);
            doc.setFont('helvetica', 'normal');
            doc.text(`File: ${issue.filePath}`, margin + 3, currentY);
            currentY += 5;
            
            doc.setTextColor(...COLORS.text);
            const issueLines = doc.splitTextToSize(`Issue: ${sanitizeText(issue.issue)}`, contentWidth - 10);
            doc.text(issueLines.slice(0, 2), margin + 3, currentY);
            currentY += Math.min(issueLines.length, 2) * 4 + 3;
            
            doc.setTextColor(...COLORS.success);
            doc.setFont('helvetica', 'bold');
            doc.text('Fix:', margin + 3, currentY);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);
            const recLines = doc.splitTextToSize(sanitizeText(issue.recommendation), contentWidth - 20);
            doc.text(recLines.slice(0, 2), margin + 15, currentY);
            currentY += Math.min(recLines.length, 2) * 4 + 3;
            
            doc.roundedRect(margin, boxStart - 3, contentWidth, currentY - boxStart + 3, 1, 1, 'S');
            currentY += 8;
        }
    }
    
    // ========================================================================
    // RECOMMENDATIONS
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Recommendations', currentY, 6);
    
    const recommendations = [
        {
            priority: 'Immediate Action Required',
            items: [
                'Rotate all exposed API keys and credentials immediately',
                'Review and revoke any unauthorized access',
                'Update all hardcoded secrets to use environment variables or secret management',
            ],
            color: COLORS.critical
        },
        {
            priority: 'High Priority',
            items: [
                'Fix all world-writable file and directory permissions',
                'Remove or secure sensitive configuration files',
                'Implement proper access controls on sensitive directories',
            ],
            color: COLORS.high
        },
        {
            priority: 'Best Practices',
            items: [
                'Implement pre-commit hooks to prevent secret commits',
                'Use a secrets management solution (HashiCorp Vault, AWS Secrets Manager)',
                'Regular automated security scanning of the filesystem',
                'Implement least-privilege access principles',
            ],
            color: COLORS.medium
        }
    ];
    
    for (const rec of recommendations) {
        doc.setFillColor(...rec.color);
        doc.circle(margin + 3, currentY - 1, 2, 'F');
        
        doc.setTextColor(...rec.color);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(rec.priority, margin + 8, currentY);
        currentY += 6;
        
        doc.setTextColor(...COLORS.text);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        
        for (const item of rec.items) {
            const itemLines = doc.splitTextToSize(`- ${item}`, contentWidth - 15);
            doc.text(itemLines, margin + 8, currentY);
            currentY += itemLines.length * 4 + 2;
        }
        
        currentY += 5;
    }
    
    // Add footers
    addAllPageFooters(doc, options.classification);
    
    return doc;
}

/**
 * Download directory report as PDF
 */
export function downloadDirectoryReport(
    scanResult: DirectoryScanResult,
    options: DirectoryReportOptions = {},
    filename?: string
): void {
    const doc = generateDirectoryReport(scanResult, options);
    const defaultFilename = `STRIX_Directory_Scan_${options.systemName || 'Report'}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
}

export default {
    generateDirectoryReport,
    downloadDirectoryReport
};

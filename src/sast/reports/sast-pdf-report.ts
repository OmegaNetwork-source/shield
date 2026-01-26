// STRIX SAST Professional PDF Report Generator
// Generates comprehensive, official-looking PDF reports for static code analysis

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ScanResult, SASTFinding, ScanSummary } from '../types';

// Extend jsPDF type for autoTable
declare module 'jspdf' {
    interface jsPDF {
        lastAutoTable: { finalY: number };
    }
}

// ============================================================================
// CONSTANTS & COLORS
// ============================================================================

const COLORS = {
    primary: [8, 145, 178] as [number, number, number],      // Cyan-600
    primaryLight: [34, 211, 238] as [number, number, number], // Cyan-400
    primaryDark: [6, 95, 117] as [number, number, number],   // Cyan-800
    critical: [220, 38, 38] as [number, number, number],     // Red-600
    high: [234, 88, 12] as [number, number, number],         // Orange-600
    medium: [202, 138, 4] as [number, number, number],       // Yellow-600
    low: [37, 99, 235] as [number, number, number],          // Blue-600
    info: [107, 114, 128] as [number, number, number],       // Gray-500
    success: [34, 197, 94] as [number, number, number],      // Green-500
    dark: [15, 23, 42] as [number, number, number],          // Slate-900
    darkAlt: [30, 41, 59] as [number, number, number],       // Slate-800
    text: [51, 65, 85] as [number, number, number],          // Slate-700
    textLight: [100, 116, 139] as [number, number, number],  // Slate-500
    lightBg: [248, 250, 252] as [number, number, number],    // Slate-50
    white: [255, 255, 255] as [number, number, number],
};

// ============================================================================
// INTERFACES
// ============================================================================

export interface SASTReportOptions {
    title?: string;
    projectName?: string;
    scannerUser?: string;
    organization?: string;
    classification?: 'UNCLASSIFIED' | 'CUI' | 'CONFIDENTIAL' | 'SECRET' | 'TOP SECRET';
    repositoryUrl?: string;
    branch?: string;
    commitHash?: string;
    includeAllFindings?: boolean;
    maxFindingsPerCategory?: number;
    redactSecrets?: boolean;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function getSeverityColor(severity: string): [number, number, number] {
    switch (severity?.toLowerCase()) {
        case 'critical': return COLORS.critical;
        case 'high': return COLORS.high;
        case 'medium': return COLORS.medium;
        case 'low': return COLORS.low;
        default: return COLORS.info;
    }
}

function formatDate(date: Date): string {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatShortDate(date: Date): string {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function generateReportId(): string {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    return `STRIX-SAST-${timestamp}-${random}`;
}

function sanitizeText(text: string): string {
    if (!text) return '';
    return text
        .replace(/[\u{1F300}-\u{1F9FF}]/gu, '')
        .replace(/[\u{2600}-\u{26FF}]/gu, '')
        .replace(/[\u{2700}-\u{27BF}]/gu, '')
        .replace(/[\u{1F600}-\u{1F64F}]/gu, '')
        .replace(/[\u{1F680}-\u{1F6FF}]/gu, '')
        .replace(/[═╔╗╚╝║╠╣╦╩╬─│┌┐└┘├┤┬┴┼]/g, '-')
        .replace(/[━┃┏┓┗┛┣┫┳┻╋]/g, '-')
        .replace(/[►◄▲▼●○■□◆◇★☆♠♣♥♦]/g, '*')
        .replace(/[✓✔]/g, '[OK]')
        .replace(/[✗✘×]/g, '[X]')
        .replace(/[→←↑↓↔↕]/g, '->')
        .replace(/[•·]/g, '-')
        .replace(/-{3,}/g, '---')
        .replace(/\s{2,}/g, ' ')
        .trim();
}

function getRiskLevel(score: number): { level: string; color: [number, number, number] } {
    if (score >= 70) return { level: 'CRITICAL', color: COLORS.critical };
    if (score >= 50) return { level: 'HIGH', color: COLORS.high };
    if (score >= 30) return { level: 'MEDIUM', color: COLORS.medium };
    if (score >= 10) return { level: 'LOW', color: COLORS.low };
    return { level: 'MINIMAL', color: COLORS.success };
}

// ============================================================================
// STRIX LOGO DRAWING
// ============================================================================

function drawStrixLogo(doc: jsPDF, x: number, y: number, size: number = 30): void {
    const scale = size / 100;
    
    // Owl face outline - dark slate background
    doc.setFillColor(30, 41, 59);
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(0.5 * scale);
    
    // Main face shape (hexagonal)
    const facePoints = [
        [x + 50 * scale, y + 8 * scale],
        [x + 85 * scale, y + 35 * scale],
        [x + 80 * scale, y + 75 * scale],
        [x + 50 * scale, y + 92 * scale],
        [x + 20 * scale, y + 75 * scale],
        [x + 15 * scale, y + 35 * scale],
    ];
    
    doc.moveTo(facePoints[0][0], facePoints[0][1]);
    for (let i = 1; i < facePoints.length; i++) {
        doc.lineTo(facePoints[i][0], facePoints[i][1]);
    }
    doc.lineTo(facePoints[0][0], facePoints[0][1]);
    doc.fillStroke();
    
    // Inner face
    doc.setFillColor(15, 23, 42);
    const innerPoints = [
        [x + 50 * scale, y + 15 * scale],
        [x + 75 * scale, y + 35 * scale],
        [x + 72 * scale, y + 68 * scale],
        [x + 50 * scale, y + 82 * scale],
        [x + 28 * scale, y + 68 * scale],
        [x + 25 * scale, y + 35 * scale],
    ];
    
    doc.moveTo(innerPoints[0][0], innerPoints[0][1]);
    for (let i = 1; i < innerPoints.length; i++) {
        doc.lineTo(innerPoints[i][0], innerPoints[i][1]);
    }
    doc.lineTo(innerPoints[0][0], innerPoints[0][1]);
    doc.fill();
    
    // Eye sockets
    doc.setFillColor(30, 41, 59);
    
    // Left eye socket
    doc.moveTo(x + 25 * scale, y + 38 * scale);
    doc.lineTo(x + 38 * scale, y + 30 * scale);
    doc.lineTo(x + 48 * scale, y + 38 * scale);
    doc.lineTo(x + 45 * scale, y + 52 * scale);
    doc.lineTo(x + 32 * scale, y + 55 * scale);
    doc.lineTo(x + 25 * scale, y + 48 * scale);
    doc.fill();
    
    // Right eye socket
    doc.moveTo(x + 75 * scale, y + 38 * scale);
    doc.lineTo(x + 62 * scale, y + 30 * scale);
    doc.lineTo(x + 52 * scale, y + 38 * scale);
    doc.lineTo(x + 55 * scale, y + 52 * scale);
    doc.lineTo(x + 68 * scale, y + 55 * scale);
    doc.lineTo(x + 75 * scale, y + 48 * scale);
    doc.fill();
    
    // Eyes (glowing cyan)
    doc.setFillColor(8, 145, 178);
    doc.circle(x + 36 * scale, y + 43 * scale, 10 * scale, 'F');
    doc.setFillColor(34, 211, 238);
    doc.circle(x + 36 * scale, y + 43 * scale, 6 * scale, 'F');
    doc.setFillColor(15, 23, 42);
    doc.circle(x + 36 * scale, y + 43 * scale, 3 * scale, 'F');
    doc.setFillColor(255, 255, 255);
    doc.circle(x + 34 * scale, y + 41 * scale, 1.5 * scale, 'F');
    
    doc.setFillColor(8, 145, 178);
    doc.circle(x + 64 * scale, y + 43 * scale, 10 * scale, 'F');
    doc.setFillColor(34, 211, 238);
    doc.circle(x + 64 * scale, y + 43 * scale, 6 * scale, 'F');
    doc.setFillColor(15, 23, 42);
    doc.circle(x + 64 * scale, y + 43 * scale, 3 * scale, 'F');
    doc.setFillColor(255, 255, 255);
    doc.circle(x + 62 * scale, y + 41 * scale, 1.5 * scale, 'F');
    
    // Beak
    doc.setFillColor(100, 116, 139);
    doc.moveTo(x + 50 * scale, y + 52 * scale);
    doc.lineTo(x + 44 * scale, y + 60 * scale);
    doc.lineTo(x + 50 * scale, y + 72 * scale);
    doc.lineTo(x + 56 * scale, y + 60 * scale);
    doc.fill();
    
    doc.setFillColor(71, 85, 105);
    doc.moveTo(x + 50 * scale, y + 52 * scale);
    doc.lineTo(x + 47 * scale, y + 58 * scale);
    doc.lineTo(x + 50 * scale, y + 65 * scale);
    doc.lineTo(x + 53 * scale, y + 58 * scale);
    doc.fill();
    
    // Ear tufts
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(2 * scale);
    doc.moveTo(x + 22 * scale, y + 32 * scale);
    doc.lineTo(x + 30 * scale, y + 22 * scale);
    doc.lineTo(x + 38 * scale, y + 30 * scale);
    doc.stroke();
    doc.moveTo(x + 78 * scale, y + 32 * scale);
    doc.lineTo(x + 70 * scale, y + 22 * scale);
    doc.lineTo(x + 62 * scale, y + 30 * scale);
    doc.stroke();
}

// ============================================================================
// MAIN REPORT GENERATOR
// ============================================================================

export function generateSASTReport(
    scanResult: ScanResult,
    options: SASTReportOptions = {}
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
    
    const title = options.title || 'Static Application Security Testing Report';
    const projectName = options.projectName || scanResult.targetPath.split(/[/\\]/).pop() || 'Code Project';
    const reportId = generateReportId();
    const classification = options.classification || 'UNCLASSIFIED';
    const scannerUser = options.scannerUser || 'STRIX Scanner';
    const redactSecrets = options.redactSecrets !== false;
    
    // Calculate risk score
    const riskScore = Math.min(100, 
        (scanResult.summary.bySeverity.critical * 25) + 
        (scanResult.summary.bySeverity.high * 10) + 
        (scanResult.summary.bySeverity.medium * 3) + 
        (scanResult.summary.bySeverity.low * 1)
    );
    const riskInfo = getRiskLevel(riskScore);
    
    let currentY = margin;
    
    // Track pages for TOC
    const tocEntries: Array<{ title: string; page: number; level: number }> = [];
    let currentPage = 1;
    
    // ========================================================================
    // COVER PAGE
    // ========================================================================
    
    // Classification banner
    if (classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, 0, pageWidth, 10, 'F');
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text(classification, pageWidth / 2, 6.5, { align: 'center' });
        currentY = 15;
    }
    
    // Header banner
    currentY = 20;
    doc.setFillColor(...COLORS.dark);
    doc.rect(0, currentY, pageWidth, 55, 'F');
    
    // Draw STRIX logo
    drawStrixLogo(doc, margin + 5, currentY + 5, 45);
    
    // STRIX title
    doc.setTextColor(...COLORS.primaryLight);
    doc.setFontSize(36);
    doc.setFont('helvetica', 'bold');
    doc.text('STRIX', margin + 60, currentY + 25);
    
    // Subtitle
    doc.setTextColor(...COLORS.textLight);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('Static Application Security Testing', margin + 60, currentY + 35);
    doc.text('Code Analysis & Secret Detection', margin + 60, currentY + 42);
    
    // Report ID
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(8);
    doc.text(`Report ID: ${reportId}`, pageWidth - margin, currentY + 15, { align: 'right' });
    doc.text(formatShortDate(scanResult.startTime), pageWidth - margin, currentY + 22, { align: 'right' });
    
    currentY += 65;
    
    // Report type banner
    doc.setFillColor(...COLORS.primary);
    doc.roundedRect(margin, currentY, contentWidth, 28, 3, 3, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(sanitizeText(title), pageWidth / 2, currentY + 12, { align: 'center' });
    
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text(sanitizeText(projectName), pageWidth / 2, currentY + 22, { align: 'center' });
    
    currentY += 40;
    
    // Risk Score display
    const riskBoxWidth = 80;
    const riskBoxX = pageWidth / 2 - riskBoxWidth / 2;
    
    doc.setFillColor(...riskInfo.color);
    doc.roundedRect(riskBoxX, currentY, riskBoxWidth, 45, 5, 5, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(32);
    doc.setFont('helvetica', 'bold');
    doc.text(riskScore.toString(), pageWidth / 2, currentY + 20, { align: 'center' });
    
    doc.setFontSize(10);
    doc.text('RISK SCORE', pageWidth / 2, currentY + 30, { align: 'center' });
    doc.text(riskInfo.level, pageWidth / 2, currentY + 38, { align: 'center' });
    
    currentY += 55;
    
    // Severity summary boxes
    const boxWidth = 32;
    const boxGap = 4;
    const totalBoxWidth = (boxWidth * 5) + (boxGap * 4);
    let boxX = pageWidth / 2 - totalBoxWidth / 2;
    
    const severities = [
        { label: 'Critical', count: scanResult.summary.bySeverity.critical, color: COLORS.critical },
        { label: 'High', count: scanResult.summary.bySeverity.high, color: COLORS.high },
        { label: 'Medium', count: scanResult.summary.bySeverity.medium, color: COLORS.medium },
        { label: 'Low', count: scanResult.summary.bySeverity.low, color: COLORS.low },
        { label: 'Info', count: scanResult.summary.bySeverity.info, color: COLORS.info },
    ];
    
    for (const sev of severities) {
        doc.setFillColor(...COLORS.darkAlt);
        doc.roundedRect(boxX, currentY, boxWidth, 25, 2, 2, 'F');
        doc.setFillColor(...sev.color);
        doc.rect(boxX, currentY, boxWidth, 4, 'F');
        
        doc.setTextColor(...sev.color);
        doc.setFontSize(16);
        doc.setFont('helvetica', 'bold');
        doc.text(sev.count.toString(), boxX + boxWidth / 2, currentY + 14, { align: 'center' });
        
        doc.setTextColor(...COLORS.textLight);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'normal');
        doc.text(sev.label, boxX + boxWidth / 2, currentY + 21, { align: 'center' });
        
        boxX += boxWidth + boxGap;
    }
    
    currentY += 35;
    
    // Scan metadata
    doc.setFillColor(...COLORS.lightBg);
    doc.roundedRect(margin + 20, currentY, contentWidth - 40, 50, 3, 3, 'F');
    
    const metaItems = [
        ['Files Scanned:', scanResult.filesScanned.toLocaleString()],
        ['Lines Analyzed:', scanResult.linesScanned.toLocaleString()],
        ['Scan Duration:', `${Math.round(scanResult.duration / 1000)}s`],
        ['Total Findings:', scanResult.findings.length.toLocaleString()],
        ['Scan Date:', formatDate(scanResult.startTime)],
        ['Scanner:', scannerUser],
    ];
    
    if (options.branch) metaItems.push(['Branch:', options.branch]);
    if (options.commitHash) metaItems.push(['Commit:', options.commitHash.substring(0, 8)]);
    
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(9);
    
    let metaY = currentY + 10;
    const col1X = margin + 30;
    const col2X = pageWidth / 2 + 10;
    
    for (let i = 0; i < metaItems.length; i++) {
        const [label, value] = metaItems[i];
        const x = i % 2 === 0 ? col1X : col2X;
        const y = metaY + Math.floor(i / 2) * 8;
        
        doc.setFont('helvetica', 'bold');
        doc.text(label, x, y);
        doc.setFont('helvetica', 'normal');
        doc.text(value, x + 35, y);
    }
    
    // Footer
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.textLight);
    doc.text('Generated by STRIX Security Scanner', pageWidth / 2, pageHeight - 15, { align: 'center' });
    
    if (classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text(classification, pageWidth / 2, pageHeight - 4, { align: 'center' });
    }
    
    // ========================================================================
    // TABLE OF CONTENTS
    // ========================================================================
    
    doc.addPage();
    currentPage = 2;
    currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
    
    // TOC Header
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Table of Contents', margin + 5, currentY + 7);
    
    currentY += 20;
    
    // TOC entries (we'll fill actual page numbers after generating content)
    const tocItems = [
        { title: '1. Executive Summary', page: 3, indent: 0 },
        { title: '2. Scan Overview', page: 3, indent: 0 },
        { title: '   2.1 Scan Configuration', page: 3, indent: 1 },
        { title: '   2.2 Files Analyzed', page: 3, indent: 1 },
        { title: '3. Findings Summary', page: 4, indent: 0 },
        { title: '   3.1 By Severity', page: 4, indent: 1 },
        { title: '   3.2 By Category', page: 4, indent: 1 },
        { title: '   3.3 Top Affected Files', page: 4, indent: 1 },
        { title: '4. Critical & High Findings', page: 5, indent: 0 },
        { title: '5. All Findings Detail', page: 6, indent: 0 },
        { title: '6. Recommendations', page: 7, indent: 0 },
        { title: '7. Appendix', page: 8, indent: 0 },
    ];
    
    doc.setTextColor(...COLORS.text);
    for (const item of tocItems) {
        doc.setFontSize(item.indent === 0 ? 11 : 10);
        doc.setFont('helvetica', item.indent === 0 ? 'bold' : 'normal');
        
        const titleWidth = doc.getTextWidth(item.title);
        const pageNumText = item.page.toString();
        const pageNumWidth = doc.getTextWidth(pageNumText);
        
        doc.text(item.title, margin + (item.indent * 5), currentY);
        
        // Dots
        doc.setFont('helvetica', 'normal');
        const dotsStart = margin + (item.indent * 5) + titleWidth + 2;
        const dotsEnd = pageWidth - margin - pageNumWidth - 2;
        let dotX = dotsStart;
        while (dotX < dotsEnd) {
            doc.text('.', dotX, currentY);
            dotX += 2;
        }
        
        doc.text(pageNumText, pageWidth - margin, currentY, { align: 'right' });
        currentY += item.indent === 0 ? 8 : 6;
    }
    
    // ========================================================================
    // EXECUTIVE SUMMARY
    // ========================================================================
    
    doc.addPage();
    currentPage = 3;
    currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
    
    // Section header
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Executive Summary', margin + 5, currentY + 7);
    currentY += 18;
    
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    
    const criticalCount = scanResult.summary.bySeverity.critical;
    const highCount = scanResult.summary.bySeverity.high;
    
    const execSummary = `A comprehensive static application security analysis was performed on "${projectName}". The scan analyzed ${scanResult.filesScanned.toLocaleString()} files containing ${scanResult.linesScanned.toLocaleString()} lines of code. The analysis identified ${scanResult.findings.length} security findings with an overall risk score of ${riskScore}/100 (${riskInfo.level}).`;
    
    const summaryLines = doc.splitTextToSize(execSummary, contentWidth);
    doc.text(summaryLines, margin, currentY);
    currentY += summaryLines.length * 5 + 10;
    
    // Key findings box
    if (criticalCount > 0 || highCount > 0) {
        doc.setFillColor(254, 242, 242); // Red-50
        doc.setDrawColor(...COLORS.critical);
        doc.setLineWidth(0.5);
        doc.roundedRect(margin, currentY, contentWidth, 35, 2, 2, 'FD');
        
        doc.setTextColor(...COLORS.critical);
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.text('Immediate Action Required', margin + 5, currentY + 8);
        
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        
        const urgentText = `This scan identified ${criticalCount} CRITICAL and ${highCount} HIGH severity findings that require immediate attention. These vulnerabilities could lead to data breaches, unauthorized access, or system compromise.`;
        const urgentLines = doc.splitTextToSize(urgentText, contentWidth - 10);
        doc.text(urgentLines, margin + 5, currentY + 16);
        
        currentY += 45;
    }
    
    // ========================================================================
    // SCAN OVERVIEW
    // ========================================================================
    
    currentY += 5;
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('2. Scan Overview', margin + 5, currentY + 7);
    currentY += 18;
    
    // Scan configuration table
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.dark);
    doc.setFont('helvetica', 'bold');
    doc.text('2.1 Scan Configuration', margin, currentY);
    currentY += 8;
    
    const configData = [
        ['Target Path', scanResult.targetPath],
        ['Scan Start', formatDate(scanResult.startTime)],
        ['Scan End', formatDate(scanResult.endTime)],
        ['Duration', `${Math.round(scanResult.duration / 1000)} seconds`],
        ['Files Scanned', scanResult.filesScanned.toLocaleString()],
        ['Lines Analyzed', scanResult.linesScanned.toLocaleString()],
    ];
    
    if (options.repositoryUrl) configData.push(['Repository', options.repositoryUrl]);
    if (options.branch) configData.push(['Branch', options.branch]);
    
    autoTable(doc, {
        startY: currentY,
        head: [['Parameter', 'Value']],
        body: configData,
        theme: 'striped',
        headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
        styles: { fontSize: 9, cellPadding: 3 },
        columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
        margin: { left: margin, right: margin }
    });
    
    currentY = doc.lastAutoTable.finalY + 15;
    
    // ========================================================================
    // FINDINGS SUMMARY
    // ========================================================================
    
    doc.addPage();
    currentPage = 4;
    currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
    
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('3. Findings Summary', margin + 5, currentY + 7);
    currentY += 18;
    
    // By severity
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.dark);
    doc.setFont('helvetica', 'bold');
    doc.text('3.1 Findings by Severity', margin, currentY);
    currentY += 8;
    
    const severityData = [
        ['Critical', scanResult.summary.bySeverity.critical.toString(), 'Immediate remediation required'],
        ['High', scanResult.summary.bySeverity.high.toString(), 'Address before production deployment'],
        ['Medium', scanResult.summary.bySeverity.medium.toString(), 'Plan for remediation'],
        ['Low', scanResult.summary.bySeverity.low.toString(), 'Address when convenient'],
        ['Info', scanResult.summary.bySeverity.info.toString(), 'Informational only'],
    ];
    
    autoTable(doc, {
        startY: currentY,
        head: [['Severity', 'Count', 'Priority']],
        body: severityData,
        theme: 'striped',
        headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
        styles: { fontSize: 9 },
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
    
    currentY = doc.lastAutoTable.finalY + 15;
    
    // By category
    doc.setFontSize(11);
    doc.setTextColor(...COLORS.dark);
    doc.setFont('helvetica', 'bold');
    doc.text('3.2 Findings by Category', margin, currentY);
    currentY += 8;
    
    const categoryData = Object.entries(scanResult.summary.byCategory)
        .filter(([_, count]) => count > 0)
        .sort((a, b) => b[1] - a[1])
        .map(([cat, count]) => [cat.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()), count.toString()]);
    
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
        currentY = doc.lastAutoTable.finalY + 15;
    }
    
    // Top files
    if (scanResult.summary.topFiles && scanResult.summary.topFiles.length > 0) {
        doc.setFontSize(11);
        doc.setTextColor(...COLORS.dark);
        doc.setFont('helvetica', 'bold');
        doc.text('3.3 Top Affected Files', margin, currentY);
        currentY += 8;
        
        const fileData = scanResult.summary.topFiles.slice(0, 10).map(f => [
            f.file.length > 50 ? '...' + f.file.slice(-47) : f.file,
            f.findings.toString()
        ]);
        
        autoTable(doc, {
            startY: currentY,
            head: [['File Path', 'Findings']],
            body: fileData,
            theme: 'striped',
            headStyles: { fillColor: COLORS.primary, textColor: COLORS.white },
            styles: { fontSize: 8 },
            columnStyles: { 0: { cellWidth: 130 }, 1: { cellWidth: 25, halign: 'center' } },
            margin: { left: margin, right: margin }
        });
        currentY = doc.lastAutoTable.finalY + 10;
    }
    
    // ========================================================================
    // CRITICAL & HIGH FINDINGS
    // ========================================================================
    
    doc.addPage();
    currentPage = 5;
    currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
    
    doc.setFillColor(...COLORS.critical);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('4. Critical & High Severity Findings', margin + 5, currentY + 7);
    currentY += 18;
    
    const criticalHighFindings = scanResult.findings
        .filter(f => f.severity === 'critical' || f.severity === 'high')
        .sort((a, b) => {
            if (a.severity === 'critical' && b.severity !== 'critical') return -1;
            if (b.severity === 'critical' && a.severity !== 'critical') return 1;
            return 0;
        });
    
    if (criticalHighFindings.length === 0) {
        doc.setTextColor(...COLORS.success);
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.text('No critical or high severity findings detected.', margin, currentY);
        currentY += 15;
    } else {
        for (let i = 0; i < Math.min(criticalHighFindings.length, 15); i++) {
            const finding = criticalHighFindings[i];
            
            if (currentY > pageHeight - 70) {
                doc.addPage();
                currentPage++;
                currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
            }
            
            const sevColor = getSeverityColor(finding.severity);
            
            // Finding header
            doc.setFillColor(...sevColor);
            doc.roundedRect(margin, currentY, contentWidth, 8, 1, 1, 'F');
            doc.setTextColor(...COLORS.white);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(`${i + 1}. ${sanitizeText(finding.title)}`, margin + 3, currentY + 5.5);
            doc.text(finding.severity.toUpperCase(), pageWidth - margin - 20, currentY + 5.5);
            currentY += 11;
            
            // File location
            doc.setTextColor(...COLORS.textLight);
            doc.setFontSize(8);
            doc.setFont('helvetica', 'normal');
            doc.text(`File: ${finding.location.file}:${finding.location.line}`, margin + 3, currentY);
            currentY += 5;
            
            // Description
            doc.setTextColor(...COLORS.text);
            doc.setFontSize(9);
            const descLines = doc.splitTextToSize(sanitizeText(finding.description), contentWidth - 10);
            doc.text(descLines.slice(0, 2), margin + 3, currentY);
            currentY += Math.min(descLines.length, 2) * 4 + 3;
            
            // Code snippet
            if (finding.location.snippet) {
                doc.setFillColor(...COLORS.lightBg);
                doc.setFont('courier', 'normal');
                doc.setFontSize(7);
                const snippetText = redactSecrets ? sanitizeText(finding.location.snippet).substring(0, 100) : finding.location.snippet.substring(0, 100);
                doc.rect(margin + 3, currentY - 2, contentWidth - 6, 10, 'F');
                doc.setTextColor(...COLORS.text);
                doc.text(snippetText + (finding.location.snippet.length > 100 ? '...' : ''), margin + 5, currentY + 3);
                currentY += 12;
                doc.setFont('helvetica', 'normal');
            }
            
            // Remediation
            if (finding.remediation) {
                doc.setTextColor(...COLORS.success);
                doc.setFontSize(8);
                doc.setFont('helvetica', 'bold');
                doc.text('Fix:', margin + 3, currentY);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.text);
                const remLines = doc.splitTextToSize(sanitizeText(finding.remediation), contentWidth - 20);
                doc.text(remLines.slice(0, 2), margin + 15, currentY);
                currentY += Math.min(remLines.length, 2) * 4;
            }
            
            currentY += 8;
        }
    }
    
    // ========================================================================
    // RECOMMENDATIONS
    // ========================================================================
    
    doc.addPage();
    currentPage++;
    currentY = classification !== 'UNCLASSIFIED' ? 20 : 15;
    
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, contentWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('6. Recommendations', margin + 5, currentY + 7);
    currentY += 18;
    
    const recommendations = [
        {
            priority: 'Immediate (Critical)',
            items: [
                'Rotate all exposed API keys, tokens, and credentials immediately',
                'Review and revoke any compromised service account permissions',
                'Audit access logs for any unauthorized usage of exposed credentials',
                'Remove all hardcoded secrets from source code',
            ],
            color: COLORS.critical
        },
        {
            priority: 'High Priority',
            items: [
                'Implement secrets management solution (HashiCorp Vault, AWS Secrets Manager)',
                'Add pre-commit hooks to prevent secret commits',
                'Enable branch protection and require code reviews',
                'Implement automated secret scanning in CI/CD pipeline',
            ],
            color: COLORS.high
        },
        {
            priority: 'Best Practices',
            items: [
                'Use environment variables for all configuration secrets',
                'Implement least-privilege access for all service accounts',
                'Regular rotation schedule for all credentials',
                'Security awareness training for development team',
            ],
            color: COLORS.medium
        }
    ];
    
    for (const rec of recommendations) {
        doc.setFillColor(...rec.color);
        doc.circle(margin + 3, currentY - 1, 2, 'F');
        
        doc.setTextColor(...rec.color);
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.text(rec.priority, margin + 8, currentY);
        currentY += 7;
        
        doc.setTextColor(...COLORS.text);
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        
        for (const item of rec.items) {
            doc.text(`- ${item}`, margin + 8, currentY);
            currentY += 5;
        }
        currentY += 8;
    }
    
    // ========================================================================
    // ADD PAGE FOOTERS
    // ========================================================================
    
    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.textLight);
        doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - (classification !== 'UNCLASSIFIED' ? 15 : 8), { align: 'center' });
        doc.text('STRIX SAST Report', pageWidth - margin, pageHeight - (classification !== 'UNCLASSIFIED' ? 15 : 8), { align: 'right' });
        
        if (classification !== 'UNCLASSIFIED') {
            doc.setFillColor(...COLORS.critical);
            doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
            doc.setTextColor(...COLORS.white);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(classification, pageWidth / 2, pageHeight - 4, { align: 'center' });
        }
    }
    
    return doc;
}

/**
 * Download SAST report as PDF
 */
export function downloadSASTReport(
    scanResult: ScanResult,
    options: SASTReportOptions = {},
    filename?: string
): void {
    const doc = generateSASTReport(scanResult, options);
    const projectName = options.projectName || scanResult.targetPath.split(/[/\\]/).pop() || 'Project';
    const defaultFilename = `STRIX_SAST_Report_${projectName}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
}

export default {
    generateSASTReport,
    downloadSASTReport
};

// STRIX Report Base Module
// Shared utilities, logo, and styling for all PDF reports

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

// Extend jsPDF type for autoTable
declare module 'jspdf' {
    interface jsPDF {
        lastAutoTable: { finalY: number };
    }
}

// ============================================================================
// STRIX LOGO (Simplified vector representation for PDF)
// ============================================================================

/**
 * Draw the STRIX owl logo on the PDF
 */
export function drawStrixLogo(doc: jsPDF, x: number, y: number, size: number = 30): void {
    const scale = size / 100;
    
    // Owl face outline - dark slate background
    doc.setFillColor(30, 41, 59); // slate-800
    doc.setDrawColor(51, 65, 85); // slate-600
    doc.setLineWidth(0.5 * scale);
    
    // Main face shape (hexagonal)
    const facePoints = [
        [x + 50 * scale, y + 8 * scale],   // top
        [x + 85 * scale, y + 35 * scale],  // top-right
        [x + 80 * scale, y + 75 * scale],  // bottom-right
        [x + 50 * scale, y + 92 * scale],  // bottom
        [x + 20 * scale, y + 75 * scale],  // bottom-left
        [x + 15 * scale, y + 35 * scale],  // top-left
    ];
    
    doc.moveTo(facePoints[0][0], facePoints[0][1]);
    for (let i = 1; i < facePoints.length; i++) {
        doc.lineTo(facePoints[i][0], facePoints[i][1]);
    }
    doc.lineTo(facePoints[0][0], facePoints[0][1]);
    doc.fillStroke();
    
    // Inner face (darker)
    doc.setFillColor(15, 23, 42); // slate-900
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
    
    // Eye sockets (angular shapes)
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
    // Left eye outer
    doc.setFillColor(8, 145, 178); // cyan-600
    doc.circle(x + 36 * scale, y + 43 * scale, 10 * scale, 'F');
    
    // Left eye inner
    doc.setFillColor(34, 211, 238); // cyan-400
    doc.circle(x + 36 * scale, y + 43 * scale, 6 * scale, 'F');
    
    // Left pupil
    doc.setFillColor(15, 23, 42);
    doc.circle(x + 36 * scale, y + 43 * scale, 3 * scale, 'F');
    
    // Left eye highlight
    doc.setFillColor(255, 255, 255);
    doc.circle(x + 34 * scale, y + 41 * scale, 1.5 * scale, 'F');
    
    // Right eye outer
    doc.setFillColor(8, 145, 178);
    doc.circle(x + 64 * scale, y + 43 * scale, 10 * scale, 'F');
    
    // Right eye inner
    doc.setFillColor(34, 211, 238);
    doc.circle(x + 64 * scale, y + 43 * scale, 6 * scale, 'F');
    
    // Right pupil
    doc.setFillColor(15, 23, 42);
    doc.circle(x + 64 * scale, y + 43 * scale, 3 * scale, 'F');
    
    // Right eye highlight
    doc.setFillColor(255, 255, 255);
    doc.circle(x + 62 * scale, y + 41 * scale, 1.5 * scale, 'F');
    
    // Beak
    doc.setFillColor(100, 116, 139); // slate-500
    doc.moveTo(x + 50 * scale, y + 52 * scale);
    doc.lineTo(x + 44 * scale, y + 60 * scale);
    doc.lineTo(x + 50 * scale, y + 72 * scale);
    doc.lineTo(x + 56 * scale, y + 60 * scale);
    doc.fill();
    
    // Beak detail
    doc.setFillColor(71, 85, 105); // slate-600
    doc.moveTo(x + 50 * scale, y + 52 * scale);
    doc.lineTo(x + 47 * scale, y + 58 * scale);
    doc.lineTo(x + 50 * scale, y + 65 * scale);
    doc.lineTo(x + 53 * scale, y + 58 * scale);
    doc.fill();
    
    // Ear tufts
    doc.setDrawColor(51, 65, 85);
    doc.setLineWidth(2 * scale);
    
    // Left tuft
    doc.moveTo(x + 22 * scale, y + 32 * scale);
    doc.lineTo(x + 30 * scale, y + 22 * scale);
    doc.lineTo(x + 38 * scale, y + 30 * scale);
    doc.stroke();
    
    // Right tuft
    doc.moveTo(x + 78 * scale, y + 32 * scale);
    doc.lineTo(x + 70 * scale, y + 22 * scale);
    doc.lineTo(x + 62 * scale, y + 30 * scale);
    doc.stroke();
}

// ============================================================================
// COLOR PALETTES
// ============================================================================

export const COLORS = {
    // Brand colors
    primary: [8, 145, 178] as [number, number, number],      // Cyan-600
    primaryLight: [34, 211, 238] as [number, number, number], // Cyan-400
    primaryDark: [6, 95, 117] as [number, number, number],   // Cyan-800
    
    // Severity colors
    critical: [220, 38, 38] as [number, number, number],     // Red-600
    high: [234, 88, 12] as [number, number, number],         // Orange-600
    medium: [202, 138, 4] as [number, number, number],       // Yellow-600
    low: [37, 99, 235] as [number, number, number],          // Blue-600
    info: [107, 114, 128] as [number, number, number],       // Gray-500
    success: [34, 197, 94] as [number, number, number],      // Green-500
    
    // UI colors
    dark: [15, 23, 42] as [number, number, number],          // Slate-900
    darkAlt: [30, 41, 59] as [number, number, number],       // Slate-800
    text: [51, 65, 85] as [number, number, number],          // Slate-700
    textLight: [100, 116, 139] as [number, number, number],  // Slate-500
    lightBg: [248, 250, 252] as [number, number, number],    // Slate-50
    white: [255, 255, 255] as [number, number, number],
    
    // Blockchain specific
    ethereum: [98, 126, 234] as [number, number, number],
    bitcoin: [247, 147, 26] as [number, number, number],
    solana: [156, 106, 222] as [number, number, number],
};

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// ============================================================================
// REPORT OPTIONS INTERFACES
// ============================================================================

export interface BaseReportOptions {
    title?: string;
    scannerUser?: string;
    organization?: string;
    classification?: 'UNCLASSIFIED' | 'CUI' | 'CONFIDENTIAL' | 'SECRET' | 'TOP SECRET';
    includeEvidence?: boolean;
    includeRemediation?: boolean;
    includeCompliance?: boolean;
    redactSensitive?: boolean;
    reportDate?: Date;
    reportId?: string;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

export function getSeverityColor(severity: string): [number, number, number] {
    switch (severity?.toLowerCase()) {
        case 'critical': return COLORS.critical;
        case 'high': return COLORS.high;
        case 'medium': return COLORS.medium;
        case 'low': return COLORS.low;
        default: return COLORS.info;
    }
}

export function formatDate(date: Date): string {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short'
    });
}

export function formatShortDate(date: Date): string {
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

/**
 * Sanitize text for PDF output - removes emojis and special Unicode characters
 */
export function sanitizeText(text: string): string {
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

export function generateReportId(): string {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    return `STRIX-${timestamp}-${random}`;
}

export function calculateRiskScore(findings: Array<{ severity: string }>): number {
    let score = 0;
    for (const finding of findings) {
        switch (finding.severity?.toLowerCase()) {
            case 'critical': score += 25; break;
            case 'high': score += 15; break;
            case 'medium': score += 8; break;
            case 'low': score += 3; break;
            case 'info': score += 1; break;
        }
    }
    return Math.min(100, score);
}

export function getRiskLevel(score: number): { level: string; color: [number, number, number] } {
    if (score >= 70) return { level: 'CRITICAL', color: COLORS.critical };
    if (score >= 50) return { level: 'HIGH', color: COLORS.high };
    if (score >= 30) return { level: 'MEDIUM', color: COLORS.medium };
    if (score >= 10) return { level: 'LOW', color: COLORS.low };
    return { level: 'MINIMAL', color: COLORS.success };
}

// ============================================================================
// COMMON REPORT COMPONENTS
// ============================================================================

/**
 * Draw the official report header with STRIX branding
 */
export function drawReportHeader(
    doc: jsPDF, 
    title: string, 
    subtitle: string,
    options: BaseReportOptions = {}
): number {
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 15;
    let currentY = margin;
    
    // Classification banner at top (if not unclassified)
    if (options.classification && options.classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, 0, pageWidth, 12, 'F');
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(options.classification, pageWidth / 2, 8, { align: 'center' });
        currentY = 18;
    }
    
    // Header background
    doc.setFillColor(...COLORS.dark);
    doc.rect(0, currentY - 5, pageWidth, 50, 'F');
    
    // Draw logo
    drawStrixLogo(doc, margin, currentY - 2, 40);
    
    // STRIX title
    doc.setTextColor(...COLORS.primaryLight);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text('STRIX', margin + 50, currentY + 12);
    
    // Subtitle
    doc.setTextColor(...COLORS.textLight);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text('Security Technical Risk & Implementation eXaminer', margin + 50, currentY + 20);
    
    // Report ID on right
    const reportId = options.reportId || generateReportId();
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(8);
    doc.text(`Report ID: ${reportId}`, pageWidth - margin, currentY + 8, { align: 'right' });
    doc.text(formatShortDate(options.reportDate || new Date()), pageWidth - margin, currentY + 14, { align: 'right' });
    
    currentY += 55;
    
    // Report title section
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, currentY, pageWidth - margin * 2, 25, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(sanitizeText(title), pageWidth / 2, currentY + 10, { align: 'center' });
    
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(sanitizeText(subtitle), pageWidth / 2, currentY + 19, { align: 'center' });
    
    return currentY + 35;
}

/**
 * Draw classification footer on page
 */
export function drawClassificationFooter(doc: jsPDF, classification?: string): void {
    if (!classification || classification === 'UNCLASSIFIED') return;
    
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    
    doc.setFillColor(...COLORS.critical);
    doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.text(classification, pageWidth / 2, pageHeight - 4, { align: 'center' });
}

/**
 * Draw page footer with page numbers
 */
export function drawPageFooter(doc: jsPDF, pageNum: number, totalPages: number, classification?: string): void {
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.textLight);
    doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth / 2, pageHeight - (classification && classification !== 'UNCLASSIFIED' ? 15 : 8), { align: 'center' });
    doc.text('Generated by STRIX Security Scanner', pageWidth - 15, pageHeight - (classification && classification !== 'UNCLASSIFIED' ? 15 : 8), { align: 'right' });
    
    drawClassificationFooter(doc, classification);
}

/**
 * Draw a risk score gauge
 */
export function drawRiskGauge(
    doc: jsPDF, 
    x: number, 
    y: number, 
    score: number, 
    size: number = 50
): void {
    const riskInfo = getRiskLevel(score);
    const radius = size / 2;
    
    // Background circle
    doc.setFillColor(...COLORS.darkAlt);
    doc.circle(x + radius, y + radius, radius, 'F');
    
    // Score arc (simplified - just a colored ring)
    doc.setDrawColor(...riskInfo.color);
    doc.setLineWidth(4);
    doc.circle(x + radius, y + radius, radius - 5, 'S');
    
    // Inner circle
    doc.setFillColor(...COLORS.dark);
    doc.circle(x + radius, y + radius, radius - 10, 'F');
    
    // Score text
    doc.setTextColor(...riskInfo.color);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text(score.toString(), x + radius, y + radius + 2, { align: 'center' });
    
    // Risk level text
    doc.setFontSize(7);
    doc.text(riskInfo.level, x + radius, y + radius + 10, { align: 'center' });
}

/**
 * Draw severity summary boxes
 */
export function drawSeveritySummary(
    doc: jsPDF,
    x: number,
    y: number,
    counts: { critical: number; high: number; medium: number; low: number; info: number },
    boxWidth: number = 30
): number {
    const boxHeight = 20;
    const gap = 3;
    let currentX = x;
    
    const severities = [
        { label: 'Critical', count: counts.critical, color: COLORS.critical },
        { label: 'High', count: counts.high, color: COLORS.high },
        { label: 'Medium', count: counts.medium, color: COLORS.medium },
        { label: 'Low', count: counts.low, color: COLORS.low },
        { label: 'Info', count: counts.info, color: COLORS.info },
    ];
    
    for (const sev of severities) {
        // Box background
        doc.setFillColor(...COLORS.darkAlt);
        doc.roundedRect(currentX, y, boxWidth, boxHeight, 2, 2, 'F');
        
        // Colored top border
        doc.setFillColor(...sev.color);
        doc.rect(currentX, y, boxWidth, 3, 'F');
        
        // Count
        doc.setTextColor(...sev.color);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text(sev.count.toString(), currentX + boxWidth / 2, y + 12, { align: 'center' });
        
        // Label
        doc.setTextColor(...COLORS.textLight);
        doc.setFontSize(6);
        doc.setFont('helvetica', 'normal');
        doc.text(sev.label, currentX + boxWidth / 2, y + 18, { align: 'center' });
        
        currentX += boxWidth + gap;
    }
    
    return y + boxHeight + 5;
}

/**
 * Draw a section header
 */
export function drawSectionHeader(doc: jsPDF, title: string, y: number, sectionNum?: number): number {
    const pageWidth = doc.internal.pageSize.getWidth();
    const margin = 15;
    
    doc.setFillColor(...COLORS.primary);
    doc.rect(margin, y, pageWidth - margin * 2, 8, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    
    const text = sectionNum ? `${sectionNum}. ${title}` : title;
    doc.text(text, margin + 5, y + 5.5);
    
    return y + 15;
}

/**
 * Create a new page with consistent styling
 */
export function addNewPage(doc: jsPDF, classification?: string): number {
    doc.addPage();
    
    // Add classification header if needed
    if (classification && classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, 0, doc.internal.pageSize.getWidth(), 8, 'F');
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(classification, doc.internal.pageSize.getWidth() / 2, 5.5, { align: 'center' });
        return 15;
    }
    
    return 15;
}

/**
 * Add footers to all pages
 */
export function addAllPageFooters(doc: jsPDF, classification?: string): void {
    const totalPages = doc.getNumberOfPages();
    
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        drawPageFooter(doc, i, totalPages, classification);
    }
}

export default {
    drawStrixLogo,
    drawReportHeader,
    drawClassificationFooter,
    drawPageFooter,
    drawRiskGauge,
    drawSeveritySummary,
    drawSectionHeader,
    addNewPage,
    addAllPageFooters,
    getSeverityColor,
    formatDate,
    formatShortDate,
    sanitizeText,
    generateReportId,
    calculateRiskScore,
    getRiskLevel,
    COLORS,
    SEVERITY_ORDER
};

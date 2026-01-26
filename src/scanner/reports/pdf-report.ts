// STRIX PDF Report Generator
// Generates comprehensive PDF reports for web security scans

import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { ScanResult, UnifiedVulnerability } from '../types';
import { getComplianceMapping, generateComplianceSummary } from '../compliance';
import { drawStrixLogo, generateReportId } from './report-base';

// Extend jsPDF type for autoTable
declare module 'jspdf' {
    interface jsPDF {
        lastAutoTable: { finalY: number };
    }
}

// ============================================================================
// INTERFACES
// ============================================================================

export interface PdfReportOptions {
    title?: string;
    scannerUser?: string;
    organization?: string;
    classification?: 'UNCLASSIFIED' | 'CUI' | 'CONFIDENTIAL' | 'SECRET' | 'TOP SECRET';
    includeEvidence?: boolean;
    includeExploitation?: boolean;
    includeRemediation?: boolean;
    includeTechnicalDetails?: boolean;
    includeCompliance?: boolean;
    redactSensitive?: boolean;
    logoBase64?: string;
    // Scan configuration for methodology section
    scanConfig?: {
        depth?: 'quick' | 'standard' | 'deep' | 'comprehensive';
        crawlPages?: boolean;
        maxPages?: number;
        maxDepth?: number;
        directoryEnum?: boolean;
        dirWordlist?: 'small' | 'medium' | 'large';
        timeBasedTests?: boolean;
        testAllParams?: boolean;
        payloadsPerParam?: number;
        delayBetweenRequests?: number;
        testXss?: boolean;
        testSqli?: boolean;
        scanHeaders?: boolean;
        scanBlockchain?: boolean;
    };
}

export interface ScanMetadata {
    scannerVersion: string;
    scannerUser: string;
    scanDate: Date;
    scanDuration: number;
    targetUrl: string;
    scanType: string;
    methodsUsed: string[];
    testsPerformed: string[];
}

// ============================================================================
// CONSTANTS
// ============================================================================

const COLORS = {
    primary: [8, 145, 178] as [number, number, number],      // Cyan
    critical: [220, 38, 38] as [number, number, number],     // Red
    high: [234, 88, 12] as [number, number, number],         // Orange
    medium: [202, 138, 4] as [number, number, number],       // Yellow
    low: [37, 99, 235] as [number, number, number],          // Blue
    info: [107, 114, 128] as [number, number, number],       // Gray
    success: [34, 197, 94] as [number, number, number],      // Green
    dark: [15, 23, 42] as [number, number, number],          // Slate 900
    text: [51, 65, 85] as [number, number, number],          // Slate 700
    lightBg: [248, 250, 252] as [number, number, number],    // Slate 50
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Sanitize text for PDF output - removes emojis and special Unicode characters
 * that jsPDF can't render properly with standard fonts
 */
function sanitizeText(text: string): string {
    if (!text) return '';

    return text
        // Remove emojis and special symbols
        .replace(/[\u{1F300}-\u{1F9FF}]/gu, '')  // Misc symbols, emojis
        .replace(/[\u{2600}-\u{26FF}]/gu, '')    // Misc symbols
        .replace(/[\u{2700}-\u{27BF}]/gu, '')    // Dingbats
        .replace(/[\u{1F600}-\u{1F64F}]/gu, '')  // Emoticons
        .replace(/[\u{1F680}-\u{1F6FF}]/gu, '')  // Transport/map symbols
        // Replace box drawing characters with simple alternatives
        .replace(/[═╔╗╚╝║╠╣╦╩╬─│┌┐└┘├┤┬┴┼]/g, '-')
        .replace(/[━┃┏┓┗┛┣┫┳┻╋]/g, '-')
        // Replace other problematic characters
        .replace(/[►◄▲▼●○■□◆◇★☆♠♣♥♦]/g, '*')
        .replace(/[✓✔]/g, '[OK]')
        .replace(/[✗✘×]/g, '[X]')
        .replace(/[→←↑↓↔↕]/g, '->')
        .replace(/[•·]/g, '-')
        // Clean up excessive dashes/spaces from replacements
        .replace(/-{3,}/g, '---')
        .replace(/\s{2,}/g, ' ')
        .trim();
}

/**
 * Sanitize text and also remove line prefixes used in detailed evidence reports
 */
function sanitizeEvidence(text: string): string {
    if (!text) return '';

    // First apply general sanitization
    let sanitized = sanitizeText(text);

    // Clean up the detailed evidence format to be more readable in PDF
    sanitized = sanitized
        .replace(/SERVICE:/g, '\nService:')
        .replace(/SECRET VALUE:/g, '\nSecret Value:')
        .replace(/LOCATION:/g, '\nLocation:')
        .replace(/DETECTION CONFIDENCE:/g, '\nConfidence:')
        .replace(/SECURITY IMPACT:/g, '\nSecurity Impact:')
        .replace(/CODE CONTEXT:/g, '\nCode Context:')
        .replace(/---+/g, '')
        .replace(/\n{3,}/g, '\n\n')
        .trim();

    return sanitized;
}

function getSeverityColor(severity: string): [number, number, number] {
    switch (severity) {
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
        minute: '2-digit',
        timeZoneName: 'short'
    });
}

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

function getRiskLevel(score: number): string {
    if (score >= 70) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 30) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'MINIMAL';
}

function wrapText(text: string, maxWidth: number, fontSize: number): string[] {
    // Approximate characters per line based on font size
    const charsPerLine = Math.floor(maxWidth / (fontSize * 0.5));
    const words = text.split(' ');
    const lines: string[] = [];
    let currentLine = '';

    for (const word of words) {
        if ((currentLine + ' ' + word).length <= charsPerLine) {
            currentLine = currentLine ? currentLine + ' ' + word : word;
        } else {
            if (currentLine) lines.push(currentLine);
            currentLine = word;
        }
    }
    if (currentLine) lines.push(currentLine);
    return lines;
}

function getScanMethodsUsed(scanResult: ScanResult, scanConfig?: any): string[] {
    const methods: string[] = [];

    methods.push('HTTP/HTTPS Request Analysis');
    methods.push('Security Header Analysis');

    if (scanResult.headerAnalysis) {
        methods.push('Security Header Validation');
    }

    if (scanResult.web3Detection?.hasWeb3) {
        methods.push('Web3/Blockchain Detection');
        methods.push('Smart Contract Analysis');
        methods.push('API Key/Secret Scanning');
    }

    if (scanResult.crawlResults && scanResult.crawlResults.length > 0) {
        methods.push('Site Crawling & Discovery');
        methods.push('Form Analysis');
        methods.push('CSRF Token Detection');
        methods.push('Parameter Extraction');
    }

    // Check vulnerability categories to determine what was tested
    const categories = new Set(scanResult.vulnerabilities.map(v => v.category));
    if (categories.has('xss')) methods.push('XSS Payload Testing');
    if (categories.has('injection')) methods.push('SQL Injection Testing');

    // Add methods based on scan configuration
    if (scanConfig) {
        if (scanConfig.directoryEnum) methods.push('Directory/Path Enumeration');
        if (scanConfig.timeBasedTests) methods.push('Time-based Blind Injection Testing');
        if (scanConfig.testAllParams) methods.push('Comprehensive Parameter Fuzzing');
    }

    return methods;
}

/**
 * Get scan intensity level description
 */
function getScanIntensityInfo(depth: string): { level: string; description: string; color: [number, number, number] } {
    switch (depth) {
        case 'quick':
            return {
                level: 'Quick Scan',
                description: 'Fast security header and basic Web3 detection only',
                color: [59, 130, 246] // Blue
            };
        case 'standard':
            return {
                level: 'Standard Scan',
                description: 'Headers, Web3 detection, and basic XSS/SQLi testing',
                color: [34, 197, 94] // Green
            };
        case 'deep':
            return {
                level: 'Deep Scan',
                description: 'Full site crawling, parameter fuzzing, and directory enumeration',
                color: [234, 88, 12] // Orange
            };
        case 'comprehensive':
            return {
                level: 'Comprehensive Scan',
                description: 'Full penetration testing with time-based blind detection and comprehensive payload coverage',
                color: [220, 38, 38] // Red
            };
        default:
            return {
                level: 'Standard Scan',
                description: 'Standard security assessment',
                color: [107, 114, 128] // Gray
            };
    }
}

function getExploitationSteps(vuln: UnifiedVulnerability): string[] {
    // Return custom repro steps if available
    if (vuln.reproSteps && vuln.reproSteps.length > 0) {
        return vuln.reproSteps;
    }

    const steps: string[] = [];

    switch (vuln.category) {
        case 'xss':
            steps.push('1. Identify the vulnerable input parameter');
            steps.push('2. Craft a malicious JavaScript payload');
            if (vuln.payload) steps.push(`3. Inject payload: ${vuln.payload}`);
            steps.push('4. Payload executes in victim\'s browser context');
            steps.push('5. Attacker can steal cookies, session tokens, or perform actions as the victim');
            break;

        case 'injection':
            steps.push('1. Identify input field that interacts with database');
            steps.push('2. Test with SQL syntax characters (\', ", --, etc.)');
            if (vuln.payload) steps.push(`3. Craft injection payload: ${vuln.payload}`);
            steps.push('4. Extract sensitive data or modify database contents');
            steps.push('5. Potential for complete database compromise');
            break;

        case 'authentication':
            if (vuln.title.includes('CSRF')) {
                steps.push('1. Create malicious webpage with hidden form');
                steps.push('2. Form targets vulnerable endpoint');
                steps.push('3. Trick authenticated user into visiting malicious page');
                steps.push('4. Form auto-submits, performing action as victim');
            }
            break;

        case 'configuration':
            if (vuln.title.includes('CSP')) {
                steps.push('1. Find XSS vulnerability or injection point');
                steps.push('2. Due to weak/missing CSP, inline scripts execute');
                steps.push('3. Load external malicious scripts');
            } else if (vuln.title.includes('HSTS')) {
                steps.push('1. Perform man-in-the-middle attack');
                steps.push('2. Downgrade HTTPS connection to HTTP');
                steps.push('3. Intercept sensitive data in transit');
            }
            break;

        case 'disclosure':
            if (vuln.title.includes('API Key')) {
                steps.push('1. Extract exposed API key from source code');
                steps.push('2. Test key against provider API endpoints');
                steps.push('3. Access services using stolen credentials');
                steps.push('4. Potential financial impact from API abuse');
            }
            break;

        case 'smart-contract':
            if (vuln.title.includes('Private Key')) {
                steps.push('1. Extract private key from client-side code');
                steps.push('2. Import key into wallet software');
                steps.push('3. Transfer all funds to attacker-controlled address');
                steps.push('4. IMMEDIATE and IRREVERSIBLE financial loss');
            }
            break;

        default:
            steps.push('Exploitation steps depend on specific vulnerability context');
            steps.push('Refer to CWE/OWASP references for detailed attack scenarios');
    }

    return steps;
}

function getRemediationSteps(vuln: UnifiedVulnerability): string[] {
    const steps: string[] = [];

    // Start with the built-in recommendation
    if (vuln.recommendation) {
        steps.push(vuln.recommendation);
    }

    // Add category-specific detailed steps
    switch (vuln.category) {
        case 'xss':
            steps.push('Implement context-aware output encoding');
            steps.push('Use Content Security Policy (CSP) headers');
            steps.push('Validate and sanitize all user inputs');
            steps.push('Use modern frameworks with built-in XSS protection');
            break;

        case 'injection':
            steps.push('Use parameterized queries / prepared statements');
            steps.push('Implement input validation with allowlists');
            steps.push('Apply principle of least privilege to database accounts');
            steps.push('Use ORM frameworks that prevent SQL injection');
            break;

        case 'authentication':
            steps.push('Implement anti-CSRF tokens for all state-changing operations');
            steps.push('Use SameSite cookie attribute');
            steps.push('Verify Origin/Referer headers');
            steps.push('Require re-authentication for sensitive actions');
            break;

        case 'configuration':
            steps.push('Review and harden web server configuration');
            steps.push('Implement all recommended security headers');
            steps.push('Use automated security header scanning in CI/CD');
            steps.push('Regular security configuration audits');
            break;

        case 'disclosure':
            steps.push('Move secrets to server-side environment variables');
            steps.push('Use secret management services (Vault, AWS Secrets Manager)');
            steps.push('Implement secret scanning in CI/CD pipeline');
            steps.push('Rotate all exposed credentials immediately');
            break;

        case 'smart-contract':
            steps.push('NEVER store private keys in client-side code');
            steps.push('Use hardware wallets for key management');
            steps.push('Implement proper key derivation and storage');
            steps.push('Audit all blockchain integration code');
            break;
    }

    return [...new Set(steps)]; // Remove duplicates
}

// ============================================================================
// PDF GENERATION
// ============================================================================

export function generatePdfReport(
    scanResult: ScanResult,
    options: PdfReportOptions = {}
): jsPDF {
    const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4'
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 15;
    const contentWidth = pageWidth - (margin * 2);

    const title = options.title || 'Web Security Assessment Report';
    const scannerUser = options.scannerUser || 'STRIX Scanner';
    const organization = options.organization || '';
    const classification = options.classification || 'UNCLASSIFIED';

    let currentY = margin;

    // ========================================================================
    // COVER PAGE
    // ========================================================================

    // Classification banner (if not unclassified)
    if (classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, 0, pageWidth, 10, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(classification, pageWidth / 2, 6, { align: 'center' });
        currentY = 15;
    }

    // Generate Report ID
    const reportId = generateReportId();

    // Header banner with dark background
    currentY = 20;
    doc.setFillColor(15, 23, 42); // Slate-900
    doc.rect(0, currentY, pageWidth, 55, 'F');

    // Draw STRIX owl logo
    drawStrixLogo(doc, margin + 5, currentY + 5, 45);

    // STRIX Title next to logo
    doc.setTextColor(34, 211, 238); // Cyan-400
    doc.setFontSize(36);
    doc.setFont('helvetica', 'bold');
    doc.text('STRIX', margin + 60, currentY + 25);

    // Subtitle
    doc.setTextColor(148, 163, 184); // Slate-400
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('Security Technical Risk & Implementation eXaminer', margin + 60, currentY + 35);

    // Report ID on right
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(8);
    doc.text(`Report ID: ${reportId}`, pageWidth - margin, currentY + 15, { align: 'right' });
    doc.text(formatDate(scanResult.startTime).split(',')[0], pageWidth - margin, currentY + 22, { align: 'right' });

    currentY += 60;

    // Report type banner
    doc.setFillColor(...COLORS.primary);
    doc.roundedRect(margin, currentY, contentWidth, 25, 3, 3, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Web Security Assessment Report', pageWidth / 2, currentY + 10, { align: 'center' });

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(scanResult.target, pageWidth / 2, currentY + 19, { align: 'center' });

    currentY += 35;

    // Report Title (if custom title provided)
    if (title && title !== 'Web Security Assessment Report') {
        doc.setTextColor(...COLORS.dark);
        doc.setFontSize(18);
        doc.setFont('helvetica', 'bold');
        const titleLines = wrapText(title, contentWidth, 18);
        for (const line of titleLines) {
            doc.text(line, pageWidth / 2, currentY, { align: 'center' });
            currentY += 8;
        }
        currentY += 10;
    }

    // Risk Score Box
    const riskScore = calculateRiskScore(scanResult.vulnerabilities);
    const riskLevel = getRiskLevel(riskScore);
    const riskColor = riskScore >= 70 ? COLORS.critical :
        riskScore >= 50 ? COLORS.high :
            riskScore >= 30 ? COLORS.medium :
                riskScore >= 10 ? COLORS.low : COLORS.success;

    doc.setFillColor(...riskColor);
    doc.roundedRect(pageWidth / 2 - 40, currentY, 80, 40, 3, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text(riskScore.toString(), pageWidth / 2, currentY + 18, { align: 'center' });
    doc.setFontSize(10);
    doc.text(`${riskLevel} RISK`, pageWidth / 2, currentY + 30, { align: 'center' });

    currentY += 55;

    // Metadata table
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');

    const coverIntensity = getScanIntensityInfo(options.scanConfig?.depth || 'standard');

    const metadata = [
        ['Scan Date:', formatDate(scanResult.startTime)],
        ['Duration:', `${Math.round((scanResult.duration || 0) / 1000)} seconds`],
        ['Scan Type:', coverIntensity.level],
        ['Scanner:', scannerUser],
        ['Scanner Version:', 'STRIX v1.0.0'],
    ];

    if (organization) {
        metadata.push(['Organization:', organization]);
    }

    metadata.push(['Total Findings:', scanResult.vulnerabilities.length.toString()]);

    autoTable(doc, {
        startY: currentY,
        head: [],
        body: metadata,
        theme: 'plain',
        styles: {
            fontSize: 10,
            cellPadding: 3,
        },
        columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 40 },
            1: { cellWidth: 80 }
        },
        margin: { left: pageWidth / 2 - 60 }
    });

    // Footer with classification
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.info);
    doc.text(`Generated by STRIX Security Scanner | ${new Date().toISOString()}`, pageWidth / 2, pageHeight - 10, { align: 'center' });

    if (classification !== 'UNCLASSIFIED') {
        doc.setFillColor(...COLORS.critical);
        doc.rect(0, pageHeight - 10, pageWidth, 10, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(classification, pageWidth / 2, pageHeight - 4, { align: 'center' });
    }

    // ========================================================================
    // TABLE OF CONTENTS
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.dark);
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('Table of Contents', margin, currentY);
    currentY += 15;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');

    const tocItems = [
        '1. Executive Summary',
        '2. Scan Methodology',
        '3. Findings Summary',
        '4. Detailed Findings',
        '5. Compliance Mapping',
        '6. Recommendations',
        '7. Technical Appendix'
    ];

    for (const item of tocItems) {
        doc.setTextColor(...COLORS.text);
        doc.text(item, margin + 5, currentY);
        currentY += 8;
    }

    // ========================================================================
    // EXECUTIVE SUMMARY
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.primary);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Executive Summary', margin, currentY);
    currentY += 12;

    // Summary paragraph
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');

    const summaryText = `A comprehensive security assessment was performed on ${scanResult.target} on ${formatDate(scanResult.startTime)}. The scan identified ${scanResult.vulnerabilities.length} potential security findings across multiple categories. The overall risk score is ${riskScore}/100, classified as ${riskLevel} risk.`;

    const summaryLines = doc.splitTextToSize(summaryText, contentWidth);
    doc.text(summaryLines, margin, currentY);
    currentY += summaryLines.length * 5 + 10;

    // Findings breakdown by severity
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Findings by Severity', margin, currentY);
    currentY += 8;

    const severityCounts = [
        { severity: 'Critical', count: scanResult.summary.critical, color: COLORS.critical },
        { severity: 'High', count: scanResult.summary.high, color: COLORS.high },
        { severity: 'Medium', count: scanResult.summary.medium, color: COLORS.medium },
        { severity: 'Low', count: scanResult.summary.low, color: COLORS.low },
        { severity: 'Informational', count: scanResult.summary.info, color: COLORS.info },
    ];

    // Draw severity bars
    const barWidth = 100;
    const barHeight = 8;
    const maxCount = Math.max(...severityCounts.map(s => s.count), 1);

    for (const item of severityCounts) {
        // Label
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        doc.text(`${item.severity}:`, margin, currentY + 5);

        // Background bar
        doc.setFillColor(...COLORS.lightBg);
        doc.rect(margin + 30, currentY, barWidth, barHeight, 'F');

        // Filled bar
        const fillWidth = (item.count / maxCount) * barWidth;
        if (fillWidth > 0) {
            doc.setFillColor(...item.color);
            doc.rect(margin + 30, currentY, fillWidth, barHeight, 'F');
        }

        // Count
        doc.setTextColor(...item.color);
        doc.setFont('helvetica', 'bold');
        doc.text(item.count.toString(), margin + 35 + barWidth, currentY + 5);

        currentY += 12;
    }

    currentY += 10;

    // Key findings
    doc.setTextColor(...COLORS.dark);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('Key Findings', margin, currentY);
    currentY += 8;

    const criticalAndHigh = scanResult.vulnerabilities
        .filter(v => v.severity === 'critical' || v.severity === 'high')
        .slice(0, 5);

    if (criticalAndHigh.length > 0) {
        for (const vuln of criticalAndHigh) {
            const severityColor = getSeverityColor(vuln.severity);
            doc.setFillColor(...severityColor);
            doc.circle(margin + 2, currentY - 1, 2, 'F');

            doc.setTextColor(...COLORS.text);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            const vulnText = doc.splitTextToSize(`${sanitizeText(vuln.title)} (${vuln.severity.toUpperCase()})`, contentWidth - 10);
            doc.text(vulnText, margin + 7, currentY);
            currentY += vulnText.length * 4 + 4;
        }
    } else {
        doc.setTextColor(...COLORS.success);
        doc.setFontSize(10);
        doc.text('No critical or high severity findings identified.', margin, currentY);
        currentY += 8;
    }

    // ========================================================================
    // SCAN METHODOLOGY
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.primary);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('2. Scan Methodology', margin, currentY);
    currentY += 12;

    // Scan intensity badge
    const scanConfig = options.scanConfig;
    const intensityInfo = getScanIntensityInfo(scanConfig?.depth || 'standard');

    doc.setFillColor(...intensityInfo.color);
    doc.roundedRect(margin, currentY, contentWidth, 20, 2, 2, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text(intensityInfo.level.toUpperCase(), margin + 5, currentY + 8);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(intensityInfo.description, margin + 5, currentY + 15);
    currentY += 28;

    // Scanner information
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');

    const methodologyText = `This assessment was conducted using STRIX Security Scanner, a comprehensive web application security testing platform. The scanner performs automated vulnerability detection, parameter fuzzing, injection testing, and compliance mapping against NIST 800-53 and DISA STIG standards.`;
    const methodLines = doc.splitTextToSize(methodologyText, contentWidth);
    doc.text(methodLines, margin, currentY);
    currentY += methodLines.length * 5 + 10;

    // Build dynamic methods table based on scan configuration
    const methodsTableData: string[][] = [
        ['HTTP Analysis', 'Analysis of HTTP requests, responses, and status codes'],
        ['Header Security', 'Validation of security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.)'],
    ];

    if (scanConfig?.scanBlockchain !== false) {
        methodsTableData.push(['Web3 Detection', 'Detection of blockchain integration, wallet connections, smart contracts, and DeFi features']);
        methodsTableData.push(['Secret Scanning', 'Identification of exposed API keys, private keys, mnemonics, and credentials']);
    }

    if (scanConfig?.crawlPages) {
        methodsTableData.push(['Site Crawling', `Automated page discovery and link following (max ${scanConfig.maxPages || 50} pages, depth ${scanConfig.maxDepth || 3})`]);
        methodsTableData.push(['Parameter Discovery', 'Extraction of URL parameters, form inputs, and hidden fields']);
    }

    if (scanConfig?.testXss !== false) {
        const payloadCount = scanConfig?.payloadsPerParam || 10;
        methodsTableData.push(['XSS Testing', `Cross-site scripting detection with ${payloadCount}+ payloads including DOM-based, reflected, and stored XSS`]);
    }

    if (scanConfig?.testSqli !== false) {
        methodsTableData.push(['SQL Injection', 'Error-based, boolean-based, and UNION-based SQL injection testing']);
    }

    if (scanConfig?.timeBasedTests) {
        methodsTableData.push(['Time-based Blind', 'Blind SQL injection and command injection via response timing analysis']);
    }

    if (scanConfig?.directoryEnum) {
        const wordlistSize = scanConfig.dirWordlist === 'large' ? '2000+' : scanConfig.dirWordlist === 'medium' ? '500+' : '100+';
        methodsTableData.push(['Directory Enumeration', `Brute-force discovery of hidden paths and files (${wordlistSize} paths wordlist)`]);
    }

    if (scanConfig?.testAllParams) {
        methodsTableData.push(['Parameter Fuzzing', 'Comprehensive testing of all discovered input parameters']);
    }

    methodsTableData.push(['Form Analysis', 'Analysis of forms for CSRF protection, file uploads, and injection points']);
    methodsTableData.push(['Compliance Mapping', 'Mapping findings to OWASP Top 10, CWE, NIST 800-53, and DISA STIG standards']);

    autoTable(doc, {
        startY: currentY,
        head: [['Method', 'Description']],
        body: methodsTableData,
        theme: 'striped',
        headStyles: {
            fillColor: COLORS.primary,
            textColor: [255, 255, 255],
            fontStyle: 'bold'
        },
        styles: {
            fontSize: 8,
            cellPadding: 3,
        },
        columnStyles: {
            0: { cellWidth: 38, fontStyle: 'bold' },
            1: { cellWidth: contentWidth - 38 }
        },
        margin: { left: margin, right: margin }
    });

    currentY = doc.lastAutoTable.finalY + 10;

    // Scan Configuration Details
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('Scan Configuration', margin, currentY);
    currentY += 8;

    const configDetails: string[][] = [
        ['Target URL', scanResult.target],
        ['Scan Started', formatDate(scanResult.startTime)],
        ['Scan Completed', scanResult.endTime ? formatDate(scanResult.endTime) : 'N/A'],
        ['Duration', `${Math.round((scanResult.duration || 0) / 1000)} seconds`],
        ['Scanner', scannerUser],
        ['Scan Intensity', intensityInfo.level],
    ];

    // Add configuration details if available
    if (scanConfig) {
        if (scanConfig.crawlPages) {
            configDetails.push(['Page Crawling', `Enabled (max ${scanConfig.maxPages || 50} pages)`]);
        }
        if (scanConfig.directoryEnum) {
            configDetails.push(['Directory Enumeration', `Enabled (${scanConfig.dirWordlist || 'medium'} wordlist)`]);
        }
        if (scanConfig.timeBasedTests) {
            configDetails.push(['Time-based Tests', 'Enabled']);
        }
        if (scanConfig.payloadsPerParam) {
            configDetails.push(['Payloads per Parameter', scanConfig.payloadsPerParam.toString()]);
        }
        if (scanConfig.delayBetweenRequests) {
            configDetails.push(['Request Delay', `${scanConfig.delayBetweenRequests}ms`]);
        }
    }

    // Add scan statistics
    if (scanResult.crawlResults && scanResult.crawlResults.length > 0) {
        const crawlStats = scanResult.crawlResults[0].crawlStats;
        if (crawlStats) {
            configDetails.push(['Pages Crawled', crawlStats.pagesCrawled?.toString() || 'N/A']);
            configDetails.push(['Forms Found', crawlStats.formsFound?.toString() || 'N/A']);
            configDetails.push(['Parameters Found', crawlStats.parametersFound?.toString() || 'N/A']);
        }
    }

    configDetails.push(['Total Findings', scanResult.vulnerabilities.length.toString()]);
    configDetails.push(['Scan Status', scanResult.status.toUpperCase()]);

    autoTable(doc, {
        startY: currentY,
        head: [],
        body: configDetails,
        theme: 'plain',
        styles: {
            fontSize: 9,
            cellPadding: 3,
        },
        columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 45 },
            1: { cellWidth: contentWidth - 45 }
        },
        margin: { left: margin, right: margin }
    });

    // ========================================================================
    // FINDINGS SUMMARY
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.primary);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('3. Findings Summary', margin, currentY);
    currentY += 12;

    // Summary table
    const findingsData = scanResult.vulnerabilities
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
        .map((vuln, index) => [
            (index + 1).toString(),
            vuln.severity.toUpperCase(),
            sanitizeText(vuln.title),
            vuln.category,
            vuln.cwe || 'N/A'
        ]);

    autoTable(doc, {
        startY: currentY,
        head: [['#', 'Severity', 'Finding', 'Category', 'CWE']],
        body: findingsData,
        theme: 'striped',
        headStyles: {
            fillColor: COLORS.primary,
            textColor: [255, 255, 255],
            fontStyle: 'bold'
        },
        styles: {
            fontSize: 8,
            cellPadding: 3,
        },
        columnStyles: {
            0: { cellWidth: 10 },
            1: { cellWidth: 20 },
            2: { cellWidth: 70 },
            3: { cellWidth: 30 },
            4: { cellWidth: 25 }
        },
        margin: { left: margin, right: margin },
        didParseCell: (data) => {
            if (data.column.index === 1 && data.section === 'body') {
                const severity = data.cell.raw?.toString().toLowerCase();
                if (severity) {
                    data.cell.styles.textColor = getSeverityColor(severity);
                    data.cell.styles.fontStyle = 'bold';
                }
            }
        }
    });

    // ========================================================================
    // DETAILED FINDINGS
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.primary);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('4. Detailed Findings', margin, currentY);
    currentY += 12;

    // Sort vulnerabilities by severity
    const sortedVulns = [...scanResult.vulnerabilities].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );

    for (let i = 0; i < sortedVulns.length; i++) {
        const vuln = sortedVulns[i];
        const compliance = options.includeCompliance !== false ? getComplianceMapping(vuln) : null;

        // Check if we need a new page
        if (currentY > pageHeight - 80) {
            doc.addPage();
            currentY = margin;
        }

        // Finding header with severity badge
        const severityColor = getSeverityColor(vuln.severity);
        doc.setFillColor(...severityColor);
        doc.roundedRect(margin, currentY, contentWidth, 8, 1, 1, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(`${i + 1}. ${sanitizeText(vuln.title)}`, margin + 3, currentY + 5.5);

        doc.setFontSize(8);
        doc.text(vuln.severity.toUpperCase(), pageWidth - margin - 20, currentY + 5.5);

        currentY += 12;

        // Finding details box
        doc.setDrawColor(...severityColor);
        doc.setLineWidth(0.3);
        const boxStartY = currentY;

        // Description
        doc.setTextColor(...COLORS.dark);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text('Description:', margin + 3, currentY);
        currentY += 4;

        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        const descLines = doc.splitTextToSize(sanitizeText(vuln.description), contentWidth - 10);
        doc.text(descLines, margin + 3, currentY);
        currentY += descLines.length * 4 + 6;

        // Location/URL
        if (vuln.url || vuln.location) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Location:', margin + 3, currentY);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);
            const locText = doc.splitTextToSize(vuln.url || vuln.location || '', contentWidth - 35);
            doc.text(locText, margin + 25, currentY);
            currentY += locText.length * 4 + 4;
        }

        // Evidence
        if (vuln.evidence && options.includeEvidence !== false) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Evidence:', margin + 3, currentY);
            currentY += 4;

            doc.setFillColor(...COLORS.lightBg);
            doc.setFont('courier', 'normal');
            doc.setFontSize(7);
            doc.setTextColor(...COLORS.text);

            // Sanitize and truncate evidence
            let evidenceText = sanitizeEvidence(vuln.evidence);
            if (evidenceText.length > 400) {
                evidenceText = evidenceText.substring(0, 400) + '...';
            }
            const evidenceLines = doc.splitTextToSize(evidenceText, contentWidth - 10);

            doc.rect(margin + 3, currentY - 2, contentWidth - 6, Math.min(evidenceLines.length * 3 + 4, 60), 'F');
            doc.text(evidenceLines.slice(0, 15), margin + 5, currentY + 2); // Limit lines displayed
            currentY += Math.min(evidenceLines.length * 3, 45) + 8;

            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
        }

        // How to Exploit
        if (options.includeExploitation !== false) {
            const exploitSteps = getExploitationSteps(vuln);
            if (exploitSteps.length > 0 || vuln.reproCommand) {
                // Check for page break
                if (currentY > pageHeight - 60) {
                    doc.addPage();
                    currentY = margin;
                }

                doc.setFont('helvetica', 'bold');
                doc.setTextColor(...COLORS.critical);
                doc.text('How to Exploit:', margin + 3, currentY);
                currentY += 4;

                if (vuln.reproCommand) {
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(...COLORS.text);
                    doc.setFontSize(8);
                    doc.text('Reproduction Command:', margin + 5, currentY);
                    currentY += 4;

                    doc.setFillColor(...COLORS.lightBg);
                    doc.setFont('courier', 'normal');
                    doc.setFontSize(7);
                    const cmdLines = doc.splitTextToSize(vuln.reproCommand, contentWidth - 15);
                    doc.rect(margin + 5, currentY - 2, contentWidth - 10, cmdLines.length * 3 + 4, 'F');
                    doc.text(cmdLines, margin + 7, currentY + 2);
                    currentY += cmdLines.length * 3 + 8;

                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(9);
                }

                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.text);
                for (const step of exploitSteps.slice(0, 10)) {
                    const stepLines = doc.splitTextToSize(`- ${sanitizeText(step)}`, contentWidth - 15);
                    doc.text(stepLines, margin + 5, currentY);
                    currentY += stepLines.length * 4;
                }
                currentY += 4;
            }
        }

        // How to Fix
        if (options.includeRemediation !== false) {
            const remediationSteps = getRemediationSteps(vuln);
            if (remediationSteps.length > 0) {
                // Check for page break
                if (currentY > pageHeight - 50) {
                    doc.addPage();
                    currentY = margin;
                }

                doc.setFont('helvetica', 'bold');
                doc.setTextColor(...COLORS.success);
                doc.text('How to Fix:', margin + 3, currentY);
                currentY += 4;

                doc.setFont('helvetica', 'normal');
                doc.setTextColor(...COLORS.text);
                for (const step of remediationSteps.slice(0, 5)) {
                    const stepLines = doc.splitTextToSize(`- ${sanitizeText(step)}`, contentWidth - 15);
                    doc.text(stepLines, margin + 5, currentY);
                    currentY += stepLines.length * 4;
                }
                currentY += 4;
            }
        }

        // Compliance references - always show if there's any reference data
        const refs: string[] = [];
        if (vuln.cwe) refs.push(`CWE: ${vuln.cwe}`);
        if (vuln.owasp) refs.push(`OWASP: ${vuln.owasp}`);
        if (compliance?.nist?.length) refs.push(`NIST: ${compliance.nist.slice(0, 3).join(', ')}`);
        if (compliance?.stig?.length) refs.push(`STIG: ${compliance.stig[0]}`);
        if (vuln.category) refs.push(`Category: ${vuln.category}`);

        if (refs.length > 0) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('References:', margin + 3, currentY);

            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);
            doc.setFontSize(8);

            const refsText = refs.join(' | ');
            const refsLines = doc.splitTextToSize(refsText, contentWidth - 35);
            doc.text(refsLines, margin + 28, currentY);
            currentY += refsLines.length * 3 + 3;
            doc.setFontSize(9);
        }

        // Draw border around finding
        const boxHeight = currentY - boxStartY;
        doc.roundedRect(margin, boxStartY - 4, contentWidth, boxHeight + 4, 1, 1, 'S');

        currentY += 10;
    }

    // ========================================================================
    // COMPLIANCE MAPPING
    // ========================================================================

    if (options.includeCompliance !== false) {
        doc.addPage();
        currentY = margin;

        doc.setTextColor(...COLORS.primary);
        doc.setFontSize(18);
        doc.setFont('helvetica', 'bold');
        doc.text('5. Compliance Mapping', margin, currentY);
        currentY += 12;

        const complianceSummary = generateComplianceSummary(scanResult.vulnerabilities);

        // OWASP Top 10
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...COLORS.dark);
        doc.text('OWASP Top 10 2021', margin, currentY);
        currentY += 8;

        const owaspData = Object.entries(complianceSummary.owaspCoverage).map(([id, count]) => [
            id,
            count.toString()
        ]);

        if (owaspData.length > 0) {
            autoTable(doc, {
                startY: currentY,
                head: [['OWASP Category', 'Finding Count']],
                body: owaspData,
                theme: 'striped',
                headStyles: { fillColor: COLORS.primary },
                styles: { fontSize: 9 },
                margin: { left: margin, right: margin }
            });
            currentY = doc.lastAutoTable.finalY + 10;
        } else {
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.text('No OWASP mappings applicable.', margin, currentY);
            currentY += 10;
        }

        // NIST 800-53
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...COLORS.dark);
        doc.text('NIST 800-53 Controls', margin, currentY);
        currentY += 8;

        const nistData = Object.entries(complianceSummary.nistControls).slice(0, 10).map(([id, count]) => [
            id,
            count.toString()
        ]);

        if (nistData.length > 0) {
            autoTable(doc, {
                startY: currentY,
                head: [['NIST Control', 'Finding Count']],
                body: nistData,
                theme: 'striped',
                headStyles: { fillColor: COLORS.primary },
                styles: { fontSize: 9 },
                margin: { left: margin, right: margin }
            });
            currentY = doc.lastAutoTable.finalY + 10;
        }

        // DISA STIG
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...COLORS.dark);
        doc.text('DISA STIG Compliance', margin, currentY);
        currentY += 8;

        const stigData = Object.entries(complianceSummary.stigFindings).map(([id, info]) => [
            id,
            info.severity,
            info.count.toString()
        ]);

        if (stigData.length > 0) {
            autoTable(doc, {
                startY: currentY,
                head: [['STIG ID', 'Severity', 'Finding Count']],
                body: stigData,
                theme: 'striped',
                headStyles: { fillColor: COLORS.primary },
                styles: { fontSize: 9 },
                margin: { left: margin, right: margin }
            });
            currentY = doc.lastAutoTable.finalY + 10;
        } else {
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.text('No DISA STIG controls currently violated.', margin, currentY);
            currentY += 10;
        }
    }

    // ========================================================================
    // RECOMMENDATIONS
    // ========================================================================

    doc.addPage();
    currentY = margin;

    doc.setTextColor(...COLORS.primary);
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('6. Recommendations', margin, currentY);
    currentY += 12;

    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');

    const allRecommendations = scanResult.recommendations.length > 0
        ? scanResult.recommendations
        : ['Review all findings and implement remediation steps', 'Conduct regular security assessments'];

    // Prioritized recommendations
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('Prioritized Actions:', margin, currentY);
    currentY += 8;

    const priorityActions = [
        { priority: 'Immediate', items: scanResult.vulnerabilities.filter(v => v.severity === 'critical'), color: COLORS.critical },
        { priority: 'High Priority', items: scanResult.vulnerabilities.filter(v => v.severity === 'high'), color: COLORS.high },
        { priority: 'Medium Priority', items: scanResult.vulnerabilities.filter(v => v.severity === 'medium'), color: COLORS.medium },
    ];

    for (const action of priorityActions) {
        if (action.items.length > 0) {
            doc.setFillColor(...action.color);
            doc.circle(margin + 3, currentY - 1, 2, 'F');

            doc.setTextColor(...action.color);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(`${action.priority} (${action.items.length} items):`, margin + 8, currentY);
            currentY += 5;

            doc.setTextColor(...COLORS.text);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);

            for (const item of action.items.slice(0, 3)) {
                const sanitizedTitle = sanitizeText(item.title);
                const sanitizedRec = sanitizeText(item.recommendation);
                const itemText = doc.splitTextToSize(`- ${sanitizedTitle}: ${sanitizedRec}`, contentWidth - 15);
                doc.text(itemText, margin + 8, currentY);
                currentY += itemText.length * 4 + 2;
            }

            if (action.items.length > 3) {
                doc.setTextColor(...COLORS.info);
                doc.text(`  ... and ${action.items.length - 3} more`, margin + 8, currentY);
                currentY += 5;
            }

            currentY += 5;
        }
    }

    // General recommendations
    currentY += 5;
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('General Recommendations:', margin, currentY);
    currentY += 8;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.text);

    for (const rec of allRecommendations) {
        // Sanitize recommendation text to remove emojis
        const sanitizedRec = sanitizeText(rec);
        if (sanitizedRec) {
            const recLines = doc.splitTextToSize(`- ${sanitizedRec}`, contentWidth - 10);
            doc.text(recLines, margin + 3, currentY);
            currentY += recLines.length * 4 + 3;
        }
    }

    // ========================================================================
    // TECHNICAL APPENDIX
    // ========================================================================

    if (options.includeTechnicalDetails !== false) {
        doc.addPage();
        currentY = margin;

        doc.setTextColor(...COLORS.primary);
        doc.setFontSize(18);
        doc.setFont('helvetica', 'bold');
        doc.text('7. Technical Appendix', margin, currentY);
        currentY += 12;

        // Header analysis
        if (scanResult.headerAnalysis) {
            doc.setFontSize(12);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Security Headers Analysis', margin, currentY);
            currentY += 8;

            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);
            doc.text(`Score: ${scanResult.headerAnalysis.score.toFixed(0)}%`, margin, currentY);
            currentY += 6;

            // Present headers
            const presentHeaders = Object.entries(scanResult.headerAnalysis.present)
                .filter(([key]) => key.startsWith('x-') || key.includes('security') || key.includes('content') || key.includes('strict'))
                .slice(0, 10);

            if (presentHeaders.length > 0) {
                autoTable(doc, {
                    startY: currentY,
                    head: [['Header', 'Value']],
                    body: presentHeaders.map(([k, v]) => [k, v.substring(0, 60) + (v.length > 60 ? '...' : '')]),
                    theme: 'striped',
                    headStyles: { fillColor: COLORS.success },
                    styles: { fontSize: 7 },
                    margin: { left: margin, right: margin }
                });
                currentY = doc.lastAutoTable.finalY + 8;
            }

            // Missing headers
            if (scanResult.headerAnalysis.missing.length > 0) {
                doc.setTextColor(...COLORS.critical);
                doc.setFontSize(10);
                doc.setFont('helvetica', 'bold');
                doc.text('Missing Security Headers:', margin, currentY);
                currentY += 5;

                doc.setFont('helvetica', 'normal');
                doc.setFontSize(8);
                for (const header of scanResult.headerAnalysis.missing) {
                    doc.text(`• ${header}`, margin + 5, currentY);
                    currentY += 4;
                }
            }
        }

        // Web3 detection
        if (scanResult.web3Detection?.hasWeb3) {
            currentY += 10;
            doc.setFontSize(12);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Web3/Blockchain Detection', margin, currentY);
            currentY += 8;

            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);

            if (scanResult.web3Detection.provider) {
                doc.text(`Provider: ${scanResult.web3Detection.provider}`, margin, currentY);
                currentY += 5;
            }

            if (scanResult.web3Detection.contracts.length > 0) {
                doc.text(`Contracts Detected: ${scanResult.web3Detection.contracts.length}`, margin, currentY);
                currentY += 5;

                for (const contract of scanResult.web3Detection.contracts.slice(0, 5)) {
                    doc.setFontSize(7);
                    doc.setFont('courier', 'normal');
                    doc.text(`  ${contract.address} (${contract.chain})`, margin + 5, currentY);
                    currentY += 4;
                }
            }
        }
    }

    // ========================================================================
    // FOOTER ON ALL PAGES
    // ========================================================================

    const totalPages = doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);

        // Page number
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.info);
        doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 5, { align: 'center' });

        // Classification footer (skip cover page)
        if (i > 1 && classification !== 'UNCLASSIFIED') {
            doc.setFillColor(...COLORS.critical);
            doc.rect(0, pageHeight - 8, pageWidth, 8, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.text(classification, pageWidth / 2, pageHeight - 3, { align: 'center' });
        }
    }

    return doc;
}

/**
 * Generate PDF and trigger download
 */
export function downloadPdfReport(
    scanResult: ScanResult,
    options: PdfReportOptions = {},
    filename?: string
): void {
    const doc = generatePdfReport(scanResult, options);
    const defaultFilename = `STRIX_Report_${new URL(scanResult.target).hostname}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
}

/**
 * Generate PDF as blob for preview
 */
export function generatePdfBlob(
    scanResult: ScanResult,
    options: PdfReportOptions = {}
): Blob {
    const doc = generatePdfReport(scanResult, options);
    return doc.output('blob');
}

export default {
    generatePdfReport,
    downloadPdfReport,
    generatePdfBlob
};

// STRIX Blockchain Security Report Generator
// Generates comprehensive PDF reports for smart contract and DeFi audits

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

export interface BlockchainFinding {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    category: string;
    contractAddress?: string;
    functionName?: string;
    lineNumber?: number;
    codeSnippet?: string;
    swcId?: string;
    recommendation: string;
    references?: string[];
    exploitScenario?: string;
    gasImpact?: string;
}

export interface ContractInfo {
    address: string;
    name?: string;
    chain: string;
    chainId: number;
    compiler?: string;
    verified: boolean;
    proxyImplementation?: string;
    totalValue?: string;
    functions: string[];
    events?: string[];
}

export interface BlockchainScanResult {
    contracts: ContractInfo[];
    findings: BlockchainFinding[];
    defiProtocols?: string[];
    tokenStandards?: string[];
    externalCalls?: string[];
    storageLayout?: any;
    gasAnalysis?: {
        totalFunctions: number;
        highGasFunctions: string[];
        optimizationSuggestions: string[];
    };
}

export interface BlockchainReportOptions extends BaseReportOptions {
    projectName?: string;
    auditType?: 'smart-contract' | 'defi-protocol' | 'token' | 'nft' | 'bridge';
    chainName?: string;
    includeGasAnalysis?: boolean;
    includeStorageLayout?: boolean;
    commitHash?: string;
}

// ============================================================================
// BLOCKCHAIN REPORT GENERATOR
// ============================================================================

export function generateBlockchainReport(
    scanResult: BlockchainScanResult,
    options: BlockchainReportOptions = {}
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
    
    const title = options.title || 'Smart Contract Security Audit';
    const projectName = options.projectName || 'Blockchain Project';
    const chainName = options.chainName || 'Ethereum';
    const reportId = options.reportId || generateReportId();
    
    let currentY = margin;
    
    // ========================================================================
    // COVER PAGE
    // ========================================================================
    
    currentY = drawReportHeader(doc, title, `${projectName} - ${chainName}`, {
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
    
    // Audit summary box
    doc.setFillColor(...COLORS.darkAlt);
    doc.roundedRect(margin, currentY, contentWidth, 50, 3, 3, 'F');
    
    doc.setTextColor(...COLORS.white);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Audit Summary', margin + 5, currentY + 8);
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...COLORS.textLight);
    
    const summaryItems = [
        ['Contracts Analyzed:', scanResult.contracts.length.toString()],
        ['Total Findings:', scanResult.findings.length.toString()],
        ['Chain:', chainName],
        ['Audit Date:', formatDate(options.reportDate || new Date())],
        ['Auditor:', options.scannerUser || 'STRIX Scanner'],
    ];
    
    let summaryY = currentY + 16;
    for (const [label, value] of summaryItems) {
        doc.setTextColor(...COLORS.textLight);
        doc.text(label, margin + 5, summaryY);
        doc.setTextColor(...COLORS.white);
        doc.text(value, margin + 45, summaryY);
        summaryY += 7;
    }
    
    // ========================================================================
    // EXECUTIVE SUMMARY
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Executive Summary', currentY, 1);
    
    doc.setTextColor(...COLORS.text);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    
    const execSummary = `This security audit was conducted on ${projectName} deployed on ${chainName}. The audit identified ${scanResult.findings.length} findings across ${scanResult.contracts.length} smart contract(s). The overall security posture is rated as ${riskInfo.level} with a risk score of ${riskScore}/100.`;
    
    const summaryLines = doc.splitTextToSize(execSummary, contentWidth);
    doc.text(summaryLines, margin, currentY);
    currentY += summaryLines.length * 5 + 10;
    
    // Key findings
    if (counts.critical > 0 || counts.high > 0) {
        doc.setFillColor(...COLORS.critical);
        doc.setTextColor(...COLORS.critical);
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.text('Critical Issues Requiring Immediate Attention', margin, currentY);
        currentY += 6;
        
        const criticalFindings = scanResult.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        
        for (const finding of criticalFindings.slice(0, 5)) {
            const severityColor = getSeverityColor(finding.severity);
            doc.setFillColor(...severityColor);
            doc.circle(margin + 2, currentY - 1, 2, 'F');
            
            const findingText = doc.splitTextToSize(`${finding.title} (${finding.severity.toUpperCase()})`, contentWidth - 10);
            doc.text(findingText, margin + 7, currentY);
            currentY += findingText.length * 4 + 3;
        }
    }
    
    // ========================================================================
    // CONTRACTS ANALYZED
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Contracts Analyzed', currentY, 2);
    
    const contractData = scanResult.contracts.map((c, i) => [
        (i + 1).toString(),
        c.name || 'Unknown',
        c.address.substring(0, 10) + '...' + c.address.substring(38),
        c.chain,
        c.verified ? 'Yes' : 'No',
        c.functions.length.toString()
    ]);
    
    autoTable(doc, {
        startY: currentY,
        head: [['#', 'Name', 'Address', 'Chain', 'Verified', 'Functions']],
        body: contractData,
        theme: 'striped',
        headStyles: {
            fillColor: COLORS.primary,
            textColor: COLORS.white,
            fontStyle: 'bold'
        },
        styles: { fontSize: 8, cellPadding: 3 },
        columnStyles: {
            0: { cellWidth: 10 },
            1: { cellWidth: 35 },
            2: { cellWidth: 50 },
            3: { cellWidth: 25 },
            4: { cellWidth: 18 },
            5: { cellWidth: 20 }
        },
        margin: { left: margin, right: margin }
    });
    
    currentY = doc.lastAutoTable.finalY + 10;
    
    // ========================================================================
    // DETAILED FINDINGS
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Detailed Findings', currentY, 3);
    
    const sortedFindings = [...scanResult.findings].sort((a, b) => {
        const order = ['critical', 'high', 'medium', 'low', 'info'];
        return order.indexOf(a.severity) - order.indexOf(b.severity);
    });
    
    for (let i = 0; i < sortedFindings.length; i++) {
        const finding = sortedFindings[i];
        
        // Check for page break
        if (currentY > pageHeight - 60) {
            currentY = addNewPage(doc, options.classification);
        }
        
        // Finding header
        const severityColor = getSeverityColor(finding.severity);
        doc.setFillColor(...severityColor);
        doc.roundedRect(margin, currentY, contentWidth, 8, 1, 1, 'F');
        
        doc.setTextColor(...COLORS.white);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text(`${finding.id}: ${sanitizeText(finding.title)}`, margin + 3, currentY + 5.5);
        
        doc.setFontSize(8);
        doc.text(finding.severity.toUpperCase(), pageWidth - margin - 20, currentY + 5.5);
        
        currentY += 12;
        
        // Finding details
        doc.setDrawColor(...severityColor);
        doc.setLineWidth(0.3);
        const boxStartY = currentY;
        
        // Category and SWC
        doc.setTextColor(...COLORS.textLight);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        let metaText = `Category: ${finding.category}`;
        if (finding.swcId) metaText += ` | SWC: ${finding.swcId}`;
        if (finding.contractAddress) metaText += ` | Contract: ${finding.contractAddress.substring(0, 12)}...`;
        doc.text(metaText, margin + 3, currentY);
        currentY += 5;
        
        // Description
        doc.setTextColor(...COLORS.dark);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text('Description:', margin + 3, currentY);
        currentY += 4;
        
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        const descLines = doc.splitTextToSize(sanitizeText(finding.description), contentWidth - 10);
        doc.text(descLines, margin + 3, currentY);
        currentY += descLines.length * 4 + 4;
        
        // Code snippet (if available)
        if (finding.codeSnippet) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.dark);
            doc.text('Vulnerable Code:', margin + 3, currentY);
            currentY += 4;
            
            doc.setFillColor(...COLORS.lightBg);
            doc.setFont('courier', 'normal');
            doc.setFontSize(7);
            doc.setTextColor(...COLORS.text);
            
            const codeText = sanitizeText(finding.codeSnippet).substring(0, 300);
            const codeLines = doc.splitTextToSize(codeText, contentWidth - 10);
            
            doc.rect(margin + 3, currentY - 2, contentWidth - 6, Math.min(codeLines.length * 3 + 4, 30), 'F');
            doc.text(codeLines.slice(0, 8), margin + 5, currentY + 2);
            currentY += Math.min(codeLines.length * 3, 24) + 6;
            
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
        }
        
        // Exploit scenario
        if (finding.exploitScenario) {
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...COLORS.critical);
            doc.text('Exploit Scenario:', margin + 3, currentY);
            currentY += 4;
            
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(...COLORS.text);
            const exploitLines = doc.splitTextToSize(sanitizeText(finding.exploitScenario), contentWidth - 10);
            doc.text(exploitLines.slice(0, 4), margin + 3, currentY);
            currentY += Math.min(exploitLines.length, 4) * 4 + 4;
        }
        
        // Recommendation
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(...COLORS.success);
        doc.text('Recommendation:', margin + 3, currentY);
        currentY += 4;
        
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(...COLORS.text);
        const recLines = doc.splitTextToSize(sanitizeText(finding.recommendation), contentWidth - 10);
        doc.text(recLines.slice(0, 3), margin + 3, currentY);
        currentY += Math.min(recLines.length, 3) * 4 + 4;
        
        // Draw border
        doc.roundedRect(margin, boxStartY - 4, contentWidth, currentY - boxStartY + 4, 1, 1, 'S');
        currentY += 8;
    }
    
    // ========================================================================
    // GAS ANALYSIS (if enabled)
    // ========================================================================
    
    if (options.includeGasAnalysis && scanResult.gasAnalysis) {
        currentY = addNewPage(doc, options.classification);
        currentY = drawSectionHeader(doc, 'Gas Optimization Analysis', currentY, 4);
        
        doc.setTextColor(...COLORS.text);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        
        doc.text(`Total Functions Analyzed: ${scanResult.gasAnalysis.totalFunctions}`, margin, currentY);
        currentY += 8;
        
        if (scanResult.gasAnalysis.highGasFunctions.length > 0) {
            doc.setFont('helvetica', 'bold');
            doc.text('High Gas Consumption Functions:', margin, currentY);
            currentY += 5;
            
            doc.setFont('helvetica', 'normal');
            for (const func of scanResult.gasAnalysis.highGasFunctions.slice(0, 10)) {
                doc.text(`- ${sanitizeText(func)}`, margin + 5, currentY);
                currentY += 5;
            }
        }
        
        currentY += 5;
        
        if (scanResult.gasAnalysis.optimizationSuggestions.length > 0) {
            doc.setFont('helvetica', 'bold');
            doc.text('Optimization Suggestions:', margin, currentY);
            currentY += 5;
            
            doc.setFont('helvetica', 'normal');
            for (const suggestion of scanResult.gasAnalysis.optimizationSuggestions.slice(0, 10)) {
                const suggLines = doc.splitTextToSize(`- ${sanitizeText(suggestion)}`, contentWidth - 10);
                doc.text(suggLines, margin + 5, currentY);
                currentY += suggLines.length * 4 + 2;
            }
        }
    }
    
    // ========================================================================
    // RECOMMENDATIONS SUMMARY
    // ========================================================================
    
    currentY = addNewPage(doc, options.classification);
    currentY = drawSectionHeader(doc, 'Recommendations Summary', currentY, 5);
    
    const recommendations = [
        { priority: 'Immediate', findings: sortedFindings.filter(f => f.severity === 'critical'), color: COLORS.critical },
        { priority: 'High Priority', findings: sortedFindings.filter(f => f.severity === 'high'), color: COLORS.high },
        { priority: 'Medium Priority', findings: sortedFindings.filter(f => f.severity === 'medium'), color: COLORS.medium },
    ];
    
    for (const rec of recommendations) {
        if (rec.findings.length > 0) {
            doc.setFillColor(...rec.color);
            doc.circle(margin + 3, currentY - 1, 2, 'F');
            
            doc.setTextColor(...rec.color);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(`${rec.priority} (${rec.findings.length} items)`, margin + 8, currentY);
            currentY += 6;
            
            doc.setTextColor(...COLORS.text);
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(9);
            
            for (const finding of rec.findings.slice(0, 5)) {
                const recText = doc.splitTextToSize(`- ${sanitizeText(finding.title)}: ${sanitizeText(finding.recommendation)}`, contentWidth - 15);
                doc.text(recText.slice(0, 2), margin + 8, currentY);
                currentY += Math.min(recText.length, 2) * 4 + 2;
            }
            
            currentY += 5;
        }
    }
    
    // Add footers to all pages
    addAllPageFooters(doc, options.classification);
    
    return doc;
}

/**
 * Download blockchain report as PDF
 */
export function downloadBlockchainReport(
    scanResult: BlockchainScanResult,
    options: BlockchainReportOptions = {},
    filename?: string
): void {
    const doc = generateBlockchainReport(scanResult, options);
    const defaultFilename = `STRIX_Blockchain_Audit_${options.projectName || 'Report'}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename || defaultFilename);
}

export default {
    generateBlockchainReport,
    downloadBlockchainReport
};

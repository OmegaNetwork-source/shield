// STRIX Unified Scanner Module
// DoD-Grade Security Scanner - Main Export File

// Core types
export * from './types';

// Web3/Blockchain detection
export * from './web3-detector';

// Main scanner
export * from './unified-scanner';

// Site crawler
export { SiteCrawler, quickCrawl, deepCrawl } from './crawler';

// Evidence collection
export * from './evidence';

// Test modules
export { tests } from './tests';

// Deep scanning (extended payloads)
export {
    XSS_PAYLOADS_EXTENDED,
    SQLI_PAYLOADS_EXTENDED,
    DIRECTORY_WORDLIST,
    COMMON_PARAMETERS,
    SQL_ERROR_PATTERNS,
    detectSqlError,
    detectXssReflection
} from './deep-scan';

// Advanced vulnerability tests
export { detectSSRF, detectCommandInjection, detectPathTraversal, detectXXE, detectSSTI, detectOpenRedirect, detectCORSMisconfig } from './advanced-tests';

// Compliance mapping
export * from './compliance';

// Report generation
export { generateReport, generateHtmlReport, generateJsonReport, generateCsvReport, generateStigCkl, generateExecutiveSummary, generatePdfReport, downloadPdfReport } from './reports';

// Imports for default export
import { UnifiedScanner, quickScan, fullScan } from './unified-scanner';
import { detectWeb3, analyzeScript, extractSecrets, extractContracts } from './web3-detector';
import { SiteCrawler, quickCrawl, deepCrawl } from './crawler';
import { EvidenceCollector, createEvidenceCollector } from './evidence';
import { tests } from './tests';
import compliance from './compliance';
import reports from './reports';
import { OWASP_TOP_10, SWC_REGISTRY } from './types';
import deepScan from './deep-scan';
import advancedTests from './advanced-tests';

export const scanner = {
    // Main scanner class
    Scanner: UnifiedScanner,

    // Crawler class
    Crawler: SiteCrawler,

    // Quick scan functions
    quick: quickScan,
    full: fullScan,

    // Crawl functions
    crawl: {
        quick: quickCrawl,
        deep: deepCrawl,
        Crawler: SiteCrawler
    },

    // Security tests
    tests: {
        injection: tests.injection,
        sqli: tests.injection.testSqlInjection,
        xss: tests.injection.testXss,
        directory: tests.directoryEnum,
        owasp: tests.owasp,
        ssl: tests.ssl,
        fingerprint: tests.fingerprint
    },

    // Compliance mapping
    compliance: {
        map: compliance.getComplianceMapping,
        enrich: compliance.enrichWithCompliance,
        summary: compliance.generateComplianceSummary,
        check: compliance.checkCompliance,
        nist: compliance.NIST_CONTROLS,
        owasp: compliance.OWASP_TOP_10_2021,
        stig: compliance.STIG_WEB_APP_CONTROLS
    },

    // Evidence collection
    evidence: {
        Collector: EvidenceCollector,
        create: createEvidenceCollector
    },

    // Report generation
    reports: {
        generate: reports.generateReport,
        html: reports.generateHtmlReport,
        json: reports.generateJsonReport,
        csv: reports.generateCsvReport,
        stig: reports.generateStigCkl,
        executive: reports.generateExecutiveSummary,
        // Web Security Reports
        pdf: reports.generatePdfReport,
        downloadPdf: reports.downloadPdfReport,
        pdfBlob: reports.generatePdfBlob,

        // Blockchain Security Reports
        blockchain: reports.generateBlockchainReport,
        downloadBlockchain: reports.downloadBlockchainReport,

        // Code Security Reports
        code: reports.generateCodeReport,
        downloadCode: reports.downloadCodeReport,

        // Directory Security Reports
        directory: reports.generateDirectoryReport,
        downloadDirectory: reports.downloadDirectoryReport,

        // Report utilities
        base: reports.base
    },

    // Web3 detection
    web3: {
        detect: detectWeb3,
        analyzeScript,
        extractSecrets,
        extractContracts
    },

    // Deep scanning payloads and utilities
    payloads: {
        xss: deepScan.XSS_PAYLOADS_EXTENDED,
        sqli: deepScan.SQLI_PAYLOADS_EXTENDED,
        directories: deepScan.DIRECTORY_WORDLIST,
        parameters: deepScan.COMMON_PARAMETERS,
        sqlErrors: deepScan.SQL_ERROR_PATTERNS
    },

    // Deep scan utilities
    deepScan: {
        extractLinks: deepScan.extractLinks,
        extractParameters: deepScan.extractParameters,
        extractForms: deepScan.extractForms,
        detectSqlError: deepScan.detectSqlError,
        detectXssReflection: deepScan.detectXssReflection
    },

    // Advanced vulnerability tests
    advanced: {
        payloads: {
            ssrf: advancedTests.SSRF_PAYLOADS,
            commandInjection: advancedTests.COMMAND_INJECTION_PAYLOADS,
            pathTraversal: advancedTests.PATH_TRAVERSAL_PAYLOADS,
            xxe: advancedTests.XXE_PAYLOADS,
            ssti: advancedTests.SSTI_PAYLOADS,
            openRedirect: advancedTests.OPEN_REDIRECT_PAYLOADS,
            crlf: advancedTests.CRLF_PAYLOADS,
            hostHeader: advancedTests.HOST_HEADER_PAYLOADS
        },
        detect: {
            ssrf: advancedTests.detectSSRF,
            commandInjection: advancedTests.detectCommandInjection,
            pathTraversal: advancedTests.detectPathTraversal,
            xxe: advancedTests.detectXXE,
            ssti: advancedTests.detectSSTI,
            openRedirect: advancedTests.detectOpenRedirect,
            cors: advancedTests.detectCORSMisconfig
        },
        createVulnerability: advancedTests.createVulnerabilityFromTest
    },

    // Reference data
    reference: {
        owasp: OWASP_TOP_10,
        swc: SWC_REGISTRY
    }
};

export default scanner;

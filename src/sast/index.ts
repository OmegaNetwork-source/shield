// STRIX SAST Module
// Static Application Security Testing & GitHub Secret Scanner

// Core types
export * from './types';

// Scanner
export { SASTScanner, scanDirectory, scanContent } from './scanner';

// GitHub Scanner
export { 
    GitHubScanner, 
    searchGitHubSecrets, 
    searchByCategory,
    scanRepository,
    SECRET_SEARCH_QUERIES,
    SECRET_DORKS,
} from './github-scanner';

// Re-export types
export type { GitHubRepoScanOptions } from './types';

// Rules
export { 
    ALL_SECRET_PATTERNS,
    API_KEY_PATTERNS,
    PRIVATE_KEY_PATTERNS,
    DATABASE_PATTERNS,
    GENERIC_SECRET_PATTERNS,
    BLOCKCHAIN_PATTERNS,
} from './rules/secrets';

export {
    ALL_VULNERABILITY_RULES,
    INJECTION_RULES,
    XSS_RULES,
    PATH_TRAVERSAL_RULES,
    CRYPTO_RULES,
    AUTH_RULES,
    DESERIALIZATION_RULES,
    DATA_EXPOSURE_RULES,
    MISCONFIG_RULES,
} from './rules/vulnerabilities';

// Reports
export {
    generateHtmlReport,
    generateGitHubHtmlReport,
    generateJsonReport,
    generateCsvReport,
    generateGitHubCsvReport,
    generateSarifReport,
} from './reports';

// PDF Reports
export {
    generateSASTReport,
    downloadSASTReport,
} from './reports/sast-pdf-report';

// Wallet Checker
export {
    // Chain configs
    PUBLIC_RPCS,
    SOLANA_RPCS,
    BITCOIN_APIS,
    ERC20_TOKENS,
    
    // Balance checking - EVM
    checkBalance,
    checkTokenBalance,
    checkAllTokensOnChain,
    checkAllBalances,
    
    // Balance checking - Solana
    checkSolanaBalance,
    checkSolanaTokens,
    checkSolanaWallet,
    
    // Balance checking - Bitcoin
    checkBitcoinBalance,
    checkBitcoinWallet,
    
    // Multi-chain
    checkAllChainsComprehensive,
    
    // Extraction
    extractPrivateKeys,
    extractAddresses,
    extractSolanaAddresses,
    extractBitcoinAddresses,
    extractAllAddresses,
    extractMnemonics,
    
    // Mnemonic
    isMnemonicPhrase,
    checkMnemonicBalances,
    
    // Filtering & quick checks
    quickKeyCheck,
    checkTextForFundedAddresses,
    filterFindingsWithBalance,
    
    // Types
    type WalletBalance,
    type TokenBalance,
    type WalletCheckResult,
    type MultiChainCheckResult,
    type MnemonicCheckResult,
} from './wallet-checker';

// API Credential Tester
export {
    testAPICredentials,
    detectServiceFromKey,
    extractCredentialsFromSnippet,
    type APIService,
    type APITestResult,
    type APICredentials,
} from './api-tester';

// Convenience imports
import { SASTScanner, scanDirectory, scanContent } from './scanner';
import { GitHubScanner, searchGitHubSecrets, searchByCategory, SECRET_DORKS } from './github-scanner';
import reports from './reports';
import rules from './rules';
import { generateSASTReport, downloadSASTReport } from './reports/sast-pdf-report';

// Default export with organized API
export const sast = {
    // Local code scanning
    Scanner: SASTScanner,
    scanDirectory,
    scanContent,

    // GitHub scanning
    GitHubScanner,
    github: {
        Scanner: GitHubScanner,
        search: searchGitHubSecrets,
        searchByCategory,
        dorks: SECRET_DORKS,
    },

    // Rules
    rules: {
        secrets: rules.secrets,
        vulnerabilities: rules.vulnerabilities,
    },

    // Reports
    reports: {
        html: reports.generateHtmlReport,
        githubHtml: reports.generateGitHubHtmlReport,
        json: reports.generateJsonReport,
        csv: reports.generateCsvReport,
        githubCsv: reports.generateGitHubCsvReport,
        sarif: reports.generateSarifReport,
        // PDF Reports
        pdf: generateSASTReport,
        downloadPdf: downloadSASTReport,
    },
};

export default sast;

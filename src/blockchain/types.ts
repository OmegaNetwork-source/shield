// Blockchain Scanner Types
// Type definitions for live blockchain scanning

import type { ContractAnalysis, VulnerabilityResult } from './index';

// Chain configuration
export interface ChainConfig {
    chainId: number;
    name: string;
    symbol: string;
    rpcUrl: string;
    explorerUrl: string;
    explorerApiUrl: string;
    explorerApiKey?: string;
}

// Pre-configured chains
export const CHAINS: Record<string, ChainConfig> = {
    ethereum: {
        chainId: 1,
        name: 'Ethereum Mainnet',
        symbol: 'ETH',
        rpcUrl: 'https://eth.llamarpc.com',
        explorerUrl: 'https://etherscan.io',
        explorerApiUrl: 'https://api.etherscan.io/api'
    },
    goerli: {
        chainId: 5,
        name: 'Goerli Testnet',
        symbol: 'ETH',
        rpcUrl: 'https://rpc.ankr.com/eth_goerli',
        explorerUrl: 'https://goerli.etherscan.io',
        explorerApiUrl: 'https://api-goerli.etherscan.io/api'
    },
    sepolia: {
        chainId: 11155111,
        name: 'Sepolia Testnet',
        symbol: 'ETH',
        rpcUrl: 'https://rpc.sepolia.org',
        explorerUrl: 'https://sepolia.etherscan.io',
        explorerApiUrl: 'https://api-sepolia.etherscan.io/api'
    },
    polygon: {
        chainId: 137,
        name: 'Polygon',
        symbol: 'MATIC',
        rpcUrl: 'https://polygon-rpc.com',
        explorerUrl: 'https://polygonscan.com',
        explorerApiUrl: 'https://api.polygonscan.com/api'
    },
    arbitrum: {
        chainId: 42161,
        name: 'Arbitrum One',
        symbol: 'ETH',
        rpcUrl: 'https://arb1.arbitrum.io/rpc',
        explorerUrl: 'https://arbiscan.io',
        explorerApiUrl: 'https://api.arbiscan.io/api'
    },
    optimism: {
        chainId: 10,
        name: 'Optimism',
        symbol: 'ETH',
        rpcUrl: 'https://mainnet.optimism.io',
        explorerUrl: 'https://optimistic.etherscan.io',
        explorerApiUrl: 'https://api-optimistic.etherscan.io/api'
    },
    bsc: {
        chainId: 56,
        name: 'BNB Chain',
        symbol: 'BNB',
        rpcUrl: 'https://bsc-dataseed.binance.org',
        explorerUrl: 'https://bscscan.com',
        explorerApiUrl: 'https://api.bscscan.com/api'
    },
    base: {
        chainId: 8453,
        name: 'Base',
        symbol: 'ETH',
        rpcUrl: 'https://mainnet.base.org',
        explorerUrl: 'https://basescan.org',
        explorerApiUrl: 'https://api.basescan.org/api'
    },
    avalanche: {
        chainId: 43114,
        name: 'Avalanche C-Chain',
        symbol: 'AVAX',
        rpcUrl: 'https://api.avax.network/ext/bc/C/rpc',
        explorerUrl: 'https://snowtrace.io',
        explorerApiUrl: 'https://api.snowtrace.io/api'
    }
};

// Scanner configuration
export interface ScannerConfig {
    chain: ChainConfig;
    apiKeys?: {
        etherscan?: string;
        polygonscan?: string;
        arbiscan?: string;
        bscscan?: string;
        basescan?: string;
        snowtrace?: string;      // Avalanche
        ftmscan?: string;        // Fantom
        optimism?: string;       // Optimism Etherscan
        scrollscan?: string;     // Scroll
        lineascan?: string;      // Linea
    };
    timeout?: number;
    retries?: number;
    rateLimit?: number; // requests per second
}

// Contract metadata from explorer
export interface ContractMetadata {
    address: string;
    name?: string;
    symbol?: string;
    compiler?: string;
    optimizationUsed?: boolean;
    runs?: number;
    constructorArguments?: string;
    evmVersion?: string;
    library?: string;
    licenseType?: string;
    proxy?: string;
    implementation?: string;
    swarmSource?: string;
}

// Source code result
export interface SourceCodeResult {
    address: string;
    verified: boolean;
    sourceCode?: string;
    abi?: any[];
    metadata?: ContractMetadata;
    error?: string;
    decompiled?: boolean;
}

// Bytecode analysis
export interface BytecodeInfo {
    address: string;
    bytecode: string;
    deployedBytecode: string;
    size: number;
    isContract: boolean;
    hasSelfdestruct: boolean;
    hasDelegatecall: boolean;
    functionSelectors: string[];
}

// Transaction info
export interface TransactionInfo {
    hash: string;
    from: string;
    to: string | null;
    value: string;
    gasUsed: string;
    gasPrice: string;
    input: string;
    blockNumber: number;
    timestamp: number;
    contractAddress?: string;
    status: boolean;
}

// Contract creation info
export interface ContractCreation {
    address: string;
    creator: string;
    txHash: string;
    blockNumber: number;
    timestamp: number;
}

// Scan result for a single contract
export interface ContractScanResult {
    address: string;
    chain: string;
    chainId: number;
    scanTime: Date;
    source: SourceCodeResult;
    bytecode?: BytecodeInfo;
    analysis?: ContractAnalysis;
    knownExploit?: KnownExploit;
    creation?: ContractCreation;
    riskScore: number;
    riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'unknown';
}

// Known exploit database entry
export interface KnownExploit {
    address: string;
    chain: string;
    name: string;
    type: string;
    date: string;
    amountLost: string;
    description: string;
    attackTx?: string;
    postMortem?: string;
    attacker?: string;
    cve?: string;
}

// Mempool monitoring
export interface PendingTransaction {
    hash: string;
    from: string;
    to: string | null;
    value: string;
    gasPrice: string;
    maxFeePerGas?: string;
    maxPriorityFeePerGas?: string;
    input: string;
    nonce: number;
    isContractCreation: boolean;
}

export interface MempoolMonitorConfig {
    chain: ChainConfig;
    filters?: {
        minValue?: string;
        contractCreationOnly?: boolean;
        addresses?: string[];
        selectors?: string[];
    };
    onTransaction?: (tx: PendingTransaction) => void;
    onContractDeployed?: (result: ContractScanResult) => void;
}

// Batch scan options
export interface BatchScanOptions {
    addresses: string[];
    chain: ChainConfig;
    parallel?: number;
    onProgress?: (completed: number, total: number, current: string) => void;
    onResult?: (result: ContractScanResult) => void;
    skipUnverified?: boolean;
    includeByteCode?: boolean;
}

// Batch scan results
export interface BatchScanResults {
    chain: string;
    total: number;
    scanned: number;
    verified: number;
    vulnerable: number;
    results: ContractScanResult[];
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        safe: number;
        unknown: number;
    };
    scanTime: number;
}

// Report generation
export interface ScanReport {
    title: string;
    generatedAt: Date;
    chain: string;
    target: string | string[];
    summary: {
        totalContracts: number;
        verifiedContracts: number;
        vulnerableContracts: number;
        criticalIssues: number;
        highIssues: number;
        mediumIssues: number;
        lowIssues: number;
        infoIssues: number;
        knownExploits: number;
    };
    results: ContractScanResult[];
    recommendations: string[];
}

// Explorer API response types
export interface EtherscanResponse<T> {
    status: '0' | '1';
    message: string;
    result: T;
}

export interface EtherscanSourceCode {
    SourceCode: string;
    ABI: string;
    ContractName: string;
    CompilerVersion: string;
    OptimizationUsed: string;
    Runs: string;
    ConstructorArguments: string;
    EVMVersion: string;
    Library: string;
    LicenseType: string;
    Proxy: string;
    Implementation: string;
    SwarmSource: string;
}

export interface EtherscanTransaction {
    blockNumber: string;
    timeStamp: string;
    hash: string;
    nonce: string;
    blockHash: string;
    transactionIndex: string;
    from: string;
    to: string;
    value: string;
    gas: string;
    gasPrice: string;
    isError: string;
    txreceipt_status: string;
    input: string;
    contractAddress: string;
    cumulativeGasUsed: string;
    gasUsed: string;
    confirmations: string;
}

// RPC request/response
export interface JsonRpcRequest {
    jsonrpc: '2.0';
    method: string;
    params: any[];
    id: number;
}

export interface JsonRpcResponse<T> {
    jsonrpc: '2.0';
    id: number;
    result?: T;
    error?: {
        code: number;
        message: string;
        data?: any;
    };
}

// Decompiler output
export interface DecompiledContract {
    address: string;
    functions: DecompiledFunction[];
    storage: StorageSlot[];
    events: string[];
    pseudocode: string;
    confidence: number;
}

export interface DecompiledFunction {
    selector: string;
    name?: string;
    signature?: string;
    visibility: 'public' | 'external' | 'internal' | 'private';
    stateMutability: 'pure' | 'view' | 'nonpayable' | 'payable';
    inputs: { type: string; name?: string }[];
    outputs: { type: string; name?: string }[];
    pseudocode: string;
}

export interface StorageSlot {
    slot: number;
    offset: number;
    type: string;
    name?: string;
    size: number;
}

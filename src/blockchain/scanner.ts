// Blockchain Contract Scanner
// Scans live blockchain contracts for vulnerabilities

import type {
    ChainConfig,
    ScannerConfig,
    ContractScanResult,
    BatchScanOptions,
    BatchScanResults,
    MempoolMonitorConfig,
    ScanReport,
    SourceCodeResult,
    BytecodeInfo,
    ContractCreation
} from './types';
import { CHAINS } from './types';
import { ExplorerAPI, createExplorerAPI } from './explorer-api';
import { analyzeContract, type ContractAnalysis } from './index';
import { findExploitByAddress, isKnownAttacker, KNOWN_EXPLOITS } from './known-exploits';
import { decompile, analyzeBytecode, extractSelectors } from './decompiler';

// Main scanner class
export class BlockchainScanner {
    private api: ExplorerAPI;
    private config: ScannerConfig;

    constructor(config: ScannerConfig | string) {
        if (typeof config === 'string') {
            const chain = CHAINS[config.toLowerCase()];
            if (!chain) {
                throw new Error(`Unknown chain: ${config}`);
            }
            this.config = { chain };
        } else {
            this.config = config;
        }
        this.api = new ExplorerAPI(this.config);
    }

    // Calculate risk score from analysis
    private calculateRiskScore(
        analysis: ContractAnalysis | undefined,
        bytecodeAnalysis: ReturnType<typeof analyzeBytecode> | undefined,
        hasKnownExploit: boolean
    ): { score: number; level: ContractScanResult['riskLevel'] } {
        let score = 0;

        // Known exploit = maximum risk
        if (hasKnownExploit) {
            return { score: 100, level: 'critical' };
        }

        // Source code analysis
        if (analysis) {
            score += (analysis.stats?.critical || 0) * 25;
            score += (analysis.stats?.high || 0) * 15;
            score += (analysis.stats?.medium || 0) * 8;
            score += (analysis.stats?.low || 0) * 3;
            score += (analysis.stats?.info || 0) * 1;
        }

        // Bytecode analysis
        if (bytecodeAnalysis) {
            if (bytecodeAnalysis.hasSelfdestruct) score += 30;
            if (bytecodeAnalysis.hasDelegatecall) score += 20;
            if (bytecodeAnalysis.hasCallcode) score += 25;
            if (bytecodeAnalysis.hasCreate2) score += 10;
        }

        // Cap at 100
        score = Math.min(score, 100);

        // Determine level
        let level: ContractScanResult['riskLevel'];
        if (score >= 80) level = 'critical';
        else if (score >= 60) level = 'high';
        else if (score >= 40) level = 'medium';
        else if (score >= 20) level = 'low';
        else if (score > 0) level = 'safe';
        else level = 'unknown';

        return { score, level };
    }

    // Scan a single contract by address
    async scanContract(address: string): Promise<ContractScanResult> {
        const startTime = Date.now();

        // Check for known exploit
        const knownExploit = findExploitByAddress(address);

        // Get source code (verified)
        const source = await this.api.getSourceCode(address);

        // Get bytecode
        let bytecode: BytecodeInfo | undefined;
        let bytecodeAnalysis: ReturnType<typeof analyzeBytecode> | undefined;
        
        try {
            bytecode = await this.api.getBytecode(address);
            if (bytecode.isContract) {
                bytecodeAnalysis = analyzeBytecode(bytecode.bytecode);
            }
        } catch (e) {
            // Bytecode fetch failed, continue without it
        }

        // Analyze source code if available
        let analysis: ContractAnalysis | undefined;
        if (source.verified && source.sourceCode) {
            analysis = analyzeContract(source.sourceCode);
        } else if (bytecode?.isContract) {
            // Try decompiled analysis
            const decompiled = decompile(bytecode.bytecode, address);
            if (decompiled.pseudocode) {
                analysis = analyzeContract(decompiled.pseudocode);
            }
        }

        // Get creation info
        let creation: ContractCreation | undefined;
        try {
            const creationInfo = await this.api.getContractCreation(address);
            if (creationInfo) {
                creation = creationInfo;
            }
        } catch {
            // Creation info not available
        }

        // Calculate risk
        const { score, level } = this.calculateRiskScore(analysis, bytecodeAnalysis, !!knownExploit);

        return {
            address,
            chain: this.config.chain.name,
            chainId: this.config.chain.chainId,
            scanTime: new Date(),
            source,
            bytecode,
            analysis,
            knownExploit: knownExploit || undefined,
            creation,
            riskScore: score,
            riskLevel: level
        };
    }

    // Quick scan - bytecode only
    async quickScan(address: string): Promise<{
        address: string;
        isContract: boolean;
        selectors: string[];
        bytecodeAnalysis: ReturnType<typeof analyzeBytecode> | null;
        knownExploit: boolean;
        riskLevel: string;
    }> {
        const bytecode = await this.api.getBytecode(address);
        const knownExploit = findExploitByAddress(address);

        if (!bytecode.isContract) {
            return {
                address,
                isContract: false,
                selectors: [],
                bytecodeAnalysis: null,
                knownExploit: !!knownExploit,
                riskLevel: 'unknown'
            };
        }

        const bytecodeAnalysis = analyzeBytecode(bytecode.bytecode);
        const selectors = extractSelectors(bytecode.bytecode);

        let riskLevel = bytecodeAnalysis.dangerLevel;
        if (knownExploit) riskLevel = 'critical';

        return {
            address,
            isContract: true,
            selectors,
            bytecodeAnalysis,
            knownExploit: !!knownExploit,
            riskLevel
        };
    }

    // Batch scan multiple addresses
    async batchScan(options: BatchScanOptions): Promise<BatchScanResults> {
        const startTime = Date.now();
        const results: ContractScanResult[] = [];
        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            safe: 0,
            unknown: 0
        };

        const parallel = options.parallel || 3;
        let verified = 0;
        let vulnerable = 0;

        // Process in batches
        for (let i = 0; i < options.addresses.length; i += parallel) {
            const batch = options.addresses.slice(i, i + parallel);
            
            const batchResults = await Promise.all(
                batch.map(async (address) => {
                    try {
                        if (options.onProgress) {
                            options.onProgress(i + 1, options.addresses.length, address);
                        }

                        const result = await this.scanContract(address);
                        
                        if (options.onResult) {
                            options.onResult(result);
                        }

                        return result;
                    } catch (error) {
                        console.error(`Failed to scan ${address}:`, error);
                        return null;
                    }
                })
            );

            for (const result of batchResults) {
                if (result) {
                    results.push(result);
                    summary[result.riskLevel]++;
                    
                    if (result.source.verified) verified++;
                    if (result.riskLevel === 'critical' || result.riskLevel === 'high') {
                        vulnerable++;
                    }
                }
            }

            // Small delay between batches to avoid rate limiting
            if (i + parallel < options.addresses.length) {
                await new Promise(r => setTimeout(r, 500));
            }
        }

        return {
            chain: this.config.chain.name,
            total: options.addresses.length,
            scanned: results.length,
            verified,
            vulnerable,
            results,
            summary,
            scanTime: Date.now() - startTime
        };
    }

    // Scan recently deployed contracts
    async scanRecentDeployments(blockCount = 100): Promise<ContractScanResult[]> {
        const contracts = await this.api.getRecentContracts(blockCount);
        const results: ContractScanResult[] = [];

        for (const contract of contracts) {
            try {
                const result = await this.scanContract(contract.address);
                result.creation = contract;
                results.push(result);
            } catch (error) {
                console.error(`Failed to scan ${contract.address}:`, error);
            }
        }

        return results;
    }

    // Monitor for new contract deployments
    async monitorDeployments(
        callback: (result: ContractScanResult) => void,
        options?: { interval?: number; autoScan?: boolean }
    ): Promise<() => void> {
        const interval = options?.interval || 15000; // 15 seconds default
        const autoScan = options?.autoScan !== false;

        let lastBlock = await this.api.getBlockNumber();
        let running = true;

        const poll = async () => {
            while (running) {
                try {
                    const currentBlock = await this.api.getBlockNumber();
                    
                    for (let i = lastBlock + 1; i <= currentBlock; i++) {
                        const block = await this.api.getBlock(i, true);
                        
                        for (const tx of block.transactions || []) {
                            // Contract creation = tx.to is null
                            if (tx.to === null) {
                                const receipt = await this.api.getTransactionReceipt(tx.hash);
                                if (receipt.contractAddress) {
                                    if (autoScan) {
                                        // Wait a bit for contract to be indexed
                                        await new Promise(r => setTimeout(r, 2000));
                                        
                                        try {
                                            const result = await this.scanContract(receipt.contractAddress);
                                            result.creation = {
                                                address: receipt.contractAddress,
                                                creator: tx.from,
                                                txHash: tx.hash,
                                                blockNumber: i,
                                                timestamp: parseInt(block.timestamp, 16)
                                            };
                                            callback(result);
                                        } catch (e) {
                                            console.error(`Failed to scan new contract ${receipt.contractAddress}:`, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    lastBlock = currentBlock;
                } catch (error) {
                    console.error('Monitoring error:', error);
                }
                
                await new Promise(r => setTimeout(r, interval));
            }
        };

        poll();

        return () => {
            running = false;
        };
    }

    // Check if address is a known attacker
    async checkAddress(address: string): Promise<{
        address: string;
        isContract: boolean;
        isKnownAttacker: boolean;
        attackerInfo?: { name: string; exploits: string[] };
        balance: string;
        transactionCount?: number;
    }> {
        const isContract = await this.api.isContract(address);
        const balance = await this.api.getBalance(address);
        const attackerCheck = isKnownAttacker(address);

        return {
            address,
            isContract,
            isKnownAttacker: attackerCheck.isAttacker,
            attackerInfo: attackerCheck.info,
            balance
        };
    }

    // Generate scan report
    generateReport(results: ContractScanResult | ContractScanResult[]): ScanReport {
        const resultArray = Array.isArray(results) ? results : [results];
        
        const summary = {
            totalContracts: resultArray.length,
            verifiedContracts: resultArray.filter(r => r.source.verified).length,
            vulnerableContracts: resultArray.filter(r => r.riskLevel === 'critical' || r.riskLevel === 'high').length,
            criticalIssues: 0,
            highIssues: 0,
            mediumIssues: 0,
            lowIssues: 0,
            infoIssues: 0,
            knownExploits: resultArray.filter(r => r.knownExploit).length
        };

        // Aggregate issues
        for (const result of resultArray) {
            if (result.analysis?.stats) {
                summary.criticalIssues += result.analysis.stats.critical;
                summary.highIssues += result.analysis.stats.high;
                summary.mediumIssues += result.analysis.stats.medium;
                summary.lowIssues += result.analysis.stats.low;
                summary.infoIssues += result.analysis.stats.info;
            }
        }

        // Generate recommendations
        const recommendations: string[] = [];
        
        if (summary.knownExploits > 0) {
            recommendations.push('⚠️ CRITICAL: One or more contracts have been involved in known exploits. Avoid interaction.');
        }
        if (summary.criticalIssues > 0) {
            recommendations.push('🚨 Critical vulnerabilities detected. Do not interact with these contracts.');
        }
        if (summary.highIssues > 0) {
            recommendations.push('⚡ High severity issues found. Proceed with extreme caution.');
        }
        if (summary.verifiedContracts < summary.totalContracts) {
            recommendations.push('📋 Some contracts are not verified. Unable to perform full source analysis.');
        }
        
        // Specific recommendations based on issues found
        const allVulns = resultArray.flatMap(r => r.analysis?.vulnerabilities || []);
        const vulnTypes = new Set(allVulns.map(v => v.title));
        
        if (vulnTypes.has('Reentrancy - External Call Before State Update') || vulnTypes.has('Missing Reentrancy Protection')) {
            recommendations.push('🔄 Reentrancy vulnerabilities detected. Check if contracts use ReentrancyGuard.');
        }
        if (vulnTypes.has('tx.origin Authentication')) {
            recommendations.push('🔑 tx.origin authentication found. This is vulnerable to phishing attacks.');
        }
        if (vulnTypes.has('DEX Spot Price Oracle')) {
            recommendations.push('📊 Oracle manipulation risk. Verify if TWAP or Chainlink oracles are used.');
        }
        if (vulnTypes.has('Self-destruct Function')) {
            recommendations.push('💀 Selfdestruct present. Contract can be permanently destroyed.');
        }

        return {
            title: `Blockchain Security Scan Report`,
            generatedAt: new Date(),
            chain: resultArray[0]?.chain || 'Unknown',
            target: resultArray.length === 1 ? resultArray[0].address : resultArray.map(r => r.address),
            summary,
            results: resultArray,
            recommendations
        };
    }

    // Get chain info
    getChainInfo(): ChainConfig {
        return this.config.chain;
    }

    // Switch chain
    switchChain(chainOrConfig: string | ChainConfig): void {
        if (typeof chainOrConfig === 'string') {
            const chain = CHAINS[chainOrConfig.toLowerCase()];
            if (!chain) {
                throw new Error(`Unknown chain: ${chainOrConfig}`);
            }
            this.config.chain = chain;
        } else {
            this.config.chain = chainOrConfig;
        }
        this.api = new ExplorerAPI(this.config);
    }

    // Set API keys
    setApiKeys(keys: ScannerConfig['apiKeys']): void {
        this.config.apiKeys = { ...this.config.apiKeys, ...keys };
        this.api = new ExplorerAPI(this.config);
    }
}

// Factory functions
export function createScanner(chainOrConfig: string | ScannerConfig): BlockchainScanner {
    return new BlockchainScanner(chainOrConfig);
}

// Quick scan function (no class instantiation needed)
export async function scanAddress(address: string, chain = 'ethereum'): Promise<ContractScanResult> {
    const scanner = new BlockchainScanner(chain);
    return scanner.scanContract(address);
}

// Quick batch scan
export async function scanAddresses(addresses: string[], chain = 'ethereum'): Promise<BatchScanResults> {
    const scanner = new BlockchainScanner(chain);
    const chainConfig = CHAINS[chain.toLowerCase()];
    return scanner.batchScan({
        addresses,
        chain: chainConfig
    });
}

// Check against known exploits database
export function checkKnownExploits(address: string): {
    isKnown: boolean;
    exploit?: typeof KNOWN_EXPLOITS[0];
    isAttacker?: boolean;
    attackerInfo?: { name: string; exploits: string[] };
} {
    const exploit = findExploitByAddress(address);
    const attackerCheck = isKnownAttacker(address);

    return {
        isKnown: !!exploit || attackerCheck.isAttacker,
        exploit: exploit || undefined,
        isAttacker: attackerCheck.isAttacker,
        attackerInfo: attackerCheck.info
    };
}

export default {
    BlockchainScanner,
    createScanner,
    scanAddress,
    scanAddresses,
    checkKnownExploits,
    CHAINS
};

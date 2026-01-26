// Explorer API Integration
// Etherscan, Polygonscan, and other block explorer APIs

import type {
    ChainConfig,
    ScannerConfig,
    EtherscanResponse,
    EtherscanSourceCode,
    EtherscanTransaction,
    SourceCodeResult,
    ContractMetadata,
    ContractCreation,
    JsonRpcRequest,
    JsonRpcResponse,
    BytecodeInfo
} from './types';
import { CHAINS } from './types';

// Rate limiter for API calls
class RateLimiter {
    private lastCall = 0;
    private queue: Array<() => void> = [];
    private processing = false;

    constructor(private minInterval: number = 200) {} // 5 requests/sec default

    async throttle(): Promise<void> {
        return new Promise((resolve) => {
            this.queue.push(resolve);
            this.processQueue();
        });
    }

    private async processQueue() {
        if (this.processing) return;
        this.processing = true;

        while (this.queue.length > 0) {
            const now = Date.now();
            const elapsed = now - this.lastCall;
            
            if (elapsed < this.minInterval) {
                await new Promise(r => setTimeout(r, this.minInterval - elapsed));
            }
            
            this.lastCall = Date.now();
            const resolve = this.queue.shift();
            if (resolve) resolve();
        }

        this.processing = false;
    }
}

// Explorer API client
export class ExplorerAPI {
    private config: ScannerConfig;
    private rateLimiter: RateLimiter;
    private rpcId = 1;

    constructor(config: ScannerConfig) {
        this.config = config;
        this.rateLimiter = new RateLimiter(config.rateLimit ? 1000 / config.rateLimit : 200);
    }

    // Get API key for current chain
    private getApiKey(): string | undefined {
        const chainName = this.config.chain.name.toLowerCase();
        if (chainName.includes('ethereum') || chainName.includes('goerli') || chainName.includes('sepolia')) {
            return this.config.apiKeys?.etherscan;
        }
        if (chainName.includes('polygon')) {
            return this.config.apiKeys?.polygonscan;
        }
        if (chainName.includes('arbitrum')) {
            return this.config.apiKeys?.arbiscan;
        }
        if (chainName.includes('bnb') || chainName.includes('bsc')) {
            return this.config.apiKeys?.bscscan;
        }
        if (chainName.includes('base')) {
            return this.config.apiKeys?.basescan;
        }
        if (chainName.includes('avalanche') || chainName.includes('avax')) {
            return this.config.apiKeys?.snowtrace;
        }
        if (chainName.includes('fantom') || chainName.includes('ftm')) {
            return this.config.apiKeys?.ftmscan;
        }
        if (chainName.includes('optimism')) {
            return this.config.apiKeys?.optimism;
        }
        if (chainName.includes('scroll')) {
            return this.config.apiKeys?.scrollscan;
        }
        if (chainName.includes('linea')) {
            return this.config.apiKeys?.lineascan;
        }
        return this.config.chain.explorerApiKey;
    }

    // Make API request to block explorer
    private async explorerRequest<T>(params: Record<string, string>): Promise<EtherscanResponse<T>> {
        await this.rateLimiter.throttle();

        const apiKey = this.getApiKey();
        const url = new URL(this.config.chain.explorerApiUrl);
        
        Object.entries(params).forEach(([key, value]) => {
            url.searchParams.append(key, value);
        });
        
        if (apiKey) {
            url.searchParams.append('apikey', apiKey);
        }

        const response = await fetch(url.toString(), {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Explorer API error: ${response.status} ${response.statusText}`);
        }

        return response.json();
    }

    // Make RPC request
    private async rpcRequest<T>(method: string, params: any[]): Promise<T> {
        await this.rateLimiter.throttle();

        const request: JsonRpcRequest = {
            jsonrpc: '2.0',
            method,
            params,
            id: this.rpcId++
        };

        const response = await fetch(this.config.chain.rpcUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(request)
        });

        if (!response.ok) {
            throw new Error(`RPC error: ${response.status} ${response.statusText}`);
        }

        const json: JsonRpcResponse<T> = await response.json();
        
        if (json.error) {
            throw new Error(`RPC error: ${json.error.message}`);
        }

        return json.result!;
    }

    // Get verified source code from explorer
    async getSourceCode(address: string): Promise<SourceCodeResult> {
        try {
            const response = await this.explorerRequest<EtherscanSourceCode[]>({
                module: 'contract',
                action: 'getsourcecode',
                address
            });

            if (response.status !== '1' || !response.result || response.result.length === 0) {
                return {
                    address,
                    verified: false,
                    error: response.message || 'Contract not verified'
                };
            }

            const result = response.result[0];
            
            // Check if actually verified
            if (!result.SourceCode || result.SourceCode === '') {
                return {
                    address,
                    verified: false,
                    error: 'Contract source code not verified'
                };
            }

            // Parse ABI
            let abi: any[] = [];
            try {
                abi = JSON.parse(result.ABI);
            } catch {
                // ABI might be "Contract source code not verified"
            }

            // Handle multi-file source (Solidity Standard JSON)
            let sourceCode = result.SourceCode;
            if (sourceCode.startsWith('{{')) {
                // Double-braced JSON format
                try {
                    const parsed = JSON.parse(sourceCode.slice(1, -1));
                    // Combine all source files
                    const sources = parsed.sources || {};
                    sourceCode = Object.entries(sources)
                        .map(([filename, content]: [string, any]) => {
                            return `// File: ${filename}\n${content.content || content}`;
                        })
                        .join('\n\n');
                } catch {
                    // Keep original if parsing fails
                }
            } else if (sourceCode.startsWith('{')) {
                // Single-braced JSON format
                try {
                    const parsed = JSON.parse(sourceCode);
                    if (parsed.sources) {
                        sourceCode = Object.entries(parsed.sources)
                            .map(([filename, content]: [string, any]) => {
                                return `// File: ${filename}\n${content.content || content}`;
                            })
                            .join('\n\n');
                    }
                } catch {
                    // Keep original
                }
            }

            const metadata: ContractMetadata = {
                address,
                name: result.ContractName,
                compiler: result.CompilerVersion,
                optimizationUsed: result.OptimizationUsed === '1',
                runs: parseInt(result.Runs) || undefined,
                constructorArguments: result.ConstructorArguments || undefined,
                evmVersion: result.EVMVersion || undefined,
                library: result.Library || undefined,
                licenseType: result.LicenseType || undefined,
                proxy: result.Proxy === '1' ? 'yes' : undefined,
                implementation: result.Implementation || undefined,
                swarmSource: result.SwarmSource || undefined
            };

            return {
                address,
                verified: true,
                sourceCode,
                abi,
                metadata,
                decompiled: false
            };
        } catch (error) {
            return {
                address,
                verified: false,
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    // Get contract bytecode from RPC
    async getBytecode(address: string): Promise<BytecodeInfo> {
        const bytecode = await this.rpcRequest<string>('eth_getCode', [address, 'latest']);
        
        const isContract = bytecode !== '0x' && bytecode.length > 2;
        
        // Extract function selectors (first 4 bytes of each PUSH4)
        const selectors: string[] = [];
        if (isContract) {
            const selectorRegex = /63([a-fA-F0-9]{8})/g;
            let match;
            while ((match = selectorRegex.exec(bytecode)) !== null) {
                const selector = '0x' + match[1];
                if (!selectors.includes(selector)) {
                    selectors.push(selector);
                }
            }
        }

        // Check for dangerous opcodes
        const hasSelfdestruct = bytecode.includes('ff'); // SELFDESTRUCT
        const hasDelegatecall = bytecode.includes('f4'); // DELEGATECALL

        return {
            address,
            bytecode,
            deployedBytecode: bytecode,
            size: (bytecode.length - 2) / 2, // Bytes
            isContract,
            hasSelfdestruct,
            hasDelegatecall,
            functionSelectors: selectors
        };
    }

    // Get contract creation info
    async getContractCreation(address: string): Promise<ContractCreation | null> {
        try {
            const response = await this.explorerRequest<Array<{ contractAddress: string; contractCreator: string; txHash: string }>>({
                module: 'contract',
                action: 'getcontractcreation',
                contractaddresses: address
            });

            if (response.status !== '1' || !response.result || response.result.length === 0) {
                return null;
            }

            const creation = response.result[0];
            
            // Get block info for the creation tx
            const txReceipt = await this.rpcRequest<any>('eth_getTransactionReceipt', [creation.txHash]);
            const block = await this.rpcRequest<any>('eth_getBlockByNumber', [txReceipt.blockNumber, false]);

            return {
                address,
                creator: creation.contractCreator,
                txHash: creation.txHash,
                blockNumber: parseInt(txReceipt.blockNumber, 16),
                timestamp: parseInt(block.timestamp, 16)
            };
        } catch {
            return null;
        }
    }

    // Get recent transactions for an address
    async getTransactions(address: string, options?: { 
        startBlock?: number; 
        endBlock?: number; 
        page?: number; 
        offset?: number;
        sort?: 'asc' | 'desc';
    }): Promise<EtherscanTransaction[]> {
        try {
            const response = await this.explorerRequest<EtherscanTransaction[]>({
                module: 'account',
                action: 'txlist',
                address,
                startblock: String(options?.startBlock || 0),
                endblock: String(options?.endBlock || 99999999),
                page: String(options?.page || 1),
                offset: String(options?.offset || 100),
                sort: options?.sort || 'desc'
            });

            if (response.status !== '1') {
                return [];
            }

            return response.result;
        } catch {
            return [];
        }
    }

    // Get internal transactions (for detecting contract creations)
    async getInternalTransactions(address: string, options?: {
        startBlock?: number;
        endBlock?: number;
        page?: number;
        offset?: number;
    }): Promise<any[]> {
        try {
            const response = await this.explorerRequest<any[]>({
                module: 'account',
                action: 'txlistinternal',
                address,
                startblock: String(options?.startBlock || 0),
                endblock: String(options?.endBlock || 99999999),
                page: String(options?.page || 1),
                offset: String(options?.offset || 100),
                sort: 'desc'
            });

            if (response.status !== '1') {
                return [];
            }

            return response.result;
        } catch {
            return [];
        }
    }

    // Get latest block number
    async getBlockNumber(): Promise<number> {
        const result = await this.rpcRequest<string>('eth_blockNumber', []);
        return parseInt(result, 16);
    }

    // Get block by number
    async getBlock(blockNumber: number | 'latest' | 'pending', includeTransactions = false): Promise<any> {
        const blockParam = typeof blockNumber === 'number' ? '0x' + blockNumber.toString(16) : blockNumber;
        return this.rpcRequest<any>('eth_getBlockByNumber', [blockParam, includeTransactions]);
    }

    // Get transaction by hash
    async getTransaction(hash: string): Promise<any> {
        return this.rpcRequest<any>('eth_getTransactionByHash', [hash]);
    }

    // Get transaction receipt
    async getTransactionReceipt(hash: string): Promise<any> {
        return this.rpcRequest<any>('eth_getTransactionReceipt', [hash]);
    }

    // Check if address is a contract
    async isContract(address: string): Promise<boolean> {
        const code = await this.rpcRequest<string>('eth_getCode', [address, 'latest']);
        return code !== '0x' && code.length > 2;
    }

    // Get ETH balance
    async getBalance(address: string): Promise<string> {
        const balance = await this.rpcRequest<string>('eth_getBalance', [address, 'latest']);
        return BigInt(balance).toString();
    }

    // Get storage at slot
    async getStorageAt(address: string, slot: number | string): Promise<string> {
        const slotHex = typeof slot === 'number' ? '0x' + slot.toString(16) : slot;
        return this.rpcRequest<string>('eth_getStorageAt', [address, slotHex, 'latest']);
    }

    // Subscribe to pending transactions (requires WebSocket RPC)
    async subscribePendingTransactions(callback: (txHash: string) => void): Promise<string> {
        // Note: This requires WebSocket connection
        // For HTTP, we'll poll for new blocks instead
        console.warn('Pending transaction subscription requires WebSocket RPC. Using block polling instead.');
        return 'polling';
    }

    // Poll for new blocks
    async pollBlocks(callback: (block: any) => void, interval = 12000): Promise<() => void> {
        let lastBlock = await this.getBlockNumber();
        let running = true;

        const poll = async () => {
            while (running) {
                try {
                    const currentBlock = await this.getBlockNumber();
                    
                    for (let i = lastBlock + 1; i <= currentBlock; i++) {
                        const block = await this.getBlock(i, true);
                        callback(block);
                    }
                    
                    lastBlock = currentBlock;
                } catch (error) {
                    console.error('Block polling error:', error);
                }
                
                await new Promise(r => setTimeout(r, interval));
            }
        };

        poll();

        return () => {
            running = false;
        };
    }

    // Get recently deployed contracts
    async getRecentContracts(blockCount = 100): Promise<ContractCreation[]> {
        const contracts: ContractCreation[] = [];
        const currentBlock = await this.getBlockNumber();
        
        for (let i = currentBlock; i > currentBlock - blockCount && i > 0; i--) {
            const block = await this.getBlock(i, true);
            
            for (const tx of block.transactions || []) {
                // Contract creation = tx.to is null
                if (tx.to === null) {
                    const receipt = await this.getTransactionReceipt(tx.hash);
                    if (receipt.contractAddress) {
                        contracts.push({
                            address: receipt.contractAddress,
                            creator: tx.from,
                            txHash: tx.hash,
                            blockNumber: i,
                            timestamp: parseInt(block.timestamp, 16)
                        });
                    }
                }
            }
        }

        return contracts;
    }

    // Verify contract on explorer (submit source code)
    async verifyContract(params: {
        address: string;
        sourceCode: string;
        contractName: string;
        compilerVersion: string;
        optimizationUsed: boolean;
        runs: number;
        constructorArguments?: string;
        evmVersion?: string;
    }): Promise<{ success: boolean; guid?: string; error?: string }> {
        try {
            const response = await this.explorerRequest<string>({
                module: 'contract',
                action: 'verifysourcecode',
                sourceCode: params.sourceCode,
                contractaddress: params.address,
                codeformat: 'solidity-single-file',
                contractname: params.contractName,
                compilerversion: params.compilerVersion,
                optimizationUsed: params.optimizationUsed ? '1' : '0',
                runs: String(params.runs),
                constructorArguements: params.constructorArguments || '',
                evmversion: params.evmVersion || ''
            });

            if (response.status === '1') {
                return { success: true, guid: response.result };
            }
            
            return { success: false, error: response.result };
        } catch (error) {
            return { 
                success: false, 
                error: error instanceof Error ? error.message : 'Unknown error' 
            };
        }
    }
}

// Factory function
export function createExplorerAPI(chainOrConfig: string | ChainConfig | ScannerConfig): ExplorerAPI {
    if (typeof chainOrConfig === 'string') {
        const chain = CHAINS[chainOrConfig.toLowerCase()];
        if (!chain) {
            throw new Error(`Unknown chain: ${chainOrConfig}`);
        }
        return new ExplorerAPI({ chain });
    }
    
    if ('chainId' in chainOrConfig && 'rpcUrl' in chainOrConfig) {
        return new ExplorerAPI({ chain: chainOrConfig });
    }
    
    return new ExplorerAPI(chainOrConfig as ScannerConfig);
}

export default ExplorerAPI;

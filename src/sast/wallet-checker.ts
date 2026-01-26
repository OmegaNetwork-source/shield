// STRIX SAST - Wallet Balance Checker
// Check if leaked private keys have balances on various chains

// ============================================
// EVM Chain Configuration
// ============================================

// Public RPC endpoints (no API key required)
export const PUBLIC_RPCS: Record<string, { name: string; rpc: string; explorer: string; symbol: string; chainId: number }> = {
    ethereum: {
        name: 'Ethereum',
        rpc: 'https://eth.llamarpc.com',
        explorer: 'https://etherscan.io',
        symbol: 'ETH',
        chainId: 1
    },
    bsc: {
        name: 'BNB Chain',
        rpc: 'https://bsc-dataseed.binance.org',
        explorer: 'https://bscscan.com',
        symbol: 'BNB',
        chainId: 56
    },
    polygon: {
        name: 'Polygon',
        rpc: 'https://polygon-rpc.com',
        explorer: 'https://polygonscan.com',
        symbol: 'MATIC',
        chainId: 137
    },
    arbitrum: {
        name: 'Arbitrum',
        rpc: 'https://arb1.arbitrum.io/rpc',
        explorer: 'https://arbiscan.io',
        symbol: 'ETH',
        chainId: 42161
    },
    optimism: {
        name: 'Optimism',
        rpc: 'https://mainnet.optimism.io',
        explorer: 'https://optimistic.etherscan.io',
        symbol: 'ETH',
        chainId: 10
    },
    avalanche: {
        name: 'Avalanche',
        rpc: 'https://api.avax.network/ext/bc/C/rpc',
        explorer: 'https://snowtrace.io',
        symbol: 'AVAX',
        chainId: 43114
    },
    fantom: {
        name: 'Fantom',
        rpc: 'https://rpc.ftm.tools',
        explorer: 'https://ftmscan.com',
        symbol: 'FTM',
        chainId: 250
    },
    base: {
        name: 'Base',
        rpc: 'https://mainnet.base.org',
        explorer: 'https://basescan.org',
        symbol: 'ETH',
        chainId: 8453
    },
};

// ============================================
// Solana Configuration
// ============================================

export const SOLANA_RPCS = {
    mainnet: {
        name: 'Solana',
        rpc: 'https://api.mainnet-beta.solana.com',
        explorer: 'https://solscan.io',
        symbol: 'SOL'
    },
};

// ============================================
// Bitcoin Configuration
// ============================================

export const BITCOIN_APIS = {
    mainnet: {
        name: 'Bitcoin',
        api: 'https://blockstream.info/api',
        explorer: 'https://blockstream.info',
        symbol: 'BTC'
    },
};

// ============================================
// ERC-20 Token Configuration
// ============================================

export interface TokenConfig {
    symbol: string;
    name: string;
    decimals: number;
    addresses: Record<string, string>; // chainId -> contract address
}

// Popular stablecoins and tokens
export const ERC20_TOKENS: TokenConfig[] = [
    {
        symbol: 'USDT',
        name: 'Tether USD',
        decimals: 6,
        addresses: {
            '1': '0xdAC17F958D2ee523a2206206994597C13D831ec7',      // Ethereum
            '56': '0x55d398326f99059fF775485246999027B3197955',     // BSC
            '137': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',    // Polygon
            '42161': '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',  // Arbitrum
            '10': '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58',     // Optimism
            '43114': '0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7',  // Avalanche
        }
    },
    {
        symbol: 'USDC',
        name: 'USD Coin',
        decimals: 6,
        addresses: {
            '1': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',      // Ethereum
            '56': '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',     // BSC
            '137': '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359',    // Polygon (native)
            '42161': '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',  // Arbitrum (native)
            '10': '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',     // Optimism (native)
            '43114': '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E',  // Avalanche
            '8453': '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',   // Base
        }
    },
    {
        symbol: 'DAI',
        name: 'Dai Stablecoin',
        decimals: 18,
        addresses: {
            '1': '0x6B175474E89094C44Da98b954EedeAC495271d0F',      // Ethereum
            '137': '0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063',    // Polygon
            '42161': '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1',  // Arbitrum
            '10': '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1',     // Optimism
        }
    },
    {
        symbol: 'WETH',
        name: 'Wrapped Ether',
        decimals: 18,
        addresses: {
            '1': '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',      // Ethereum
            '56': '0x2170Ed0880ac9A755fd29B2688956BD959F933F8',     // BSC
            '137': '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619',    // Polygon
            '42161': '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1',  // Arbitrum
            '10': '0x4200000000000000000000000000000000000006',     // Optimism
            '43114': '0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB',  // Avalanche
            '8453': '0x4200000000000000000000000000000000000006',   // Base
        }
    },
    {
        symbol: 'WBTC',
        name: 'Wrapped Bitcoin',
        decimals: 8,
        addresses: {
            '1': '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',      // Ethereum
            '137': '0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6',    // Polygon
            '42161': '0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f',  // Arbitrum
            '10': '0x68f180fcCe6836688e9084f035309E29Bf0A2095',     // Optimism
        }
    },
];

export interface WalletBalance {
    chain: string;
    chainName: string;
    balance: string;
    balanceFormatted: string;
    symbol: string;
    hasBalance: boolean;
    explorerUrl: string;
    error?: string;
}

export interface TokenBalance {
    chain: string;
    chainName: string;
    token: string;
    tokenName: string;
    balance: string;
    balanceFormatted: string;
    hasBalance: boolean;
    contractAddress: string;
    error?: string;
}

export interface WalletCheckResult {
    address: string;
    addressType: 'evm' | 'solana' | 'bitcoin';
    privateKeyPreview: string;
    totalChains: number;
    chainsWithBalance: number;
    balances: WalletBalance[];
    tokenBalances: TokenBalance[];
    totalValueUsd?: number;
    isLive: boolean;
    checkTime: Date;
}

export interface MultiChainCheckResult {
    evmResult?: WalletCheckResult;
    solanaResult?: WalletCheckResult;
    bitcoinResult?: WalletCheckResult;
    hasAnyBalance: boolean;
    summary: {
        totalNativeValue: number;
        totalTokenValue: number;
        chainsWithFunds: string[];
    };
}

/**
 * Derive Ethereum address from private key
 * Uses simple keccak256 hash (browser-compatible)
 */
export async function deriveAddress(privateKey: string): Promise<string | null> {
    try {
        // Clean the private key
        let cleanKey = privateKey.trim();
        if (cleanKey.startsWith('0x')) {
            cleanKey = cleanKey.slice(2);
        }
        
        // Validate hex format (64 characters)
        if (!/^[a-fA-F0-9]{64}$/.test(cleanKey)) {
            return null;
        }
        
        // Convert hex to bytes
        const privateKeyBytes = hexToBytes(cleanKey);
        
        // Get public key using SubtleCrypto (browser native)
        // Note: This is a simplified approach - for production, use ethers.js
        const publicKey = await getPublicKeyFromPrivate(privateKeyBytes);
        if (!publicKey) return null;
        
        // Keccak256 hash of public key, take last 20 bytes
        const hash = await keccak256(publicKey.slice(1)); // Remove 04 prefix
        const address = '0x' + bytesToHex(hash.slice(-20));
        
        return address.toLowerCase();
    } catch (e) {
        console.error('Address derivation error:', e);
        return null;
    }
}

/**
 * Simple keccak256 implementation for browser
 */
async function keccak256(data: Uint8Array): Promise<Uint8Array> {
    // Use a pure JS implementation since SubtleCrypto doesn't support keccak256
    return keccak256Js(data);
}

// Keccak256 constants
const KECCAK_ROUNDS = 24;
const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
    0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
    0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
    0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
    0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
    0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
    0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];

function keccak256Js(input: Uint8Array): Uint8Array {
    const rate = 136; // 1088 bits for keccak256
    const outputLen = 32;
    
    // Pad the input
    const padded = keccakPad(input, rate);
    
    // Initialize state
    const state = new BigUint64Array(25);
    
    // Absorb
    for (let i = 0; i < padded.length; i += rate) {
        for (let j = 0; j < rate / 8; j++) {
            const idx = i + j * 8;
            let val = 0n;
            for (let k = 0; k < 8; k++) {
                val |= BigInt(padded[idx + k] || 0) << BigInt(k * 8);
            }
            state[j] ^= val;
        }
        keccakF(state);
    }
    
    // Squeeze
    const output = new Uint8Array(outputLen);
    for (let i = 0; i < outputLen / 8; i++) {
        const val = state[i];
        for (let j = 0; j < 8 && i * 8 + j < outputLen; j++) {
            output[i * 8 + j] = Number((val >> BigInt(j * 8)) & 0xffn);
        }
    }
    
    return output;
}

function keccakPad(input: Uint8Array, rate: number): Uint8Array {
    const padLen = rate - (input.length % rate);
    const padded = new Uint8Array(input.length + padLen);
    padded.set(input);
    padded[input.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    return padded;
}

function keccakF(state: BigUint64Array): void {
    for (let round = 0; round < KECCAK_ROUNDS; round++) {
        // θ step
        const C = new BigUint64Array(5);
        for (let x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        const D = new BigUint64Array(5);
        for (let x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
        }
        for (let i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }
        
        // ρ and π steps
        const B = new BigUint64Array(25);
        const rotations = [
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
        ];
        const piLane = [
            0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21
        ];
        for (let i = 0; i < 25; i++) {
            B[piLane[i]] = rotl64(state[i], BigInt(rotations[i]));
        }
        
        // χ step
        for (let y = 0; y < 5; y++) {
            for (let x = 0; x < 5; x++) {
                state[y * 5 + x] = B[y * 5 + x] ^ (~B[y * 5 + (x + 1) % 5] & B[y * 5 + (x + 2) % 5]);
            }
        }
        
        // ι step
        state[0] ^= KECCAK_RC[round];
    }
}

function rotl64(x: bigint, n: bigint): bigint {
    return ((x << n) | (x >> (64n - n))) & 0xffffffffffffffffn;
}

/**
 * Get public key from private key using secp256k1
 * Simplified implementation for browser
 */
async function getPublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array | null> {
    try {
        // Use WebCrypto if available, otherwise fall back to simple computation
        // For now, we'll use a lookup-based approach for common test keys
        // In production, you'd want ethers.js or a proper secp256k1 library
        
        // This is a placeholder - real implementation needs secp256k1
        // For the demo, we'll try to use the address if provided in context
        return null;
    } catch {
        return null;
    }
}

// Helper functions
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// EVM Balance Checking
// ============================================

/**
 * Check native balance on a single EVM chain
 */
export async function checkBalance(address: string, chain: keyof typeof PUBLIC_RPCS): Promise<WalletBalance> {
    const chainInfo = PUBLIC_RPCS[chain];
    
    if (!chainInfo) {
        return {
            chain,
            chainName: chain,
            balance: '0',
            balanceFormatted: '0',
            symbol: '?',
            hasBalance: false,
            explorerUrl: '',
            error: 'Unknown chain'
        };
    }
    
    try {
        const response = await fetch(chainInfo.rpc, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_getBalance',
                params: [address, 'latest'],
                id: 1
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error.message);
        }
        
        const balanceWei = BigInt(data.result || '0');
        const balanceEth = Number(balanceWei) / 1e18;
        const hasBalance = balanceWei > 0n;
        
        return {
            chain,
            chainName: chainInfo.name,
            balance: balanceWei.toString(),
            balanceFormatted: balanceEth.toFixed(6),
            symbol: chainInfo.symbol,
            hasBalance,
            explorerUrl: `${chainInfo.explorer}/address/${address}`
        };
    } catch (e: any) {
        return {
            chain,
            chainName: chainInfo.name,
            balance: '0',
            balanceFormatted: '0',
            symbol: chainInfo.symbol,
            hasBalance: false,
            explorerUrl: `${chainInfo.explorer}/address/${address}`,
            error: e.message
        };
    }
}

/**
 * Check ERC-20 token balance on a single chain
 */
export async function checkTokenBalance(
    address: string, 
    chain: keyof typeof PUBLIC_RPCS,
    token: TokenConfig
): Promise<TokenBalance> {
    const chainInfo = PUBLIC_RPCS[chain];
    const contractAddress = token.addresses[chainInfo.chainId.toString()];
    
    if (!contractAddress) {
        return {
            chain,
            chainName: chainInfo.name,
            token: token.symbol,
            tokenName: token.name,
            balance: '0',
            balanceFormatted: '0',
            hasBalance: false,
            contractAddress: '',
            error: 'Token not available on this chain'
        };
    }
    
    try {
        // ERC-20 balanceOf function signature: 0x70a08231
        // Padded address (remove 0x, pad to 64 chars)
        const paddedAddress = address.slice(2).padStart(64, '0');
        const data = `0x70a08231${paddedAddress}`;
        
        const response = await fetch(chainInfo.rpc, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_call',
                params: [
                    { to: contractAddress, data },
                    'latest'
                ],
                id: 1
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            throw new Error(result.error.message);
        }
        
        const balanceRaw = BigInt(result.result || '0');
        const balanceFormatted = Number(balanceRaw) / Math.pow(10, token.decimals);
        const hasBalance = balanceRaw > 0n;
        
        return {
            chain,
            chainName: chainInfo.name,
            token: token.symbol,
            tokenName: token.name,
            balance: balanceRaw.toString(),
            balanceFormatted: balanceFormatted.toFixed(token.decimals > 6 ? 6 : token.decimals),
            hasBalance,
            contractAddress,
        };
    } catch (e: any) {
        return {
            chain,
            chainName: chainInfo.name,
            token: token.symbol,
            tokenName: token.name,
            balance: '0',
            balanceFormatted: '0',
            hasBalance: false,
            contractAddress,
            error: e.message
        };
    }
}

/**
 * Check all ERC-20 tokens on a single chain
 */
export async function checkAllTokensOnChain(
    address: string,
    chain: keyof typeof PUBLIC_RPCS
): Promise<TokenBalance[]> {
    const promises = ERC20_TOKENS.map(token => checkTokenBalance(address, chain, token));
    return Promise.all(promises);
}

// ============================================
// Solana Balance Checking
// ============================================

/**
 * Check Solana balance
 */
export async function checkSolanaBalance(address: string): Promise<WalletBalance> {
    try {
        const response = await fetch(SOLANA_RPCS.mainnet.rpc, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'getBalance',
                params: [address]
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error.message);
        }
        
        const balanceLamports = BigInt(data.result?.value || 0);
        const balanceSol = Number(balanceLamports) / 1e9; // 1 SOL = 1e9 lamports
        const hasBalance = balanceLamports > 0n;
        
        return {
            chain: 'solana',
            chainName: 'Solana',
            balance: balanceLamports.toString(),
            balanceFormatted: balanceSol.toFixed(6),
            symbol: 'SOL',
            hasBalance,
            explorerUrl: `${SOLANA_RPCS.mainnet.explorer}/account/${address}`
        };
    } catch (e: any) {
        return {
            chain: 'solana',
            chainName: 'Solana',
            balance: '0',
            balanceFormatted: '0',
            symbol: 'SOL',
            hasBalance: false,
            explorerUrl: `${SOLANA_RPCS.mainnet.explorer}/account/${address}`,
            error: e.message
        };
    }
}

/**
 * Check Solana SPL token balances (USDC, USDT on Solana)
 */
export async function checkSolanaTokens(address: string): Promise<TokenBalance[]> {
    try {
        const response = await fetch(SOLANA_RPCS.mainnet.rpc, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 1,
                method: 'getTokenAccountsByOwner',
                params: [
                    address,
                    { programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' },
                    { encoding: 'jsonParsed' }
                ]
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            return [];
        }
        
        const accounts = data.result?.value || [];
        const tokens: TokenBalance[] = [];
        
        for (const account of accounts) {
            const info = account.account?.data?.parsed?.info;
            if (info && info.tokenAmount) {
                const balance = BigInt(info.tokenAmount.amount || '0');
                if (balance > 0n) {
                    tokens.push({
                        chain: 'solana',
                        chainName: 'Solana',
                        token: info.mint.slice(0, 8) + '...',
                        tokenName: 'SPL Token',
                        balance: balance.toString(),
                        balanceFormatted: info.tokenAmount.uiAmountString || '0',
                        hasBalance: true,
                        contractAddress: info.mint,
                    });
                }
            }
        }
        
        return tokens;
    } catch (e: any) {
        return [];
    }
}

// ============================================
// Bitcoin Balance Checking
// ============================================

/**
 * Check Bitcoin balance using Blockstream API
 */
export async function checkBitcoinBalance(address: string): Promise<WalletBalance> {
    try {
        // Validate Bitcoin address format
        if (!isValidBitcoinAddress(address)) {
            throw new Error('Invalid Bitcoin address format');
        }
        
        const response = await fetch(`${BITCOIN_APIS.mainnet.api}/address/${address}`);
        
        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Balance in satoshis (funded - spent)
        const balanceSats = BigInt(data.chain_stats?.funded_txo_sum || 0) - 
                          BigInt(data.chain_stats?.spent_txo_sum || 0);
        const balanceBtc = Number(balanceSats) / 1e8; // 1 BTC = 1e8 satoshis
        const hasBalance = balanceSats > 0n;
        
        return {
            chain: 'bitcoin',
            chainName: 'Bitcoin',
            balance: balanceSats.toString(),
            balanceFormatted: balanceBtc.toFixed(8),
            symbol: 'BTC',
            hasBalance,
            explorerUrl: `${BITCOIN_APIS.mainnet.explorer}/address/${address}`
        };
    } catch (e: any) {
        return {
            chain: 'bitcoin',
            chainName: 'Bitcoin',
            balance: '0',
            balanceFormatted: '0',
            symbol: 'BTC',
            hasBalance: false,
            explorerUrl: `${BITCOIN_APIS.mainnet.explorer}/address/${address}`,
            error: e.message
        };
    }
}

/**
 * Validate Bitcoin address format
 */
function isValidBitcoinAddress(address: string): boolean {
    // Legacy addresses (P2PKH) start with 1
    // P2SH addresses start with 3
    // Native SegWit (Bech32) start with bc1
    const legacyRegex = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
    const bech32Regex = /^bc1[a-z0-9]{39,59}$/i;
    
    return legacyRegex.test(address) || bech32Regex.test(address);
}

/**
 * Check balance on all supported EVM chains (native + tokens)
 */
export async function checkAllBalances(address: string, includeTokens: boolean = true): Promise<WalletCheckResult> {
    const chains = Object.keys(PUBLIC_RPCS) as (keyof typeof PUBLIC_RPCS)[];
    
    // Check native balances on all chains in parallel
    const balancePromises = chains.map(chain => checkBalance(address, chain));
    const balances = await Promise.all(balancePromises);
    
    // Check token balances if requested
    let tokenBalances: TokenBalance[] = [];
    if (includeTokens) {
        const tokenPromises = chains.map(chain => checkAllTokensOnChain(address, chain));
        const tokenResults = await Promise.all(tokenPromises);
        tokenBalances = tokenResults.flat().filter(t => t.hasBalance);
    }
    
    const chainsWithBalance = balances.filter(b => b.hasBalance).length;
    const hasTokens = tokenBalances.length > 0;
    
    return {
        address,
        addressType: 'evm',
        privateKeyPreview: '', // Will be set by caller
        totalChains: chains.length,
        chainsWithBalance,
        balances,
        tokenBalances,
        isLive: chainsWithBalance > 0 || hasTokens,
        checkTime: new Date()
    };
}

/**
 * Check Solana wallet (native + SPL tokens)
 */
export async function checkSolanaWallet(address: string): Promise<WalletCheckResult> {
    const [nativeBalance, tokens] = await Promise.all([
        checkSolanaBalance(address),
        checkSolanaTokens(address)
    ]);
    
    return {
        address,
        addressType: 'solana',
        privateKeyPreview: '',
        totalChains: 1,
        chainsWithBalance: nativeBalance.hasBalance ? 1 : 0,
        balances: [nativeBalance],
        tokenBalances: tokens,
        isLive: nativeBalance.hasBalance || tokens.length > 0,
        checkTime: new Date()
    };
}

/**
 * Check Bitcoin wallet
 */
export async function checkBitcoinWallet(address: string): Promise<WalletCheckResult> {
    const balance = await checkBitcoinBalance(address);
    
    return {
        address,
        addressType: 'bitcoin',
        privateKeyPreview: '',
        totalChains: 1,
        chainsWithBalance: balance.hasBalance ? 1 : 0,
        balances: [balance],
        tokenBalances: [],
        isLive: balance.hasBalance,
        checkTime: new Date()
    };
}

/**
 * Comprehensive multi-chain check - detects address type and checks appropriate chains
 */
export async function checkAllChainsComprehensive(
    evmAddress?: string,
    solanaAddress?: string,
    bitcoinAddress?: string
): Promise<MultiChainCheckResult> {
    const results: MultiChainCheckResult = {
        hasAnyBalance: false,
        summary: {
            totalNativeValue: 0,
            totalTokenValue: 0,
            chainsWithFunds: []
        }
    };
    
    const promises: Promise<void>[] = [];
    
    // Check EVM if address provided
    if (evmAddress && evmAddress.startsWith('0x') && evmAddress.length === 42) {
        promises.push(
            checkAllBalances(evmAddress, true).then(result => {
                results.evmResult = result;
                if (result.isLive) {
                    results.hasAnyBalance = true;
                    result.balances.filter(b => b.hasBalance).forEach(b => {
                        results.summary.chainsWithFunds.push(`${b.chainName} (${b.balanceFormatted} ${b.symbol})`);
                    });
                    result.tokenBalances.forEach(t => {
                        results.summary.chainsWithFunds.push(`${t.chainName} ${t.token} (${t.balanceFormatted})`);
                    });
                }
            })
        );
    }
    
    // Check Solana if address provided
    if (solanaAddress && isValidSolanaAddress(solanaAddress)) {
        promises.push(
            checkSolanaWallet(solanaAddress).then(result => {
                results.solanaResult = result;
                if (result.isLive) {
                    results.hasAnyBalance = true;
                    result.balances.filter(b => b.hasBalance).forEach(b => {
                        results.summary.chainsWithFunds.push(`${b.chainName} (${b.balanceFormatted} ${b.symbol})`);
                    });
                }
            })
        );
    }
    
    // Check Bitcoin if address provided
    if (bitcoinAddress && isValidBitcoinAddress(bitcoinAddress)) {
        promises.push(
            checkBitcoinWallet(bitcoinAddress).then(result => {
                results.bitcoinResult = result;
                if (result.isLive) {
                    results.hasAnyBalance = true;
                    result.balances.filter(b => b.hasBalance).forEach(b => {
                        results.summary.chainsWithFunds.push(`${b.chainName} (${b.balanceFormatted} ${b.symbol})`);
                    });
                }
            })
        );
    }
    
    await Promise.all(promises);
    
    return results;
}

/**
 * Validate Solana address format (Base58, 32-44 chars)
 */
function isValidSolanaAddress(address: string): boolean {
    const base58Regex = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
    return base58Regex.test(address);
}

/**
 * Check if a private key is a placeholder/example that should be ignored
 */
function isPlaceholderKey(key: string): boolean {
    const cleanKey = key.toLowerCase().replace(/^0x/, '');
    
    // All zeros
    if (/^0+$/.test(cleanKey)) return true;
    
    // All same character
    if (/^(.)\1+$/.test(cleanKey)) return true;
    
    // Common test/example patterns
    if (cleanKey.startsWith('1234') || cleanKey.startsWith('abcd')) return true;
    if (cleanKey.startsWith('dead') || cleanKey.startsWith('beef')) return true;
    
    // Mostly zeros (placeholder with only last few chars)
    const nonZeroCount = (cleanKey.match(/[1-9a-f]/gi) || []).length;
    if (nonZeroCount <= 8) return true; // Key is mostly zeros - likely a placeholder
    
    // Sequential patterns like 0123456789abcdef...
    if (/^0123456789abcdef/i.test(cleanKey)) return true;
    
    return false;
}

/**
 * Extract potential private keys from text
 */
export function extractPrivateKeys(text: string): string[] {
    const keys: string[] = [];
    
    // Match 0x-prefixed 64 hex chars
    const hex0xPattern = /0x[a-fA-F0-9]{64}/g;
    let match;
    while ((match = hex0xPattern.exec(text)) !== null) {
        if (!isPlaceholderKey(match[0])) {
            keys.push(match[0]);
        }
    }
    
    // Match raw 64 hex chars (after = or : or in quotes)
    const rawHexPattern = /["'=:\s]([a-fA-F0-9]{64})["'\s,;]/g;
    while ((match = rawHexPattern.exec(text)) !== null) {
        const key = match[1];
        if (!isPlaceholderKey(key) && !keys.includes('0x' + key) && !keys.includes(key)) {
            keys.push(key);
        }
    }
    
    return [...new Set(keys)]; // Dedupe
}

/**
 * Check if an address is a placeholder/null address that should be ignored
 */
export function isPlaceholderAddress(address: string): boolean {
    const addr = address.toLowerCase();
    
    // Null address
    if (addr === '0x0000000000000000000000000000000000000000') return true;
    
    // Precompile addresses (0x01 - 0x09) - these are system contracts
    if (/^0x0{39}[0-9a-f]$/.test(addr)) return true;
    
    // Dead/burn addresses
    if (addr === '0x000000000000000000000000000000000000dead') return true;
    if (addr === '0xdead000000000000000000000000000000000000') return true;
    
    // Common placeholder patterns (mostly zeros with only a few non-zero chars)
    const nonZeroCount = (addr.slice(2).match(/[1-9a-f]/gi) || []).length;
    if (nonZeroCount <= 4) return true; // Address is mostly zeros - likely a placeholder
    
    // Repeated patterns that look like examples
    if (/^0x([0-9a-f])\1{39}$/i.test(addr)) return true; // All same char like 0xaaa...aaa
    if (/^0x(1234|abcd|dead|beef|cafe|babe|face)/i.test(addr)) return true; // Common test prefixes
    
    return false;
}

/**
 * Extract EVM wallet addresses from text
 */
export function extractAddresses(text: string): string[] {
    const addresses: string[] = [];
    const pattern = /0x[a-fA-F0-9]{40}/g;
    let match;
    while ((match = pattern.exec(text)) !== null) {
        const addr = match[0].toLowerCase();
        // Filter out placeholder addresses
        if (!isPlaceholderAddress(addr)) {
            addresses.push(addr);
        }
    }
    return [...new Set(addresses)];
}

/**
 * Extract Solana addresses from text (Base58, typically 32-44 chars)
 */
export function extractSolanaAddresses(text: string): string[] {
    const addresses: string[] = [];
    // Solana addresses are Base58 encoded, 32-44 characters
    const patterns = [
        /(?:pubkey|address|wallet|account|solana)[\s]*[=:][\s]*["']?([1-9A-HJ-NP-Za-km-z]{32,44})["']?/gi,
        /["']([1-9A-HJ-NP-Za-km-z]{43,44})["']/g,
    ];
    
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const addr = match[1] || match[0];
            if (addr.length >= 32 && addr.length <= 44 && !addr.includes('0x')) {
                addresses.push(addr);
            }
        }
    }
    
    return [...new Set(addresses)];
}

/**
 * Extract Bitcoin addresses from text
 */
export function extractBitcoinAddresses(text: string): string[] {
    const addresses: string[] = [];
    
    // Legacy (P2PKH) - starts with 1
    const legacyPattern = /\b(1[a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
    // P2SH - starts with 3
    const p2shPattern = /\b(3[a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
    // Native SegWit (Bech32) - starts with bc1
    const bech32Pattern = /\b(bc1[a-z0-9]{39,59})\b/gi;
    
    let match;
    while ((match = legacyPattern.exec(text)) !== null) {
        addresses.push(match[1]);
    }
    while ((match = p2shPattern.exec(text)) !== null) {
        addresses.push(match[1]);
    }
    while ((match = bech32Pattern.exec(text)) !== null) {
        addresses.push(match[1].toLowerCase());
    }
    
    return [...new Set(addresses)];
}

/**
 * Extract all types of addresses from text
 */
export function extractAllAddresses(text: string): {
    evm: string[];
    solana: string[];
    bitcoin: string[];
} {
    return {
        evm: extractAddresses(text),
        solana: extractSolanaAddresses(text),
        bitcoin: extractBitcoinAddresses(text),
    };
}

/**
 * Quick check if a private key has any value
 */
export async function quickKeyCheck(privateKey: string, address?: string): Promise<{
    hasValue: boolean;
    address: string | null;
    chains: string[];
    tokenBalances: string[];
}> {
    let walletAddress = address;
    
    if (!walletAddress) {
        walletAddress = await deriveAddress(privateKey) || undefined;
    }
    
    if (!walletAddress) {
        return { hasValue: false, address: null, chains: [], tokenBalances: [] };
    }
    
    const result = await checkAllBalances(walletAddress, true);
    const chainsWithValue = result.balances
        .filter(b => b.hasBalance)
        .map(b => `${b.chainName}: ${b.balanceFormatted} ${b.symbol}`);
    
    const tokensWithValue = result.tokenBalances
        .filter(t => t.hasBalance)
        .map(t => `${t.chainName} ${t.token}: ${t.balanceFormatted}`);
    
    return {
        hasValue: result.isLive,
        address: walletAddress,
        chains: chainsWithValue,
        tokenBalances: tokensWithValue
    };
}

/**
 * Quick check if any extracted address from text has balance
 */
export async function checkTextForFundedAddresses(text: string): Promise<{
    hasFunds: boolean;
    fundedAddresses: {
        address: string;
        type: 'evm' | 'solana' | 'bitcoin';
        balances: string[];
    }[];
}> {
    const addresses = extractAllAddresses(text);
    const fundedAddresses: { address: string; type: 'evm' | 'solana' | 'bitcoin'; balances: string[] }[] = [];
    
    const promises: Promise<void>[] = [];
    
    // Check EVM addresses (limit to avoid rate limits)
    for (const addr of addresses.evm.slice(0, 5)) {
        promises.push(
            checkAllBalances(addr, true).then(result => {
                if (result.isLive) {
                    const balances = [
                        ...result.balances.filter(b => b.hasBalance).map(b => `${b.chainName}: ${b.balanceFormatted} ${b.symbol}`),
                        ...result.tokenBalances.map(t => `${t.chainName} ${t.token}: ${t.balanceFormatted}`)
                    ];
                    fundedAddresses.push({ address: addr, type: 'evm', balances });
                }
            }).catch(() => {})
        );
    }
    
    // Check Solana addresses
    for (const addr of addresses.solana.slice(0, 3)) {
        promises.push(
            checkSolanaWallet(addr).then(result => {
                if (result.isLive) {
                    const balances = [
                        ...result.balances.filter(b => b.hasBalance).map(b => `${b.chainName}: ${b.balanceFormatted} ${b.symbol}`),
                        ...result.tokenBalances.map(t => `SPL Token: ${t.balanceFormatted}`)
                    ];
                    fundedAddresses.push({ address: addr, type: 'solana', balances });
                }
            }).catch(() => {})
        );
    }
    
    // Check Bitcoin addresses
    for (const addr of addresses.bitcoin.slice(0, 3)) {
        promises.push(
            checkBitcoinWallet(addr).then(result => {
                if (result.isLive) {
                    const balances = result.balances.filter(b => b.hasBalance).map(b => `${b.chainName}: ${b.balanceFormatted} ${b.symbol}`);
                    fundedAddresses.push({ address: addr, type: 'bitcoin', balances });
                }
            }).catch(() => {})
        );
    }
    
    await Promise.all(promises);
    
    return {
        hasFunds: fundedAddresses.length > 0,
        fundedAddresses
    };
}

/**
 * Filter findings to only those with funded wallets
 * This is the main function for "only show findings with balance"
 */
export async function filterFindingsWithBalance<T extends { match: { snippet: string }; id: string }>(
    findings: T[],
    onProgress?: (checked: number, total: number, funded: number) => void
): Promise<{
    fundedFindings: T[];
    balanceInfo: Record<string, { address: string; type: string; balances: string[] }>;
}> {
    const fundedFindings: T[] = [];
    const balanceInfo: Record<string, { address: string; type: string; balances: string[] }> = {};
    let checked = 0;
    let funded = 0;
    
    // Process in batches
    const batchSize = 5;
    for (let i = 0; i < findings.length; i += batchSize) {
        const batch = findings.slice(i, i + batchSize);
        
        await Promise.all(batch.map(async (finding) => {
            try {
                const result = await checkTextForFundedAddresses(finding.match.snippet);
                checked++;
                
                if (result.hasFunds) {
                    funded++;
                    fundedFindings.push(finding);
                    const firstFunded = result.fundedAddresses[0];
                    balanceInfo[finding.id] = {
                        address: firstFunded.address,
                        type: firstFunded.type,
                        balances: firstFunded.balances
                    };
                }
                
                if (onProgress) {
                    onProgress(checked, findings.length, funded);
                }
            } catch (e) {
                checked++;
                if (onProgress) {
                    onProgress(checked, findings.length, funded);
                }
            }
        }));
        
        // Delay between batches
        if (i + batchSize < findings.length) {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    
    return { fundedFindings, balanceInfo };
}

// BIP-39 English wordlist (first 100 words for validation - full list would be 2048)
const BIP39_WORDLIST_SAMPLE = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
    'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
    'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
    'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
    'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent',
    'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album',
    'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone',
    'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
    'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
    'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique',
    'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april',
    'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor',
    'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact',
    'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume',
    'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction',
    'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado',
    'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis',
    'baby', 'bachelor', 'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball',
    'bamboo', 'banana', 'banner', 'bar', 'barely', 'bargain', 'barrel', 'base',
    'basic', 'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become',
    'beef', 'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt',
    'bench', 'benefit', 'best', 'betray', 'better', 'between', 'beyond', 'bicycle',
    'bid', 'bike', 'bind', 'biology', 'bird', 'birth', 'bitter', 'black',
    'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood',
    'blossom', 'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body',
    'boil', 'bomb', 'bone', 'bonus', 'book', 'boost', 'border', 'boring',
    'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain',
    'brand', 'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief',
    'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother',
    'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb',
    'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus',
    'business', 'busy', 'butter', 'buyer', 'buzz', 'cabbage', 'cabin', 'cable',
    'cactus', 'cage', 'cake', 'call', 'calm', 'camera', 'camp', 'can',
    'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas', 'canyon', 'capable',
    'capital', 'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry',
    'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat', 'catalog',
    'catch', 'category', 'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling',
    'celery', 'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk',
    'champion', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat', 'cheap',
    'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child',
    'chimney', 'choice', 'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar',
    'cinnamon', 'circle', 'citizen', 'city', 'civil', 'claim', 'clap', 'clarify',
    'claw', 'clay', 'clean', 'clerk', 'clever', 'click', 'client', 'cliff',
    'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud',
    'clown', 'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut',
    'code', 'coffee', 'coil', 'coin', 'collect', 'color', 'column', 'combine',
    'come', 'comfort', 'comic', 'common', 'company', 'concert', 'conduct', 'confirm',
    'congress', 'connect', 'consider', 'control', 'convince', 'cook', 'cool', 'copper',
    'copy', 'coral', 'core', 'corn', 'correct', 'cost', 'cotton', 'couch',
    'country', 'couple', 'course', 'cousin', 'cover', 'coyote', 'crack', 'cradle',
    'craft', 'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream',
    'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop',
    'cross', 'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch',
    'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard', 'curious',
    'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad',
    'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn',
    'day', 'deal', 'debate', 'debris', 'decade', 'december', 'decide', 'decline',
    'decorate', 'decrease', 'deer', 'defense', 'define', 'defy', 'degree', 'delay',
    'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny', 'depart', 'depend',
    'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk',
    'despair', 'destroy', 'detail', 'detect', 'develop', 'device', 'devote', 'diagram',
    'dial', 'diamond', 'diary', 'dice', 'diesel', 'diet', 'differ', 'digital',
    'dignity', 'dilemma', 'dinner', 'dinosaur', 'direct', 'dirt', 'disagree', 'discover',
    'disease', 'dish', 'dismiss', 'disorder', 'display', 'distance', 'divert', 'divide',
    'divorce', 'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain',
    // ... more words would go here (2048 total)
];

/**
 * Extract mnemonic phrases from text
 */
export function extractMnemonics(text: string): string[] {
    const mnemonics: string[] = [];
    const words = text.toLowerCase().split(/[\s\n\r,;:"']+/).filter(w => w.length > 0);
    
    // Look for sequences of 12, 15, 18, 21, or 24 valid BIP-39 words
    const validLengths = [12, 15, 18, 21, 24];
    
    for (let i = 0; i < words.length; i++) {
        for (const len of validLengths) {
            if (i + len <= words.length) {
                const phrase = words.slice(i, i + len);
                // Check if all words look like BIP-39 words (lowercase, alpha only)
                const looksValid = phrase.every(w => /^[a-z]{3,8}$/.test(w));
                if (looksValid) {
                    // Check if at least 80% of words are in our sample wordlist
                    const matchCount = phrase.filter(w => BIP39_WORDLIST_SAMPLE.includes(w)).length;
                    if (matchCount >= len * 0.5) { // At least 50% match (we only have partial wordlist)
                        mnemonics.push(phrase.join(' '));
                    }
                }
            }
        }
    }
    
    // Also look for quoted phrases
    const quotedPattern = /["']([a-z\s]{20,200})["']/gi;
    let match;
    while ((match = quotedPattern.exec(text)) !== null) {
        const words = match[1].toLowerCase().trim().split(/\s+/);
        if (validLengths.includes(words.length)) {
            const matchCount = words.filter(w => BIP39_WORDLIST_SAMPLE.includes(w)).length;
            if (matchCount >= words.length * 0.5) {
                mnemonics.push(words.join(' '));
            }
        }
    }
    
    return [...new Set(mnemonics)];
}

/**
 * Validate if a string looks like a mnemonic phrase
 */
export function isMnemonicPhrase(text: string): boolean {
    const words = text.toLowerCase().trim().split(/\s+/);
    const validLengths = [12, 15, 18, 21, 24];
    
    if (!validLengths.includes(words.length)) return false;
    
    // Check if words look valid
    const validWords = words.filter(w => /^[a-z]{3,8}$/.test(w));
    if (validWords.length !== words.length) return false;
    
    // Check against our wordlist sample
    const matchCount = words.filter(w => BIP39_WORDLIST_SAMPLE.includes(w)).length;
    return matchCount >= words.length * 0.4; // 40% threshold since we have partial list
}

export interface MnemonicCheckResult {
    mnemonic: string;
    wordCount: number;
    isValid: boolean;
    derivedAddresses: {
        path: string;
        address: string;
        balanceResult?: WalletCheckResult;
    }[];
    totalChains: number;
    chainsWithBalance: number;
    hasValue: boolean;
    checkTime: Date;
}

/**
 * Check mnemonic phrase by deriving addresses and checking balances
 * Note: Full BIP-39 derivation requires crypto libraries
 * This implementation prompts user for derived address or uses common patterns
 */
export async function checkMnemonicBalances(
    mnemonic: string,
    knownAddresses?: string[]
): Promise<MnemonicCheckResult> {
    const words = mnemonic.toLowerCase().trim().split(/\s+/);
    
    const result: MnemonicCheckResult = {
        mnemonic: mnemonic,
        wordCount: words.length,
        isValid: isMnemonicPhrase(mnemonic),
        derivedAddresses: [],
        totalChains: Object.keys(PUBLIC_RPCS).length,
        chainsWithBalance: 0,
        hasValue: false,
        checkTime: new Date()
    };
    
    // If known addresses provided, check those
    const addressesToCheck = knownAddresses || [];
    
    // Common derivation paths
    const derivationPaths = [
        "m/44'/60'/0'/0/0",  // Ethereum default (MetaMask, etc.)
        "m/44'/60'/0'/0/1",  // Second account
        "m/44'/60'/0'/0/2",  // Third account
    ];
    
    // Check each address
    for (let i = 0; i < addressesToCheck.length; i++) {
        const address = addressesToCheck[i];
        if (!address || !address.startsWith('0x') || address.length !== 42) continue;
        
        const balanceResult = await checkAllBalances(address);
        
        result.derivedAddresses.push({
            path: derivationPaths[i] || `Address ${i + 1}`,
            address: address,
            balanceResult: balanceResult
        });
        
        if (balanceResult.isLive) {
            result.hasValue = true;
            result.chainsWithBalance += balanceResult.chainsWithBalance;
        }
    }
    
    return result;
}

export default {
    // Chain configs
    PUBLIC_RPCS,
    SOLANA_RPCS,
    BITCOIN_APIS,
    ERC20_TOKENS,
    
    // Address derivation
    deriveAddress,
    
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
    
    // Validation
    isPlaceholderAddress,
    
    // Mnemonic
    isMnemonicPhrase,
    checkMnemonicBalances,
    
    // Filtering & quick checks
    quickKeyCheck,
    checkTextForFundedAddresses,
    filterFindingsWithBalance,
};

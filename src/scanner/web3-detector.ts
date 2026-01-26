// STRIX Web3 Detector
// Detects blockchain/Web3 integrations on websites (Ethereum, Solana, and more)

import type { Web3Detection, DetectedContract, ScriptInfo, SecretFinding } from './types';

// Common Web3 patterns to detect
const WEB3_PATTERNS = {
    // Provider detection - Ethereum
    providers: [
        /window\.ethereum/gi,
        /window\.web3/gi,
        /ethereum\.request/gi,
        /ethereum\.send/gi,
        /ethereum\.on\(/gi,
        /ethereum\.selectedAddress/gi,
        /ethereum\.chainId/gi,
        /MetaMask/gi,
        /WalletConnect/gi,
        /Coinbase\s*Wallet/gi,
        /Trust\s*Wallet/gi,
        /Rainbow/gi,
    ],

    // Provider detection - Solana
    solanaProviders: [
        /window\.solana/gi,
        /window\.phantom/gi,
        /window\.solflare/gi,
        /window\.backpack/gi,
        /Phantom/gi,
        /Solflare/gi,
        /Backpack/gi,
        /Slope\s*Wallet/gi,
        /Glow\s*Wallet/gi,
        /solana\.connect/gi,
        /solana\.signTransaction/gi,
        /solana\.signAllTransactions/gi,
        /solana\.signMessage/gi,
        /solana\.publicKey/gi,
    ],

    // Contract interactions - Ethereum
    contracts: [
        /new\s+ethers\.Contract\(/gi,
        /new\s+web3\.eth\.Contract\(/gi,
        /\.methods\.\w+\(/gi,
        /contract\.call\(/gi,
        /contract\.send\(/gi,
        /\.estimateGas\(/gi,
        /\.encodeABI\(/gi,
        /abi\s*:\s*\[/gi,
        /parseAbi|parseAbiItem/gi,
    ],

    // Contract interactions - Solana
    solanaContracts: [
        /new\s+PublicKey\(/gi,
        /PublicKey\.findProgramAddressSync/gi,
        /new\s+Program\(/gi,
        /program\.methods/gi,
        /program\.account/gi,
        /program\.rpc/gi,
        /anchorProvider/gi,
        /AnchorProvider/gi,
        /Instruction/gi,
        /TransactionInstruction/gi,
        /SystemProgram/gi,
        /TokenProgram/gi,
        /AssociatedTokenProgram/gi,
        /\.programId/gi,
        /IDL|idl/g,
    ],

    // Wallet operations - Ethereum
    wallet: [
        /eth_requestAccounts/gi,
        /eth_accounts/gi,
        /eth_sendTransaction/gi,
        /eth_signTransaction/gi,
        /eth_sign/gi,
        /personal_sign/gi,
        /eth_signTypedData/gi,
        /wallet_addEthereumChain/gi,
        /wallet_switchEthereumChain/gi,
    ],

    // Libraries - Ethereum
    libraries: [
        { pattern: /ethers\.js|from\s+['"]ethers['"]/gi, name: 'ethers.js', chain: 'ethereum' },
        { pattern: /web3\.js|from\s+['"]web3['"]/gi, name: 'web3.js', chain: 'ethereum' },
        { pattern: /@wagmi|wagmi/gi, name: 'wagmi', chain: 'ethereum' },
        { pattern: /viem/gi, name: 'viem', chain: 'ethereum' },
        { pattern: /@rainbow-me\/rainbowkit/gi, name: 'RainbowKit', chain: 'ethereum' },
        { pattern: /@web3modal/gi, name: 'Web3Modal', chain: 'ethereum' },
        { pattern: /@walletconnect/gi, name: 'WalletConnect', chain: 'ethereum' },
        { pattern: /useDApp/gi, name: 'useDApp', chain: 'ethereum' },
        { pattern: /moralis/gi, name: 'Moralis', chain: 'ethereum' },
        { pattern: /alchemy-sdk/gi, name: 'Alchemy SDK', chain: 'ethereum' },
        { pattern: /thirdweb/gi, name: 'Thirdweb', chain: 'ethereum' },
        { pattern: /@openzeppelin/gi, name: 'OpenZeppelin', chain: 'ethereum' },
    ],

    // Libraries - Solana
    solanaLibraries: [
        { pattern: /@solana\/web3\.js|solana\/web3/gi, name: '@solana/web3.js', chain: 'solana' },
        { pattern: /@solana\/spl-token/gi, name: '@solana/spl-token', chain: 'solana' },
        { pattern: /@solana\/wallet-adapter/gi, name: '@solana/wallet-adapter', chain: 'solana' },
        { pattern: /@project-serum\/anchor|@coral-xyz\/anchor/gi, name: 'Anchor', chain: 'solana' },
        { pattern: /@metaplex/gi, name: 'Metaplex', chain: 'solana' },
        { pattern: /raydium-sdk|@raydium-io/gi, name: 'Raydium SDK', chain: 'solana' },
        { pattern: /@jup-ag|jupiter-core/gi, name: 'Jupiter', chain: 'solana' },
        { pattern: /orca-sdk|@orca-so/gi, name: 'Orca', chain: 'solana' },
        { pattern: /marinade/gi, name: 'Marinade', chain: 'solana' },
        { pattern: /@switchboard-xyz/gi, name: 'Switchboard', chain: 'solana' },
        { pattern: /@pythnetwork/gi, name: 'Pyth Oracle', chain: 'solana' },
    ],

    // DeFi specific patterns
    defiPatterns: [
        { pattern: /swap|Swap|SWAP/g, name: 'Swap functionality' },
        { pattern: /liquidity|Liquidity|addLiquidity|removeLiquidity/gi, name: 'Liquidity pools' },
        { pattern: /stake|Stake|staking|unstake/gi, name: 'Staking' },
        { pattern: /farm|Farm|farming|yield/gi, name: 'Yield farming' },
        { pattern: /lend|borrow|Lending|Borrowing/gi, name: 'Lending/Borrowing' },
        { pattern: /apy|APY|apr|APR/g, name: 'Yield display' },
        { pattern: /slippage|Slippage/gi, name: 'Slippage settings' },
        { pattern: /priceImpact|price.?impact/gi, name: 'Price impact' },
        { pattern: /amm|AMM|constantProduct/gi, name: 'AMM' },
        { pattern: /oracle|Oracle|priceFeed/gi, name: 'Oracle integration' },
    ],

    // Blockchain networks
    chains: [
        { pattern: /chainId.*0x1\b|chainId.*["']1["']/gi, chainId: 1, name: 'Ethereum' },
        { pattern: /chainId.*0x89|chainId.*["']137["']/gi, chainId: 137, name: 'Polygon' },
        { pattern: /chainId.*0xa4b1|chainId.*["']42161["']/gi, chainId: 42161, name: 'Arbitrum' },
        { pattern: /chainId.*0xa|chainId.*["']10["']/gi, chainId: 10, name: 'Optimism' },
        { pattern: /chainId.*0x38|chainId.*["']56["']/gi, chainId: 56, name: 'BSC' },
        { pattern: /chainId.*0x2105|chainId.*["']8453["']/gi, chainId: 8453, name: 'Base' },
        { pattern: /chainId.*0xa86a|chainId.*["']43114["']/gi, chainId: 43114, name: 'Avalanche' },
        { pattern: /mainnet-beta|devnet|testnet/gi, chainId: -1, name: 'Solana' },
        { pattern: /solana|Solana|SOL/g, chainId: -1, name: 'Solana' },
    ],
};

// Ethereum address pattern (40 hex chars)
const ETH_ADDRESS_PATTERN = /0x[a-fA-F0-9]{40}/g;

// Solana address pattern (base58, 32-44 chars, starts with specific chars)
const SOLANA_ADDRESS_PATTERN = /[1-9A-HJ-NP-Za-km-z]{32,44}/g;

// Known Solana program IDs
const KNOWN_SOLANA_PROGRAMS: Record<string, string> = {
    '11111111111111111111111111111111': 'System Program',
    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': 'Token Program',
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL': 'Associated Token Program',
    'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s': 'Metaplex Token Metadata',
    '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': 'Raydium AMM V4',
    'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK': 'Raydium CLMM',
    'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc': 'Orca Whirlpool',
    '9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP': 'Orca Swap V2',
    'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4': 'Jupiter V6',
    'srmqPvymJeFKQ4zGQed1GFppgkRHL9kaELCbyksJtPX': 'Serum DEX V3',
    'mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68': 'Marinade Finance',
};

// Known vulnerable Solana programs/patterns
const SOLANA_VULN_PATTERNS = [
    { pattern: /invoke_signed|invoke/gi, severity: 'info', title: 'Cross-program invocation', desc: 'CPI detected - verify proper signer checks' },
    { pattern: /unchecked_account|UncheckedAccount/gi, severity: 'high', title: 'Unchecked account usage', desc: 'Unchecked accounts can lead to vulnerabilities' },
    { pattern: /set_authority|SetAuthority/gi, severity: 'medium', title: 'Authority change', desc: 'Authority modification detected' },
    { pattern: /close_account|CloseAccount/gi, severity: 'info', title: 'Account closure', desc: 'Account closure detected' },
];

// IPFS patterns
const IPFS_PATTERNS = [
    /ipfs:\/\/[a-zA-Z0-9]+/gi,
    /ipfs\.io\/ipfs\/[a-zA-Z0-9]+/gi,
    /gateway\.pinata\.cloud\/ipfs\/[a-zA-Z0-9]+/gi,
    /cloudflare-ipfs\.com\/ipfs\/[a-zA-Z0-9]+/gi,
    /Qm[a-zA-Z0-9]{44}/g, // IPFS CIDv0
    /bafy[a-zA-Z0-9]+/gi, // IPFS CIDv1
];

// ENS patterns
const ENS_PATTERN = /[a-zA-Z0-9-]+\.eth\b/gi;

// RPC endpoint patterns
const RPC_PATTERNS = [
    /https?:\/\/[^"'\s]+mainnet\.infura\.io[^"'\s]*/gi,
    /https?:\/\/[^"'\s]+alchemy\.com[^"'\s]*/gi,
    /https?:\/\/[^"'\s]+quiknode\.pro[^"'\s]*/gi,
    /https?:\/\/rpc\.[^"'\s]+/gi,
    /https?:\/\/[^"'\s]+\.rpc\.[^"'\s]+/gi,
];

// Service identification from context
interface ServiceInfo {
    name: string;
    description: string;
    impact: string;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

// Map of keywords to service info with appropriate severity
const SERVICE_IDENTIFIERS: Record<string, ServiceInfo & { severity: 'critical' | 'high' | 'medium' | 'low' | 'info' }> = {
    // CRITICAL - Direct fund/account access
    'private': { name: 'Private Key', description: 'Wallet Private Key', impact: 'CRITICAL - Full wallet access, can drain ALL funds immediately', severity: 'critical' },
    'mnemonic': { name: 'Seed Phrase', description: 'Wallet Recovery Phrase', impact: 'CRITICAL - Can derive all wallet addresses and drain ALL funds', severity: 'critical' },
    'coinbase': { name: 'Coinbase', description: 'Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access depending on key permissions', severity: 'critical' },
    'binance': { name: 'Binance', description: 'Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access depending on key permissions', severity: 'critical' },
    'stripe': { name: 'Stripe', description: 'Payment Processor', impact: 'CRITICAL - May allow refunds, payment operations, or access to financial data', severity: 'critical' },

    // HIGH - Infrastructure/database access
    'aws': { name: 'AWS', description: 'Amazon Web Services', impact: 'HIGH - Cloud infrastructure access, potential server compromise, data exposure, or resource abuse', severity: 'high' },
    'firebase': { name: 'Firebase', description: 'Google Firebase', impact: 'HIGH - Database read/write access, authentication bypass, potential data exposure', severity: 'high' },
    'secret': { name: 'Secret Key', description: 'Application Secret', impact: 'HIGH - May allow authentication bypass, session hijacking, or privileged access', severity: 'high' },

    // MEDIUM - Rate limit abuse, billing impact, but NO fund access
    'infura': { name: 'Infura', description: 'Ethereum RPC Node Provider', impact: 'MEDIUM - Rate limit abuse, billing impact if on paid plan. Cannot access funds or sign transactions.', severity: 'medium' },
    'alchemy': { name: 'Alchemy', description: 'Web3 Development Platform', impact: 'MEDIUM - API quota abuse, billing impact. Read-only blockchain access, cannot move funds.', severity: 'medium' },
    'quicknode': { name: 'QuickNode', description: 'Blockchain Node Provider', impact: 'MEDIUM - RPC quota abuse across chains. Cannot access wallets or sign transactions.', severity: 'medium' },
    'moralis': { name: 'Moralis', description: 'Web3 Data API', impact: 'MEDIUM - API quota abuse for NFT/token data queries. Read-only access.', severity: 'medium' },
    'ankr': { name: 'Ankr', description: 'Multi-chain RPC Provider', impact: 'MEDIUM - RPC quota abuse. Cannot access wallets or sign transactions.', severity: 'medium' },
    'chainstack': { name: 'Chainstack', description: 'Blockchain Infrastructure', impact: 'MEDIUM - Node access quota abuse. Cannot access wallets or sign transactions.', severity: 'medium' },
    'getblock': { name: 'GetBlock', description: 'Blockchain Node Provider', impact: 'MEDIUM - RPC quota abuse. Cannot access wallets or sign transactions.', severity: 'medium' },
    'sendgrid': { name: 'SendGrid', description: 'Email API Service', impact: 'MEDIUM - Can send emails as the account, potential phishing/spam abuse.', severity: 'medium' },
    'twilio': { name: 'Twilio', description: 'SMS/Voice API', impact: 'MEDIUM - Can send SMS/calls, potential billing abuse and spam.', severity: 'medium' },
    'mailchimp': { name: 'Mailchimp', description: 'Email Marketing', impact: 'MEDIUM - Access to mailing lists, potential spam abuse.', severity: 'medium' },

    // HIGH - Significant access but may have limited scopes
    'github': { name: 'GitHub', description: 'GitHub Personal Access Token', impact: 'HIGH - Repository access, potential code modification or data exposure depending on scopes.', severity: 'high' },
    'gitlab': { name: 'GitLab', description: 'GitLab Access Token', impact: 'HIGH - Repository access, potential code modification or data exposure.', severity: 'high' },
    'slack': { name: 'Slack', description: 'Slack Token/Webhook', impact: 'HIGH - Workspace access, can read/send messages, potential data exposure.', severity: 'high' },
    'discord': { name: 'Discord', description: 'Discord Bot Token/Webhook', impact: 'MEDIUM - Can post messages to channels, bot account access.', severity: 'medium' },
    'telegram': { name: 'Telegram', description: 'Telegram Bot Token', impact: 'MEDIUM - Bot access, can send messages and access bot data.', severity: 'medium' },

    // CRITICAL - Exchange APIs
    'kraken': { name: 'Kraken', description: 'Kraken Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'kucoin': { name: 'KuCoin', description: 'KuCoin Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'bybit': { name: 'Bybit', description: 'Bybit Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'okx': { name: 'OKX', description: 'OKX Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'gateio': { name: 'Gate.io', description: 'Gate.io Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'ftx': { name: 'FTX', description: 'FTX Exchange API (defunct)', impact: 'INFO - FTX is defunct, key is useless.', severity: 'low' },
    'huobi': { name: 'Huobi/HTX', description: 'HTX Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'gemini': { name: 'Gemini', description: 'Gemini Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },
    'bitfinex': { name: 'Bitfinex', description: 'Bitfinex Exchange API', impact: 'CRITICAL - May allow trading, withdrawals, or fund access.', severity: 'critical' },

    // LOW - Minimal impact, often intended to be public
    'etherscan': { name: 'Etherscan', description: 'Block Explorer API', impact: 'LOW - Rate limit abuse only. All blockchain data is already public.', severity: 'low' },
    'opensea': { name: 'OpenSea', description: 'NFT Marketplace API', impact: 'LOW - API quota abuse for NFT queries. Public data access only.', severity: 'low' },
    'thirdweb': { name: 'Thirdweb', description: 'Web3 SDK Platform', impact: 'LOW - SDK access, typically client-side keys are expected to be public.', severity: 'low' },
    'google': { name: 'Google API', description: 'Google API Key', impact: 'LOW-HIGH - Depends on enabled APIs. Could allow billing abuse or data access.', severity: 'medium' },
    'mapbox': { name: 'Mapbox', description: 'Mapbox API', impact: 'LOW - Map tile quota abuse, billing impact.', severity: 'low' },
    'openai': { name: 'OpenAI', description: 'OpenAI API Key', impact: 'HIGH - Potential billing abuse and access to trained models/data.', severity: 'high' },
    'anthropic': { name: 'Anthropic', description: 'Anthropic/Claude API Key', impact: 'HIGH - Potential billing abuse and access to AI models.', severity: 'high' },
    'huggingface': { name: 'HuggingFace', description: 'HuggingFace API Key', impact: 'MEDIUM-HIGH - Access to private models and datasets.', severity: 'high' },
    'digitalocean': { name: 'DigitalOcean', description: 'DigitalOcean API Token', impact: 'CRITICAL - Full cloud infrastructure management, potential server compromise.', severity: 'critical' },
    'pagerduty': { name: 'PagerDuty', description: 'PagerDuty API Key', impact: 'HIGH - Incident management control, potential security bypass.', severity: 'high' },
    'algolia': { name: 'Algolia', description: 'Algolia Admin API Key', impact: 'HIGH - Can delete/modify search indices and data.', severity: 'high' },
    'mailgun': { name: 'Mailgun', description: 'Mailgun API Key', impact: 'MEDIUM-HIGH - Can send emails, manage domains, access logs.', severity: 'high' },
};

// Secret patterns (Web3 specific) - STRICT matching to avoid false positives
const SECRET_PATTERNS = [
    // Only flag private keys if they have explicit context
    {
        pattern: /(?:private[_-]?key|secret[_-]?key|wallet[_-]?key|signing[_-]?key)['":\s=]+['"]?(0x[a-fA-F0-9]{64}|[a-fA-F0-9]{64})['"]?/gi,
        type: 'private_key' as const,
        confidence: 'high' as const,
        serviceHint: 'private'
    },
    // Mnemonic phrases (12 or 24 words)
    {
        pattern: /(?:mnemonic|seed[_-]?phrase|recovery[_-]?phrase)['":\s=]+['"]?([a-z]+(?:\s+[a-z]+){11,23})['"]?/gi,
        type: 'wallet' as const,
        confidence: 'high' as const,
        serviceHint: 'mnemonic'
    },

    // ============ RPC URL PATTERNS (keys embedded in URLs) ============
    // Alchemy RPC URLs: https://eth-mainnet.g.alchemy.com/v2/API_KEY
    {
        pattern: /https?:\/\/[a-z0-9-]+\.g\.alchemy\.com\/v2\/([a-zA-Z0-9_-]{20,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'alchemy'
    },
    // Alchemy WebSocket: wss://eth-mainnet.g.alchemy.com/v2/API_KEY
    {
        pattern: /wss?:\/\/[a-z0-9-]+\.g\.alchemy\.com\/v2\/([a-zA-Z0-9_-]{20,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'alchemy'
    },
    // Infura RPC URLs: https://mainnet.infura.io/v3/API_KEY
    {
        pattern: /https?:\/\/[a-z0-9-]+\.infura\.io\/v3\/([a-fA-F0-9]{32})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'infura'
    },
    // Infura WebSocket: wss://mainnet.infura.io/ws/v3/API_KEY
    {
        pattern: /wss?:\/\/[a-z0-9-]+\.infura\.io\/(?:ws\/)?v3\/([a-fA-F0-9]{32})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'infura'
    },
    // QuickNode RPC URLs: https://xxx.quiknode.pro/API_KEY/
    {
        pattern: /https?:\/\/[a-z0-9-]+\.(?:quiknode|quicknode)\.pro\/([a-zA-Z0-9]{20,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'quicknode'
    },
    // Moralis RPC URLs
    {
        pattern: /https?:\/\/[a-z0-9-]+\.moralis\.io\/([a-zA-Z0-9]{20,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'moralis'
    },
    // Ankr RPC URLs
    {
        pattern: /https?:\/\/rpc\.ankr\.com\/[a-z0-9_]+\/([a-zA-Z0-9]{32,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'ankr'
    },
    // Chainstack RPC URLs
    {
        pattern: /https?:\/\/[a-z0-9-]+\.p\.chainstack\.com\/([a-zA-Z0-9]{20,})/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'chainstack'
    },
    // GetBlock RPC URLs
    {
        pattern: /https?:\/\/[a-z]+\.getblock\.io\/([a-zA-Z0-9-]{32,})\/mainnet/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'getblock'
    },

    // ============ LABELED KEY PATTERNS ============
    // API Keys with explicit labels - case insensitive
    {
        pattern: /infura[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'infura'
    },
    {
        pattern: /alchemy[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'alchemy'
    },
    {
        pattern: /etherscan[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'etherscan'
    },
    {
        pattern: /moralis[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'moralis'
    },
    {
        pattern: /quicknode[_-]?(?:api[_-]?)?(?:key|url)['":\s=]+['"]?([a-zA-Z0-9_\-\.\/\:]+)['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'quicknode'
    },
    {
        pattern: /opensea[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'opensea'
    },
    // AWS/Cloud keys
    {
        pattern: /(?:aws[_-]?)?(?:secret[_-]?)?access[_-]?key[_-]?(?:id)?['":\s=]+['"]?([A-Za-z0-9\/+=]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'aws'
    },
    // Firebase
    {
        pattern: /firebase[_-]?(?:api[_-]?)?key['":\s=]+['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'firebase'
    },
    // Generic but labeled API keys
    {
        pattern: /['"](api[_-]?key|apikey)['"]\s*:\s*['"]([a-zA-Z0-9_-]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'medium' as const,
        serviceHint: undefined
    },

    // ============ EXCHANGE API KEYS ============
    // Binance
    {
        pattern: /binance[_-]?(?:api[_-]?)?key['":\s=]+['"]?([A-Za-z0-9]{64})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'binance'
    },
    {
        pattern: /binance[_-]?(?:api[_-]?)?secret['":\s=]+['"]?([A-Za-z0-9]{64})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'binance'
    },
    // Coinbase
    {
        pattern: /coinbase[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9+\/=]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'coinbase'
    },
    // Kraken
    {
        pattern: /kraken[_-]?(?:api[_-]?)?(?:key|secret|private)['":\s=]+['"]?([A-Za-z0-9+\/=]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'kraken'
    },
    // KuCoin
    {
        pattern: /kucoin[_-]?(?:api[_-]?)?(?:key|secret|passphrase)['":\s=]+['"]?([A-Za-z0-9-]{16,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'kucoin'
    },
    // Bybit
    {
        pattern: /bybit[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9]{16,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'bybit'
    },
    // OKX/OKEx
    {
        pattern: /ok(?:x|ex)[_-]?(?:api[_-]?)?(?:key|secret|passphrase)['":\s=]+['"]?([A-Za-z0-9-]{16,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'okx'
    },
    // Gate.io
    {
        pattern: /gate(?:io)?[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9]{16,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'gateio'
    },
    // Huobi/HTX
    {
        pattern: /(?:huobi|htx)[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9-]{16,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'huobi'
    },
    // Gemini
    {
        pattern: /gemini[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'gemini'
    },
    // Bitfinex
    {
        pattern: /bitfinex[_-]?(?:api[_-]?)?(?:key|secret)['":\s=]+['"]?([A-Za-z0-9]{20,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'bitfinex'
    },

    // ============ GITHUB/GIT TOKENS ============
    // GitHub PAT (classic and fine-grained)
    {
        pattern: /ghp_[A-Za-z0-9]{36}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'github'
    },
    {
        pattern: /gho_[A-Za-z0-9]{36}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'github'
    },
    {
        pattern: /ghu_[A-Za-z0-9]{36}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'github'
    },
    {
        pattern: /ghs_[A-Za-z0-9]{36}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'github'
    },
    {
        pattern: /github_pat_[A-Za-z0-9_]{22,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'github'
    },
    // GitLab tokens
    {
        pattern: /glpat-[A-Za-z0-9_-]{20}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'gitlab'
    },

    // ============ PAYMENT/COMMUNICATION SERVICES ============
    // Stripe
    {
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'stripe'
    },
    {
        pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
        type: 'api_key' as const,
        confidence: 'medium' as const,
        serviceHint: 'stripe'
    },
    {
        pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'stripe'
    },
    // SendGrid
    {
        pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'sendgrid'
    },
    // Twilio
    {
        pattern: /twilio[_-]?(?:account[_-]?sid|auth[_-]?token)['":\s=]+['"]?([A-Za-z0-9]{32,})['"]?/gi,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'twilio'
    },
    {
        pattern: /SK[a-f0-9]{32}/g,
        type: 'api_key' as const,
        confidence: 'medium' as const,
        serviceHint: 'twilio'
    },
    // Mailchimp
    {
        pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'mailchimp'
    },

    // ============ MESSAGING/SOCIAL ============
    // Slack
    {
        pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'slack'
    },
    {
        pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'slack'
    },
    // Discord webhooks
    {
        pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'discord'
    },
    // Discord bot token
    {
        pattern: /[MN][A-Za-z0-9]{23,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'discord'
    },
    // Telegram bot token
    {
        pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'telegram'
    },

    // ============ CLOUD/MISC ============
    // Google API Key
    {
        pattern: /AIza[A-Za-z0-9_-]{35}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'google'
    },
    // Mapbox
    {
        pattern: /pk\.[A-Za-z0-9]{60,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'mapbox'
    },
    {
        pattern: /sk\.[A-Za-z0-9]{60,}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'mapbox'
    },
    // NPM tokens
    {
        pattern: /npm_[A-Za-z0-9]{36}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'npm'
    },
    // Heroku
    {
        pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
        type: 'api_key' as const,
        confidence: 'low' as const,
        serviceHint: undefined // UUIDs are common, low confidence
    },
    // OpenAI
    {
        pattern: /sk-[a-zA-Z0-9]{48}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'openai'
    },
    // Anthropic
    {
        pattern: /sk-ant-sid01-[a-zA-Z0-9_-]{93}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'anthropic'
    },
    // HuggingFace
    {
        pattern: /hf_[a-zA-Z0-9]{34}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'huggingface'
    },
    // DigitalOcean
    {
        pattern: /dop_v1_[a-z0-9]{64}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'digitalocean'
    },
    // PagerDuty
    {
        pattern: /pd[a-z0-9]{20}/g,
        type: 'api_key' as const,
        confidence: 'medium' as const,
        serviceHint: 'pagerduty'
    },
    // Mailgun
    {
        pattern: /key-[a-z0-9]{32}/g,
        type: 'api_key' as const,
        confidence: 'high' as const,
        serviceHint: 'mailgun'
    },
];

// Known false positives to exclude
const FALSE_POSITIVE_PATTERNS = [
    /^0{10,}/,           // Strings of zeros
    /^f{10,}/i,          // Strings of f's
    /test|example|sample|dummy|placeholder|mock/i,  // Test values
    /^[0-9]+$/,          // Pure numbers (not hex)
    /deadline|timestamp|expir|block|nonce/i,  // Common blockchain data fields
];

/**
 * Analyze script content for Web3 patterns
 */
export function analyzeScript(content: string, src?: string): ScriptInfo {
    const libraries: string[] = [];
    const suspiciousPatterns: string[] = [];
    let hasWeb3 = false;

    // Check for Web3 providers
    for (const pattern of WEB3_PATTERNS.providers) {
        if (pattern.test(content)) {
            hasWeb3 = true;
            break;
        }
    }

    // Check for libraries
    for (const lib of WEB3_PATTERNS.libraries) {
        if (lib.pattern.test(content)) {
            libraries.push(lib.name);
            hasWeb3 = true;
        }
    }

    // Check for contract interactions
    for (const pattern of WEB3_PATTERNS.contracts) {
        if (pattern.test(content)) {
            hasWeb3 = true;
            break;
        }
    }

    // Check for suspicious patterns
    if (/eval\s*\(/gi.test(content)) {
        suspiciousPatterns.push('eval() usage detected');
    }
    if (/document\.write/gi.test(content)) {
        suspiciousPatterns.push('document.write() usage');
    }
    if (/innerHTML\s*=/gi.test(content) && /\+/g.test(content)) {
        suspiciousPatterns.push('Potential DOM XSS via innerHTML');
    }
    if (/fromCharCode/gi.test(content) && /eval|Function/gi.test(content)) {
        suspiciousPatterns.push('Obfuscated code execution');
    }

    return {
        src,
        inline: !src,
        hasWeb3,
        libraries,
        suspiciousPatterns
    };
}

/**
 * Extract contract addresses from content
 */
export function extractContracts(content: string): DetectedContract[] {
    const contracts: DetectedContract[] = [];
    const addresses = new Set<string>();

    // Find all Ethereum addresses
    const matches = content.match(ETH_ADDRESS_PATTERN) || [];

    for (const address of matches) {
        // Skip if already found or if it's all zeros/ones (placeholder)
        if (addresses.has(address.toLowerCase())) continue;
        if (/^0x0+$/.test(address) || /^0xf+$/i.test(address)) continue;

        addresses.add(address.toLowerCase());

        // Try to detect contract type from context
        let type: DetectedContract['type'] = 'unknown';
        const contextPattern = new RegExp(`['"]?${address}['"]?[^}]{0,200}`, 'gi');
        const context = content.match(contextPattern)?.[0] || '';

        if (/erc20|token|transfer|balanceOf/i.test(context)) {
            type = 'erc20';
        } else if (/erc721|nft|tokenURI|ownerOf/i.test(context)) {
            type = 'erc721';
        } else if (/erc1155|balanceOfBatch/i.test(context)) {
            type = 'erc1155';
        } else if (/swap|pool|liquidity|router|factory/i.test(context)) {
            type = 'defi';
        }

        // Detect chain from context
        let chainId = 1; // Default to mainnet
        let chain = 'ethereum';

        for (const chainPattern of WEB3_PATTERNS.chains) {
            const chainContext = content.substring(
                Math.max(0, content.indexOf(address) - 500),
                content.indexOf(address) + 500
            );
            if (chainPattern.pattern.test(chainContext)) {
                chainId = chainPattern.chainId;
                chain = chainPattern.name.toLowerCase();
                break;
            }
        }

        // Extract function names near the address
        const functions: string[] = [];
        const funcPattern = /\.(?:methods\.)?(\w+)\s*\(/g;
        let funcMatch;
        while ((funcMatch = funcPattern.exec(context)) !== null) {
            if (!functions.includes(funcMatch[1])) {
                functions.push(funcMatch[1]);
            }
        }

        contracts.push({
            address,
            chain,
            chainId,
            type,
            functions
        });
    }

    return contracts;
}

/**
 * Extract secrets from content - with strict validation to avoid false positives
 */
export function extractSecrets(content: string, location: string): SecretFinding[] {
    const secrets: SecretFinding[] = [];
    const seen = new Set<string>();

    for (const secretPattern of SECRET_PATTERNS) {
        // Use matchAll to get capture groups properly
        const regex = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags);
        const matches = content.matchAll(regex);

        for (const match of matches) {
            // Get the captured value (group 1) or the full match
            const value = match[1] || match[0];

            // Skip if already seen
            if (seen.has(value)) continue;
            seen.add(value);

            // Validate - skip false positives
            let isFalsePositive = false;
            for (const fpPattern of FALSE_POSITIVE_PATTERNS) {
                if (fpPattern.test(value) || fpPattern.test(match[0])) {
                    isFalsePositive = true;
                    break;
                }
            }
            if (isFalsePositive) continue;

            // For private keys, verify it's actually hex
            if (secretPattern.type === 'private_key') {
                const hexValue = value.startsWith('0x') ? value.slice(2) : value;
                // Must be exactly 64 hex characters
                if (!/^[a-fA-F0-9]{64}$/.test(hexValue)) continue;
                // Skip if it looks like a transaction hash (usually has more even distribution)
                // Real private keys are random, but we can't easily detect that
            }

            // For mnemonic phrases, verify word count
            if (secretPattern.type === 'wallet') {
                const words = value.trim().split(/\s+/);
                if (words.length !== 12 && words.length !== 24) continue;
            }

            // Identify service - first try the pattern's serviceHint, then scan context
            let service: (ServiceInfo & { severity?: string }) | undefined;
            const patternServiceHint = (secretPattern as any).serviceHint;

            if (patternServiceHint && SERVICE_IDENTIFIERS[patternServiceHint]) {
                service = SERVICE_IDENTIFIERS[patternServiceHint];
            } else {
                // Fall back to scanning context for service keywords
                const contextLower = match[0].toLowerCase();
                for (const [keyword, info] of Object.entries(SERVICE_IDENTIFIERS)) {
                    if (contextLower.includes(keyword)) {
                        service = info;
                        break;
                    }
                }
            }

            // Get extended context - find surrounding code
            const matchIndex = content.indexOf(match[0]);
            const contextStart = Math.max(0, matchIndex - 100);
            const contextEnd = Math.min(content.length, matchIndex + match[0].length + 100);
            const extendedContext = content.substring(contextStart, contextEnd);

            // Try to find line number
            const beforeMatch = content.substring(0, matchIndex);
            const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;

            // Show FULL value - this is a security tool, analysts need to verify
            secrets.push({
                type: secretPattern.type,
                value: value, // Full value for security review
                fullValue: value,
                location,
                confidence: secretPattern.confidence,
                context: extendedContext.trim(), // Extended context
                serviceName: service?.name,
                serviceDescription: service?.description,
                serviceImpact: service?.impact,
                serviceSeverity: service?.severity,
                lineNumber
            });
        }
    }

    return secrets;
}

/**
 * Full Web3 detection on page content
 */
/**
 * Extract Solana addresses from content
 */
export function extractSolanaAddresses(content: string): DetectedContract[] {
    const contracts: DetectedContract[] = [];
    const seen = new Set<string>();

    // Find potential Solana addresses (base58, 32-44 chars)
    const matches = content.match(SOLANA_ADDRESS_PATTERN) || [];

    for (const address of matches) {
        // Skip if too short/long or already seen
        if (address.length < 32 || address.length > 44) continue;
        if (seen.has(address)) continue;

        // Skip common false positives (words, hashes that aren't addresses)
        if (/^[a-z]+$/i.test(address)) continue; // All letters = probably a word
        if (address.length < 40 && !/[1-9]/.test(address)) continue; // Needs numbers

        seen.add(address);

        // Check if it's a known program
        const knownProgram = KNOWN_SOLANA_PROGRAMS[address];

        contracts.push({
            address,
            chain: 'solana',
            chainId: -1,
            type: knownProgram ? 'defi' : 'unknown',
            name: knownProgram,
            functions: [],
            verified: !!knownProgram
        });
    }

    return contracts;
}

export function detectWeb3(html: string, scripts: string[]): Web3Detection {
    const result: Web3Detection = {
        hasWeb3: false,
        contracts: [],
        walletConnections: [],
        chainIds: [],
        rpcEndpoints: [],
        ipfsLinks: [],
        ensNames: []
    };

    const allContent = html + '\n' + scripts.join('\n');
    const detectedChains: string[] = [];
    const detectedLibraries: string[] = [];
    const detectedFeatures: string[] = [];

    // === ETHEREUM DETECTION ===

    // Detect Ethereum providers
    for (const pattern of WEB3_PATTERNS.providers) {
        if (pattern.test(allContent)) {
            result.hasWeb3 = true;
            detectedChains.push('ethereum');
            const providerMatch = allContent.match(pattern);
            if (providerMatch && !result.provider) {
                if (/MetaMask/i.test(providerMatch[0])) result.provider = 'MetaMask';
                else if (/WalletConnect/i.test(providerMatch[0])) result.provider = 'WalletConnect';
                else if (/Coinbase/i.test(providerMatch[0])) result.provider = 'Coinbase Wallet';
            }
            break;
        }
    }

    // Detect Ethereum libraries
    for (const lib of WEB3_PATTERNS.libraries) {
        if (lib.pattern.test(allContent)) {
            result.hasWeb3 = true;
            detectedChains.push('ethereum');
            if (!detectedLibraries.includes(lib.name)) {
                detectedLibraries.push(lib.name);
            }
        }
    }

    // Detect Ethereum wallet operations
    for (const pattern of WEB3_PATTERNS.wallet) {
        const matches = allContent.match(pattern) || [];
        for (const match of matches) {
            if (!result.walletConnections.includes(match)) {
                result.walletConnections.push(match.replace(/['"]/g, ''));
            }
        }
    }

    // Extract Ethereum contracts
    const ethContracts = extractContracts(allContent);
    result.contracts.push(...ethContracts);

    // === SOLANA DETECTION ===

    // Detect Solana providers
    for (const pattern of WEB3_PATTERNS.solanaProviders) {
        if (pattern.test(allContent)) {
            result.hasWeb3 = true;
            detectedChains.push('solana');
            const providerMatch = allContent.match(pattern);
            if (providerMatch && !result.provider) {
                if (/Phantom/i.test(providerMatch[0])) result.provider = 'Phantom';
                else if (/Solflare/i.test(providerMatch[0])) result.provider = 'Solflare';
                else if (/Backpack/i.test(providerMatch[0])) result.provider = 'Backpack';
                else result.provider = 'Solana Wallet';
            }
            break;
        }
    }

    // Detect Solana libraries
    for (const lib of WEB3_PATTERNS.solanaLibraries) {
        if (lib.pattern.test(allContent)) {
            result.hasWeb3 = true;
            detectedChains.push('solana');
            if (!detectedLibraries.includes(lib.name)) {
                detectedLibraries.push(lib.name);
            }
        }
    }

    // Detect Solana contract patterns
    for (const pattern of WEB3_PATTERNS.solanaContracts) {
        if (pattern.test(allContent)) {
            result.hasWeb3 = true;
            detectedChains.push('solana');
        }
    }

    // Extract Solana program addresses
    const solanaContracts = extractSolanaAddresses(allContent);
    result.contracts.push(...solanaContracts);

    // === DEFI FEATURE DETECTION ===

    for (const feature of WEB3_PATTERNS.defiPatterns) {
        if (feature.pattern.test(allContent)) {
            result.hasWeb3 = true;
            if (!detectedFeatures.includes(feature.name)) {
                detectedFeatures.push(feature.name);
            }
        }
    }

    // === CHAIN DETECTION ===

    for (const chain of WEB3_PATTERNS.chains) {
        if (chain.pattern.test(allContent)) {
            result.hasWeb3 = true;
            if (!result.chainIds.includes(chain.chainId)) {
                result.chainIds.push(chain.chainId);
            }
            if (!detectedChains.includes(chain.name.toLowerCase())) {
                detectedChains.push(chain.name.toLowerCase());
            }
        }
    }

    // === RPC ENDPOINTS ===

    for (const pattern of RPC_PATTERNS) {
        const matches = allContent.match(pattern) || [];
        for (const match of matches) {
            if (!result.rpcEndpoints.includes(match)) {
                result.rpcEndpoints.push(match);
            }
        }
    }

    // Solana RPC endpoints
    const solanaRpcPattern = /https?:\/\/[^"'\s]*(solana|helius|quicknode|triton|rpcpool)[^"'\s]*/gi;
    const solanaRpcMatches = allContent.match(solanaRpcPattern) || [];
    for (const match of solanaRpcMatches) {
        if (!result.rpcEndpoints.includes(match)) {
            result.rpcEndpoints.push(match);
            detectedChains.push('solana');
        }
    }

    // === IPFS ===

    for (const pattern of IPFS_PATTERNS) {
        const matches = allContent.match(pattern) || [];
        for (const match of matches) {
            if (!result.ipfsLinks.includes(match)) {
                result.ipfsLinks.push(match);
            }
        }
    }

    // === ENS NAMES ===

    const ensMatches = allContent.match(ENS_PATTERN) || [];
    for (const match of ensMatches) {
        if (!result.ensNames.includes(match) && match !== 'example.eth') {
            result.ensNames.push(match);
        }
    }

    // === FINALIZE ===

    // Store detected info (extend type if needed)
    (result as any).detectedChains = [...new Set(detectedChains)];
    (result as any).detectedLibraries = detectedLibraries;
    (result as any).detectedFeatures = detectedFeatures;

    // If we found contracts or libraries, mark as Web3
    if (result.contracts.length > 0 || detectedLibraries.length > 0) {
        result.hasWeb3 = true;
    }

    return result;
}

export default {
    analyzeScript,
    extractContracts,
    extractSecrets,
    detectWeb3,
    WEB3_PATTERNS,
    SECRET_PATTERNS
};

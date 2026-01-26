// STRIX SAST - Secret Detection Patterns
// Comprehensive patterns for detecting hardcoded secrets, API keys, and credentials

import { SecretPattern, SeverityLevel } from '../types';

// Helper to create patterns with common settings
const createPattern = (
    id: string,
    name: string,
    description: string,
    pattern: RegExp,
    severity: SeverityLevel = 'high',
    keywords?: string[]
): SecretPattern => ({
    id,
    name,
    description,
    pattern,
    severity,
    confidence: 'high',
    keywords,
});

// ============================================
// API Keys and Tokens
// ============================================

export const API_KEY_PATTERNS: SecretPattern[] = [
    // AWS
    {
        id: 'aws-access-key',
        name: 'AWS Access Key ID',
        description: 'AWS Access Key ID that could provide access to AWS services',
        pattern: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['AKIA', 'AWS', 'amazon'],
    },
    {
        id: 'aws-secret-key',
        name: 'AWS Secret Access Key',
        description: 'AWS Secret Access Key for API authentication',
        pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretAccessKey)[\s]*[=:]["']?\s*([A-Za-z0-9/+=]{40})/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['aws_secret', 'secret_access_key'],
    },

    // Google Cloud
    {
        id: 'gcp-api-key',
        name: 'Google Cloud API Key',
        description: 'Google Cloud Platform API Key',
        pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['AIza', 'google', 'gcp'],
    },
    {
        id: 'gcp-service-account',
        name: 'GCP Service Account Key',
        description: 'Google Cloud service account private key',
        pattern: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+-----END (?:RSA )?PRIVATE KEY-----"/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['private_key', 'BEGIN PRIVATE KEY'],
    },

    // Azure
    {
        id: 'azure-storage-key',
        name: 'Azure Storage Account Key',
        description: 'Azure Storage Account access key',
        pattern: /(?:AccountKey|azure_storage_key|storageAccountKey)[\s]*[=:][\s]*["']?([A-Za-z0-9+/=]{88})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['AccountKey', 'azure_storage'],
    },
    {
        id: 'azure-connection-string',
        name: 'Azure Connection String',
        description: 'Azure service connection string with embedded credentials',
        pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['DefaultEndpointsProtocol', 'AccountKey'],
    },

    // GitHub
    {
        id: 'github-pat',
        name: 'GitHub Personal Access Token',
        description: 'GitHub Personal Access Token (classic)',
        pattern: /\b(ghp_[A-Za-z0-9]{36})\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['ghp_', 'github'],
    },
    {
        id: 'github-oauth',
        name: 'GitHub OAuth Access Token',
        description: 'GitHub OAuth application token',
        pattern: /\b(gho_[A-Za-z0-9]{36})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['gho_', 'github'],
    },
    {
        id: 'github-app-token',
        name: 'GitHub App Token',
        description: 'GitHub App installation access token',
        pattern: /\b(ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['ghu_', 'ghs_', 'github'],
    },
    {
        id: 'github-refresh-token',
        name: 'GitHub Refresh Token',
        description: 'GitHub OAuth refresh token',
        pattern: /\b(ghr_[A-Za-z0-9]{36})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['ghr_', 'github'],
    },

    // GitLab
    {
        id: 'gitlab-pat',
        name: 'GitLab Personal Access Token',
        description: 'GitLab Personal Access Token',
        pattern: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['glpat-', 'gitlab'],
    },
    {
        id: 'gitlab-runner-token',
        name: 'GitLab Runner Token',
        description: 'GitLab CI Runner registration token',
        pattern: /\b(GR1348941[A-Za-z0-9\-_]{20,})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['GR1348941', 'gitlab'],
    },

    // Slack
    {
        id: 'slack-token',
        name: 'Slack Token',
        description: 'Slack Bot, User, or App token',
        pattern: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['xoxb', 'xoxa', 'xoxp', 'slack'],
    },
    {
        id: 'slack-webhook',
        name: 'Slack Webhook URL',
        description: 'Slack incoming webhook URL',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
        severity: 'medium',
        confidence: 'high',
        keywords: ['hooks.slack.com', 'webhook'],
    },

    // Discord
    {
        id: 'discord-bot-token',
        name: 'Discord Bot Token',
        description: 'Discord bot authentication token',
        pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
        severity: 'high',
        confidence: 'medium',
        keywords: ['discord', 'bot'],
    },
    {
        id: 'discord-webhook',
        name: 'Discord Webhook URL',
        description: 'Discord webhook URL',
        pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/gi,
        severity: 'medium',
        confidence: 'high',
        keywords: ['discord', 'webhook'],
    },

    // Stripe
    {
        id: 'stripe-secret-key',
        name: 'Stripe Secret Key',
        description: 'Stripe API secret key',
        pattern: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['sk_live', 'stripe'],
    },
    {
        id: 'stripe-restricted-key',
        name: 'Stripe Restricted Key',
        description: 'Stripe restricted API key',
        pattern: /\b(rk_live_[0-9a-zA-Z]{24,})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['rk_live', 'stripe'],
    },
    {
        id: 'stripe-test-key',
        name: 'Stripe Test Key',
        description: 'Stripe test API key (lower risk but should not be committed)',
        pattern: /\b(sk_test_[0-9a-zA-Z]{24,})\b/g,
        severity: 'medium',
        confidence: 'high',
        keywords: ['sk_test', 'stripe'],
    },

    // Twilio
    {
        id: 'twilio-api-key',
        name: 'Twilio API Key',
        description: 'Twilio API Key SID',
        pattern: /\bSK[a-f0-9]{32}\b/g,
        severity: 'high',
        confidence: 'medium',
        keywords: ['twilio', 'SK'],
    },
    {
        id: 'twilio-account-sid',
        name: 'Twilio Account SID',
        description: 'Twilio Account SID',
        pattern: /\bAC[a-f0-9]{32}\b/g,
        severity: 'medium',
        confidence: 'medium',
        keywords: ['twilio', 'AC'],
    },

    // SendGrid
    {
        id: 'sendgrid-api-key',
        name: 'SendGrid API Key',
        description: 'SendGrid email service API key',
        pattern: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['SG.', 'sendgrid'],
    },

    // Mailchimp
    {
        id: 'mailchimp-api-key',
        name: 'Mailchimp API Key',
        description: 'Mailchimp API key',
        pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
        severity: 'high',
        confidence: 'medium',
        keywords: ['mailchimp', '-us'],
    },

    // NPM
    {
        id: 'npm-token',
        name: 'NPM Access Token',
        description: 'NPM registry access token',
        pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['npm_', 'npmjs'],
    },

    // PyPI
    {
        id: 'pypi-token',
        name: 'PyPI API Token',
        description: 'PyPI package index API token',
        pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})\b/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['pypi-', 'pypi'],
    },

    // Heroku
    {
        id: 'heroku-api-key',
        name: 'Heroku API Key',
        description: 'Heroku platform API key',
        pattern: /(?:heroku_api_key|HEROKU_API_KEY)[\s]*[=:][\s]*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['heroku', 'HEROKU_API_KEY'],
    },

    // Firebase
    {
        id: 'firebase-api-key',
        name: 'Firebase API Key',
        description: 'Firebase/Google API key (often public, but verify usage)',
        pattern: /(?:firebase|FIREBASE).*[=:].*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
        severity: 'medium',
        confidence: 'medium',
        keywords: ['firebase', 'AIza'],
    },

    // Shopify
    {
        id: 'shopify-private-token',
        name: 'Shopify Private App Token',
        description: 'Shopify private app access token',
        pattern: /shppa_[a-fA-F0-9]{32}/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['shppa_', 'shopify'],
    },
    {
        id: 'shopify-shared-secret',
        name: 'Shopify Shared Secret',
        description: 'Shopify app shared secret',
        pattern: /shpss_[a-fA-F0-9]{32}/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['shpss_', 'shopify'],
    },
];

// ============================================
// Private Keys and Certificates
// ============================================

export const PRIVATE_KEY_PATTERNS: SecretPattern[] = [
    {
        id: 'rsa-private-key',
        name: 'RSA Private Key',
        description: 'RSA private key that could be used for authentication or signing',
        pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN RSA PRIVATE KEY'],
    },
    {
        id: 'openssh-private-key',
        name: 'OpenSSH Private Key',
        description: 'OpenSSH private key for SSH authentication',
        pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN OPENSSH PRIVATE KEY'],
    },
    {
        id: 'dsa-private-key',
        name: 'DSA Private Key',
        description: 'DSA private key',
        pattern: /-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN DSA PRIVATE KEY'],
    },
    {
        id: 'ec-private-key',
        name: 'EC Private Key',
        description: 'Elliptic Curve private key',
        pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN EC PRIVATE KEY'],
    },
    {
        id: 'pgp-private-key',
        name: 'PGP Private Key',
        description: 'PGP/GPG private key block',
        pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN PGP PRIVATE KEY'],
    },
    {
        id: 'pkcs8-private-key',
        name: 'PKCS8 Private Key',
        description: 'PKCS#8 formatted private key',
        pattern: /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['BEGIN PRIVATE KEY'],
    },
    {
        id: 'encrypted-private-key',
        name: 'Encrypted Private Key',
        description: 'Encrypted private key (still sensitive)',
        pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]+?-----END ENCRYPTED PRIVATE KEY-----/g,
        severity: 'high',
        confidence: 'high',
        keywords: ['BEGIN ENCRYPTED PRIVATE KEY'],
    },
];

// ============================================
// Database and Service Credentials
// ============================================

export const DATABASE_PATTERNS: SecretPattern[] = [
    {
        id: 'mongodb-uri',
        name: 'MongoDB Connection URI',
        description: 'MongoDB connection string with embedded credentials',
        pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['mongodb://', 'mongodb+srv://'],
    },
    {
        id: 'postgres-uri',
        name: 'PostgreSQL Connection URI',
        description: 'PostgreSQL connection string with embedded credentials',
        pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['postgres://', 'postgresql://'],
    },
    {
        id: 'mysql-uri',
        name: 'MySQL Connection URI',
        description: 'MySQL connection string with embedded credentials',
        pattern: /mysql:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['mysql://'],
    },
    {
        id: 'redis-uri',
        name: 'Redis Connection URI',
        description: 'Redis connection string with embedded credentials',
        pattern: /redis(?:s)?:\/\/[^:]+:[^@]+@[^/\s]+/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['redis://'],
    },
    {
        id: 'jdbc-password',
        name: 'JDBC Connection with Password',
        description: 'JDBC connection string with embedded password',
        pattern: /jdbc:[a-z]+:\/\/[^;]+;.*password=[^;]+/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['jdbc:', 'password='],
    },
];

// ============================================
// Generic Credentials Patterns
// ============================================

export const GENERIC_SECRET_PATTERNS: SecretPattern[] = [
    {
        id: 'generic-password-assignment',
        name: 'Hardcoded Password',
        description: 'Password assigned in code',
        pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|api-key|auth_token|access_token|bearer)[\s]*[=:][\s]*["']([^"'\s]{8,})["']/gi,
        severity: 'high',
        confidence: 'medium',
        keywords: ['password', 'secret', 'token', 'api_key'],
        falsePositivePatterns: [
            /password.*example/i,
            /password.*placeholder/i,
            /password.*\$\{/i, // Template variable
            /password.*process\.env/i,
            /password.*getenv/i,
        ],
    },
    {
        id: 'base64-encoded-secret',
        name: 'Base64 Encoded Secret',
        description: 'Potential base64 encoded credential',
        pattern: /(?:password|secret|key|token|credential)[\s]*[=:][\s]*["']?([A-Za-z0-9+/]{40,}={0,2})["']?/gi,
        severity: 'medium',
        confidence: 'low',
        keywords: ['password', 'secret', 'token'],
    },
    {
        id: 'jwt-token',
        name: 'JWT Token',
        description: 'JSON Web Token (verify if contains sensitive claims)',
        pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        severity: 'medium',
        confidence: 'high',
        keywords: ['eyJ', 'jwt', 'bearer'],
    },
    {
        id: 'bearer-token',
        name: 'Bearer Token in Code',
        description: 'Authorization bearer token hardcoded',
        pattern: /['"](Bearer\s+[A-Za-z0-9\-_.~+/]+=*)["']/gi,
        severity: 'high',
        confidence: 'medium',
        keywords: ['Bearer'],
    },
    {
        id: 'basic-auth-header',
        name: 'Basic Auth Credentials',
        description: 'Basic authentication header with encoded credentials',
        pattern: /Basic\s+[A-Za-z0-9+/]{20,}={0,2}/gi,
        severity: 'high',
        confidence: 'medium',
        keywords: ['Basic'],
    },
];

// ============================================
// Blockchain/Crypto Keys
// ============================================

export const BLOCKCHAIN_PATTERNS: SecretPattern[] = [
    // Ethereum/EVM Private Keys
    {
        id: 'ethereum-private-key-labeled',
        name: 'Ethereum Private Key (Labeled)',
        description: 'Ethereum/EVM chain private key with variable name (64 hex characters)',
        pattern: /(?:private_key|privateKey|PRIVATE_KEY|privKey|priv_key|secret_key|secretKey|wallet_key|walletKey)[\s]*[=:][\s]*["']?(0x)?([a-fA-F0-9]{64})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['private_key', 'privateKey', 'secret_key', 'wallet'],
    },
    {
        id: 'ethereum-private-key-hex',
        name: 'Ethereum Private Key (0x Prefixed)',
        description: 'Ethereum private key with 0x prefix (66 characters total)',
        pattern: /["'](0x[a-fA-F0-9]{64})["']/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['0x'],
    },
    {
        id: 'ethereum-private-key-raw',
        name: 'Ethereum Private Key (Raw Hex)',
        description: 'Potential raw 64-character hex private key',
        pattern: /[=:]\s*["']([a-fA-F0-9]{64})["']/g,
        severity: 'critical',
        confidence: 'medium',
        keywords: ['key', 'private', 'wallet'],
    },

    // Bitcoin Private Keys
    {
        id: 'bitcoin-wif-private-key',
        name: 'Bitcoin WIF Private Key',
        description: 'Bitcoin Wallet Import Format private key (starts with 5, K, or L)',
        pattern: /\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bitcoin', 'btc', 'wallet'],
    },
    {
        id: 'bitcoin-wif-compressed',
        name: 'Bitcoin WIF Compressed',
        description: 'Bitcoin compressed WIF private key',
        pattern: /\b([KL][1-9A-HJ-NP-Za-km-z]{51})\b/g,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bitcoin', 'btc'],
    },

    // Solana Private Keys
    {
        id: 'solana-private-key',
        name: 'Solana Private Key',
        description: 'Solana private key (base58 encoded, 64 or 88 characters)',
        pattern: /(?:solana|phantom|sol).*?["']([1-9A-HJ-NP-Za-km-z]{64,88})["']/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['solana', 'phantom', 'sol'],
    },
    {
        id: 'solana-keypair-array',
        name: 'Solana Keypair Array',
        description: 'Solana keypair as byte array',
        pattern: /\[(\d{1,3},\s*){63}\d{1,3}\]/g,
        severity: 'critical',
        confidence: 'medium',
        keywords: ['solana', 'keypair', 'wallet'],
    },

    // Mnemonic/Seed Phrases
    {
        id: 'mnemonic-phrase-labeled',
        name: 'Cryptocurrency Mnemonic (Labeled)',
        description: 'BIP39 mnemonic seed phrase with variable name',
        pattern: /(?:mnemonic|seed_phrase|seed|seedPhrase|MNEMONIC|recovery_phrase|recoveryPhrase|backup_phrase|secret_phrase)[\s]*[=:][\s]*["']([a-z]+(?:\s+[a-z]+){11,23})["']/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['mnemonic', 'seed', 'phrase', 'recovery', 'backup'],
    },
    {
        id: 'mnemonic-phrase-12-words',
        name: '12-Word Seed Phrase',
        description: 'Potential 12-word BIP39 mnemonic',
        pattern: /["']([a-z]{3,8}(?:\s+[a-z]{3,8}){11})["']/gi,
        severity: 'critical',
        confidence: 'medium',
        keywords: ['seed', 'mnemonic', 'phrase', 'wallet'],
    },
    {
        id: 'mnemonic-phrase-24-words',
        name: '24-Word Seed Phrase',
        description: 'Potential 24-word BIP39 mnemonic',
        pattern: /["']([a-z]{3,8}(?:\s+[a-z]{3,8}){23})["']/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['seed', 'mnemonic', 'phrase', 'wallet'],
    },

    // Web3 Provider Keys
    {
        id: 'infura-api-key',
        name: 'Infura API Key',
        description: 'Infura Ethereum node API key',
        pattern: /(?:infura\.io|infura_key|INFURA_KEY|INFURA_PROJECT_ID|infuraId)[\s]*[=:]?\s*["']?([a-f0-9]{32})["']?/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['infura'],
    },
    {
        id: 'infura-url',
        name: 'Infura RPC URL',
        description: 'Infura RPC endpoint URL with embedded key',
        pattern: /https:\/\/(?:mainnet|goerli|sepolia|polygon|arbitrum|optimism)[^/]*\.infura\.io\/v3\/([a-f0-9]{32})/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['infura.io'],
    },
    {
        id: 'alchemy-api-key',
        name: 'Alchemy API Key',
        description: 'Alchemy Web3 API key',
        pattern: /(?:alchemy|ALCHEMY_KEY|ALCHEMY_API_KEY|alchemyKey|alchemyApiKey)[\s]*[=:]?\s*["']?([A-Za-z0-9_-]{32})["']?/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['alchemy'],
    },
    {
        id: 'alchemy-url',
        name: 'Alchemy RPC URL',
        description: 'Alchemy RPC endpoint URL with embedded key',
        pattern: /https:\/\/[^/]+\.g\.alchemy\.com\/v2\/([A-Za-z0-9_-]{32})/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['alchemy.com'],
    },
    {
        id: 'quicknode-api-key',
        name: 'QuickNode API Key',
        description: 'QuickNode RPC endpoint',
        pattern: /https:\/\/[^/]+\.quiknode\.pro\/([a-f0-9]{32,})/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['quiknode', 'quicknode'],
    },
    {
        id: 'moralis-api-key',
        name: 'Moralis API Key',
        description: 'Moralis Web3 API key',
        pattern: /(?:moralis|MORALIS_API_KEY|moralisApiKey)[\s]*[=:]?\s*["']?([A-Za-z0-9]{64})["']?/gi,
        severity: 'high',
        confidence: 'high',
        keywords: ['moralis'],
    },

    // Crypto Exchange API Keys - Improved patterns with accurate formats
    {
        id: 'binance-api-key',
        name: 'Binance API Key',
        description: 'Binance exchange API key (64 alphanumeric characters)',
        pattern: /(?:binance[_-]?(?:api[_-]?)?key|BINANCE[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([A-Za-z0-9]{64})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['binance', 'BINANCE_API'],
    },
    {
        id: 'binance-secret-key',
        name: 'Binance Secret Key',
        description: 'Binance exchange API secret key',
        pattern: /(?:binance[_-]?(?:api[_-]?)?secret|BINANCE[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([A-Za-z0-9]{64})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['binance', 'BINANCE_SECRET'],
    },
    {
        id: 'coinbase-api-key',
        name: 'Coinbase API Key',
        description: 'Coinbase exchange API key',
        pattern: /(?:coinbase[_-]?(?:api[_-]?)?key|COINBASE[_-]?(?:API[_-]?)?KEY|CB[_-]?API[_-]?KEY)[\s]*[=:][\s]*["']?([a-zA-Z0-9\-]{20,})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['coinbase', 'CB_API'],
    },
    {
        id: 'coinbase-secret-key',
        name: 'Coinbase Secret Key',
        description: 'Coinbase exchange API secret',
        pattern: /(?:coinbase[_-]?(?:api[_-]?)?secret|COINBASE[_-]?(?:API[_-]?)?SECRET|CB[_-]?API[_-]?SECRET)[\s]*[=:][\s]*["']?([a-zA-Z0-9+/=]{40,})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['coinbase', 'CB_SECRET'],
    },
    {
        id: 'kraken-api-key',
        name: 'Kraken API Key',
        description: 'Kraken exchange API key (starts with specific prefix)',
        pattern: /(?:kraken[_-]?(?:api[_-]?)?key|KRAKEN[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([A-Za-z0-9+/]{54,58}={0,2})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['kraken', 'KRAKEN_API'],
    },
    {
        id: 'kraken-private-key',
        name: 'Kraken Private Key',
        description: 'Kraken exchange API private key',
        pattern: /(?:kraken[_-]?(?:api[_-]?)?(?:private|secret)|KRAKEN[_-]?(?:API[_-]?)?(?:PRIVATE|SECRET))[\s]*[=:][\s]*["']?([A-Za-z0-9+/]{80,90}={0,2})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['kraken', 'KRAKEN_PRIVATE'],
    },
    {
        id: 'kucoin-api-key',
        name: 'KuCoin API Key',
        description: 'KuCoin exchange API key (24 hex characters)',
        pattern: /(?:kucoin[_-]?(?:api[_-]?)?key|KUCOIN[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([a-f0-9]{24})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['kucoin', 'KUCOIN_API'],
    },
    {
        id: 'kucoin-secret-key',
        name: 'KuCoin Secret Key',
        description: 'KuCoin exchange API secret',
        pattern: /(?:kucoin[_-]?(?:api[_-]?)?secret|KUCOIN[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([a-f0-9\-]{36})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['kucoin', 'KUCOIN_SECRET'],
    },
    {
        id: 'kucoin-passphrase',
        name: 'KuCoin API Passphrase',
        description: 'KuCoin exchange API passphrase',
        pattern: /(?:kucoin[_-]?(?:api[_-]?)?passphrase|KUCOIN[_-]?(?:API[_-]?)?PASSPHRASE)[\s]*[=:][\s]*["']?([^\s"']{6,})["']?/gi,
        severity: 'critical',
        confidence: 'medium',
        keywords: ['kucoin', 'passphrase'],
    },
    {
        id: 'bybit-api-key',
        name: 'Bybit API Key',
        description: 'Bybit exchange API key (18 alphanumeric characters)',
        pattern: /(?:bybit[_-]?(?:api[_-]?)?key|BYBIT[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([A-Za-z0-9]{18})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bybit', 'BYBIT_API'],
    },
    {
        id: 'bybit-secret-key',
        name: 'Bybit Secret Key',
        description: 'Bybit exchange API secret',
        pattern: /(?:bybit[_-]?(?:api[_-]?)?secret|BYBIT[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([A-Za-z0-9]{36})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bybit', 'BYBIT_SECRET'],
    },
    {
        id: 'okx-api-key',
        name: 'OKX API Key',
        description: 'OKX (OKEx) exchange API key',
        pattern: /(?:okx[_-]?(?:api[_-]?)?key|OKX[_-]?(?:API[_-]?)?KEY|okex[_-]?(?:api[_-]?)?key|OKEX[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([a-f0-9\-]{36})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['okx', 'okex', 'OKX_API'],
    },
    {
        id: 'okx-secret-key',
        name: 'OKX Secret Key',
        description: 'OKX (OKEx) exchange API secret',
        pattern: /(?:okx[_-]?(?:api[_-]?)?secret|OKX[_-]?(?:API[_-]?)?SECRET|okex[_-]?(?:api[_-]?)?secret|OKEX[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([A-Z0-9]{32})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['okx', 'okex', 'OKX_SECRET'],
    },
    {
        id: 'okx-passphrase',
        name: 'OKX API Passphrase',
        description: 'OKX (OKEx) exchange API passphrase',
        pattern: /(?:okx[_-]?(?:api[_-]?)?passphrase|OKX[_-]?(?:API[_-]?)?PASSPHRASE|okex[_-]?passphrase)[\s]*[=:][\s]*["']?([^\s"']{6,})["']?/gi,
        severity: 'critical',
        confidence: 'medium',
        keywords: ['okx', 'okex', 'passphrase'],
    },
    {
        id: 'gateio-api-key',
        name: 'Gate.io API Key',
        description: 'Gate.io exchange API key',
        pattern: /(?:gate[_-]?(?:io[_-]?)?(?:api[_-]?)?key|GATE[_-]?(?:IO[_-]?)?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([a-f0-9]{32})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['gate', 'gateio', 'GATE_API'],
    },
    {
        id: 'gateio-secret-key',
        name: 'Gate.io Secret Key',
        description: 'Gate.io exchange API secret',
        pattern: /(?:gate[_-]?(?:io[_-]?)?(?:api[_-]?)?secret|GATE[_-]?(?:IO[_-]?)?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([a-f0-9]{64})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['gate', 'gateio', 'GATE_SECRET'],
    },
    {
        id: 'htx-api-key',
        name: 'HTX (Huobi) API Key',
        description: 'HTX (formerly Huobi) exchange API key',
        pattern: /(?:htx[_-]?(?:api[_-]?)?key|HTX[_-]?(?:API[_-]?)?KEY|huobi[_-]?(?:api[_-]?)?key|HUOBI[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([a-z0-9\-]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['htx', 'huobi', 'HTX_API', 'HUOBI_API'],
    },
    {
        id: 'htx-secret-key',
        name: 'HTX (Huobi) Secret Key',
        description: 'HTX (formerly Huobi) exchange API secret',
        pattern: /(?:htx[_-]?(?:api[_-]?)?secret|HTX[_-]?(?:API[_-]?)?SECRET|huobi[_-]?(?:api[_-]?)?secret|HUOBI[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([a-f0-9\-]{36})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['htx', 'huobi', 'HTX_SECRET', 'HUOBI_SECRET'],
    },
    {
        id: 'bitfinex-api-key',
        name: 'Bitfinex API Key',
        description: 'Bitfinex exchange API key',
        pattern: /(?:bitfinex[_-]?(?:api[_-]?)?key|BITFINEX[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?([A-Za-z0-9]{43})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bitfinex', 'BITFINEX_API'],
    },
    {
        id: 'bitfinex-secret-key',
        name: 'Bitfinex Secret Key',
        description: 'Bitfinex exchange API secret',
        pattern: /(?:bitfinex[_-]?(?:api[_-]?)?secret|BITFINEX[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([A-Za-z0-9]{43})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['bitfinex', 'BITFINEX_SECRET'],
    },
    {
        id: 'gemini-api-key',
        name: 'Gemini API Key',
        description: 'Gemini exchange API key',
        pattern: /(?:gemini[_-]?(?:api[_-]?)?key|GEMINI[_-]?(?:API[_-]?)?KEY)[\s]*[=:][\s]*["']?(account-[A-Za-z0-9]{20,})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['gemini', 'GEMINI_API'],
    },
    {
        id: 'gemini-secret-key',
        name: 'Gemini Secret Key',
        description: 'Gemini exchange API secret',
        pattern: /(?:gemini[_-]?(?:api[_-]?)?secret|GEMINI[_-]?(?:API[_-]?)?SECRET)[\s]*[=:][\s]*["']?([A-Za-z0-9]{28})["']?/gi,
        severity: 'critical',
        confidence: 'high',
        keywords: ['gemini', 'GEMINI_SECRET'],
    },

    // Etherscan and Block Explorer Keys
    {
        id: 'etherscan-api-key',
        name: 'Etherscan API Key',
        description: 'Etherscan block explorer API key',
        pattern: /(?:etherscan|ETHERSCAN_API_KEY|etherscanApiKey)[\s]*[=:]?\s*["']?([A-Z0-9]{34})["']?/gi,
        severity: 'medium',
        confidence: 'high',
        keywords: ['etherscan'],
    },
    {
        id: 'bscscan-api-key',
        name: 'BSCScan API Key',
        description: 'BSCScan block explorer API key',
        pattern: /(?:bscscan|BSCSCAN_API_KEY|bscscanApiKey)[\s]*[=:]?\s*["']?([A-Z0-9]{34})["']?/gi,
        severity: 'medium',
        confidence: 'high',
        keywords: ['bscscan'],
    },
    {
        id: 'polygonscan-api-key',
        name: 'PolygonScan API Key',
        description: 'PolygonScan block explorer API key',
        pattern: /(?:polygonscan|POLYGONSCAN_API_KEY)[\s]*[=:]?\s*["']?([A-Z0-9]{34})["']?/gi,
        severity: 'medium',
        confidence: 'high',
        keywords: ['polygonscan'],
    },

    // Wallet Connect
    {
        id: 'walletconnect-project-id',
        name: 'WalletConnect Project ID',
        description: 'WalletConnect cloud project ID',
        pattern: /(?:walletconnect|WALLETCONNECT_PROJECT_ID|projectId)[\s]*[=:]?\s*["']?([a-f0-9]{32})["']?/gi,
        severity: 'medium',
        confidence: 'medium',
        keywords: ['walletconnect', 'projectId'],
    },
];

// ============================================
// All Patterns Combined
// ============================================

export const ALL_SECRET_PATTERNS: SecretPattern[] = [
    ...API_KEY_PATTERNS,
    ...PRIVATE_KEY_PATTERNS,
    ...DATABASE_PATTERNS,
    ...GENERIC_SECRET_PATTERNS,
    ...BLOCKCHAIN_PATTERNS,
];

// Export categorized for flexibility
export default {
    all: ALL_SECRET_PATTERNS,
    apiKeys: API_KEY_PATTERNS,
    privateKeys: PRIVATE_KEY_PATTERNS,
    database: DATABASE_PATTERNS,
    generic: GENERIC_SECRET_PATTERNS,
    blockchain: BLOCKCHAIN_PATTERNS,
};

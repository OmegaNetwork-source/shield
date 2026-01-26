// STRIX SAST - API Credential Tester
// Test if discovered API keys are active/valid

import CryptoJS from 'crypto-js';

// Debug logging
const DEBUG = true;
const log = (...args: any[]) => DEBUG && console.log('[API-Tester]', ...args);

export type APIService = 
    | 'binance' 
    | 'coinbase' 
    | 'kraken' 
    | 'kucoin' 
    | 'bybit' 
    | 'okx' 
    | 'gateio' 
    | 'htx'
    | 'bitfinex'
    | 'gemini'
    | 'github' 
    | 'stripe' 
    | 'sendgrid' 
    | 'twilio'
    | 'slack'
    | 'discord'
    | 'etherscan'
    | 'infura'
    | 'alchemy'
    | 'aws';

export interface APITestResult {
    service: APIService;
    isActive: boolean;
    permissions?: string[];
    balance?: string;
    accountInfo?: Record<string, any>;
    error?: string;
    testTime: Date;
    rateLimit?: {
        remaining: number;
        total: number;
        resetAt?: Date;
    };
}

export interface APICredentials {
    service: APIService;
    apiKey: string;
    secretKey?: string;
    passphrase?: string;  // For exchanges that require it (KuCoin, OKX)
}

// Helper to create HMAC signatures
function hmacSha256(message: string, secret: string): string {
    return CryptoJS.HmacSHA256(message, secret).toString(CryptoJS.enc.Hex);
}

function hmacSha256Base64(message: string, secret: string): string {
    return CryptoJS.HmacSHA256(message, secret).toString(CryptoJS.enc.Base64);
}

function hmacSha512(message: string, secret: string): string {
    return CryptoJS.HmacSHA512(message, secret).toString(CryptoJS.enc.Hex);
}

function hmacSha384Base64(message: string, secret: string): string {
    return CryptoJS.HmacSHA384(message, secret).toString(CryptoJS.enc.Base64);
}

// ============================================
// Exchange API Testers
// ============================================

/**
 * Test Binance API credentials
 */
async function testBinance(apiKey: string, secretKey?: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'binance',
        isActive: false,
        testTime: new Date(),
    };

    try {
        // Test with account info endpoint (requires signature if secret provided)
        if (secretKey) {
            const timestamp = Date.now();
            const queryString = `timestamp=${timestamp}`;
            const signature = hmacSha256(queryString, secretKey);
            
            const response = await fetch(
                `https://api.binance.com/api/v3/account?${queryString}&signature=${signature}`,
                {
                    headers: {
                        'X-MBX-APIKEY': apiKey,
                    },
                }
            );

            if (response.ok) {
                const data = await response.json();
                result.isActive = true;
                result.permissions = data.permissions || [];
                result.accountInfo = {
                    canTrade: data.canTrade,
                    canWithdraw: data.canWithdraw,
                    canDeposit: data.canDeposit,
                    accountType: data.accountType,
                };
                
                // Get balances with value > 0
                const nonZeroBalances = (data.balances || [])
                    .filter((b: any) => parseFloat(b.free) > 0 || parseFloat(b.locked) > 0)
                    .slice(0, 10);
                if (nonZeroBalances.length > 0) {
                    result.balance = nonZeroBalances
                        .map((b: any) => `${b.asset}: ${b.free}`)
                        .join(', ');
                }
            } else {
                const error = await response.json().catch(() => ({}));
                result.error = error.msg || `HTTP ${response.status}`;
                
                // Check if key is valid but wrong permissions
                if (response.status === 401 || error.code === -2015) {
                    result.error = 'Invalid API key';
                } else if (error.code === -1022) {
                    result.error = 'Invalid signature (wrong secret key)';
                }
            }
        } else {
            // Test API key only with ping + time endpoints
            const pingResponse = await fetch('https://api.binance.com/api/v3/ping', {
                headers: { 'X-MBX-APIKEY': apiKey },
            });
            
            if (pingResponse.ok) {
                result.isActive = true;
                result.error = 'API key format valid (provide secret to test full access)';
            }
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test KuCoin API credentials
 */
async function testKuCoin(apiKey: string, secretKey?: string, passphrase?: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'kucoin',
        isActive: false,
        testTime: new Date(),
    };

    try {
        if (secretKey && passphrase) {
            const timestamp = Date.now().toString();
            const method = 'GET';
            const endpoint = '/api/v1/accounts';
            const strToSign = timestamp + method + endpoint;
            
            const signature = hmacSha256Base64(strToSign, secretKey);
            const passphraseEncrypted = hmacSha256Base64(passphrase, secretKey);

            const response = await fetch(`https://api.kucoin.com${endpoint}`, {
                headers: {
                    'KC-API-KEY': apiKey,
                    'KC-API-SIGN': signature,
                    'KC-API-TIMESTAMP': timestamp,
                    'KC-API-PASSPHRASE': passphraseEncrypted,
                    'KC-API-KEY-VERSION': '2',
                },
            });

            if (response.ok) {
                const data = await response.json();
                if (data.code === '200000') {
                    result.isActive = true;
                    const accounts = data.data || [];
                    const nonZero = accounts.filter((a: any) => parseFloat(a.balance) > 0);
                    if (nonZero.length > 0) {
                        result.balance = nonZero
                            .slice(0, 5)
                            .map((a: any) => `${a.currency}: ${a.balance}`)
                            .join(', ');
                    }
                    result.accountInfo = {
                        totalAccounts: accounts.length,
                        accountsWithBalance: nonZero.length,
                    };
                } else {
                    result.error = data.msg || 'API error';
                }
            } else {
                result.error = `HTTP ${response.status}`;
            }
        } else {
            result.error = 'KuCoin requires API key, secret, and passphrase';
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Bybit API credentials
 */
async function testBybit(apiKey: string, secretKey?: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'bybit',
        isActive: false,
        testTime: new Date(),
    };

    try {
        if (secretKey) {
            const timestamp = Date.now().toString();
            const recvWindow = '5000';
            const queryString = `api_key=${apiKey}&recv_window=${recvWindow}&timestamp=${timestamp}`;
            const signature = hmacSha256(queryString, secretKey);

            const response = await fetch(
                `https://api.bybit.com/v5/account/wallet-balance?accountType=UNIFIED&${queryString}&sign=${signature}`,
                {
                    headers: {
                        'X-BAPI-API-KEY': apiKey,
                        'X-BAPI-TIMESTAMP': timestamp,
                        'X-BAPI-RECV-WINDOW': recvWindow,
                        'X-BAPI-SIGN': signature,
                    },
                }
            );

            if (response.ok) {
                const data = await response.json();
                if (data.retCode === 0) {
                    result.isActive = true;
                    const accounts = data.result?.list || [];
                    if (accounts.length > 0) {
                        result.accountInfo = {
                            accountType: accounts[0].accountType,
                        };
                        const totalEquity = accounts[0].totalEquity;
                        if (totalEquity && parseFloat(totalEquity) > 0) {
                            result.balance = `Total Equity: $${totalEquity}`;
                        }
                    }
                } else {
                    result.error = data.retMsg || 'API error';
                }
            } else {
                result.error = `HTTP ${response.status}`;
            }
        } else {
            result.error = 'Bybit requires both API key and secret';
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test OKX API credentials
 */
async function testOKX(apiKey: string, secretKey?: string, passphrase?: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'okx',
        isActive: false,
        testTime: new Date(),
    };

    try {
        if (secretKey && passphrase) {
            const timestamp = new Date().toISOString();
            const method = 'GET';
            const requestPath = '/api/v5/account/balance';
            const body = '';
            
            const preHash = timestamp + method + requestPath + body;
            const signature = hmacSha256Base64(preHash, secretKey);

            const response = await fetch(`https://www.okx.com${requestPath}`, {
                headers: {
                    'OK-ACCESS-KEY': apiKey,
                    'OK-ACCESS-SIGN': signature,
                    'OK-ACCESS-TIMESTAMP': timestamp,
                    'OK-ACCESS-PASSPHRASE': passphrase,
                    'Content-Type': 'application/json',
                },
            });

            if (response.ok) {
                const data = await response.json();
                if (data.code === '0') {
                    result.isActive = true;
                    const balances = data.data?.[0]?.details || [];
                    const nonZero = balances.filter((b: any) => parseFloat(b.cashBal) > 0);
                    if (nonZero.length > 0) {
                        result.balance = nonZero
                            .slice(0, 5)
                            .map((b: any) => `${b.ccy}: ${b.cashBal}`)
                            .join(', ');
                    }
                    result.accountInfo = {
                        totalEquity: data.data?.[0]?.totalEq,
                    };
                } else {
                    result.error = data.msg || 'API error';
                }
            } else {
                result.error = `HTTP ${response.status}`;
            }
        } else {
            result.error = 'OKX requires API key, secret, and passphrase';
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Gate.io API credentials  
 */
async function testGateIO(apiKey: string, secretKey?: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'gateio',
        isActive: false,
        testTime: new Date(),
    };

    try {
        if (secretKey) {
            const timestamp = Math.floor(Date.now() / 1000).toString();
            const method = 'GET';
            const url = '/api/v4/spot/accounts';
            const queryString = '';
            const bodyHash = CryptoJS.SHA512('').toString(CryptoJS.enc.Hex);
            
            const signString = `${method}\n${url}\n${queryString}\n${bodyHash}\n${timestamp}`;
            const signature = hmacSha512(signString, secretKey);

            const response = await fetch(`https://api.gateio.ws${url}`, {
                headers: {
                    'KEY': apiKey,
                    'SIGN': signature,
                    'Timestamp': timestamp,
                    'Content-Type': 'application/json',
                },
            });

            if (response.ok) {
                const data = await response.json();
                if (Array.isArray(data)) {
                    result.isActive = true;
                    const nonZero = data.filter((a: any) => parseFloat(a.available) > 0);
                    if (nonZero.length > 0) {
                        result.balance = nonZero
                            .slice(0, 5)
                            .map((a: any) => `${a.currency}: ${a.available}`)
                            .join(', ');
                    }
                    result.accountInfo = {
                        totalAssets: data.length,
                        assetsWithBalance: nonZero.length,
                    };
                } else {
                    result.error = data.message || 'Unexpected response';
                }
            } else {
                const error = await response.json().catch(() => ({}));
                result.error = error.message || `HTTP ${response.status}`;
            }
        } else {
            result.error = 'Gate.io requires both API key and secret';
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

// ============================================
// Service API Testers
// ============================================

/**
 * Test GitHub token
 */
async function testGitHub(token: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'github',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'STRIX-API-Tester',
            },
        });

        // Get rate limit info
        const rateRemaining = response.headers.get('X-RateLimit-Remaining');
        const rateLimit = response.headers.get('X-RateLimit-Limit');
        const rateReset = response.headers.get('X-RateLimit-Reset');
        
        if (rateRemaining && rateLimit) {
            result.rateLimit = {
                remaining: parseInt(rateRemaining),
                total: parseInt(rateLimit),
                resetAt: rateReset ? new Date(parseInt(rateReset) * 1000) : undefined,
            };
        }

        if (response.ok) {
            const data = await response.json();
            result.isActive = true;
            result.accountInfo = {
                login: data.login,
                name: data.name,
                type: data.type,
                createdAt: data.created_at,
            };
            
            // Get scopes from response headers
            const scopes = response.headers.get('X-OAuth-Scopes');
            if (scopes) {
                result.permissions = scopes.split(', ');
            }
        } else if (response.status === 401) {
            result.error = 'Invalid or expired token';
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Stripe API key
 */
async function testStripe(apiKey: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'stripe',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch('https://api.stripe.com/v1/balance', {
            headers: {
                'Authorization': `Bearer ${apiKey}`,
            },
        });

        if (response.ok) {
            const data = await response.json();
            result.isActive = true;
            
            // Determine if live or test key
            const isLiveKey = apiKey.startsWith('sk_live_');
            result.accountInfo = {
                mode: isLiveKey ? 'live' : 'test',
                livemode: data.livemode,
            };
            
            // Get available balance
            const available = data.available || [];
            if (available.length > 0) {
                result.balance = available
                    .map((b: any) => `${(b.amount / 100).toFixed(2)} ${b.currency.toUpperCase()}`)
                    .join(', ');
            }
        } else if (response.status === 401) {
            result.error = 'Invalid API key';
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test SendGrid API key
 */
async function testSendGrid(apiKey: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'sendgrid',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch('https://api.sendgrid.com/v3/user/profile', {
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            const data = await response.json();
            result.isActive = true;
            result.accountInfo = {
                email: data.email,
                firstName: data.first_name,
                lastName: data.last_name,
            };
        } else if (response.status === 401 || response.status === 403) {
            result.error = 'Invalid API key';
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Slack token
 */
async function testSlack(token: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'slack',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch('https://slack.com/api/auth.test', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            const data = await response.json();
            if (data.ok) {
                result.isActive = true;
                result.accountInfo = {
                    user: data.user,
                    userId: data.user_id,
                    team: data.team,
                    teamId: data.team_id,
                };
                
                // Determine token type
                if (token.startsWith('xoxb-')) {
                    result.accountInfo.tokenType = 'bot';
                } else if (token.startsWith('xoxp-')) {
                    result.accountInfo.tokenType = 'user';
                } else if (token.startsWith('xoxa-')) {
                    result.accountInfo.tokenType = 'app';
                }
            } else {
                result.error = data.error || 'Invalid token';
            }
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Etherscan API key
 */
async function testEtherscan(apiKey: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'etherscan',
        isActive: false,
        testTime: new Date(),
    };

    try {
        // Test with a simple balance check for a known address
        const response = await fetch(
            `https://api.etherscan.io/api?module=account&action=balance&address=0x0000000000000000000000000000000000000000&tag=latest&apikey=${apiKey}`
        );

        if (response.ok) {
            const data = await response.json();
            if (data.status === '1') {
                result.isActive = true;
                result.accountInfo = {
                    plan: 'active',
                };
            } else if (data.result?.includes('Invalid API Key')) {
                result.error = 'Invalid API key';
            } else {
                result.error = data.message || data.result || 'API error';
            }
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Infura API key
 */
async function testInfura(apiKey: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'infura',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch(`https://mainnet.infura.io/v3/${apiKey}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_blockNumber',
                params: [],
                id: 1,
            }),
        });

        if (response.ok) {
            const data = await response.json();
            if (data.result) {
                result.isActive = true;
                result.accountInfo = {
                    latestBlock: parseInt(data.result, 16),
                };
            } else if (data.error) {
                result.error = data.error.message || 'Invalid project ID';
            }
        } else if (response.status === 401) {
            result.error = 'Invalid project ID';
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

/**
 * Test Alchemy API key
 */
async function testAlchemy(apiKey: string): Promise<APITestResult> {
    const result: APITestResult = {
        service: 'alchemy',
        isActive: false,
        testTime: new Date(),
    };

    try {
        const response = await fetch(`https://eth-mainnet.g.alchemy.com/v2/${apiKey}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_blockNumber',
                params: [],
                id: 1,
            }),
        });

        if (response.ok) {
            const data = await response.json();
            if (data.result) {
                result.isActive = true;
                result.accountInfo = {
                    latestBlock: parseInt(data.result, 16),
                };
            } else if (data.error) {
                result.error = data.error.message || 'Invalid API key';
            }
        } else if (response.status === 401 || response.status === 403) {
            result.error = 'Invalid API key';
        } else {
            result.error = `HTTP ${response.status}`;
        }
    } catch (e: any) {
        result.error = e.message || 'Connection failed';
    }

    return result;
}

// ============================================
// Main Test Function
// ============================================

// Check if we're in Electron with IPC available
function hasElectronIPC(): boolean {
    const hasWindow = typeof window !== 'undefined';
    const hasIpc = hasWindow && 'ipcRenderer' in window;
    const hasInvoke = hasIpc && typeof (window as any).ipcRenderer?.invoke === 'function';
    
    log('hasElectronIPC check:', { hasWindow, hasIpc, hasInvoke });
    
    return hasInvoke;
}

/**
 * Test API credentials via Electron IPC (bypasses CORS)
 */
async function testViaElectron(credentials: APICredentials): Promise<APITestResult> {
    const { service, apiKey, secretKey, passphrase } = credentials;
    
    log('Testing via Electron IPC:', service);
    
    try {
        const response = await (window as any).ipcRenderer.invoke('test-api-credential', {
            service,
            apiKey,
            secretKey,
            passphrase,
        });
        
        log('Electron IPC response:', response);
        
        if (response.success && response.active) {
            return {
                service: response.service.toLowerCase() as APIService,
                isActive: true,
                permissions: response.permissions,
                balance: response.balance,
                accountInfo: response.accountInfo,
                testTime: new Date(),
            };
        } else {
            return {
                service: response.service.toLowerCase() as APIService,
                isActive: false,
                error: response.message || response.error,
                accountInfo: response.accountInfo,
                testTime: new Date(),
            };
        }
    } catch (e: any) {
        log('Electron IPC error:', e);
        return {
            service,
            isActive: false,
            error: `IPC Error: ${e.message}`,
            testTime: new Date(),
        };
    }
}

// Services supported by Electron IPC backend
const ELECTRON_SUPPORTED_SERVICES: APIService[] = [
    'binance', 'coinbase', 'kraken', 'kucoin', 'bybit',
    'github', 'stripe', 'etherscan', 'polygonscan' as any, 'bscscan' as any, 'arbiscan' as any
];

// Services that work in browser (have CORS enabled)
const BROWSER_COMPATIBLE_SERVICES: APIService[] = [
    'github', 'etherscan', 'infura', 'alchemy', 'slack'
];

/**
 * Test API credentials for any supported service
 */
export async function testAPICredentials(credentials: APICredentials): Promise<APITestResult> {
    const { service, apiKey, secretKey, passphrase } = credentials;
    
    log('Testing credentials for service:', service);
    log('API Key (first 10 chars):', apiKey?.substring(0, 10) + '...');
    log('Has Electron IPC:', hasElectronIPC());

    // Use Electron IPC if available (bypasses CORS)
    if (hasElectronIPC() && ELECTRON_SUPPORTED_SERVICES.includes(service)) {
        return testViaElectron(credentials);
    }

    // Fall back to browser fetch for compatible services
    try {
        let result: APITestResult;
        
        switch (service) {
            case 'binance':
                result = await testBinance(apiKey, secretKey);
                break;
            case 'kucoin':
                result = await testKuCoin(apiKey, secretKey, passphrase);
                break;
            case 'bybit':
                result = await testBybit(apiKey, secretKey);
                break;
            case 'okx':
                result = await testOKX(apiKey, secretKey, passphrase);
                break;
            case 'gateio':
                result = await testGateIO(apiKey, secretKey);
                break;
            case 'github':
                result = await testGitHub(apiKey);
                break;
            case 'stripe':
                result = await testStripe(apiKey);
                break;
            case 'sendgrid':
                result = await testSendGrid(apiKey);
                break;
            case 'slack':
                result = await testSlack(apiKey);
                break;
            case 'etherscan':
                result = await testEtherscan(apiKey);
                break;
            case 'infura':
                result = await testInfura(apiKey);
                break;
            case 'alchemy':
                result = await testAlchemy(apiKey);
                break;
            default:
                result = {
                    service,
                    isActive: false,
                    error: `Unsupported service: ${service}`,
                    testTime: new Date(),
                };
        }
        
        log('Test result:', result);
        return result;
    } catch (error: any) {
        log('Test error:', error);
        
        // Check if it's a CORS error
        if (error.message?.includes('CORS') || error.message?.includes('NetworkError') || error.message?.includes('Failed to fetch')) {
            return {
                service,
                isActive: false,
                error: `CORS blocked - cannot test ${service} API directly from browser. The key format appears valid.`,
                testTime: new Date(),
                accountInfo: {
                    note: 'Browser security prevents direct API testing. Use a backend service or test manually.',
                    keyFormatValid: validateKeyFormatOnly(service, apiKey),
                },
            };
        }
        
        return {
            service,
            isActive: false,
            error: error.message || 'Unknown error occurred',
            testTime: new Date(),
        };
    }
}

/**
 * Validate key format only (for CORS-blocked services)
 */
function validateKeyFormat(service: APIService, apiKey: string, secretKey?: string, passphrase?: string): APITestResult {
    const formatValid = validateKeyFormatOnly(service, apiKey);
    
    let accountInfo: Record<string, any> = {
        keyFormatValid: formatValid,
        note: 'Cannot test live API from browser due to CORS. Key format validation only.',
    };
    
    // Add service-specific format info
    switch (service) {
        case 'binance':
            accountInfo.expectedKeyLength = 64;
            accountInfo.actualKeyLength = apiKey.length;
            accountInfo.hasSecretKey = !!secretKey;
            if (secretKey) accountInfo.secretKeyLength = secretKey.length;
            break;
        case 'kucoin':
            accountInfo.expectedKeyLength = 24;
            accountInfo.hasSecretKey = !!secretKey;
            accountInfo.hasPassphrase = !!passphrase;
            break;
        case 'stripe':
            accountInfo.isLiveKey = apiKey.startsWith('sk_live_');
            accountInfo.isTestKey = apiKey.startsWith('sk_test_');
            break;
    }
    
    return {
        service,
        isActive: false, // Can't confirm without live test
        error: formatValid 
            ? 'Key format valid but cannot verify live status from browser (CORS blocked)'
            : 'Invalid key format',
        testTime: new Date(),
        accountInfo,
    };
}

/**
 * Check if key format matches expected pattern
 */
function validateKeyFormatOnly(service: APIService, apiKey: string): boolean {
    switch (service) {
        case 'binance':
            return /^[A-Za-z0-9]{64}$/.test(apiKey);
        case 'kucoin':
            return /^[a-f0-9]{24}$/.test(apiKey);
        case 'bybit':
            return /^[A-Za-z0-9]{18}$/.test(apiKey);
        case 'stripe':
            return /^(sk_live_|sk_test_|rk_live_|rk_test_)[0-9a-zA-Z]{24,}$/.test(apiKey);
        case 'sendgrid':
            return /^SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$/.test(apiKey);
        case 'github':
            return /^gh[pous]_[A-Za-z0-9]{36}$/.test(apiKey);
        case 'slack':
            return /^xox[bpars]-/.test(apiKey);
        case 'etherscan':
            return /^[A-Z0-9]{34}$/.test(apiKey);
        case 'infura':
            return /^[a-f0-9]{32}$/.test(apiKey);
        case 'alchemy':
            return /^[A-Za-z0-9_-]{32}$/.test(apiKey);
        default:
            return apiKey.length >= 16; // Generic check
    }
}

/**
 * Auto-detect service type from API key format
 */
export function detectServiceFromKey(apiKey: string): APIService | null {
    const key = apiKey.trim();
    
    // GitHub tokens
    if (key.startsWith('ghp_') || key.startsWith('gho_') || key.startsWith('ghu_') || key.startsWith('ghs_')) {
        return 'github';
    }
    
    // Stripe keys
    if (key.startsWith('sk_live_') || key.startsWith('sk_test_') || key.startsWith('rk_live_') || key.startsWith('rk_test_')) {
        return 'stripe';
    }
    
    // SendGrid
    if (key.startsWith('SG.')) {
        return 'sendgrid';
    }
    
    // Slack tokens
    if (key.startsWith('xoxb-') || key.startsWith('xoxp-') || key.startsWith('xoxa-')) {
        return 'slack';
    }
    
    // Infura (32 hex chars)
    if (/^[a-f0-9]{32}$/.test(key)) {
        return 'infura';
    }
    
    // Alchemy (32 alphanumeric with dashes)
    if (/^[A-Za-z0-9_-]{32}$/.test(key)) {
        return 'alchemy';
    }
    
    // Etherscan (34 uppercase alphanumeric)
    if (/^[A-Z0-9]{34}$/.test(key)) {
        return 'etherscan';
    }
    
    // Binance (64 alphanumeric)
    if (/^[A-Za-z0-9]{64}$/.test(key)) {
        return 'binance';
    }
    
    // KuCoin (24 hex)
    if (/^[a-f0-9]{24}$/.test(key)) {
        return 'kucoin';
    }
    
    // Bybit (18 alphanumeric)
    if (/^[A-Za-z0-9]{18}$/.test(key)) {
        return 'bybit';
    }
    
    return null;
}

/**
 * Extract credentials from a code snippet
 */
export function extractCredentialsFromSnippet(snippet: string): Partial<APICredentials>[] {
    const credentials: Partial<APICredentials>[] = [];
    
    // Common patterns
    const patterns = [
        // Labeled keys
        { pattern: /(?:binance[_-]?api[_-]?key|BINANCE_API_KEY)[\s]*[=:][\s]*["']?([A-Za-z0-9]{64})["']?/gi, service: 'binance' as APIService, type: 'apiKey' },
        { pattern: /(?:binance[_-]?(?:api[_-]?)?secret|BINANCE_SECRET)[\s]*[=:][\s]*["']?([A-Za-z0-9]{64})["']?/gi, service: 'binance' as APIService, type: 'secretKey' },
        { pattern: /ghp_[A-Za-z0-9]{36}/g, service: 'github' as APIService, type: 'apiKey' },
        { pattern: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g, service: 'stripe' as APIService, type: 'apiKey' },
        { pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, service: 'sendgrid' as APIService, type: 'apiKey' },
        { pattern: /xox[bpars]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, service: 'slack' as APIService, type: 'apiKey' },
    ];
    
    for (const { pattern, service, type } of patterns) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(snippet)) !== null) {
            const value = match[1] || match[0];
            const existing = credentials.find(c => c.service === service);
            if (existing) {
                (existing as any)[type] = value;
            } else {
                credentials.push({
                    service,
                    [type]: value,
                });
            }
        }
    }
    
    return credentials;
}

export default {
    testAPICredentials,
    detectServiceFromKey,
    extractCredentialsFromSnippet,
};

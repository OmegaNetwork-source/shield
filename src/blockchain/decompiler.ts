// Bytecode Decompiler
// Analyzes EVM bytecode to extract patterns and pseudo-source code

import type { DecompiledContract, DecompiledFunction, StorageSlot, BytecodeInfo } from './types';

// EVM Opcodes
const OPCODES: Record<number, { name: string; push?: number; args?: number }> = {
    0x00: { name: 'STOP' },
    0x01: { name: 'ADD', args: 2 },
    0x02: { name: 'MUL', args: 2 },
    0x03: { name: 'SUB', args: 2 },
    0x04: { name: 'DIV', args: 2 },
    0x05: { name: 'SDIV', args: 2 },
    0x06: { name: 'MOD', args: 2 },
    0x07: { name: 'SMOD', args: 2 },
    0x08: { name: 'ADDMOD', args: 3 },
    0x09: { name: 'MULMOD', args: 3 },
    0x0a: { name: 'EXP', args: 2 },
    0x0b: { name: 'SIGNEXTEND', args: 2 },
    0x10: { name: 'LT', args: 2 },
    0x11: { name: 'GT', args: 2 },
    0x12: { name: 'SLT', args: 2 },
    0x13: { name: 'SGT', args: 2 },
    0x14: { name: 'EQ', args: 2 },
    0x15: { name: 'ISZERO', args: 1 },
    0x16: { name: 'AND', args: 2 },
    0x17: { name: 'OR', args: 2 },
    0x18: { name: 'XOR', args: 2 },
    0x19: { name: 'NOT', args: 1 },
    0x1a: { name: 'BYTE', args: 2 },
    0x1b: { name: 'SHL', args: 2 },
    0x1c: { name: 'SHR', args: 2 },
    0x1d: { name: 'SAR', args: 2 },
    0x20: { name: 'SHA3', args: 2 },
    0x30: { name: 'ADDRESS' },
    0x31: { name: 'BALANCE', args: 1 },
    0x32: { name: 'ORIGIN' },
    0x33: { name: 'CALLER' },
    0x34: { name: 'CALLVALUE' },
    0x35: { name: 'CALLDATALOAD', args: 1 },
    0x36: { name: 'CALLDATASIZE' },
    0x37: { name: 'CALLDATACOPY', args: 3 },
    0x38: { name: 'CODESIZE' },
    0x39: { name: 'CODECOPY', args: 3 },
    0x3a: { name: 'GASPRICE' },
    0x3b: { name: 'EXTCODESIZE', args: 1 },
    0x3c: { name: 'EXTCODECOPY', args: 4 },
    0x3d: { name: 'RETURNDATASIZE' },
    0x3e: { name: 'RETURNDATACOPY', args: 3 },
    0x3f: { name: 'EXTCODEHASH', args: 1 },
    0x40: { name: 'BLOCKHASH', args: 1 },
    0x41: { name: 'COINBASE' },
    0x42: { name: 'TIMESTAMP' },
    0x43: { name: 'NUMBER' },
    0x44: { name: 'DIFFICULTY' },
    0x45: { name: 'GASLIMIT' },
    0x46: { name: 'CHAINID' },
    0x47: { name: 'SELFBALANCE' },
    0x48: { name: 'BASEFEE' },
    0x50: { name: 'POP', args: 1 },
    0x51: { name: 'MLOAD', args: 1 },
    0x52: { name: 'MSTORE', args: 2 },
    0x53: { name: 'MSTORE8', args: 2 },
    0x54: { name: 'SLOAD', args: 1 },
    0x55: { name: 'SSTORE', args: 2 },
    0x56: { name: 'JUMP', args: 1 },
    0x57: { name: 'JUMPI', args: 2 },
    0x58: { name: 'PC' },
    0x59: { name: 'MSIZE' },
    0x5a: { name: 'GAS' },
    0x5b: { name: 'JUMPDEST' },
    // PUSH operations (0x60 - 0x7f)
    ...Object.fromEntries(
        Array.from({ length: 32 }, (_, i) => [
            0x60 + i,
            { name: `PUSH${i + 1}`, push: i + 1 }
        ])
    ),
    // DUP operations (0x80 - 0x8f)
    ...Object.fromEntries(
        Array.from({ length: 16 }, (_, i) => [
            0x80 + i,
            { name: `DUP${i + 1}` }
        ])
    ),
    // SWAP operations (0x90 - 0x9f)
    ...Object.fromEntries(
        Array.from({ length: 16 }, (_, i) => [
            0x90 + i,
            { name: `SWAP${i + 1}` }
        ])
    ),
    // LOG operations (0xa0 - 0xa4)
    0xa0: { name: 'LOG0', args: 2 },
    0xa1: { name: 'LOG1', args: 3 },
    0xa2: { name: 'LOG2', args: 4 },
    0xa3: { name: 'LOG3', args: 5 },
    0xa4: { name: 'LOG4', args: 6 },
    0xf0: { name: 'CREATE', args: 3 },
    0xf1: { name: 'CALL', args: 7 },
    0xf2: { name: 'CALLCODE', args: 7 },
    0xf3: { name: 'RETURN', args: 2 },
    0xf4: { name: 'DELEGATECALL', args: 6 },
    0xf5: { name: 'CREATE2', args: 4 },
    0xfa: { name: 'STATICCALL', args: 6 },
    0xfd: { name: 'REVERT', args: 2 },
    0xfe: { name: 'INVALID' },
    0xff: { name: 'SELFDESTRUCT', args: 1 }
};

// Common function signature database
const KNOWN_SIGNATURES: Record<string, string> = {
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
    '0x8456cb59': 'pause()',
    '0x3f4ba83a': 'unpause()',
    '0x5c975abb': 'paused()',
    '0x01ffc9a7': 'supportsInterface(bytes4)',
    '0x6352211e': 'ownerOf(uint256)',
    '0xe985e9c5': 'isApprovedForAll(address,address)',
    '0xa22cb465': 'setApprovalForAll(address,bool)',
    '0xb88d4fde': 'safeTransferFrom(address,address,uint256,bytes)',
    '0x42842e0e': 'safeTransferFrom(address,address,uint256)',
    '0x150b7a02': 'onERC721Received(address,address,uint256,bytes)',
    '0xf23a6e61': 'onERC1155Received(address,address,uint256,uint256,bytes)',
    '0xbc197c81': 'onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)',
    '0x2eb2c2d6': 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
    '0xf242432a': 'safeTransferFrom(address,address,uint256,uint256,bytes)',
    '0x00fdd58e': 'balanceOf(address,uint256)',
    '0x4e1273f4': 'balanceOfBatch(address[],uint256[])',
    '0x4f6ccce7': 'tokenByIndex(uint256)',
    '0x2f745c59': 'tokenOfOwnerByIndex(address,uint256)',
    '0xc87b56dd': 'tokenURI(uint256)',
    '0xe8a3d485': 'contractURI()',
    '0x2a55205a': 'royaltyInfo(uint256,uint256)',
    '0xd5abeb01': 'maxSupply()',
    '0xa035b1fe': 'price()',
    '0x55f804b3': 'setBaseURI(string)',
    '0x7d8966e4': 'reveal()',
    '0x5c19a95c': 'delegate(address)',
    '0xb4b5ea57': 'getVotes(address)',
    '0x3a46b1a8': 'getPastVotes(address,uint256)',
    '0x8e539e8c': 'getPastTotalSupply(uint256)',
    '0xc3cda520': 'delegateBySig(address,uint256,uint256,uint8,bytes32,bytes32)',
    '0x587cde1e': 'delegates(address)',
    '0xe9580e91': 'quorumVotes()',
    '0xd33219b4': 'timelock()',
    '0x013cf08b': 'getActions(uint256)',
    '0xda35c664': 'proposalCount()',
    '0x3e4f49e6': 'state(uint256)',
    '0x7bdbe4d0': 'votingPeriod()',
    '0xf8ce560a': 'votingDelay()',
};

// Parse bytecode into opcodes
export function disassemble(bytecode: string): Array<{ offset: number; opcode: string; operand?: string }> {
    const result: Array<{ offset: number; opcode: string; operand?: string }> = [];

    // Remove 0x prefix
    const code = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;

    let i = 0;
    while (i < code.length) {
        const offset = i / 2;
        const byte = parseInt(code.slice(i, i + 2), 16);
        const op = OPCODES[byte];

        if (op) {
            if (op.push) {
                // PUSH operation - read operand
                const operandLength = op.push * 2;
                const operand = '0x' + code.slice(i + 2, i + 2 + operandLength);
                result.push({ offset, opcode: op.name, operand });
                i += 2 + operandLength;
            } else {
                result.push({ offset, opcode: op.name });
                i += 2;
            }
        } else {
            result.push({ offset, opcode: `UNKNOWN(0x${byte.toString(16)})` });
            i += 2;
        }
    }

    return result;
}

// Extract function selectors from bytecode
export function extractSelectors(bytecode: string): string[] {
    const selectors: Set<string> = new Set();
    const code = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;

    // Look for PUSH4 followed by EQ pattern (function dispatcher)
    const push4Pattern = /63([a-fA-F0-9]{8})/g;
    let match;

    while ((match = push4Pattern.exec(code)) !== null) {
        selectors.add('0x' + match[1].toLowerCase());
    }

    return Array.from(selectors);
}

// Identify function signature from selector
export function identifySelector(selector: string): string | undefined {
    return KNOWN_SIGNATURES[selector.toLowerCase()];
}

// Analyze bytecode for dangerous patterns
export function analyzeBytecode(bytecode: string): {
    hasSelfdestruct: boolean;
    hasDelegatecall: boolean;
    hasCreate: boolean;
    hasCreate2: boolean;
    hasCall: boolean;
    hasCallcode: boolean;
    hasStaticCall: boolean;
    hasSstore: boolean;
    hasSload: boolean;
    dangerLevel: 'critical' | 'high' | 'medium' | 'low';
    warnings: string[];
} {
    const code = bytecode.startsWith('0x') ? bytecode.slice(2) : bytecode;
    const warnings: string[] = [];

    // Check for dangerous opcodes
    const hasSelfdestruct = code.includes('ff');
    const hasDelegatecall = code.includes('f4');
    const hasCreate = code.includes('f0');
    const hasCreate2 = code.includes('f5');
    const hasCall = code.includes('f1');
    const hasCallcode = code.includes('f2');
    const hasStaticCall = code.includes('fa');
    const hasSstore = code.includes('55');
    const hasSload = code.includes('54');

    if (hasSelfdestruct) {
        warnings.push('Contract contains SELFDESTRUCT - can be destroyed permanently');
    }
    if (hasDelegatecall) {
        warnings.push('Contract uses DELEGATECALL - potential proxy or vulnerability');
    }
    if (hasCallcode) {
        warnings.push('Contract uses CALLCODE (deprecated) - potential vulnerability');
    }
    if (hasCreate2) {
        warnings.push('Contract uses CREATE2 - can deploy contracts to predetermined addresses');
    }

    // Determine danger level
    let dangerLevel: 'critical' | 'high' | 'medium' | 'low' = 'low';

    if (hasSelfdestruct || hasCallcode) {
        dangerLevel = 'critical';
    } else if (hasDelegatecall || hasCreate2) {
        dangerLevel = 'high';
    } else if (hasCreate || hasCall) {
        dangerLevel = 'medium';
    }

    return {
        hasSelfdestruct,
        hasDelegatecall,
        hasCreate,
        hasCreate2,
        hasCall,
        hasCallcode,
        hasStaticCall,
        hasSstore,
        hasSload,
        dangerLevel,
        warnings
    };
}

// Generate pseudo-source code from bytecode
export function decompile(bytecode: string, address: string): DecompiledContract {
    const selectors = extractSelectors(bytecode);
    const analysis = analyzeBytecode(bytecode);
    const disasm = disassemble(bytecode);

    // Build function list
    const functions: DecompiledFunction[] = selectors.map(selector => {
        const signature = identifySelector(selector);
        let name: string | undefined;
        let inputs: { type: string; name?: string }[] = [];
        let outputs: { type: string; name?: string }[] = [];

        if (signature) {
            // Parse signature
            const match = signature.match(/^(\w+)\(([^)]*)\)(?:\s*returns\s*\(([^)]*)\))?$/);
            if (match) {
                name = match[1];
                if (match[2]) {
                    inputs = match[2].split(',').map((p, i) => {
                        const parts = p.trim().split(/\s+/);
                        return {
                            type: parts[0],
                            name: parts[1] || `arg${i}`
                        };
                    });
                }
                if (match[3]) {
                    outputs = match[3].split(',').map((p, i) => ({
                        type: p.trim(),
                        name: `ret${i}`
                    }));
                }
            }
        }

        // Determine visibility and mutability from signature patterns
        let visibility: 'public' | 'external' | 'internal' | 'private' = 'external';
        let stateMutability: 'pure' | 'view' | 'nonpayable' | 'payable' = 'nonpayable';

        if (name) {
            // Common view functions
            if (['balanceOf', 'totalSupply', 'allowance', 'owner', 'name', 'symbol', 'decimals', 'paused', 'getVotes'].includes(name)) {
                stateMutability = 'view';
            }
            // Common payable functions
            if (['deposit', 'mint', 'buy', 'swap'].some(p => name!.toLowerCase().includes(p))) {
                stateMutability = 'payable';
            }
        }

        // Generate pseudocode
        let pseudocode = '';
        if (signature) {
            pseudocode = `function ${name || 'unknown'}(${inputs.map(i => `${i.type} ${i.name}`).join(', ')})`;
            pseudocode += ` ${visibility} ${stateMutability}`;
            if (outputs.length > 0) {
                pseudocode += ` returns (${outputs.map(o => o.type).join(', ')})`;
            }
            pseudocode += ' {\n    // Decompiled bytecode\n}';
        } else {
            pseudocode = `function func_${selector.slice(2)}() external {\n    // Unknown function\n}`;
        }

        return {
            selector,
            name,
            signature,
            visibility,
            stateMutability,
            inputs,
            outputs,
            pseudocode
        };
    });

    // Extract storage slots (simplified)
    const storage: StorageSlot[] = [];
    let slotIndex = 0;

    // Look for SLOAD/SSTORE with constant slot values
    for (let i = 0; i < disasm.length - 1; i++) {
        if (disasm[i].opcode.startsWith('PUSH') && disasm[i].operand) {
            const nextOp = disasm[i + 1].opcode;
            if (nextOp === 'SLOAD' || nextOp === 'SSTORE') {
                const slot = parseInt(disasm[i].operand!, 16);
                if (slot < 100 && !storage.find(s => s.slot === slot)) {
                    storage.push({
                        slot,
                        offset: 0,
                        type: 'unknown',
                        size: 32
                    });
                }
            }
        }
    }

    // Sort storage by slot
    storage.sort((a, b) => a.slot - b.slot);

    // Extract events (LOG operations)
    const events: string[] = [];
    for (let i = 0; i < disasm.length; i++) {
        if (disasm[i].opcode.startsWith('LOG')) {
            // Try to find event topic (usually PUSH32 before LOG)
            for (let j = i - 1; j >= Math.max(0, i - 5); j--) {
                if (disasm[j].opcode === 'PUSH32' && disasm[j].operand) {
                    events.push(disasm[j].operand);
                    break;
                }
            }
        }
    }

    // Generate full pseudocode
    let pseudocode = `// DECOMPILED CONTRACT\n`;
    pseudocode += `// Address: ${address}\n`;
    pseudocode += `// Bytecode size: ${(bytecode.length - 2) / 2} bytes\n`;
    pseudocode += `// Functions: ${functions.length}\n`;
    pseudocode += `// Storage slots used: ${storage.length}\n\n`;

    pseudocode += `pragma solidity ^0.8.0;\n\n`;
    pseudocode += `contract Decompiled_${address.slice(2, 10)} {\n\n`;

    // Storage variables
    if (storage.length > 0) {
        pseudocode += `    // Storage layout (${storage.length} slots)\n`;
        for (const slot of storage) {
            pseudocode += `    ${slot.type} private storage_${slot.slot}; // slot ${slot.slot}\n`;
        }
        pseudocode += '\n';
    }

    // Analysis warnings
    if (analysis.warnings.length > 0) {
        pseudocode += '    // ⚠️ WARNINGS:\n';
        for (const warning of analysis.warnings) {
            pseudocode += `    // - ${warning}\n`;
        }
        pseudocode += '\n';
    }

    // Functions
    for (const func of functions) {
        pseudocode += `    ${func.pseudocode}\n\n`;
    }

    pseudocode += `}\n`;

    // Calculate confidence based on how many functions we identified
    const identifiedCount = functions.filter(f => f.name).length;
    const confidence = functions.length > 0 ? (identifiedCount / functions.length) : 0;

    return {
        address,
        functions,
        storage,
        events,
        pseudocode,
        confidence
    };
}

// Compare bytecodes (useful for finding similar contracts)
export function compareBytecodes(bytecode1: string, bytecode2: string): {
    similarity: number;
    matchingSelectors: string[];
    uniqueTo1: string[];
    uniqueTo2: string[];
} {
    const selectors1 = extractSelectors(bytecode1);
    const selectors2 = extractSelectors(bytecode2);

    const set1 = new Set(selectors1);
    const set2 = new Set(selectors2);

    const matchingSelectors = selectors1.filter(s => set2.has(s));
    const uniqueTo1 = selectors1.filter(s => !set2.has(s));
    const uniqueTo2 = selectors2.filter(s => !set1.has(s));

    const totalUnique = new Set([...selectors1, ...selectors2]).size;
    const similarity = totalUnique > 0 ? matchingSelectors.length / totalUnique : 0;

    return {
        similarity,
        matchingSelectors,
        uniqueTo1,
        uniqueTo2
    };
}

export default {
    disassemble,
    extractSelectors,
    identifySelector,
    analyzeBytecode,
    decompile,
    compareBytecodes,
    OPCODES,
    KNOWN_SIGNATURES
};

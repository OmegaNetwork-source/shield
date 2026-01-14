// STIG XCCDF Parser
// Parses DISA STIG XML files and extracts rules with automated checks

export interface ParsedStigRule {
    vulnId: string;         // V-253260
    stigId: string;         // WN11-00-000031
    title: string;
    severity: 'high' | 'medium' | 'low';
    description: string;
    checkContent: string;   // Raw check procedure text
    fixContent: string;     // Raw fix procedure text
    ccis: string[];

    // Extracted automated check (if possible)
    automatedCheck?: {
        type: 'registry' | 'auditpol' | 'powershell' | 'manual';
        registryPath?: string;
        valueName?: string;
        expectedValue?: string | number;
        operator?: 'eq' | 'gte' | 'lte' | 'exists';
        command?: string;
    };
}

// Parse registry check from check content
function parseRegistryCheck(checkContent: string): ParsedStigRule['automatedCheck'] | null {
    // Format 1 (Windows 11 STIG):
    // Registry Hive: HKEY_LOCAL_MACHINE
    // Registry Path: \SOFTWARE\Policies\Microsoft\FVE\
    // Value Name: MinimumPIN
    // Type: REG_DWORD
    // Value: 0x00000006 (6)

    // Format 2 (Edge STIG):
    // HKLM\SOFTWARE\Policies\Microsoft\Edge
    // If the value for "ValueName" is not set to "REG_DWORD = 1", this is a finding.

    let psPath = '';
    let valueName = '';
    let expectedValue: number | undefined;
    let operator: 'eq' | 'gte' | 'lte' | 'exists' = 'eq';

    // Try Format 1 first (Windows 11 style)
    const hiveMatch = checkContent.match(/Registry Hive:\s*(HKEY_[A-Z_]+)/i);
    const pathMatch = checkContent.match(/Registry Path:\s*([^\n]+)/i);
    const valueNameMatch = checkContent.match(/Value Name:\s*([^\n]+)/i);
    const valueMatch = checkContent.match(/Value:\s*(?:0x[0-9a-fA-F]+\s*\()?(\d+)\)?/i);

    if (hiveMatch && pathMatch && valueNameMatch) {
        const hive = hiveMatch[1].trim();
        let path = pathMatch[1].trim();
        valueName = valueNameMatch[1].trim();

        if (hive === 'HKEY_LOCAL_MACHINE') {
            psPath = 'HKLM:' + path;
        } else if (hive === 'HKEY_CURRENT_USER') {
            psPath = 'HKCU:' + path;
        }

        expectedValue = valueMatch ? parseInt(valueMatch[1], 10) : undefined;
    } else {
        // Try Format 2 (Edge STIG style)
        // Look for: HKLM\SOFTWARE\Policies\Microsoft\Edge
        const edgePathMatch = checkContent.match(/navigate to[^:]*:\s*(HKLM\\[^\n]+)/i) ||
            checkContent.match(/(HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge[^\\\n]*)/i);

        // Master pattern for Edge: "value for "ValueName" is not set to "REG_TYPE = value"
        // This captures both REG_DWORD and REG_SZ patterns
        const edgeValueMatch = checkContent.match(/value for\s*["""]?(\w+)["""]?\s*is not set to\s*["""]?REG_(DWORD|SZ)\s*=\s*([^"""\n,]+)/i);

        // Also check for REG_SZ with quoted values
        const edgeSzQuotedMatch = checkContent.match(/REG_SZ value for\s*["""]?(\w+)["""]?/i);

        if (edgePathMatch) {
            const path = edgePathMatch[1].trim().replace(/^HKLM/, 'HKLM:');
            psPath = path;

            if (edgeValueMatch) {
                valueName = edgeValueMatch[1].trim();
                const regType = edgeValueMatch[2].toUpperCase();
                const value = edgeValueMatch[3].trim();

                if (regType === 'DWORD') {
                    // Parse as number
                    expectedValue = parseInt(value, 10);
                } else if (regType === 'SZ') {
                    // For REG_SZ, we check if the key exists with any value
                    // (actual string comparison would require more complex logic)
                    operator = 'exists';
                }
            } else if (edgeSzQuotedMatch) {
                // REG_SZ check - just check if value exists
                valueName = edgeSzQuotedMatch[1].trim();
                operator = 'exists';
            }
        }
    }

    if (psPath && valueName) {
        // Determine operator from text
        if (checkContent.includes('or greater')) {
            operator = 'gte';
        } else if (checkContent.includes('or less')) {
            operator = 'lte';
        }

        return {
            type: 'registry',
            registryPath: psPath,
            valueName: valueName,
            expectedValue,
            operator
        };
    }

    return null;
}

// Parse auditpol check
function parseAuditpolCheck(checkContent: string): ParsedStigRule['automatedCheck'] | null {
    // Look for patterns like:
    // Use the AuditPol tool to review the current Audit Policy configuration:
    // >> AuditPol /get /category:*

    const auditMatch = checkContent.match(/AuditPol\s+\/get\s+\/subcategory:"([^"]+)"/i);

    if (auditMatch) {
        const subcategory = auditMatch[1];
        let expectedOutput = 'Success';

        if (checkContent.toLowerCase().includes('failure')) {
            expectedOutput = 'Failure';
        }
        if (checkContent.toLowerCase().includes('success and failure')) {
            expectedOutput = 'Success and Failure';
        }

        return {
            type: 'auditpol',
            command: `auditpol /get /subcategory:"${subcategory}"`,
        };
    }

    return null;
}

// Parse PowerShell command from check content
function parsePowershellCheck(checkContent: string): ParsedStigRule['automatedCheck'] | null {
    // Look for PowerShell commands in check content
    const psCommandMatch = checkContent.match(/(?:Run|Enter|Execute).*?[:]\s*(Get-[^\n]+)/i);

    if (psCommandMatch) {
        return {
            type: 'powershell',
            command: psCommandMatch[1].trim()
        };
    }

    return null;
}

// Main parser function
export function parseStigXML(xmlContent: string): ParsedStigRule[] {
    const rules: ParsedStigRule[] = [];

    // Match all Group elements containing Rules
    const groupRegex = /<Group id="(V-\d+)"[^>]*>[\s\S]*?<\/Group>/g;
    let groupMatch;

    while ((groupMatch = groupRegex.exec(xmlContent)) !== null) {
        const vulnId = groupMatch[1];
        const groupContent = groupMatch[0];

        // Extract rule details
        const ruleMatch = groupContent.match(/<Rule[^>]*severity="(high|medium|low)"[^>]*>[\s\S]*?<\/Rule>/i);
        if (!ruleMatch) continue;

        const ruleContent = ruleMatch[0];
        const severity = ruleMatch[1] as 'high' | 'medium' | 'low';

        // Extract version (STIG ID)
        const versionMatch = ruleContent.match(/<version>([^<]+)<\/version>/) || ruleContent.match(/<Rule_ID>([^<]+)<\/Rule_ID>/);
        const stigId = versionMatch ? versionMatch[1] : '';

        // Extract title
        const titleMatch = ruleContent.match(/<title>([\s\S]*?)<\/title>/);
        const title = titleMatch ? titleMatch[1].trim() : '';

        // Extract description (VulnDiscussion)
        const vulnDiscMatch = ruleContent.match(/&lt;VulnDiscussion&gt;([\s\S]*?)&lt;\/VulnDiscussion&gt;/);
        let description = vulnDiscMatch ? vulnDiscMatch[1] : '';
        description = description.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

        // Extract check content
        const checkMatch = ruleContent.match(/<check-content>([\s\S]*?)<\/check-content>/);
        let checkContent = checkMatch ? checkMatch[1] : '';
        // Decode HTML entities
        checkContent = checkContent.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

        // Extract fix content
        const fixMatch = ruleContent.match(/<fixtext[^>]*>([\s\S]*?)<\/fixtext>/);
        let fixContent = fixMatch ? fixMatch[1] : '';
        fixContent = fixContent.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

        // Extract CCIs
        const cciMatches = [...ruleContent.matchAll(/<ident[^>]*>(CCI-[^<]+)<\/ident>/g)];
        const ccis = cciMatches.map(m => m[1]);

        // Try parse automated check
        let automatedCheck = parseRegistryCheck(checkContent);
        if (!automatedCheck) {
            automatedCheck = parseAuditpolCheck(checkContent);
        }
        if (!automatedCheck) {
            automatedCheck = parsePowershellCheck(checkContent);
        }
        if (!automatedCheck) {
            automatedCheck = { type: 'manual' };
        }

        rules.push({
            vulnId,
            stigId,
            title,
            severity,
            description,
            checkContent,
            fixContent,
            ccis,
            automatedCheck
        });
    }

    return rules;
}

// Generate PowerShell command for a rule's automated check
export function generateCheckCommand(rule: ParsedStigRule): string | null {
    if (!rule.automatedCheck) return null;

    switch (rule.automatedCheck.type) {
        case 'registry':
            if (rule.automatedCheck.registryPath && rule.automatedCheck.valueName) {
                return `Get-ItemProperty -Path '${rule.automatedCheck.registryPath}' -Name '${rule.automatedCheck.valueName}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty '${rule.automatedCheck.valueName}'`;
            }
            break;

        case 'auditpol':
            return rule.automatedCheck.command || null;

        case 'powershell':
            return rule.automatedCheck.command || null;

        case 'manual':
            return null;
    }

    return null;
}

// Evaluate check result
export function evaluateCheckResult(rule: ParsedStigRule, output: string): boolean {
    if (!rule.automatedCheck) return false;

    const trimmed = output.trim();

    if (rule.automatedCheck.type === 'registry') {
        if (rule.automatedCheck.expectedValue === undefined) {
            // Just checking if value exists
            return trimmed.length > 0 && !trimmed.toLowerCase().includes('error');
        }

        const numOutput = parseInt(trimmed, 10);
        const numExpected = rule.automatedCheck.expectedValue as number;

        if (!isNaN(numOutput)) {
            switch (rule.automatedCheck.operator) {
                case 'eq': return numOutput === numExpected;
                case 'gte': return numOutput >= numExpected;
                case 'lte': return numOutput <= numExpected;
                case 'exists': return true;
            }
        }
    }

    // For auditpol - check if expected setting is present
    if (rule.automatedCheck.type === 'auditpol') {
        // Check for Success, Failure, or both
        return trimmed.includes('Success') || trimmed.includes('Failure');
    }

    return false;
}

// Output structure matches App.tsx uploadedChecklists state
export interface ParsedChecklist {
    id: string;
    filename: string;
    hostname: string;
    stigName: string;
    findings: Array<{
        vulnId: string; // Group ID (V-XXXX)
        ruleId: string; // Rule ID (SV-XXXX)
        status: string;
        severity: string;
        title: string;
        comments: string;
        findingDetails: string;
        ccis: string[];
    }>;
}

export async function parseCklFile(file: File): Promise<ParsedChecklist | null> {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const xml = e.target?.result as string;
            if (!xml) { resolve(null); return; }

            try {
                const parser = new DOMParser();
                const doc = parser.parseFromString(xml, "text/xml");

                const asset = doc.getElementsByTagName('ASSET')[0];
                const hostname = asset?.getElementsByTagName('HOST_NAME')[0]?.textContent || '';

                const stigRef = doc.getElementsByTagName('STIG_REF')[0]?.textContent || '';

                const vulns = doc.getElementsByTagName('VULN');
                const findings: ParsedChecklist['findings'] = [];

                for (let i = 0; i < vulns.length; i++) {
                    const vuln = vulns[i];
                    let vulnId = vuln.getElementsByTagName('VULN_NUM')[0]?.textContent || ''; // Default to VULN_NUM tag
                    const status = vuln.getElementsByTagName('STATUS')[0]?.textContent || 'Not_Reviewed';
                    const comments = vuln.getElementsByTagName('COMMENTS')[0]?.textContent || '';
                    const findingDetails = vuln.getElementsByTagName('FINDING_DETAILS')[0]?.textContent || '';
                    const title = vuln.getElementsByTagName('RULE_TITLE')[0]?.textContent || '';
                    const severity = vuln.getElementsByTagName('SEVERITY')[0]?.textContent || 'low';

                    // Extract CCIs and ID overrides from STIG_DATA
                    const ccis: string[] = [];
                    let ruleId = '';

                    const stigData = vuln.getElementsByTagName('STIG_DATA');
                    for (let j = 0; j < stigData.length; j++) {
                        const attr = stigData[j].getElementsByTagName('VULN_ATTRIBUTE')[0]?.textContent;
                        const data = stigData[j].getElementsByTagName('ATTRIBUTE_DATA')[0]?.textContent;

                        if (!attr || !data) continue;

                        if (attr === 'CCI_REF') {
                            ccis.push(data);
                        } else if (attr === 'Rule_ID') {
                            ruleId = data; // SV-XXXX
                        } else if (attr === 'Vuln_Num') {
                            vulnId = data; // V-XXXX (Override VULN_NUM tag if present)
                        }
                    }

                    findings.push({
                        vulnId,
                        ruleId,
                        status,
                        severity,
                        title,
                        comments,
                        findingDetails,
                        ccis
                    });
                }

                resolve({
                    id: Math.random().toString(36).substr(2, 9),
                    filename: file.name,
                    hostname,
                    stigName: stigRef,
                    findings
                });

            } catch (err) {
                console.error("Error parsing CKL", err);
                resolve(null);
            }
        };
        reader.readAsText(file);
    });
}

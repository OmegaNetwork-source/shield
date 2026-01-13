import React, { useState, useEffect } from 'react';
import {
    ShieldCheck, Play, Camera, LayoutGrid, Settings,
    ChevronRight, Check, X, Loader2, AlertTriangle, AlertCircle, Info,
    FolderOpen, RefreshCw, FileText, Download, Eye, XCircle, ClipboardList, Monitor, Globe,
    Moon, Sun, FileSpreadsheet, Upload, Trash2, GitCompare, FileWarning, Database, Server, Users, Shield
} from 'lucide-react';
import { parseStigXML, generateCheckCommand, evaluateCheckResult, ParsedStigRule } from './utils/stig-parser';
import * as XLSX from 'xlsx';
import { STIG_PATHS } from './stig-paths';

// Feature Flag: Check if running in Electron
// @ts-ignore
const isElectron = window.ipcRenderer !== undefined;

interface CheckResult {
    ruleId: string;
    status: 'pending' | 'pass' | 'fail' | 'running' | 'error' | 'notapplicable';
    output?: string;
    command?: string;
    timestamp?: Date;
}

interface StigChecklist {
    id: string;
    name: string;
    date?: string;
}

function App() {
    const [rules, setRules] = useState<ParsedStigRule[]>([]);
    const [results, setResults] = useState<Map<string, CheckResult>>(new Map());
    const [activeTab, setActiveTab] = useState<'scan' | 'evidence' | 'checklist' | 'report' | 'compare' | 'poam'>(isElectron ? 'scan' : 'checklist');
    const [evidenceList, setEvidenceList] = useState<any[]>([]);
    const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
    const [selectedStatus, setSelectedStatus] = useState<string | null>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [stigInfo, setStigInfo] = useState({ version: 'Loading...', ruleCount: 0, stigId: 'win11' });
    const [selectedRule, setSelectedRule] = useState<ParsedStigRule | null>(null);
    const [availableChecklists, setAvailableChecklists] = useState<StigChecklist[]>([]);
    const [darkMode, setDarkMode] = useState(false);
    const [uploadedChecklists, setUploadedChecklists] = useState<Array<{
        id: string;
        filename: string;
        hostname: string;
        stigName: string;
        findings: Array<{
            vulnId: string;
            status: string;
            severity: string;
            title: string;
            comments: string;
            ruleId?: string;
            groupId?: string;
            fixText?: string;
            description?: string;
            ccis?: string[];
        }>;
    }>>([]);
    const [isGeneratingReport, setIsGeneratingReport] = useState(false);

    // Compare Tab State
    const [compareBase, setCompareBase] = useState<typeof uploadedChecklists[0] | null>(null);
    const [compareNew, setCompareNew] = useState<typeof uploadedChecklists[0] | null>(null);
    const [comparisonDiffs, setComparisonDiffs] = useState<any[] | null>(null);
    const [compareFilter, setCompareFilter] = useState<'all' | 'status' | 'new' | 'removed'>('all');

    // POA&M State
    const [poamChecklists, setPoamChecklists] = useState<typeof uploadedChecklists>([]);

    // Load available checklists on mount
    useEffect(() => {
        loadChecklists();
        loadStigFile('win11'); // Default to Windows 11
    }, []);

    const loadChecklists = async () => {
        if (isElectron) {
            const list = await window.ipcRenderer.invoke('get-stig-list');
            setAvailableChecklists(list || []);
        } else {
            // Web Mode: Use static definitions
            // We could try to fetch dates, but for now just map the static list
            const list = Object.keys(STIG_PATHS).map(id => ({
                id,
                name: STIG_PATHS[id].name,
                date: 'Web Mode' // Dates are dynamically parsed in Electron, simplified here
            }));
            setAvailableChecklists(list);
        }
    };

    const exportStig = async (stigId: string, format: 'csv' | 'cklb') => {
        console.log(`Starting export for ${stigId} in ${format} format`);
        setIsLoading(true);
        try {
            let result: { success: boolean; content: string; name: string; stigId: string; error?: string };

            if (isElectron) {
                result = await window.ipcRenderer.invoke('load-stig-file', stigId);
            } else {
                // Web Mode: Fetch from public folder
                try {
                    const pathInfo = STIG_PATHS[stigId];
                    const req = await fetch(`/STIGs/${pathInfo.path}`);
                    const text = await req.text();
                    result = { success: true, content: text, name: pathInfo.name, stigId };
                } catch (e: any) {
                    result = { success: false, content: '', name: '', stigId, error: e.message };
                }
            }

            if (result.success) {
                console.log('STIG content loaded successfully');
                const parsedRules = parseStigXML(result.content);
                console.log(`Parsed ${parsedRules.length} rules`);
                const dateStr = new Date().toISOString().split('T')[0];
                const filename = `${result.stigId}_${dateStr}.${format}`;

                let content = '';
                if (format === 'csv') {
                    const header = ['Vuln ID', 'Rule ID', 'Severity', 'Title', 'Discussion', 'Fix Text', 'CCI'];
                    const rows = parsedRules.map(r => [
                        r.vulnId || '',
                        r.stigId || '',
                        r.severity || '',
                        `"${(r.title || '').replace(/"/g, '""')}"`,
                        `"${(r.description || '').replace(/"/g, '""')}"`,
                        `"${(r.fixContent || '').replace(/"/g, '""')}"`,
                        `"${(r.ccis || []).join(', ')}"`
                    ]);
                    content = [header.join(','), ...rows.map(r => r.join(','))].join('\n');
                } else {
                    const findings = parsedRules.map(rule => ({
                        vulnId: rule.vulnId,
                        status: 'Not_Reviewed',
                        severity: rule.severity,
                        title: rule.title,
                        comments: '',
                        ruleId: rule.stigId,
                        fixText: rule.fixContent,
                        description: rule.description,
                        ccis: rule.ccis
                    }));
                    const cklbData = {
                        hostname: 'Target-System',
                        stigName: result.name,
                        findings
                    };
                    content = JSON.stringify(cklbData, null, 2);
                }

                if (isElectron) {
                    const saveResult = await window.ipcRenderer.invoke('save-file', {
                        filename,
                        content,
                        type: format
                    });

                    if (saveResult.success) {
                        console.log(`File saved to ${saveResult.filePath}`);
                    } else if (saveResult.error) {
                        console.error('Save failed:', saveResult.error);
                        alert(`Failed to save file: ${saveResult.error}`);
                    }
                } else {
                    // Web Mode: Browser Download
                    const blob = new Blob([content], { type: format === 'csv' ? 'text/csv' : 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                }
            } else {
                console.error('Failed to load STIG file for export:', result.error);
                alert(`Error loading STIG: ${result.error}`);
            }
        } catch (e: any) {
            console.error('Export exception:', e);
            if (isElectron && e.message && e.message.includes('No handler registered')) {
                alert('Update Required: Please restart the application (close window and run "npm run dev") to enable the new file saving feature.');
            } else {
                alert(`An error occurred: ${e.message || e}`);
            }
        }
        setIsLoading(false);
    };

    const loadStigFile = async (stigId: string) => {
        setIsLoading(true);
        setResults(new Map()); // Clear previous results
        try {
            let result;
            if (isElectron) {
                result = await window.ipcRenderer.invoke('load-stig-file', stigId);
            } else {
                // Web Mode: Fetch from public folder
                try {
                    const pathInfo = STIG_PATHS[stigId];
                    if (!pathInfo) throw new Error('STIG definition not found in web map');
                    const req = await fetch(`/STIGs/${pathInfo.path}`);
                    if (!req.ok) throw new Error(`HTTP Error ${req.status}`);
                    const text = await req.text();
                    result = { success: true, content: text, name: pathInfo.name, stigId };
                } catch (e: any) {
                    result = { success: false, error: e.message };
                }
            }

            if (result.success) {
                const parsedRules = parseStigXML(result.content);
                setRules(parsedRules);
                setStigInfo({
                    version: result.name,
                    ruleCount: parsedRules.length,
                    stigId: result.stigId
                });
                if (isElectron) {
                    setActiveTab('scan'); // Go to scan view after loading (Electron only)
                }
            } else {
                console.error('Failed to load STIG file:', result.error);
            }
        } catch (e) {
            console.error('Error loading STIG file:', e);
        }
        setIsLoading(false);
    };

    // Filter rules by severity and status
    const filteredRules = rules.filter(r => {
        if (selectedSeverity && r.severity !== selectedSeverity) return false;
        if (selectedStatus) {
            const result = results.get(r.vulnId);
            const status = result?.status || 'pending';
            if (selectedStatus === 'pass' && status !== 'pass') return false;
            if (selectedStatus === 'fail' && status !== 'fail') return false;
            if (selectedStatus === 'manual' && status !== 'notapplicable') return false;
            if (selectedStatus === 'pending' && status !== 'pending') return false;
        }
        return true;
    });

    // Run a single check
    const runCheck = async (rule: ParsedStigRule) => {
        const command = generateCheckCommand(rule);
        if (!command) {
            setResults(prev => new Map(prev).set(rule.vulnId, {
                ruleId: rule.vulnId,
                status: 'notapplicable',
                output: 'Manual check required - no automated check available',
                command: 'N/A'
            }));
            return;
        }

        setResults(prev => new Map(prev).set(rule.vulnId, {
            ruleId: rule.vulnId,
            status: 'running',
            command
        }));

        try {
            const result = await window.ipcRenderer.invoke('run-command', command);

            // Handle the output
            let output = result.output?.trim() || '';
            let passed = false;

            if (result.success) {
                // Command succeeded - check if value matches expected
                passed = evaluateCheckResult(rule, output);
            } else {
                // Command failed - for registry checks, this usually means key doesn't exist
                // which is typically a FAIL (finding), not an error
                if (rule.automatedCheck?.type === 'registry') {
                    // If registry key doesn't exist, it's a finding (FAIL)
                    output = output || 'Registry key or value not found (policy not configured)';
                    passed = false;
                } else {
                    output = `Error: ${output}`;
                    passed = false;
                }
            }

            setResults(prev => new Map(prev).set(rule.vulnId, {
                ruleId: rule.vulnId,
                status: passed ? 'pass' : 'fail',
                output,
                command,
                timestamp: new Date()
            }));
        } catch (e: any) {
            setResults(prev => new Map(prev).set(rule.vulnId, {
                ruleId: rule.vulnId,
                status: 'error',
                output: e.toString(),
                command
            }));
        }
    };

    // Run all checks
    const runAllChecks = async () => {
        setIsScanning(true);
        for (const rule of filteredRules) {
            await runCheck(rule);
            await new Promise(r => setTimeout(r, 30));
        }
        setIsScanning(false);
    };

    // Capture evidence for a single rule
    const captureEvidence = async (rule: ParsedStigRule, skipReload = false) => {
        const result = results.get(rule.vulnId);
        const command = generateCheckCommand(rule);

        await window.ipcRenderer.invoke('save-evidence', {
            ruleId: `${rule.vulnId} (${rule.stigId})`,
            ruleTitle: rule.title,
            command: command || 'Manual check',
            output: result?.output || 'No output captured - run check first',
            status: result?.status || 'pending',
            captureScreenshot: false // Skip screenshots for bulk capture
        });
        if (!skipReload) {
            loadEvidence();
        }
    };

    // Capture evidence for ALL scanned checks
    const [isCapturingAll, setIsCapturingAll] = useState(false);
    const captureAllEvidence = async () => {
        setIsCapturingAll(true);
        const scannedRules = rules.filter(r => results.has(r.vulnId));
        for (const rule of scannedRules) {
            await captureEvidence(rule, true);
            await new Promise(r => setTimeout(r, 50)); // Small delay between captures
        }
        await loadEvidence();
        setIsCapturingAll(false);
    };

    // Load evidence list
    const loadEvidence = async () => {
        const files = await window.ipcRenderer.invoke('get-evidence');
        setEvidenceList(files || []);
    };

    // Export all evidence as JSON
    const exportAllEvidence = () => {
        const data = JSON.stringify(evidenceList, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `stig-evidence-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
    };

    // Export Results as CKLB (JSON)
    const exportToCklb = () => {
        const findings = rules.map(rule => {
            const result = results.get(rule.vulnId);
            let status = 'Not_Reviewed';
            let comments = '';

            if (result) {
                if (result.status === 'pass') status = 'NotAFinding';
                else if (result.status === 'fail') status = 'Open';
                else if (result.status === 'notapplicable') status = 'Not_Applicable';
                else if (result.status === 'error') status = 'Open';

                comments = result.output || '';
            }

            return {
                vulnId: rule.vulnId,
                status,
                severity: rule.severity,
                title: rule.title,
                comments,
                ruleId: rule.stigId,
                fixText: rule.fixContent,
                description: rule.description,
                ccis: rule.ccis
            };
        });

        const cklbData = {
            hostname: 'Local-System',
            stigName: stigInfo.version,
            findings
        };

        const data = JSON.stringify(cklbData, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `results_${stigInfo.stigId}_${new Date().toISOString().split('T')[0]}.cklb`;
        a.click();
    };

    // Parse CKL/CKLB file
    const parseCklFile = async (file: File): Promise<typeof uploadedChecklists[0] | null> => {
        const content = await file.text();

        // 1. Try JSON Parsing (CKLB / Custom JSON)
        try {
            const json = JSON.parse(content);

            // Helper to find the array of vulnerabilities recursively
            const findFindings = (obj: any): any[] => {
                if (!obj) return [];
                if (Array.isArray(obj)) {
                    // Check if this array looks like findings (has common fields)
                    if (obj.length > 0 && (obj[0].vulnId || obj[0].vulnNum || obj[0].ruleId || obj[0].Rule_ID || obj[0].STIG_ID || obj[0].vuln_num)) {
                        return obj;
                    }
                    // Continue searching inside array items
                    for (const item of obj) {
                        const result = findFindings(item);
                        if (result.length > 0) return result;
                    }
                    return [];
                }
                if (typeof obj === 'object') {
                    // Check specific known keys
                    if (obj.findings) return findFindings(obj.findings);
                    if (obj.vulns) return findFindings(obj.vulns);
                    if (obj.stigs) return findFindings(obj.stigs);
                    if (obj.checklist) return findFindings(obj.checklist);
                    if (obj.STIG_DATA) return findFindings(obj.STIG_DATA);

                    // Generic search in values
                    for (const key in obj) {
                        const result = findFindings(obj[key]);
                        if (result.length > 0) return result;
                    }
                }
                return [];
            };

            const rawFindings = findFindings(json);

            if (rawFindings.length > 0) {
                // Map raw findings to our schema
                const mappedFindings = rawFindings.map((f: any) => ({
                    vulnId: f.vulnId || f.vulnNum || f.Vuln_Num || f.vuln_num || f.id || 'Unknown',
                    status: f.status || f.STATUS || f.Status || 'Not_Reviewed',
                    severity: f.severity || f.Severity || f.sev || 'medium',
                    title: f.title || f.Rule_Title || f.rule_title || f.ruleTitle || 'Unknown Title',
                    comments: f.comments || f.COMMENTS || f.comment || '',
                    ruleId: f.ruleId || f.Rule_ID || f.STIG_ID || f.rule_id || '',
                    fixText: f.fixText || f.Fix_Text || f.fix_text || f.fix || '',
                    description: f.description || f.Vuln_Discuss || f.desc || '',
                    ccis: Array.isArray(f.ccis) ? f.ccis : []
                }));

                // Find hostname/stigName if possible
                const findValue = (obj: any, key: string): string => {
                    // simple search
                    if (!obj) return '';
                    if (typeof obj === 'object') {
                        if (obj[key]) return obj[key];
                        for (const k in obj) {
                            if (typeof obj[k] === 'object') {
                                const res = findValue(obj[k], key);
                                if (res) return res;
                            }
                        }
                    }
                    return '';
                };

                return {
                    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    filename: file.name,
                    hostname: json.hostname || json.HOST_NAME || findValue(json, 'HOST_NAME') || findValue(json, 'assetName') || 'Unknown Host',
                    stigName: json.stigName || json.SID_NAME || findValue(json, 'SID_NAME') || 'Imported Checklist',
                    findings: mappedFindings
                };
            }
        } catch (e) {
            // Not JSON, fall through to XML
        }

        try {
            // Extract hostname
            const hostMatch = content.match(/<HOST_NAME>([^<]*)<\/HOST_NAME>/i);
            const hostname = hostMatch ? hostMatch[1].trim() : 'Unknown';

            // Extract STIG name
            const stigMatch = content.match(/<STIG_INFO>[\s\S]*?<SID_NAME>([^<]*)<\/SID_NAME>/i) ||
                content.match(/<title>([^<]*)<\/title>/i);
            const stigName = stigMatch ? stigMatch[1].trim() : 'Unknown STIG';

            // Extract vulnerability findings
            const findings: typeof uploadedChecklists[0]['findings'] = [];
            const vulnRegex = /<VULN>([\s\S]*?)<\/VULN>/gi;
            let match;

            while ((match = vulnRegex.exec(content)) !== null) {
                const vulnContent = match[1];

                // Extract Vuln ID
                const vulnIdMatch = vulnContent.match(/<VULN_ATTRIBUTE>Vuln_Num<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const vulnId = vulnIdMatch ? vulnIdMatch[1].trim() : '';

                // Extract Status
                const statusMatch = vulnContent.match(/<STATUS>([^<]*)<\/STATUS>/i);
                const status = statusMatch ? statusMatch[1].trim() : 'Not_Reviewed';

                // Extract Severity
                const sevMatch = vulnContent.match(/<VULN_ATTRIBUTE>Severity<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const severity = sevMatch ? sevMatch[1].trim() : 'medium';

                // Extract Title
                const titleMatch = vulnContent.match(/<VULN_ATTRIBUTE>Rule_Title<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const title = titleMatch ? titleMatch[1].trim() : '';

                // Extract Comments
                const commentsMatch = vulnContent.match(/<COMMENTS>([^<]*)<\/COMMENTS>/i);
                const comments = commentsMatch ? commentsMatch[1].trim() : '';

                // Extract Rule ID
                const ruleIdMatch = vulnContent.match(/<VULN_ATTRIBUTE>(?:Rule_ID|Rule_Ver|STIG_ID)<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const ruleId = ruleIdMatch ? ruleIdMatch[1].trim() : '';

                // Extract Fix Text
                const fixMatch = vulnContent.match(/<VULN_ATTRIBUTE>Fix_Text<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([\s\S]*?)<\/ATTRIBUTE_DATA>/i);
                const fixText = fixMatch ? fixMatch[1].trim() : '';

                // Extract Discussion
                const discMatch = vulnContent.match(/<VULN_ATTRIBUTE>(?:Discussion|Vuln_Discuss)<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([\s\S]*?)<\/ATTRIBUTE_DATA>/i);
                const description = discMatch ? discMatch[1].trim() : '';

                // Extract CCIs
                const cciRegex = /<VULN_ATTRIBUTE>CCI_REF<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>(CCI-[^<]*)<\/ATTRIBUTE_DATA>/gi;
                const ccis: string[] = [];
                let cciMatch;
                while ((cciMatch = cciRegex.exec(vulnContent)) !== null) {
                    ccis.push(cciMatch[1].trim());
                }

                if (vulnId) {
                    findings.push({ vulnId, status, severity, title, comments, ruleId, fixText, description, ccis });
                }
            }

            return {
                id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                filename: file.name,
                hostname,
                stigName,
                findings
            };
        } catch (e) {
            console.error('Error parsing CKL file:', e);
            return null;
        }
    };

    // Handle file upload
    const handleCklFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = e.target.files;
        if (!files) return;

        setIsGeneratingReport(true);
        const newChecklists: typeof uploadedChecklists = [];

        for (let i = 0; i < files.length; i++) {
            const file = files[i];

            // Only process likely checklist files
            if (file.name.endsWith('.ckl') || file.name.endsWith('.xml') || file.name.endsWith('.cklb') || file.name.endsWith('.json')) {
                const parsed = await parseCklFile(file);
                if (parsed) {
                    newChecklists.push(parsed);
                }
            }
        }

        setUploadedChecklists(prev => [...prev, ...newChecklists]);
        setIsGeneratingReport(false);
        e.target.value = ''; // Reset input
    };



    // Generate Excel Report
    const generateExcelReport = () => {
        if (uploadedChecklists.length === 0) return;

        setIsGeneratingReport(true);

        try {
            const workbook = XLSX.utils.book_new();

            // === SUMMARY SHEET ===
            const summaryData: any[][] = [
                ['STIG Compliance Report', '', '', '', ''],
                ['Generated:', new Date().toLocaleString(), '', '', ''],
                ['Total Checklists:', uploadedChecklists.length, '', '', ''],
                ['', '', '', '', ''],
                ['STIG Name', 'Hostname', 'Open', 'Not a Finding', 'Not Reviewed', 'N/A', 'Total Findings'],
            ];

            let totalOpen = 0, totalNaF = 0, totalNR = 0, totalNA = 0;

            uploadedChecklists.forEach(ckl => {
                const open = ckl.findings.filter(f => f.status === 'Open').length;
                const naf = ckl.findings.filter(f => f.status === 'NotAFinding' || f.status === 'Not_A_Finding').length;
                const nr = ckl.findings.filter(f => f.status === 'Not_Reviewed').length;
                const na = ckl.findings.filter(f => f.status === 'Not_Applicable').length;

                totalOpen += open;
                totalNaF += naf;
                totalNR += nr;
                totalNA += na;

                summaryData.push([ckl.stigName, ckl.hostname, open, naf, nr, na, ckl.findings.length]);
            });

            summaryData.push(['', '', '', '', '', '', '']);
            summaryData.push(['TOTALS', '', totalOpen, totalNaF, totalNR, totalNA, totalOpen + totalNaF + totalNR + totalNA]);

            // Group by hostname
            summaryData.push(['', '', '', '', '', '', '']);
            summaryData.push(['=== GROUPED BY HOSTNAME ===', '', '', '', '', '', '']);
            summaryData.push(['Hostname', 'STIGs', 'Open', 'Not a Finding', 'Not Reviewed', 'N/A', '']);

            const hostGroups = new Map<string, typeof uploadedChecklists>();
            uploadedChecklists.forEach(ckl => {
                if (!hostGroups.has(ckl.hostname)) {
                    hostGroups.set(ckl.hostname, []);
                }
                hostGroups.get(ckl.hostname)!.push(ckl);
            });

            hostGroups.forEach((checklists, hostname) => {
                const open = checklists.flatMap(c => c.findings).filter(f => f.status === 'Open').length;
                const naf = checklists.flatMap(c => c.findings).filter(f => f.status === 'NotAFinding' || f.status === 'Not_A_Finding').length;
                const nr = checklists.flatMap(c => c.findings).filter(f => f.status === 'Not_Reviewed').length;
                const na = checklists.flatMap(c => c.findings).filter(f => f.status === 'Not_Applicable').length;

                summaryData.push([hostname, checklists.length, open, naf, nr, na, '']);
            });

            const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
            summarySheet['!cols'] = [{ wch: 40 }, { wch: 20 }, { wch: 10 }, { wch: 15 }, { wch: 15 }, { wch: 10 }, { wch: 15 }];
            XLSX.utils.book_append_sheet(workbook, summarySheet, 'Summary');

            // === INDIVIDUAL CHECKLIST SHEETS (Consolidated by STIG) ===
            // Group by STIG Name
            const stigGroups = new Map<string, any[]>();

            uploadedChecklists.forEach(ckl => {
                const stig = ckl.stigName || 'Unknown STIG';
                if (!stigGroups.has(stig)) stigGroups.set(stig, []);

                ckl.findings.forEach(f => {
                    stigGroups.get(stig)!.push({ ...f, hostname: ckl.hostname });
                });
            });

            stigGroups.forEach((findings, stigName) => {
                const sheetData = [
                    ['Hostname', 'Vuln ID', 'Rule ID', 'Severity', 'Status', 'Message/Comments', 'Title', 'Fix Text', 'Discussion', 'CCI', 'NIST 800-53 Rev 4', 'NIST 800-53 Rev 5'],
                ];

                findings.forEach(f => {
                    // Severity Mapping: low -> CAT III, etc.
                    let sev = f.severity?.toLowerCase() || '';
                    if (sev === 'high') sev = 'CAT I';
                    else if (sev === 'medium') sev = 'CAT II';
                    else if (sev === 'low') sev = 'CAT III';

                    // CCI Join
                    const cciStr = f.ccis ? f.ccis.join(', ') : '';

                    sheetData.push([
                        f.hostname,
                        f.vulnId,
                        f.ruleId || '',
                        sev,
                        f.status,
                        f.comments,
                        f.title,
                        f.fixText || '',
                        f.description || '',
                        cciStr,
                        '', // NIST Rev 4
                        ''  // NIST Rev 5
                    ]);
                });

                const sheet = XLSX.utils.aoa_to_sheet(sheetData);
                sheet['!cols'] = [
                    { wch: 20 }, // Hostname
                    { wch: 15 }, // Vuln ID
                    { wch: 15 }, // Rule ID
                    { wch: 10 }, // Severity
                    { wch: 15 }, // Status
                    { wch: 40 }, // Comments
                    { wch: 40 }, // Title
                    { wch: 50 }, // Fix Text
                    { wch: 50 }, // Discussion
                    { wch: 20 }, // CCI
                    { wch: 15 }, // NIST 4
                    { wch: 15 }, // NIST 5
                ];

                // Truncate sheet name to 31 chars (Excel limit)
                // Clean name to remove invalid chars
                const safeName = stigName.replace(/[\\/?*[\]]/g, '').substring(0, 31);
                XLSX.utils.book_append_sheet(workbook, sheet, safeName);
            });

            // Save file
            XLSX.writeFile(workbook, `STIG-Report-${new Date().toISOString().split('T')[0]}.xlsx`);
        } finally {
            setIsGeneratingReport(false);
        }
    };

    useEffect(() => {
        loadEvidence();
    }, []);

    // === COMPARE LOGIC ===
    const handleCompareUpload = async (e: React.ChangeEvent<HTMLInputElement>, type: 'base' | 'new') => {
        const file = e.target.files?.[0];
        if (!file) return;
        const parsed = await parseCklFile(file);
        if (parsed) {
            if (type === 'base') setCompareBase(parsed);
            else setCompareNew(parsed);
            setComparisonDiffs(null); // Reset results
        }
        e.target.value = '';
    };

    const runComparison = () => {
        if (!compareBase || !compareNew) return;

        const baseMap = new Map(compareBase.findings.map(f => [f.vulnId, f]));
        const newMap = new Map(compareNew.findings.map(f => [f.vulnId, f]));
        const diffs: any[] = [];

        // 1. Removed and Changed
        baseMap.forEach((baseF, id) => {
            const newF = newMap.get(id);

            // Map severity
            let sev = baseF.severity?.toLowerCase() || '';
            if (sev === 'high') sev = 'CAT I';
            else if (sev === 'medium') sev = 'CAT II';
            else if (sev === 'low') sev = 'CAT III';

            if (!newF) {
                diffs.push({ type: 'Removed Rule', vulnId: id, severity: sev, title: baseF.title, oldStatus: baseF.status, newStatus: 'N/A' });
            } else if (baseF.status !== newF.status) {
                diffs.push({ type: 'Status Change', vulnId: id, severity: sev, title: baseF.title, oldStatus: baseF.status, newStatus: newF.status });
            }
        });

        // 2. New Findings
        newMap.forEach((newF, id) => {
            // Map severity
            let sev = newF.severity?.toLowerCase() || '';
            if (sev === 'high') sev = 'CAT I';
            else if (sev === 'medium') sev = 'CAT II';
            else if (sev === 'low') sev = 'CAT III';

            if (!baseMap.has(id)) {
                diffs.push({ type: 'New Rule', vulnId: id, severity: sev, title: newF.title, oldStatus: 'N/A', newStatus: newF.status });
            }
        });

        setComparisonDiffs(diffs);
    };

    const exportComparisonCsv = () => {
        if (!comparisonDiffs) return;

        const header = ['Type', 'Vuln ID', 'Severity', 'Title', 'Old Status', 'New Status'];
        const rows = comparisonDiffs.map(d => [d.type, d.vulnId, d.severity, `"${d.title.replace(/"/g, '""')}"`, d.oldStatus, d.newStatus]);

        const csvContent = [header.join(','), ...rows.map(r => r.join(','))].join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `comparison_${compareBase?.hostname}_vs_${compareNew?.hostname}.csv`;
        a.click();
    };

    // === POA&M LOGIC ===
    const handlePoamUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = e.target.files;
        if (!files) return;

        const newChecklists: typeof uploadedChecklists = [];
        for (const file of Array.from(files)) {
            if (file.name.endsWith('.ckl') || file.name.endsWith('.cklb')) {
                const parsed = await parseCklFile(file);
                if (parsed) newChecklists.push(parsed);
            }
        }

        setPoamChecklists(prev => [...prev, ...newChecklists]);
        e.target.value = '';
    };

    /* const generatePoam = () => {
        if (!poamChecklist) return;
    
        // Filter for OPEN findings
        const openFindings = poamChecklist.findings.filter(f => f.status === 'Open');
    
        if (openFindings.length === 0) {
            alert('No OPEN findings found in this checklist. POA&M is typically only required for open vulnerabilities.');
        }
    
        const wb = XLSX.utils.book_new();
    
        const poamRows = [['Control ID', 'Weakness Name', 'Weakness Description', 'Security Control', 'Asset ID', 'Severity', 'Status', 'Scheduled Completion', 'Resources Required', 'Milestones', 'Comments', 'Raw Severity']];
    
        openFindings.forEach(f => {
            // Map Severity
            let sev = f.severity?.toLowerCase() || 'medium';
            let cat = 'CAT II';
            let days = 90;
    
            if (sev === 'high') { cat = 'CAT I'; days = 30; }
            else if (sev === 'low') { cat = 'CAT III'; days = 365; }
    
            // Calc Date
            const date = new Date();
            date.setDate(date.getDate() + days);
            const completionDate = date.toISOString().split('T')[0];
    
            poamRows.push([
                f.vulnId,
                f.title,
                f.description || '',
                f.ccis ? f.ccis.join(', ') : '', // Security Control (using CCIs as proxy)
                poamChecklist.hostname,
                cat,
                'Ongoing',
                completionDate,
                'TBD', // Resources
                '1. Analyze\n2. Remediate\n3. Validate', // Milestones
                f.comments,
                sev
            ]);
        });
    
        const sheet = XLSX.utils.aoa_to_sheet(poamRows);
        sheet['!cols'] = [
            { wch: 15 }, // ID
            { wch: 40 }, // Title
            { wch: 50 }, // Desc
            { wch: 20 }, // Control
            { wch: 20 }, // Asset
            { wch: 10 }, // Sev
            { wch: 10 }, // Status
            { wch: 15 }, // Date
            { wch: 15 }, // Resources
            { wch: 20 }, // Milestones
            { wch: 40 }, // Comments
            { wch: 10 }  // Raw Sev
        ];
    
        XLSX.utils.book_append_sheet(wb, sheet, 'POA&M');
        XLSX.writeFile(wb, `POAM_${poamChecklist.hostname}_${new Date().toISOString().split('T')[0]}.xlsx`);
    }; */

    const generatePoamBulk = () => {
        if (poamChecklists.length === 0) return;

        // Filter for OPEN findings across ALL checklists
        const allOpenFindings: Array<{ finding: typeof uploadedChecklists[0]['findings'][0], hostname: string }> = [];

        poamChecklists.forEach(ckl => {
            ckl.findings.filter(f => f.status === 'Open').forEach(f => {
                allOpenFindings.push({ finding: f, hostname: ckl.hostname });
            });
        });

        if (allOpenFindings.length === 0) {
            alert('No OPEN findings found in the uploaded checklists. POA&M is typically only required for open vulnerabilities.');
        }

        const wb = XLSX.utils.book_new();

        const poamRows = [['Control ID', 'Weakness Name', 'Weakness Description', 'Security Control', 'Asset ID', 'Severity', 'Status', 'Scheduled Completion', 'Resources Required', 'Milestones', 'Comments', 'Raw Severity']];

        allOpenFindings.forEach(item => {
            const f = item.finding;
            const hostname = item.hostname;

            // Map Severity
            let sev = f.severity?.toLowerCase() || 'medium';
            let cat = 'CAT II';
            let days = 90;

            if (sev === 'high') { cat = 'CAT I'; days = 30; }
            else if (sev === 'low') { cat = 'CAT III'; days = 365; }

            // Calc Date
            const date = new Date();
            date.setDate(date.getDate() + days);
            const completionDate = date.toISOString().split('T')[0];

            poamRows.push([
                f.vulnId,
                f.title,
                f.description || '',
                f.ccis ? f.ccis.join(', ') : '', // Security Control (using CCIs as proxy)
                hostname,
                cat,
                'Ongoing',
                completionDate,
                'TBD', // Resources
                '1. Analyze\n2. Remediate\n3. Validate', // Milestones
                f.comments,
                sev
            ]);
        });

        const sheet = XLSX.utils.aoa_to_sheet(poamRows);
        sheet['!cols'] = [
            { wch: 15 }, // ID
            { wch: 40 }, // Title
            { wch: 50 }, // Desc
            { wch: 20 }, // Control
            { wch: 20 }, // Asset
            { wch: 10 }, // Sev
            { wch: 10 }, // Status
            { wch: 15 }, // Date
            { wch: 15 }, // Resources
            { wch: 20 }, // Milestones
            { wch: 40 }, // Comments
            { wch: 10 }  // Raw Sev
        ];

        XLSX.utils.book_append_sheet(wb, sheet, 'POA&M');
        XLSX.writeFile(wb, `POAM_Combined_${new Date().toISOString().split('T')[0]}.xlsx`);
    };

    // Stats
    const passed = Array.from(results.values()).filter(r => r.status === 'pass').length;
    const failed = Array.from(results.values()).filter(r => r.status === 'fail').length;
    const manual = Array.from(results.values()).filter(r => r.status === 'notapplicable').length;
    const total = rules.length;
    const scanned = results.size;
    const pending = total - scanned;

    // Severity counts
    const highCount = rules.filter(r => r.severity === 'high').length;
    const mediumCount = rules.filter(r => r.severity === 'medium').length;
    const lowCount = rules.filter(r => r.severity === 'low').length;

    const getSeverityIcon = (sev: string) => {
        switch (sev) {
            case 'high': return <AlertTriangle className="size-4 text-red-500" />;
            case 'medium': return <AlertCircle className="size-4 text-amber-500" />;
            case 'low': return <Info className="size-4 text-blue-500" />;
        }
    };

    const getStatusColor = (status: string) => {
        switch (status) {
            case 'pass': return 'bg-green-100 text-green-700 border-green-200';
            case 'fail': return 'bg-red-50 text-red-600 border-red-200';
            case 'running': return 'bg-blue-50 text-blue-600 border-blue-200';
            case 'error': return 'bg-orange-50 text-orange-600 border-orange-200';
            case 'notapplicable': return 'bg-gray-50 text-gray-500 border-gray-200';
            default: return 'bg-gray-50 text-gray-500 border-gray-200';
        }
    };

    if (isLoading) {
        return (
            <div className={`flex h-screen w-full items-center justify-center ${darkMode ? 'bg-gray-900' : 'bg-white'}`}>
                <div className="text-center space-y-4">
                    <Loader2 className={`size-12 animate-spin mx-auto ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                    <div className={darkMode ? 'text-gray-400' : 'text-gray-500'}>Loading STIG definitions...</div>
                </div>
            </div>
        );
    }

    return (
        <div className={`flex h-screen w-full transition-colors duration-300 ${darkMode ? 'bg-gray-900 text-gray-100' : 'bg-white text-[#1d1d1f]'}`}>
            {/* Sidebar */}
            <aside className={`w-[280px] flex flex-col border-r pt-8 pb-4 px-4 sticky top-0 h-screen overflow-y-auto transition-colors duration-300 ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-[#f5f5f7] border-[#d2d2d7]/30'}`}>
                <div className="flex items-center justify-between px-3 mb-8">
                    <div className="flex items-center gap-3">
                        <div className={`size-9 rounded-xl flex items-center justify-center shadow-lg ${darkMode ? 'bg-blue-600 text-white' : 'bg-black text-white'}`}>
                            <ShieldCheck className="size-5" strokeWidth={2.5} />
                        </div>
                        <span className="font-semibold text-lg tracking-tight">Shield</span>
                    </div>
                    <button
                        onClick={() => setDarkMode(!darkMode)}
                        className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-yellow-400' : 'hover:bg-gray-200 text-gray-600'}`}
                        title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                    >
                        {darkMode ? <Sun size={18} /> : <Moon size={18} />}
                    </button>
                </div>

                <nav className="space-y-1 flex-1">
                    {isElectron && (
                        <SidebarItem icon={<LayoutGrid size={18} />} label="Dashboard" active={activeTab === 'scan'} onClick={() => setActiveTab('scan')} darkMode={darkMode} />
                    )}
                    <SidebarItem icon={<ClipboardList size={18} />} label="Checklists" active={activeTab === 'checklist'} onClick={() => setActiveTab('checklist')} darkMode={darkMode} />
                    <SidebarItem icon={<FolderOpen size={18} />} label="Evidence Gallery" active={activeTab === 'evidence'} onClick={() => { setActiveTab('evidence'); loadEvidence(); }} darkMode={darkMode} />
                    <SidebarItem icon={<FileSpreadsheet size={18} />} label="Reports" active={activeTab === 'report'} onClick={() => setActiveTab('report')} darkMode={darkMode} />
                    <SidebarItem icon={<GitCompare size={18} />} label="Compare" active={activeTab === 'compare'} onClick={() => setActiveTab('compare')} darkMode={darkMode} />
                    <SidebarItem icon={<FileWarning size={18} />} label="POA&M" active={activeTab === 'poam'} onClick={() => setActiveTab('poam')} darkMode={darkMode} />

                    <div className={`pt-4 mt-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                        <div className={`text-xs font-semibold px-4 mb-2 uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Filter by Severity</div>
                        <button onClick={() => { setSelectedSeverity(null); setSelectedStatus(null); }} className={`w-full text-left px-4 py-2 text-sm rounded-lg transition-colors ${!selectedSeverity && !selectedStatus
                            ? (darkMode ? 'bg-gray-700 shadow-sm font-medium text-white' : 'bg-white shadow-sm font-medium')
                            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-600 hover:bg-white/50')}`}>
                            All Controls ({total})
                        </button>
                        <button onClick={() => { setSelectedSeverity('high'); setSelectedStatus(null); }} className={`w-full text-left px-4 py-2 text-sm rounded-lg transition-colors flex items-center gap-2 ${selectedSeverity === 'high'
                            ? (darkMode ? 'bg-gray-700 shadow-sm font-medium text-white' : 'bg-white shadow-sm font-medium')
                            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-600 hover:bg-white/50')}`}>
                            <AlertTriangle size={14} className="text-red-500" /> CAT I - High ({highCount})
                        </button>
                        <button onClick={() => { setSelectedSeverity('medium'); setSelectedStatus(null); }} className={`w-full text-left px-4 py-2 text-sm rounded-lg transition-colors flex items-center gap-2 ${selectedSeverity === 'medium'
                            ? (darkMode ? 'bg-gray-700 shadow-sm font-medium text-white' : 'bg-white shadow-sm font-medium')
                            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-600 hover:bg-white/50')}`}>
                            <AlertCircle size={14} className="text-amber-500" /> CAT II - Medium ({mediumCount})
                        </button>
                        <button onClick={() => { setSelectedSeverity('low'); setSelectedStatus(null); }} className={`w-full text-left px-4 py-2 text-sm rounded-lg transition-colors flex items-center gap-2 ${selectedSeverity === 'low'
                            ? (darkMode ? 'bg-gray-700 shadow-sm font-medium text-white' : 'bg-white shadow-sm font-medium')
                            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-600 hover:bg-white/50')}`}>
                            <Info size={14} className="text-blue-500" /> CAT III - Low ({lowCount})
                        </button>
                    </div>
                </nav>

                {/* CLICKABLE Stats Card */}
                <div className={`p-4 rounded-xl border shadow-sm space-y-3 ${darkMode ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-100'}`}>
                    <div className={`text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-gray-400'}`}>Scan Results</div>
                    <div className="grid grid-cols-4 gap-1.5 text-center">
                        <button
                            onClick={() => { setSelectedStatus(selectedStatus === 'pass' ? null : 'pass'); setSelectedSeverity(null); }}
                            className={`bg-green-50 rounded-lg p-1.5 transition-all hover:ring-2 hover:ring-green-300 ${selectedStatus === 'pass' ? 'ring-2 ring-green-500' : ''}`}
                        >
                            <div className="text-lg font-bold text-green-600">{passed}</div>
                            <div className="text-[9px] text-green-600/70 uppercase">Pass</div>
                        </button>
                        <button
                            onClick={() => { setSelectedStatus(selectedStatus === 'fail' ? null : 'fail'); setSelectedSeverity(null); }}
                            className={`bg-red-50 rounded-lg p-1.5 transition-all hover:ring-2 hover:ring-red-300 ${selectedStatus === 'fail' ? 'ring-2 ring-red-500' : ''}`}
                        >
                            <div className="text-lg font-bold text-red-500">{failed}</div>
                            <div className="text-[9px] text-red-500/70 uppercase">Fail</div>
                        </button>
                        <button
                            onClick={() => { setSelectedStatus(selectedStatus === 'manual' ? null : 'manual'); setSelectedSeverity(null); }}
                            className={`bg-gray-50 rounded-lg p-1.5 transition-all hover:ring-2 hover:ring-gray-300 ${selectedStatus === 'manual' ? 'ring-2 ring-gray-500' : ''}`}
                        >
                            <div className="text-lg font-bold text-gray-500">{manual}</div>
                            <div className="text-[9px] text-gray-500 uppercase">Manual</div>
                        </button>
                        <button
                            onClick={() => { setSelectedStatus(selectedStatus === 'pending' ? null : 'pending'); setSelectedSeverity(null); }}
                            className={`bg-blue-50 rounded-lg p-1.5 transition-all hover:ring-2 hover:ring-blue-300 ${selectedStatus === 'pending' ? 'ring-2 ring-blue-500' : ''}`}
                        >
                            <div className="text-lg font-bold text-blue-600">{pending}</div>
                            <div className="text-[9px] text-blue-500 uppercase">Pending</div>
                        </button>
                    </div>
                    <div className={`h-1.5 w-full rounded-full overflow-hidden ${darkMode ? 'bg-gray-600' : 'bg-gray-100'}`}>
                        <div className={`h-full rounded-full transition-all duration-500 ${darkMode ? 'bg-blue-500' : 'bg-black'}`} style={{ width: `${(scanned / total) * 100}%` }} />
                    </div>
                    <div className={`text-xs text-center ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{scanned} of {total} checked</div>
                </div>
            </aside>

            {/* Main Content */}
            <main className={`flex-1 overflow-y-auto transition-colors duration-300 ${darkMode ? 'bg-gray-900' : 'bg-white'}`}>
                <div className="max-w-5xl mx-auto p-10">

                    {activeTab === 'scan' ? (
                        <>
                            <div className="flex items-end justify-between mb-8">
                                <div>
                                    <h1 className="text-3xl font-semibold tracking-tight mb-1">{stigInfo.version}</h1>
                                    <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>
                                        {selectedStatus ? `Showing ${selectedStatus} results` : selectedSeverity ? `Showing ${selectedSeverity} severity` : `${stigInfo.ruleCount} Controls`} • DISA STIG Compliance Scanner
                                    </p>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={exportToCklb}
                                        disabled={scanned === 0}
                                        className={`px-4 py-2.5 rounded-full text-sm font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-800 text-gray-200 hover:bg-gray-700' : 'bg-white text-gray-700 border border-gray-200 hover:bg-gray-50'}`}
                                    >
                                        <Download className="size-4" /> Export CKLB
                                    </button>
                                    <button
                                        onClick={captureAllEvidence}
                                        disabled={isCapturingAll || scanned === 0}
                                        className="bg-gray-100 hover:bg-gray-200 disabled:bg-gray-100 disabled:text-gray-400 text-gray-700 px-4 py-2.5 rounded-full text-sm font-medium transition-all flex items-center gap-2"
                                    >
                                        {isCapturingAll ? <Loader2 className="size-4 animate-spin" /> : <Camera className="size-4" />}
                                        {isCapturingAll ? 'Capturing...' : `Capture All (${scanned})`}
                                    </button>
                                    <button
                                        onClick={runAllChecks}
                                        disabled={isScanning}
                                        className="bg-black hover:bg-black/80 disabled:bg-gray-300 text-white px-5 py-2.5 rounded-full text-sm font-medium transition-all shadow-lg flex items-center gap-2"
                                    >
                                        {isScanning ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4 fill-white" />}
                                        {isScanning ? 'Scanning...' : 'Run All Checks'}
                                    </button>
                                </div>
                            </div>

                            <div className="space-y-3">
                                {filteredRules.map(rule => {
                                    const result = results.get(rule.vulnId);
                                    const status = result?.status || 'pending';
                                    const hasAutomatedCheck = rule.automatedCheck?.type !== 'manual';

                                    return (
                                        <div
                                            key={rule.vulnId}
                                            className={`group rounded-xl border p-5 hover:shadow-md transition-all cursor-pointer ${darkMode ? 'bg-gray-800 border-gray-700 hover:border-gray-600' : 'bg-white border-gray-100'}`}
                                            onClick={() => setSelectedRule(rule)}
                                        >
                                            <div className="flex items-start gap-4">
                                                <div className={`mt-0.5 size-8 rounded-full flex items-center justify-center shrink-0 border ${getStatusColor(status)}`}>
                                                    {status === 'pass' && <Check size={16} strokeWidth={3} />}
                                                    {status === 'fail' && <X size={16} strokeWidth={3} />}
                                                    {status === 'running' && <Loader2 size={16} className="animate-spin" />}
                                                    {status === 'notapplicable' && <FileText size={14} />}
                                                    {status === 'pending' && <div className={`size-2 rounded-full ${darkMode ? 'bg-gray-500' : 'bg-gray-300'}`} />}
                                                </div>

                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                        <span className={`text-xs font-mono px-1.5 py-0.5 rounded border ${darkMode ? 'text-gray-400 bg-gray-700 border-gray-600' : 'text-gray-400 bg-gray-50 border-gray-100'}`}>{rule.vulnId}</span>
                                                        <span className={`text-xs font-mono ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{rule.stigId}</span>
                                                        {getSeverityIcon(rule.severity)}
                                                        <span className={`text-[10px] uppercase font-medium px-1.5 py-0.5 rounded ${rule.severity === 'high' ? 'bg-red-50 text-red-600' :
                                                            rule.severity === 'medium' ? 'bg-amber-50 text-amber-600' : 'bg-blue-50 text-blue-600'
                                                            }`}>CAT {rule.severity === 'high' ? 'I' : rule.severity === 'medium' ? 'II' : 'III'}</span>
                                                        {!hasAutomatedCheck && (
                                                            <span className="text-[10px] uppercase font-medium px-1.5 py-0.5 rounded bg-purple-50 text-purple-600">Manual</span>
                                                        )}
                                                    </div>
                                                    <h3 className={`font-medium text-[15px] mb-1 ${darkMode ? 'text-gray-100' : 'text-gray-900'}`}>{rule.title}</h3>
                                                    <p className={`text-sm leading-relaxed line-clamp-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{rule.description}</p>

                                                    {result?.output && (
                                                        <div className="mt-3 bg-gray-50 rounded-lg p-3 font-mono text-xs border border-gray-100">
                                                            <div className="flex justify-between text-gray-400 mb-1 pb-1 border-b border-gray-100">
                                                                <span>Output</span>
                                                                <span className="uppercase">{status}</span>
                                                            </div>
                                                            <pre className="whitespace-pre-wrap text-gray-700 max-h-20 overflow-auto">{result.output.substring(0, 300)}{result.output.length > 300 ? '...' : ''}</pre>
                                                        </div>
                                                    )}
                                                </div>

                                                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
                                                    <button onClick={() => runCheck(rule)} className="p-2 hover:bg-gray-100 rounded-lg text-gray-500" title="Run Check">
                                                        <Play size={16} />
                                                    </button>
                                                    <button onClick={() => captureEvidence(rule)} className="p-2 hover:bg-gray-100 rounded-lg text-gray-500" title="Capture Evidence">
                                                        <Camera size={16} />
                                                    </button>
                                                    <button onClick={() => setSelectedRule(rule)} className="p-2 hover:bg-gray-100 rounded-lg text-gray-500" title="View Details">
                                                        <Eye size={16} />
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </>
                    ) : activeTab === 'evidence' ? (
                        <div className="space-y-6">
                            <div className="flex items-end justify-between">
                                <div>
                                    <h1 className="text-3xl font-semibold tracking-tight mb-1">Evidence Gallery</h1>
                                    <p className="text-gray-500">{evidenceList.length} evidence items captured</p>
                                </div>
                                <div className="flex gap-2">
                                    <button onClick={exportAllEvidence} className="bg-black hover:bg-black/80 text-white px-4 py-2 rounded-full text-sm font-medium flex items-center gap-2">
                                        <Download size={16} /> Export All
                                    </button>
                                    <button onClick={loadEvidence} className="p-2 hover:bg-gray-100 rounded-lg text-gray-500">
                                        <RefreshCw size={18} />
                                    </button>
                                </div>
                            </div>

                            {/* Evidence List - Full Width */}
                            <div className="space-y-4">
                                {evidenceList.map((item, idx) => (
                                    <div key={idx} className="bg-white rounded-xl border border-gray-200 overflow-hidden hover:shadow-md transition-all">
                                        <div className="flex items-center justify-between px-5 py-3 bg-gray-50 border-b border-gray-100">
                                            <div className="flex items-center gap-3">
                                                <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${item.status === 'pass' ? 'bg-green-100 text-green-700' :
                                                    item.status === 'fail' ? 'bg-red-100 text-red-600' :
                                                        'bg-gray-100 text-gray-600'
                                                    }`}>{item.status}</span>
                                                <span className="font-mono text-sm font-medium text-gray-700">{item.ruleId}</span>
                                            </div>
                                            <div className="text-xs text-gray-400 font-mono">
                                                {item.timestampReadable}
                                            </div>
                                        </div>

                                        <div className="p-5">
                                            <div className="text-sm font-medium text-gray-700 mb-4">{item.ruleTitle}</div>

                                            <div className="space-y-4">
                                                <div>
                                                    <div className="text-xs font-semibold text-gray-400 uppercase mb-2">Command Executed</div>
                                                    <div className="bg-gray-900 text-green-400 font-mono text-xs p-4 rounded-lg overflow-x-auto">
                                                        <pre className="whitespace-pre-wrap">{item.command}</pre>
                                                    </div>
                                                </div>

                                                <div>
                                                    <div className="text-xs font-semibold text-gray-400 uppercase mb-2">Output</div>
                                                    <div className="bg-gray-50 font-mono text-xs p-4 rounded-lg border border-gray-100 max-h-40 overflow-auto">
                                                        <pre className="whitespace-pre-wrap text-gray-700">{item.output}</pre>
                                                    </div>
                                                </div>

                                                {item.screenshotPath && (
                                                    <div>
                                                        <div className="text-xs font-semibold text-gray-400 uppercase mb-2">Screenshot Evidence</div>
                                                        <div className="text-xs text-gray-500 bg-gray-50 p-3 rounded-lg border border-gray-100">
                                                            📁 Saved to: {item.screenshotPath}
                                                            <br />
                                                            <span className="text-gray-400">Captured at: {item.timestampReadable}</span>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                ))}

                                {evidenceList.length === 0 && (
                                    <div className="py-20 text-center text-gray-400 border-2 border-dashed border-gray-200 rounded-xl">
                                        <Camera className="mx-auto size-12 mb-4 opacity-20" />
                                        <p className="font-medium text-lg">No evidence captured yet</p>
                                        <p className="text-sm mt-1">Run a check and click the camera icon to capture evidence</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    ) : activeTab === 'checklist' ? (
                        <div className="space-y-6">
                            <div>
                                <h1 className="text-3xl font-semibold tracking-tight mb-1">STIG Checklists</h1>
                                <p className="text-gray-500">Select a STIG checklist to scan your system</p>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {
                                    [
                                        { id: 'win11', name: 'Windows 11', sub: 'STIG V2R5 • OS', icon: Monitor, color: 'from-blue-500 to-blue-700', stats: '27 CAT I • 221 CAT II' },
                                        { id: 'server2019', name: 'Server 2019', sub: 'STIG V3R6 • OS', icon: Server, color: 'from-purple-500 to-purple-700', stats: '18 CAT I • 195 CAT II' },
                                        { id: 'edge', name: 'Microsoft Edge', sub: 'STIG V2R3 • Browser', icon: Globe, color: 'from-teal-400 to-teal-600', stats: '1 CAT I • 48 CAT II' },
                                        { id: 'sql-instance', name: 'SQL Instance', sub: 'SQL 2022 • Core', icon: Database, color: 'from-orange-500 to-orange-700', stats: '10 CAT I • 50 CAT II' },
                                        { id: 'sql-db', name: 'SQL Database', sub: 'SQL 2022 • Data', icon: Database, color: 'from-amber-500 to-amber-700', stats: '8 CAT I • 40 CAT II' },
                                        { id: 'iis-server', name: 'IIS Server', sub: 'IIS 10.0 • Web', icon: Server, color: 'from-pink-500 to-pink-700', stats: '15 CAT I • 80 CAT II' },
                                        { id: 'iis-site', name: 'IIS Site', sub: 'IIS 10.0 • Site', icon: Globe, color: 'from-rose-500 to-rose-700', stats: '12 CAT I • 60 CAT II' },
                                        { id: 'ad-domain', name: 'AD Domain', sub: 'Active Directory', icon: Users, color: 'from-indigo-500 to-indigo-700', stats: '20 CAT I • 100 CAT II' },
                                        { id: 'ad-forest', name: 'AD Forest', sub: 'Active Directory', icon: Users, color: 'from-violet-500 to-violet-700', stats: '5 CAT I • 20 CAT II' },
                                        { id: 'defender', name: 'Defender', sub: 'Antivirus', icon: Shield, color: 'from-emerald-500 to-emerald-700', stats: '5 CAT I • 30 CAT II' },
                                        { id: 'firewall', name: 'Firewall', sub: 'Network Security', icon: ShieldCheck, color: 'from-red-500 to-red-700', stats: '8 CAT I • 25 CAT II' }
                                    ].map(stig => {
                                        const meta = availableChecklists.find(c => c.id === stig.id);
                                        const publishedDate = meta?.date || 'Unknown Date';

                                        return (
                                            <div
                                                key={stig.id}
                                                className={`group relative p-5 rounded-2xl border-2 text-left transition-all hover:shadow-lg flex flex-col h-full ${stigInfo.stigId === stig.id ? 'border-black bg-gray-50' : 'border-gray-200 bg-white'}`}
                                            >
                                                <div className="flex items-start gap-4 mb-4">
                                                    <div className={`size-12 bg-gradient-to-br ${stig.color} rounded-xl flex items-center justify-center shadow-lg shrink-0`}>
                                                        <stig.icon className="size-6 text-white" />
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <h3 className="font-semibold text-base text-gray-900 mb-0.5 truncate">{stig.name}</h3>
                                                        <p className="text-xs text-gray-500 mb-1">{stig.sub}</p>
                                                        <p className="text-[10px] text-gray-400 font-medium">Published: {publishedDate}</p>
                                                    </div>
                                                </div>

                                                <div className="mt-auto pt-4 border-t border-gray-100 flex gap-2">
                                                    <button
                                                        onClick={(e) => { e.preventDefault(); exportStig(stig.id, 'csv'); }}
                                                        className="flex-1 px-3 py-1.5 rounded-lg bg-gray-100 hover:bg-gray-200 text-xs font-semibold text-gray-700 transition-colors flex items-center justify-center gap-1.5"
                                                    >
                                                        <FileSpreadsheet className="size-3.5" /> CSV
                                                    </button>
                                                    <button
                                                        onClick={(e) => { e.preventDefault(); exportStig(stig.id, 'cklb'); }}
                                                        className="flex-1 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-black text-xs font-semibold text-white transition-colors flex items-center justify-center gap-1.5"
                                                    >
                                                        <Download className="size-3.5" /> CKLB
                                                    </button>
                                                </div>
                                            </div>
                                        );
                                    })
                                }
                            </div>

                            {/* Current Selection */}
                            {/* Currently Loaded (Hidden or repurposed if needed, but user just wants export for now) */}
                            {/* 
                            <div className="bg-gray-50 rounded-xl border border-gray-100 p-6 opacity-50 pointer-events-none">
                                <div className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Currently Loaded</div>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <div className="text-xl font-semibold text-gray-900">{stigInfo.version}</div>
                                        <div className="text-sm text-gray-500">{stigInfo.ruleCount} security controls</div>
                                    </div>
                                    <button className="bg-gray-200 text-gray-400 px-5 py-2.5 rounded-full text-sm font-medium flex items-center gap-2 cursor-not-allowed">
                                        <Play className="size-4" /> Go to Scanner
                                    </button>
                                </div>
                            </div>
                            */}
                        </div>
                    ) : activeTab === 'report' ? (
                        /* REPORT GENERATOR */
                        <div className="space-y-6">
                            <div>
                                <h1 className="text-3xl font-semibold tracking-tight mb-1">Report Generator</h1>
                                <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>Upload .ckl/.cklb files to generate Excel compliance reports</p>
                            </div>

                            {/* Upload Section */}
                            <div className={`p-6 rounded-2xl border-2 border-dashed ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                <div className="text-center">
                                    <Upload className={`size-12 mx-auto mb-3 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                                    <h3 className={`font-medium mb-1 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>Upload Checklists</h3>
                                    <p className={`text-sm mb-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                        Drag and drop files, or select a folder of checklists
                                    </p>
                                    <label className="inline-flex items-center gap-2 bg-black hover:bg-black/80 text-white px-5 py-2.5 rounded-full text-sm font-medium transition-all cursor-pointer">
                                        <Upload className="size-4" />
                                        Choose Files
                                        <input
                                            type="file"
                                            multiple
                                            accept=".ckl,.cklb,.xml,.json"
                                            className="hidden"
                                            onChange={handleCklFileUpload}
                                            // @ts-ignore
                                            webkitdirectory=""
                                            // @ts-ignore
                                            directory=""
                                        />
                                    </label>
                                </div>
                            </div>

                            {/* Uploaded Checklists */}
                            {uploadedChecklists.length > 0 && (
                                <div className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <h2 className={`font-semibold text-lg ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                            Uploaded Checklists ({uploadedChecklists.length})
                                        </h2>
                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => setUploadedChecklists([])}
                                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
                                            >
                                                <Trash2 className="size-4" /> Clear All
                                            </button>
                                            <button
                                                onClick={generateExcelReport}
                                                disabled={isGeneratingReport}
                                                className="bg-green-600 hover:bg-green-700 text-white px-5 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 disabled:opacity-50"
                                            >
                                                {isGeneratingReport ? (
                                                    <><Loader2 className="size-4 animate-spin" /> Generating...</>
                                                ) : (
                                                    <><Download className="size-4" /> Generate Excel Report</>
                                                )}
                                            </button>
                                        </div>
                                    </div>

                                    {/* Summary Stats */}
                                    <div className={`grid grid-cols-4 gap-4 p-4 rounded-xl ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                        <div className="text-center">
                                            <div className="text-2xl font-bold text-red-500">
                                                {uploadedChecklists.reduce((acc, c) => acc + c.findings.filter(f => f.status === 'Open').length, 0)}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Open</div>
                                        </div>
                                        <div className="text-center">
                                            <div className="text-2xl font-bold text-green-500">
                                                {uploadedChecklists.reduce((acc, c) => acc + c.findings.filter(f => f.status === 'NotAFinding' || f.status === 'Not_A_Finding').length, 0)}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Not a Finding</div>
                                        </div>
                                        <div className="text-center">
                                            <div className="text-2xl font-bold text-gray-500">
                                                {uploadedChecklists.reduce((acc, c) => acc + c.findings.filter(f => f.status === 'Not_Reviewed').length, 0)}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Not Reviewed</div>
                                        </div>
                                        <div className="text-center">
                                            <div className="text-2xl font-bold text-blue-500">
                                                {new Set(uploadedChecklists.map(c => c.hostname)).size}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Unique Hosts</div>
                                        </div>
                                    </div>

                                    {/* Checklist Cards */}
                                    <div className="grid gap-3">
                                        {uploadedChecklists.map(ckl => (
                                            <div
                                                key={ckl.id}
                                                className={`p-4 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}
                                            >
                                                <div className="flex items-start justify-between">
                                                    <div>
                                                        <div className="flex items-center gap-2 mb-1">
                                                            <span className={`text-xs font-mono px-2 py-0.5 rounded ${darkMode ? 'bg-gray-700 text-gray-400' : 'bg-gray-100 text-gray-600'}`}>
                                                                {ckl.hostname}
                                                            </span>
                                                            <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>{ckl.filename}</span>
                                                        </div>
                                                        <h4 className={`font-medium ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{ckl.stigName}</h4>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-xs bg-red-100 text-red-600 px-2 py-0.5 rounded">
                                                            {ckl.findings.filter(f => f.status === 'Open').length} Open
                                                        </span>
                                                        <span className="text-xs bg-green-100 text-green-600 px-2 py-0.5 rounded">
                                                            {ckl.findings.filter(f => f.status === 'NotAFinding' || f.status === 'Not_A_Finding').length} NaF
                                                        </span>
                                                        <button
                                                            onClick={() => setUploadedChecklists(prev => prev.filter(c => c.id !== ckl.id))}
                                                            className={`p-1.5 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-500' : 'hover:bg-gray-100 text-gray-400'}`}
                                                        >
                                                            <XCircle size={16} />
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {uploadedChecklists.length === 0 && (
                                <div className={`text-center py-12 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                    <FileSpreadsheet className="size-16 mx-auto mb-4 opacity-50" />
                                    <p className="text-lg font-medium mb-1">No checklists uploaded</p>
                                    <p className="text-sm">Upload .ckl or .cklb files from STIG Viewer to generate reports</p>
                                </div>
                            )}
                        </div>
                    ) : activeTab === 'compare' ? (
                        <div className="space-y-6">
                            <div>
                                <h1 className="text-3xl font-semibold tracking-tight mb-1">Checklist Comparison</h1>
                                <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>Compare two checklists to identify differences in status and compliance.</p>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                {/* Base File */}
                                <div className={`p-6 rounded-2xl border-2 border-dashed relative ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                    <div className="text-center">
                                        <div className={`mb-2 font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Base Checklist</div>
                                        {compareBase ? (
                                            <div className="bg-green-100 text-green-700 px-3 py-1 rounded inline-block text-sm font-medium mb-3">
                                                {compareBase.hostname} ({compareBase.filename})
                                            </div>
                                        ) : (
                                            <div className="bg-gray-200 text-gray-500 px-3 py-1 rounded inline-block text-sm font-medium mb-3">
                                                No File Selected
                                            </div>
                                        )}
                                        <label className="block">
                                            <span className="bg-black hover:bg-black/80 text-white px-4 py-2 rounded-full text-sm font-medium cursor-pointer inline-flex items-center gap-2">
                                                <Upload size={14} /> Upload Base
                                            </span>
                                            <input type="file" className="hidden" accept=".ckl,.cklb" onChange={(e) => handleCompareUpload(e, 'base')} />
                                        </label>
                                    </div>
                                </div>

                                {/* New File */}
                                <div className={`p-6 rounded-2xl border-2 border-dashed relative ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                    <div className="text-center">
                                        <div className={`mb-2 font-medium ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>New Comparison Checklist</div>
                                        {compareNew ? (
                                            <div className="bg-blue-100 text-blue-700 px-3 py-1 rounded inline-block text-sm font-medium mb-3">
                                                {compareNew.hostname} ({compareNew.filename})
                                            </div>
                                        ) : (
                                            <div className="bg-gray-200 text-gray-500 px-3 py-1 rounded inline-block text-sm font-medium mb-3">
                                                No File Selected
                                            </div>
                                        )}
                                        <label className="block">
                                            <span className="bg-black hover:bg-black/80 text-white px-4 py-2 rounded-full text-sm font-medium cursor-pointer inline-flex items-center gap-2">
                                                <Upload size={14} /> Upload New
                                            </span>
                                            <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" onChange={(e) => handleCompareUpload(e, 'new')} />
                                        </label>
                                    </div>
                                </div>
                            </div>

                            {/* Action Button */}
                            <div className="flex justify-center">
                                <button
                                    onClick={runComparison}
                                    disabled={!compareBase || !compareNew}
                                    className="bg-purple-600 hover:bg-purple-700 disabled:bg-gray-300 disabled:text-gray-500 text-white px-8 py-3 rounded-full font-medium transition-all shadow-lg flex items-center gap-2 text-lg"
                                >
                                    <GitCompare /> Compare Checklists
                                </button>
                            </div>

                            {/* Results */}
                            {comparisonDiffs && (
                                <div className="space-y-4 pt-4 border-t border-gray-200">
                                    <div className="flex items-center justify-between">
                                        <h2 className={`text-xl font-semibold ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{comparisonDiffs.length} Differences Found</h2>
                                        <button onClick={exportComparisonCsv} className="bg-white border border-gray-200 hover:bg-gray-50 text-gray-700 px-4 py-2 rounded-lg font-medium flex items-center gap-2">
                                            <Download size={16} /> Export CSV
                                        </button>
                                    </div>

                                    {/* Filters */}
                                    <div className="flex gap-2">
                                        {(['all', 'status', 'new', 'removed'] as const).map(f => (
                                            <button
                                                key={f}
                                                onClick={() => setCompareFilter(f)}
                                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-all ${compareFilter === f
                                                    ? 'bg-black text-white'
                                                    : darkMode ? 'bg-gray-700 text-gray-400 hover:bg-gray-600' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                                                    }`}
                                            >
                                                {f === 'all' ? 'All Changes' : f === 'status' ? 'Status Changes' : f === 'new' ? 'New Rules' : 'Removed Rules'}
                                            </button>
                                        ))}
                                    </div>

                                    <div className="space-y-2">
                                        {comparisonDiffs
                                            .filter(diff => {
                                                if (compareFilter === 'all') return true;
                                                if (compareFilter === 'status') return diff.type === 'Status Change';
                                                if (compareFilter === 'new') return diff.type === 'New Rule';
                                                if (compareFilter === 'removed') return diff.type === 'Removed Rule';
                                                return true;
                                            })
                                            .map((diff, idx) => (
                                                <div key={idx} className={`p-4 rounded-xl border flex items-center justify-between ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}>
                                                    <div className="flex items-start gap-3">
                                                        <div className={`mt-1 p-1.5 rounded-lg ${diff.type === 'New Rule' ? 'bg-blue-100 text-blue-600' :
                                                            diff.type === 'Removed Rule' ? 'bg-red-100 text-red-600' :
                                                                'bg-amber-100 text-amber-600'
                                                            }`}>
                                                            {diff.type === 'New Rule' ? <Info size={16} /> : diff.type === 'Removed Rule' ? <Trash2 size={16} /> : <GitCompare size={16} />}
                                                        </div>
                                                        <div>
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="font-mono text-sm font-semibold">{diff.vulnId}</span>
                                                                <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded ${diff.severity === 'CAT I' ? 'bg-red-100 text-red-600' :
                                                                    diff.severity === 'CAT II' ? 'bg-amber-50 text-amber-600' :
                                                                        'bg-blue-50 text-blue-600'
                                                                    }`}>{diff.severity}</span>
                                                                <span className="text-xs text-gray-400 uppercase font-medium tracking-wide">{diff.type}</span>
                                                            </div>
                                                            <div className={`font-medium ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{diff.title}</div>
                                                        </div>
                                                    </div>
                                                    <div className="text-right text-sm">
                                                        <div className="text-gray-500 text-xs uppercase mb-0.5">Change</div>
                                                        <div className="font-mono">
                                                            <span className="line-through text-gray-400">{diff.oldStatus}</span>
                                                            <span className="mx-2 text-gray-400">→</span>
                                                            <span className={`font-semibold ${diff.newStatus === 'Open' ? 'text-red-600' : 'text-green-600'}`}>{diff.newStatus}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        {comparisonDiffs.length === 0 && (
                                            <div className="text-center py-10 text-gray-400">
                                                <GitCompare className="mx-auto size-12 mb-3 opacity-20" />
                                                <div className="text-lg">No differences found</div>
                                                <div className="text-sm">These checklists appear to be identical in status</div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : activeTab === 'poam' ? (
                        <div className="space-y-8 max-w-2xl mx-auto">
                            <div className="text-center">
                                <h1 className="text-3xl font-semibold tracking-tight mb-2">POA&M Generator</h1>
                                <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>Generate a Plan of Action and Milestones (POA&M) document from multiple STIG checklists.</p>
                            </div>

                            <div className="w-full">
                                <div className={`p-8 rounded-2xl border-2 border-dashed relative text-center ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                    <FileWarning className={`size-16 mx-auto mb-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />

                                    {poamChecklists.length > 0 ? (
                                        <div className="mb-6">
                                            <div className="text-lg font-medium text-green-600 mb-1">Checklists Loaded</div>
                                            <div className={`text-4xl font-bold mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                                {poamChecklists.length}
                                            </div>
                                            <div className="flex justify-center gap-2 mb-4">
                                                <div className="inline-flex items-center gap-2 bg-red-100 text-red-700 px-3 py-1 rounded-full text-sm font-medium">
                                                    {poamChecklists.reduce((acc, c) => acc + c.findings.filter(f => f.status === 'Open').length, 0)} Open
                                                </div>
                                                <div className="inline-flex items-center gap-2 bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-sm font-medium">
                                                    {new Set(poamChecklists.map(c => c.hostname)).size} Hosts
                                                </div>
                                            </div>
                                            <div className="max-h-40 overflow-y-auto bg-gray-100/50 rounded-lg p-2 text-left mb-2 scrollbar-thin">
                                                {poamChecklists.map((c, i) => (
                                                    <div key={i} className="text-xs text-gray-500 py-1.5 px-2 border-b border-gray-200 last:border-0 flex justify-between items-center bg-white/50 rounded mb-1">
                                                        <span className="truncate max-w-[180px]" title={c.filename}>{c.filename}</span>
                                                        <span className="font-mono text-[10px] bg-gray-200 px-1.5 py-0.5 rounded">{c.hostname}</span>
                                                    </div>
                                                ))}
                                            </div>
                                            <button
                                                onClick={() => setPoamChecklists([])}
                                                className="text-xs text-red-500 hover:text-red-600 underline font-medium"
                                            >
                                                Clear All Files
                                            </button>
                                        </div>
                                    ) : (
                                        <div className="mb-6">
                                            <h3 className={`font-medium text-lg mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>Upload Checklists</h3>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                                Select multiple .ckl or .cklb files to auto-generate a consolidated POA&M
                                            </p>
                                        </div>
                                    )}

                                    <div className="flex justify-center gap-3">
                                        <label className={`cursor-pointer px-5 py-2.5 rounded-full text-sm font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}>
                                            <Upload size={16} />
                                            {poamChecklists.length > 0 ? 'Add More Files' : 'Choose Files'}
                                            <input type="file" multiple className="hidden" accept=".ckl,.cklb" onChange={handlePoamUpload} />
                                        </label>

                                        {poamChecklists.length > 0 && (
                                            <button
                                                onClick={generatePoamBulk}
                                                className="bg-black hover:bg-black/80 text-white px-5 py-2.5 rounded-full text-sm font-medium transition-all shadow-lg flex items-center gap-2"
                                            >
                                                <Download size={16} /> Generate POA&M
                                            </button>
                                        )}
                                    </div>
                                </div>
                            </div>

                            <div className={`p-6 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-blue-50 border-blue-100'}`}>
                                <h4 className={`font-medium mb-2 flex items-center gap-2 ${darkMode ? 'text-blue-400' : 'text-blue-800'}`}>
                                    <Info size={18} /> How it works
                                </h4>
                                <ul className={`list-disc list-inside text-sm space-y-1 ${darkMode ? 'text-gray-400' : 'text-blue-700'}`}>
                                    <li>Reads all <strong>Open</strong> findings from your checklist.</li>
                                    <li>Maps STIG Severity to standard CAT I/II/III levels.</li>
                                    <li>Auto-calculates scheduled completion dates (+30/90/365 days).</li>
                                    <li>Populates standard POA&M columns including CCIs, descriptions, and comments.</li>
                                    <li>Outputs a formatted Excel file ready for submission or review.</li>
                                </ul>
                            </div>
                        </div>
                    ) : null}
                </div>
            </main >

            {/* DETAIL MODAL */}
            {
                selectedRule && (
                    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-8" onClick={() => setSelectedRule(null)}>
                        <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
                            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-gray-50">
                                <div className="flex items-center gap-3">
                                    <span className="text-sm font-mono bg-gray-200 px-2 py-1 rounded">{selectedRule.vulnId}</span>
                                    <span className="text-sm font-mono text-gray-500">{selectedRule.stigId}</span>
                                    <span className={`text-xs uppercase font-medium px-2 py-1 rounded ${selectedRule.severity === 'high' ? 'bg-red-100 text-red-600' :
                                        selectedRule.severity === 'medium' ? 'bg-amber-100 text-amber-600' : 'bg-blue-100 text-blue-600'
                                        }`}>CAT {selectedRule.severity === 'high' ? 'I' : selectedRule.severity === 'medium' ? 'II' : 'III'}</span>
                                </div>
                                <button onClick={() => setSelectedRule(null)} className="p-2 hover:bg-gray-200 rounded-lg">
                                    <XCircle size={20} />
                                </button>
                            </div>

                            <div className="p-6 overflow-y-auto max-h-[calc(90vh-80px)] space-y-6">
                                <div>
                                    <h2 className="text-xl font-semibold text-gray-900 mb-2">{selectedRule.title}</h2>
                                    <p className="text-gray-600">{selectedRule.description}</p>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Check Procedure</h3>
                                    <div className="bg-gray-50 p-4 rounded-lg border border-gray-100 font-mono text-sm whitespace-pre-wrap text-gray-700 max-h-60 overflow-auto">
                                        {selectedRule.checkContent || 'No check content available'}
                                    </div>
                                </div>

                                <div>
                                    <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Fix Procedure</h3>
                                    <div className="bg-blue-50 p-4 rounded-lg border border-blue-100 font-mono text-sm whitespace-pre-wrap text-gray-700 max-h-60 overflow-auto">
                                        {selectedRule.fixContent || 'No fix content available'}
                                    </div>
                                </div>

                                {selectedRule.automatedCheck && selectedRule.automatedCheck.type !== 'manual' && (
                                    <div>
                                        <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Automated Check</h3>
                                        <div className="bg-gray-900 text-green-400 p-4 rounded-lg font-mono text-sm">
                                            <div className="text-gray-400 mb-1">Type: {selectedRule.automatedCheck.type}</div>
                                            {selectedRule.automatedCheck.registryPath && (
                                                <div>Registry: {selectedRule.automatedCheck.registryPath}\{selectedRule.automatedCheck.valueName}</div>
                                            )}
                                            {selectedRule.automatedCheck.expectedValue !== undefined && (
                                                <div>Expected: {selectedRule.automatedCheck.expectedValue}</div>
                                            )}
                                            {selectedRule.automatedCheck.command && (
                                                <div className="mt-2 text-white">&gt; {selectedRule.automatedCheck.command}</div>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {results.get(selectedRule.vulnId) && (
                                    <div>
                                        <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Last Result</h3>
                                        <div className={`p-4 rounded-lg border ${results.get(selectedRule.vulnId)?.status === 'pass' ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'}`}>
                                            <div className="flex items-center gap-2 mb-2">
                                                <span className={`uppercase font-medium text-sm ${results.get(selectedRule.vulnId)?.status === 'pass' ? 'text-green-600' : 'text-red-600'}`}>
                                                    {results.get(selectedRule.vulnId)?.status}
                                                </span>
                                            </div>
                                            <pre className="font-mono text-xs whitespace-pre-wrap text-gray-700">{results.get(selectedRule.vulnId)?.output}</pre>
                                        </div>
                                    </div>
                                )}

                                <div className="flex gap-3 pt-4 border-t border-gray-100">
                                    <button
                                        onClick={() => { runCheck(selectedRule); }}
                                        className="bg-black hover:bg-black/80 text-white px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2"
                                    >
                                        <Play size={16} /> Run Check
                                    </button>
                                    <button
                                        onClick={() => { captureEvidence(selectedRule); }}
                                        className="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2"
                                    >
                                        <Camera size={16} /> Capture Evidence
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )
            }
        </div >
    );
}

function SidebarItem({ icon, label, active, onClick, darkMode }: { icon: React.ReactNode; label: string; active: boolean; onClick?: () => void; darkMode?: boolean }) {
    return (
        <button onClick={onClick} className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-medium transition-all ${active
            ? (darkMode ? 'bg-gray-700 text-white shadow-sm' : 'bg-white text-black shadow-sm')
            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50 hover:text-white' : 'text-gray-500 hover:bg-white/50 hover:text-black')}`}>
            {icon}
            {label}
            {active && <ChevronRight className="ml-auto size-4" />}
        </button>
    );
}

export default App;

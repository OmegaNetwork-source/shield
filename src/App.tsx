import React, { useState, useEffect, useMemo } from 'react';
import {
    Trash2, Upload, AlertCircle, Check, X, Search, FileEdit, FolderOpen, FolderTree, FileSpreadsheet, Database, Info, Calendar, Terminal, ChevronRight, ChevronDown, ChevronUp, Copy, Maximize2, Minimize2, XCircle, RotateCw, Play, Shield, Camera, Target, Download, Settings, Image as ImageIcon,
    ShieldCheck, LayoutGrid, Loader2, AlertTriangle, RefreshCw, FileText, Eye, ClipboardList, Monitor, Globe, Moon, Sun, GitCompare, FileWarning, Server, Users, PieChart, CheckCircle2, Filter, FolderClosed,
    Wrench, Save, ArrowRight, ChevronLeft
} from 'lucide-react';
import { parseStigXML, generateCheckCommand, evaluateCheckResult, ParsedStigRule, parseCklFile } from './utils/stig-parser';
import * as XLSX from 'xlsx';
import html2canvas from 'html2canvas';
import JSZip from 'jszip';

// --- Configuration ---

import { STIG_PATHS } from './stig-paths';
import cciMapRaw from './data/cci2nist.json';

const cciMap = cciMapRaw as Record<string, string>;

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
    // --- State ---
    const [rules, setRules] = useState<ParsedStigRule[]>([]);
    const [results, setResults] = useState<Map<string, CheckResult>>(new Map());
    const [activeTab, setActiveTab] = useState<'dashboard' | 'scan' | 'evidence' | 'checklist' | 'review' | 'results' | 'report' | 'poam' | 'controls' | 'compare' | 'copy' | 'tools'>(isElectron ? 'scan' : 'checklist');
    const [evidenceList, setEvidenceList] = useState<any[]>([]);
    const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
    const [selectedStatus, setSelectedStatus] = useState<string | null>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [stigInfo, setStigInfo] = useState({ version: 'Loading...', ruleCount: 0, stigId: 'win11' });
    const [selectedRule, setSelectedRule] = useState<ParsedStigRule | null>(null);
    const [availableChecklists, setAvailableChecklists] = useState<StigChecklist[]>([]);
    const [darkMode, setDarkMode] = useState(false);

    // Tools State
    const [toolsMode, setToolsMode] = useState<'rename' | 'heatmap' | 'analyzer'>('rename');
    const [isToolsOpen, setIsToolsOpen] = useState(false);
    const [renameFiles, setRenameFiles] = useState<{ file: File; originalName: string; newName: string }[]>([]);
    const [renamePrefix, setRenamePrefix] = useState('');
    const [renameSuffix, setRenameSuffix] = useState('');
    const [heatmapChecklists, setHeatmapChecklists] = useState<typeof uploadedChecklists>([]);

    // Analyzer State
    const [analyzerOldChecklist, setAnalyzerOldChecklist] = useState<typeof uploadedChecklists[0] | null>(null);
    const [analyzerNewChecklist, setAnalyzerNewChecklist] = useState<typeof uploadedChecklists[0] | null>(null);
    const [analyzerTab, setAnalyzerTab] = useState<'notreviewed' | 'newids' | 'droppedids' | 'reviewed'>('notreviewed');
    const [analyzerSelectedIds, setAnalyzerSelectedIds] = useState<Set<string>>(new Set());
    const [analyzerCustomComment, setAnalyzerCustomComment] = useState('');
    const [analyzerFindText, setAnalyzerFindText] = useState('');
    const [analyzerReplaceText, setAnalyzerReplaceText] = useState('');
    const [analyzerExpandedRows, setAnalyzerExpandedRows] = useState<Set<string>>(new Set());
    const [analyzerEditedIds, setAnalyzerEditedIds] = useState<Set<string>>(new Set());
    const [analyzerShowAllReviewed, setAnalyzerShowAllReviewed] = useState(false);
    const [analyzerSort, setAnalyzerSort] = useState<{ key: string, dir: 'asc' | 'desc' }>({ key: 'severity', dir: 'desc' });
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
            ruleId: string; // SV-XXXX
            groupId?: string; // V-XXXX (Redundant with vulnId usually)
            fixText?: string;
            checkText?: string;
            description?: string;
            findingDetails?: string;
            legacyId?: string;
            classification?: string;
            ccis?: string[];
        }>;
        rawJson?: any; // Preserve original JSON for proper CKLB export
    }>>([]);
    const [isGeneratingReport, setIsGeneratingReport] = useState(false);

    // Compare Tab State
    const [compareBase, setCompareBase] = useState<typeof uploadedChecklists[0] | null>(null);
    const [compareNew, setCompareNew] = useState<typeof uploadedChecklists[0] | null>(null);
    const [comparisonDiffs, setComparisonDiffs] = useState<any[] | null>(null);
    const [compareFilter, setCompareFilter] = useState<'all' | 'status' | 'new' | 'removed'>('all');
    const [showHostModal, setShowHostModal] = useState(false);
    const [showStigModal, setShowStigModal] = useState(false);
    const [isSummaryExpanded, setIsSummaryExpanded] = useState(true);
    const [copying, setCopying] = useState(false);
    const [selectedStigChart, setSelectedStigChart] = useState<any | null>(null);

    // Calculate Report Summary for UI
    const reportSummary = useMemo(() => {
        if (uploadedChecklists.length === 0) return [];

        const groups = new Map<string, typeof uploadedChecklists>();
        uploadedChecklists.forEach(ckl => {
            const name = ckl.stigName || 'Unknown STIG';
            if (!groups.has(name)) groups.set(name, []);
            groups.get(name)!.push(ckl);
        });

        const rows: any[] = [];
        groups.forEach((checklists, name) => {
            const stats = {
                cat1: { total: 0, naf: 0, na: 0, open: 0 },
                cat2: { total: 0, naf: 0, na: 0, open: 0 },
                cat3: { total: 0, naf: 0, na: 0, open: 0 }
            };
            let totalControls = 0;

            checklists.forEach(ckl => {
                ckl.findings.forEach(f => {
                    totalControls++;
                    let cat = 'cat3';
                    const sev = (f.severity || '').toLowerCase();
                    if (sev === 'high' || sev === 'cat i') cat = 'cat1';
                    else if (sev === 'medium' || sev === 'cat ii') cat = 'cat2';

                    const s = (f.status || '').toLowerCase().replace(/[\s_]/g, '');
                    stats[cat as keyof typeof stats].total++;
                    if (s === 'open' || s === 'fail' || s === 'failed') stats[cat as keyof typeof stats].open++;
                    else if (s === 'notafinding' || s === 'pass' || s === 'passed' || s === 'nf') stats[cat as keyof typeof stats].naf++;
                    else if (s === 'notapplicable' || s === 'na' || s === 'n/a') stats[cat as keyof typeof stats].na++;
                });
            });

            const calcPct = (s: typeof stats.cat1) => s.total === 0 ? '100%' : Math.round(((s.naf + s.na) / s.total) * 100) + '%';

            rows.push({
                name,
                instances: checklists.length,
                controls: totalControls,
                cat1: { ...stats.cat1, pct: calcPct(stats.cat1) },
                cat2: { ...stats.cat2, pct: calcPct(stats.cat2) },
                cat3: { ...stats.cat3, pct: calcPct(stats.cat3) }
            });
        });
        return rows.sort((a, b) => a.name.localeCompare(b.name));
    }, [uploadedChecklists]);

    // COPY Feature State
    const [editMode, setEditMode] = useState<'edit' | 'copy'>('edit');
    const [editFile, setEditFile] = useState<typeof uploadedChecklists[0] | null>(null);
    const [expandedEditIdx, setExpandedEditIdx] = useState<number | null>(null);
    const [copySource, setCopySource] = useState<typeof uploadedChecklists[0] | null>(null);
    const [copyTarget, setCopyTarget] = useState<typeof uploadedChecklists[0] | null>(null);
    const [copyFields, setCopyFields] = useState({ status: true, comments: true, details: true });
    const [copySuccess, setCopySuccess] = useState<string | null>(null);
    const [findText, setFindText] = useState('');
    const [replaceText, setReplaceText] = useState('');
    const [sourceFindText, setSourceFindText] = useState('');
    const [sourceReplaceText, setSourceReplaceText] = useState('');
    const [expandedSourceIdx, setExpandedSourceIdx] = useState<number | null>(null);
    const [expandedTargetIdx, setExpandedTargetIdx] = useState<number | null>(null);
    const [commentPlusText, setCommentPlusText] = useState('');

    // Batch Tools State
    const [showBatchTools, setShowBatchTools] = useState(false);
    const [batchFind, setBatchFind] = useState('');
    const [batchReplace, setBatchReplace] = useState('');
    const [batchPrepend, setBatchPrepend] = useState('');
    const [batchField, setBatchField] = useState<'details' | 'comments'>('details');
    const [batchScope, setBatchScope] = useState<'selected' | 'filtered'>('filtered');

    // POA&M State
    const [acasData, setAcasData] = useState<any[]>([]);
    const [poamActiveCat, setPoamActiveCat] = useState<'cat1' | 'cat2' | 'cat3'>('cat1');
    const [poamConfig, setPoamConfig] = useState({
        officeOrg: "USACE CMP",
        resourcesRequired: "Man Hours",
        status: "Ongoing",
        milestones: {
            cat1: [
                { id: 1, text: "The CMP Implementation Team has identified this finding through EvaluateSTIG, and the CMP Implementation team has been notified to address this finding.", date: "" },
                { id: 2, text: "The CMP Implementation team will begin testing within the USACE CMP environment to ensure this finding has been fixed.", date: "" },
                { id: 3, text: "The CMP Implementation team will have implemented the new updated configuration to the USACE CMP environment.", date: "" },
                { id: 4, text: "Deloitte RMF Team validates the finding has been remediated via manual assessment procedures and evidence gathering.", date: "" }
            ],
            cat2: [
                { id: 1, text: "The CMP Implementation Team has identified this finding through EvaluateSTIG, and the CMP Implementation team has been notified to address this finding.", date: "" },
                { id: 2, text: "The CMP Implementation team will begin testing within the USACE CMP environment to ensure this finding has been fixed.", date: "" },
                { id: 3, text: "The CMP Implementation team will have implemented the new updated configuration to the USACE CMP environment.", date: "" },
                { id: 4, text: "Deloitte RMF Team validates the finding has been remediated via manual assessment procedures and evidence gathering.", date: "" }
            ],
            cat3: [
                { id: 1, text: "The CMP Implementation Team has identified this finding through EvaluateSTIG, and the CMP Implementation team has been notified to address this finding.", date: "" },
                { id: 2, text: "The CMP Implementation team will begin testing within the USACE CMP environment to ensure this finding has been fixed.", date: "" },
                { id: 3, text: "The CMP Implementation team will have implemented the new updated configuration to the USACE CMP environment.", date: "" },
                { id: 4, text: "Deloitte RMF Team validates the finding has been remediated via manual assessment procedures and evidence gathering.", date: "" }
            ]
        }
    });

    // Controls State
    // Rev 4/5 toggle removed as our source map is unified/flat (MITRE cci2nist)

    const controlsData = useMemo(() => {
        // We now iterate from the FINDINGS up to the CONTROLS
        const controlMap = new Map<string, {
            control: string,
            ccis: Set<string>,
            groupIds: Set<string>,
            openCount: number,
            totalCount: number,
            notAFindingCount: number
            notReviewedCount: number
        }>();

        uploadedChecklists.forEach(ckl => {
            ckl.findings.forEach(finding => {
                // Determine relevant CCIs for this finding
                let findingCcis: string[] = [];

                if (finding.ccis && finding.ccis.length > 0) {
                    findingCcis = finding.ccis;
                } else {
                    // Fallback to rules lookup
                    const rule = rules.find(r => r.vulnId === finding.vulnId);
                    if (rule && rule.ccis) {
                        findingCcis = rule.ccis;
                    }
                }

                // Map CCIs to Controls
                const findingControls = new Set<string>();

                findingCcis.forEach(cci => {
                    const mappedControl = cciMap[cci];
                    if (mappedControl) {
                        // extracted: "AC-1.3" -> base: "AC-1"
                        // Regex to grab the base control (e.g. AC-1, AC-2(1))
                        // Matches: 2 chars, dash, number, optional parens
                        const match = mappedControl.match(/^([A-Z]{2}-\d+(\(\d+\))?)/);
                        const baseControl = match ? match[1] : mappedControl;
                        findingControls.add(baseControl);
                    } else {
                        // Optional: Handle unknown CCIs?
                        // For now, only show mapped controls as that's what the user expects (NIST View)
                    }
                });

                // Add stats to each relevant control
                findingControls.forEach(control => {
                    if (!controlMap.has(control)) {
                        controlMap.set(control, {
                            control,
                            ccis: new Set(),
                            groupIds: new Set(),
                            openCount: 0,
                            totalCount: 0,
                            notAFindingCount: 0,
                            notReviewedCount: 0
                        });
                    }

                    const entry = controlMap.get(control)!;

                    // Add Group ID with V- Check
                    const rawId = finding.vulnId || finding.groupId || 'Unknown';
                    const normalizedId = rawId.startsWith('V-') ? rawId : `V-${rawId}`;
                    entry.groupIds.add(normalizedId);

                    // Add CCIs
                    findingCcis.forEach(c => {
                        // Only add if this CCI actually maps to this control? 
                        // Simplification: Add all CCIs of this finding to this control's bucket? 
                        // No, exact mapping is better.
                        if (cciMap[c] && cciMap[c].startsWith(control)) {
                            entry.ccis.add(c);
                        }
                    });

                    entry.totalCount++;
                    if (finding.status === 'Open') entry.openCount++;
                    else if (finding.status === 'NotAFinding') entry.notAFindingCount++;
                    else entry.notReviewedCount++;
                });
            });
        });

        return Array.from(controlMap.values()).map(item => {
            // Calculate Status
            // If ANY open => Fail
            // If NO open AND (At least one Pass OR NA) AND No Not_Reviewed => Pass
            // Else => No Data
            let status = 'No Data';

            if (item.openCount > 0) {
                status = 'Fail';
            } else if (item.notReviewedCount === 0 && (item.notAFindingCount > 0 || item.totalCount > 0)) {
                // Simplification: If we have findings and NONE are open and NONE are unreviewed => Pass
                status = 'Pass';
            } else {
                status = 'No Data';
            }

            return {
                ...item,
                ccis: Array.from(item.ccis).sort(),
                groupIds: Array.from(item.groupIds).sort(),
                status
            };
        }).sort((a, b) => {
            // Sort naturally (AC-1, AC-2, AC-10)
            const partsA = a.control.split('-');
            const partsB = b.control.split('-');
            if (partsA[0] !== partsB[0]) return partsA[0].localeCompare(partsB[0]);
            // Compare number part safely
            return a.control.localeCompare(b.control, undefined, { numeric: true, sensitivity: 'base' });
        });

    }, [uploadedChecklists, rules]);

    // Statistics for cards
    const controlsStats = useMemo(() => {
        const total = controlsData.length;
        const passed = controlsData.filter(d => d.status === 'Pass').length;
        const failed = controlsData.filter(d => d.status === 'Fail').length;
        const noData = controlsData.filter(d => d.status === 'No Data').length;
        return { total, passed, failed, noData };
    }, [controlsData]);

    // Heatmap Data - computed from heatmapChecklists
    const heatmapData = useMemo(() => {
        const families: Record<string, { cat1: { open: number; naf: number; nr: number }; cat2: { open: number; naf: number; nr: number }; cat3: { open: number; naf: number; nr: number } }> = {};

        heatmapChecklists.forEach(ckl => {
            ckl.findings.forEach(f => {
                const ccis = f.ccis || [];
                ccis.forEach(cci => {
                    const nist = cciMap[cci];
                    if (nist) {
                        const family = nist.split('-')[0];
                        if (!families[family]) {
                            families[family] = {
                                cat1: { open: 0, naf: 0, nr: 0 },
                                cat2: { open: 0, naf: 0, nr: 0 },
                                cat3: { open: 0, naf: 0, nr: 0 }
                            };
                        }

                        const sev = f.severity?.toLowerCase() || 'medium';
                        const cat = sev === 'high' ? 'cat1' : sev === 'medium' ? 'cat2' : 'cat3';
                        const status = f.status?.toLowerCase().replace(/[\s_]/g, '') || 'notreviewed';

                        if (status === 'open' || status === 'fail') {
                            families[family][cat].open++;
                        } else if (status === 'notafinding' || status === 'pass') {
                            families[family][cat].naf++;
                        } else {
                            families[family][cat].nr++;
                        }
                    }
                });
            });
        });

        return Object.entries(families)
            .map(([family, data]) => ({ family, ...data }))
            .sort((a, b) => {
                const riskA = a.cat1.open * 10 + a.cat2.open * 5 + a.cat3.open;
                const riskB = b.cat1.open * 10 + b.cat2.open * 5 + b.cat3.open;
                return riskB - riskA;
            });
    }, [heatmapChecklists]);

    const getRiskColor = (open: number, total: number) => {
        if (total === 0) return 'bg-gray-100 text-gray-400';
        const pct = open / total;
        if (pct === 0) return 'bg-green-100 text-green-700';
        if (pct < 0.25) return 'bg-yellow-100 text-yellow-700';
        if (pct < 0.5) return 'bg-orange-100 text-orange-700';
        return 'bg-red-100 text-red-700';
    };

    // Analyzer computed data
    const analyzerData = useMemo(() => {
        if (!analyzerOldChecklist || !analyzerNewChecklist) {
            return { notReviewed: [], newIds: [], droppedIds: [], totalOld: 0, totalNew: 0 };
        }

        const totalOld = analyzerOldChecklist.findings.length;
        const totalNew = analyzerNewChecklist.findings.length;

        const oldMap = new Map(analyzerOldChecklist.findings.map(f => [f.vulnId, f]));
        const newMap = new Map(analyzerNewChecklist.findings.map(f => [f.vulnId, f]));

        // Not Reviewed in new checklist but has data in old
        const notReviewed = analyzerNewChecklist.findings
            .filter(f => {
                const status = f.status?.toLowerCase().replace(/[\s_]/g, '') || '';
                return status === 'notreviewed' || status === 'not_reviewed';
            })
            .filter(f => oldMap.has(f.vulnId))
            .map(f => ({
                vulnId: f.vulnId,
                newFinding: f,
                oldFinding: oldMap.get(f.vulnId)!
            }));

        // New Group IDs (in new but not in old)
        const newIds = analyzerNewChecklist.findings
            .filter(f => !oldMap.has(f.vulnId))
            .map(f => ({ vulnId: f.vulnId, finding: f }));

        // Dropped IDs (in old but not in new)
        const droppedIds = analyzerOldChecklist.findings
            .filter(f => !newMap.has(f.vulnId))
            .map(f => ({ vulnId: f.vulnId, finding: f }));

        return { notReviewed, newIds, droppedIds, totalOld, totalNew };
    }, [analyzerOldChecklist, analyzerNewChecklist]);

    const [filterStatus, setFilterStatus] = useState<string>('All');
    const [filterSeverity, setFilterSeverity] = useState<string>('All');

    const handleCopyUpload = async (file: File, type: 'source' | 'target') => {
        const parsed = await parseCklFile(file);
        if (parsed) {
            if (type === 'source') setCopySource(parsed);
            else setCopyTarget(parsed);
            setCopySuccess(null);
        }
    };

    const executeFindReplace = () => {
        if (!copyTarget || !findText) return;
        const newTarget = JSON.parse(JSON.stringify(copyTarget));
        let count = 0;

        newTarget.findings.forEach((f: any) => {
            let modified = false;
            // Search in Comments
            if (f.comments && f.comments.includes(findText)) {
                f.comments = f.comments.split(findText).join(replaceText);
                modified = true;
            }
            // Search in Finding Details
            if (f.findingDetails && f.findingDetails.includes(findText)) {
                f.findingDetails = f.findingDetails.split(findText).join(replaceText);
                modified = true;
            }

            if (modified) count++;
        });

        setCopyTarget(newTarget);
        alert(`Replaced text in ${count} findings.`);
    };

    const executeCopy = () => {
        if (!copySource || !copyTarget) return;

        // Deep copy target to avoid mutation issues
        const newTarget = JSON.parse(JSON.stringify(copyTarget));
        let updateCount = 0;

        // Iterate over source findings
        copySource.findings.forEach(sourceFinding => {
            // Find matching finding in target (by Rule ID or Vuln ID)
            const targetFinding = newTarget.findings.find((f: any) =>
                (f.ruleId && f.ruleId === sourceFinding.ruleId) ||
                (f.vulnId && f.vulnId === sourceFinding.vulnId)
            );

            if (targetFinding) {
                let updated = false;
                if (copyFields.status && sourceFinding.status !== 'Not_Reviewed') {
                    targetFinding.status = sourceFinding.status;
                    updated = true;
                }
                if (copyFields.comments && sourceFinding.comments) {
                    targetFinding.comments = sourceFinding.comments;
                    updated = true;
                }
                if (copyFields.details && (sourceFinding.description || sourceFinding.findingDetails)) {
                    const sourceDetails = sourceFinding.findingDetails || sourceFinding.description || '';
                    if (sourceDetails) {
                        targetFinding.findingDetails = sourceDetails;
                        updated = true;
                    }
                }
                if (updated) updateCount++;
            }
        });

        // Update target
        setCopyTarget(newTarget);
        setCopySuccess(`Successfully updated ${updateCount} findings from ${copySource.filename} to ${copyTarget.filename}`);
    };


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
                    if (obj.length > 0) {
                        const s = obj[0];
                        console.log('[Parser] Inspecting array item:', Object.keys(s));
                        if (s.vulnId || s.vulnNum || s.ruleId || s.Rule_ID || s.STIG_ID || s.vuln_num || s.GROUP_ID || s.id || s.rule_id || s.rule) {
                            console.log('[Parser] MATCH FOUND!');
                            return obj;
                        }
                    }
                    // Continue searching inside array items
                    for (const item of obj) {
                        const result = findFindings(item);
                        if (result.length > 0) return result;
                    }
                    return [];
                }
                if (typeof obj === 'object') {
                    console.log('[Parser] Searching object keys:', Object.keys(obj));
                    // Check specific known keys
                    if (obj.findings) return findFindings(obj.findings);
                    if (obj.rules) return findFindings(obj.rules);
                    if (obj.vulns) return findFindings(obj.vulns);
                    if (obj.stigs) return findFindings(obj.stigs);
                    if (obj['evaluate-stig']) return findFindings(obj['evaluate-stig']);
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
                    vulnId: f.group_id || f.groupId || f.Group_ID || f.vulnId || f.vulnNum || f.Vuln_Num || f.vuln_num || 'Unknown', // Group ID (V-XXXX)
                    groupId: f.group_id || f.groupId || f.Group_ID || '',
                    status: (() => {
                        const raw = f.status || f.STATUS || f.Status || f.finding_status || 'Not_Reviewed';
                        const s = String(raw).toLowerCase().replace(/[\s_]/g, '');
                        if (s === 'open' || s === 'fail' || s === 'failed') return 'Open';
                        if (s === 'notafinding' || s === 'pass' || s === 'passed' || s === 'nf') return 'NotAFinding';
                        if (s === 'notapplicable' || s === 'na' || s === 'n/a') return 'Not_Applicable';
                        return 'Not_Reviewed';
                    })(),
                    severity: f.severity || f.Severity || f.sev || 'medium',
                    title: f.title || f.Rule_Title || f.rule_title || f.ruleTitle || f.group_title || 'Unknown Title',
                    comments: f.comments || f.COMMENTS || f.comment || '',
                    ruleId: f.rule_id || f.ruleId || f.Rule_ID || f.STIG_ID || '', // Rule ID (SV-XXXX)
                    fixText: f.fixText || f.Fix_Text || f.fix_text || f.fix || f.check_content || '',
                    checkText: f.checkText || f.Check_Content || f.check_content || f.checkText || '',
                    description: f.description || f.Vuln_Discuss || f.desc || f.discussion || '',
                    findingDetails: f.findingDetails || f.FINDING_DETAILS || f.finding_details || '',
                    classification: f.classification || f.Class || f.class || 'UNCLASSIFIED',
                    legacyId: f.legacyId || f.Legacy_ID || f.legacy_id || '',
                    ccis: Array.isArray(f.ccis) ? f.ccis : []
                }));

                // Find hostname/stigName if possible
                const findValue = (obj: any, key: string): string => {
                    // simple search
                    if (!obj) return '';
                    if (typeof obj === 'object') {
                        if (obj[key]) return obj[key];
                        // special case for target_data
                        if (obj.target_data && obj.target_data[key]) return obj.target_data[key];

                        for (const k in obj) {
                            if (typeof obj[k] === 'object') {
                                const res = findValue(obj[k], key);
                                if (res) return res;
                            }
                        }
                    }
                    return '';
                };

                const extractedHostname = json.hostname || json.HOST_NAME || findValue(json, 'HOST_NAME') || findValue(json, 'target_name') || findValue(json, 'host_name') || findValue(json, 'system_name') || findValue(json, 'name');
                console.log(`[Parser] Extracted Hostname for ${file.name}:`, extractedHostname);

                return {
                    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    filename: file.name,
                    hostname: extractedHostname || file.name.replace(/\.(ckl|cklb|json|xml)$/i, ''), // Fallback to filename
                    stigName: json.stigName || json.SID_NAME || findValue(json, 'SID_NAME') || findValue(json, 'STIG') || findValue(json, 'stig_name') || findValue(json, 'display_name') || findValue(json, 'title') || 'Imported Checklist',
                    findings: mappedFindings,
                    rawJson: json // Preserve original for valid CKLB export
                };
            } else {
                console.warn('[Parser] No findings array found in JSON structure.');
                alert(`Debug: Parsed JSON but found no checklists. Top keys: ${Object.keys(json).join(', ')}. Check console for details.`);
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

            // Extract findings logic
            const extractFinding = (vulnContent: string) => {
                // Extract Vuln ID
                const vulnIdMatch = vulnContent.match(/<VULN_ATTRIBUTE>Vuln_Num<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const vulnId = vulnIdMatch ? vulnIdMatch[1].trim() : '';

                // Extract Group ID
                const groupMatch = vulnContent.match(/<VULN_ATTRIBUTE>Group_ID<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const groupId = groupMatch ? groupMatch[1].trim() : '';

                // Extract Rule ID
                const ruleIdMatch = vulnContent.match(/<VULN_ATTRIBUTE>(?:Rule_ID|Rule_Ver|STIG_ID)<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const ruleId = ruleIdMatch ? ruleIdMatch[1].trim() : '';

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
                const commentsMatch = vulnContent.match(/<COMMENTS>([\s\S]*?)<\/COMMENTS>/i);
                const comments = commentsMatch ? commentsMatch[1].trim() : '';

                // Extract Fix Text
                const fixMatch = vulnContent.match(/<VULN_ATTRIBUTE>Fix_Text<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([\s\S]*?)<\/ATTRIBUTE_DATA>/i);
                const fixText = fixMatch ? fixMatch[1].trim() : '';

                // Extract Check Text
                const checkMatch = vulnContent.match(/<VULN_ATTRIBUTE>Check_Content<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([\s\S]*?)<\/ATTRIBUTE_DATA>/i);
                const checkText = checkMatch ? checkMatch[1].trim() : '';

                // Extract Discussion
                const discMatch = vulnContent.match(/<VULN_ATTRIBUTE>(?:Discussion|Vuln_Discuss)<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([\s\S]*?)<\/ATTRIBUTE_DATA>/i);
                const description = discMatch ? discMatch[1].trim() : '';

                // Finding Details
                const detailsMatch = vulnContent.match(/<FINDING_DETAILS>([\s\S]*?)<\/FINDING_DETAILS>/i);
                const findingDetails = detailsMatch ? detailsMatch[1].trim() : '';

                // Extract Classification
                const classMatch = vulnContent.match(/<VULN_ATTRIBUTE>Class<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const classification = classMatch ? classMatch[1].trim() : 'UNCLASSIFIED';

                // Extract SRG ID / STIG ID (Try to find STIG_REF or similar if widely available, else fallback)
                // NOTE: CKL files vary. We'll capture Check/Fix/Desc/Title.

                // Extract Legacy ID
                const legacyMatch = vulnContent.match(/<VULN_ATTRIBUTE>Legacy_ID<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>([^<]*)<\/ATTRIBUTE_DATA>/i);
                const legacyId = legacyMatch ? legacyMatch[1].trim() : '';

                // Extract CCIs
                const cciRegex = /<VULN_ATTRIBUTE>CCI_REF<\/VULN_ATTRIBUTE>\s*<ATTRIBUTE_DATA>(CCI-[^<]*)<\/ATTRIBUTE_DATA>/gi;
                const ccis: string[] = [];
                let cciMatch;
                while ((cciMatch = cciRegex.exec(vulnContent)) !== null) {
                    ccis.push(cciMatch[1].trim());
                }

                if (vulnId || ruleId) {
                    return {
                        vulnId, groupId, ruleId, status, severity, title, comments,
                        fixText, checkText, description, findingDetails,
                        classification, legacyId, ccis
                    };
                }
                return null;
            };

            while ((match = vulnRegex.exec(content)) !== null) {
                const f = extractFinding(match[1]);
                if (f) findings.push(f as any);
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





    // Generate Excel Report
    const generateExcelReport = () => {
        if (uploadedChecklists.length === 0) return;

        setIsGeneratingReport(true);

        try {
            const workbook = XLSX.utils.book_new();

            // 1. Group Checklists by STIG
            const stigGroups = new Map<string, typeof uploadedChecklists>();
            uploadedChecklists.forEach(ckl => {
                const name = ckl.stigName || 'Unknown STIG';
                if (!stigGroups.has(name)) stigGroups.set(name, []);
                stigGroups.get(name)!.push(ckl);
            });

            // 2. Build Summary Data
            // Headers matches the specific user request
            // Layout: STIG | Instances | Total Controls | CAT I (%/Total/NaF/NA/Open) | CAT II ... | CAT III ...
            const summaryHeader1 = [
                'STIG Name', '# of Instances', 'Total Controls',
                'CAT I', '', '', '', '', // % Comp, Total, NaF, NA, Open
                'CAT II', '', '', '', '',
                'CAT III', '', '', '', ''
            ];

            const summaryHeader2 = [
                '', '', '',
                '% Complete', 'Total CAT Is', 'Not a Finding', 'Not Applicable', 'Open',
                '% Complete', 'Total CAT IIs', 'Not a Finding', 'Not Applicable', 'Open',
                '% Complete', 'Total CAT IIIs', 'Not a Finding', 'Not Applicable', 'Open'
            ];

            const summaryRows: any[] = [];
            let grantTotalInstances = 0;
            let grandTotalControls = 0;

            // Stats Aggregators for Grand Total Row
            const grandStats = {
                cat1: { total: 0, naf: 0, na: 0, open: 0 },
                cat2: { total: 0, naf: 0, na: 0, open: 0 },
                cat3: { total: 0, naf: 0, na: 0, open: 0 }
            };

            stigGroups.forEach((checklists, stigName) => {
                const instances = checklists.length;
                grantTotalInstances += instances;

                // Aggregators for this STIG
                const stats = {
                    cat1: { total: 0, naf: 0, na: 0, open: 0 },
                    cat2: { total: 0, naf: 0, na: 0, open: 0 },
                    cat3: { total: 0, naf: 0, na: 0, open: 0 }
                };

                let totalControls = 0;

                checklists.forEach(ckl => {
                    ckl.findings.forEach(f => {
                        totalControls++;
                        grandTotalControls++;

                        let cat = 'cat3';
                        const sev = (f.severity || '').toLowerCase();
                        if (sev === 'high' || sev === 'cat i') cat = 'cat1';
                        else if (sev === 'medium' || sev === 'cat ii') cat = 'cat2';

                        // Status Normalization
                        const s = (f.status || '').toLowerCase().replace(/[\s_]/g, '');

                        // Increment Total for this Cat
                        stats[cat as keyof typeof stats].total++;
                        grandStats[cat as keyof typeof stats].total++;

                        if (s === 'open' || s === 'fail' || s === 'failed') {
                            stats[cat as keyof typeof stats].open++;
                            grandStats[cat as keyof typeof stats].open++;
                        } else if (s === 'notafinding' || s === 'pass' || s === 'passed' || s === 'nf') {
                            stats[cat as keyof typeof stats].naf++;
                            grandStats[cat as keyof typeof stats].naf++;
                        } else if (s === 'notapplicable' || s === 'na' || s === 'n/a') {
                            stats[cat as keyof typeof stats].na++;
                            grandStats[cat as keyof typeof stats].na++;
                        }
                    });
                });

                // Calculate Percentages
                const calcPct = (s: typeof stats.cat1) => {
                    if (s.total === 0) return '100%';
                    const compliant = s.naf + s.na;
                    return Math.round((compliant / s.total) * 100) + '%';
                };

                summaryRows.push([
                    stigName,
                    instances,
                    totalControls,
                    // CAT I
                    calcPct(stats.cat1), stats.cat1.total, stats.cat1.naf, stats.cat1.na, stats.cat1.open,
                    // CAT II
                    calcPct(stats.cat2), stats.cat2.total, stats.cat2.naf, stats.cat2.na, stats.cat2.open,
                    // CAT III
                    calcPct(stats.cat3), stats.cat3.total, stats.cat3.naf, stats.cat3.na, stats.cat3.open
                ]);
            });

            // Grand Total Row
            // Calculate Grand Percentages
            const calcGrandPct = (s: typeof grandStats.cat1) => {
                if (s.total === 0) return '100%';
                const compliant = s.naf + s.na;
                return Math.round((compliant / s.total) * 100) + '%';
            };

            summaryRows.push(['', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '']);
            summaryRows.push([
                'GRAND TOTAL',
                grantTotalInstances,
                grandTotalControls,
                // CAT I
                calcGrandPct(grandStats.cat1), grandStats.cat1.total, grandStats.cat1.naf, grandStats.cat1.na, grandStats.cat1.open,
                // CAT II
                calcGrandPct(grandStats.cat2), grandStats.cat2.total, grandStats.cat2.naf, grandStats.cat2.na, grandStats.cat2.open,
                // CAT III
                calcGrandPct(grandStats.cat3), grandStats.cat3.total, grandStats.cat3.naf, grandStats.cat3.na, grandStats.cat3.open
            ]);

            // Create Summary Sheet
            const summarySheet = XLSX.utils.aoa_to_sheet([summaryHeader1, summaryHeader2, ...summaryRows]);

            // Set Column Widths
            summarySheet['!cols'] = [
                { wch: 40 }, // STIG
                { wch: 15 }, // Instances
                { wch: 15 }, // Total Controls
                // CAT I
                { wch: 12 }, { wch: 10 }, { wch: 12 }, { wch: 12 }, { wch: 8 },
                // CAT II
                { wch: 12 }, { wch: 10 }, { wch: 12 }, { wch: 12 }, { wch: 8 },
                // CAT III
                { wch: 12 }, { wch: 10 }, { wch: 12 }, { wch: 12 }, { wch: 8 }
            ];

            XLSX.utils.book_append_sheet(workbook, summarySheet, 'CURRENT ENVIRONMENT');

            // 3. Create Detail Sheets (One for each STIG Group)
            stigGroups.forEach((checklists, stigName) => {
                // Sanitize sheet name
                const safeName = stigName.replace(/[[\]*?\/\\:]/g, '').substring(0, 31);

                const detailData = [['Hostname', 'Vuln ID', 'Rule ID', 'STIG ID', 'Severity', 'Classification', 'Status', 'Title', 'Comments', 'CCIs', 'Fix Text', 'Discussion']];

                checklists.forEach(ckl => {
                    ckl.findings.forEach(f => {
                        let sev = f.severity?.toLowerCase() || '';
                        if (sev === 'high') sev = 'CAT I';
                        else if (sev === 'medium') sev = 'CAT II';
                        else if (sev === 'low') sev = 'CAT III';

                        detailData.push([
                            ckl.hostname,
                            f.vulnId,           // Group ID (V-XXXX)
                            f.ruleId || 'N/A',  // Rule ID (SV-XXXX)
                            ckl.stigName,
                            sev,
                            f.classification || 'UNCLASSIFIED',
                            f.status,
                            f.title,
                            f.comments,
                            (f.ccis || []).join(', '),
                            f.fixText || '',
                            f.description || ''
                        ]);
                    });
                });

                const detailSheet = XLSX.utils.aoa_to_sheet(detailData);
                detailSheet['!cols'] = [
                    { wch: 20 }, // Hostname
                    { wch: 15 }, // Vuln ID
                    { wch: 15 }, // Rule ID
                    { wch: 30 }, // STIG ID
                    { wch: 8 },  // Severity
                    { wch: 15 }, // Classification
                    { wch: 15 }, // Status
                    { wch: 40 }, // Title
                    { wch: 40 }, // Comments
                    { wch: 20 }, // CCIs
                    { wch: 40 }, // Fix Text
                    { wch: 40 }  // Discussion
                ];

                // Append sheet
                let uniqueSheetName = safeName;
                let counter = 1;
                while (workbook.Sheets[uniqueSheetName]) {
                    uniqueSheetName = safeName.substring(0, 28) + ` (${counter++})`;
                }
                XLSX.utils.book_append_sheet(workbook, detailSheet, uniqueSheetName);
            });

            XLSX.writeFile(workbook, `STIG_Report_${new Date().toISOString().split('T')[0]}.xlsx`);

        } catch (error) {
            console.error('Report Generation Error:', error);
            alert('Failed to generate report. Check console.');
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
            const name = file.name.toLowerCase();
            if (name.endsWith('.ckl') || name.endsWith('.cklb') || name.endsWith('.json') || name.endsWith('.xml')) {
                const parsed = await parseCklFile(file);
                if (parsed) newChecklists.push(parsed);
            }
        }

        setPoamChecklists(prev => [...prev, ...newChecklists]);
        e.target.value = '';
    };

    const handleBulkFolderUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = e.target.files;
        if (!files) return;

        const fileList = Array.from(files);
        console.log(`Starting bulk upload for ${fileList.length} files...`);

        let stigCount = 0;
        let acasCount = 0;
        const newChecklists: any[] = [];
        const newAcasRows: any[] = [];

        for (const file of fileList) {
            const name = file.name.toLowerCase();
            // STIG Checklists (.ckl, .cklb, .json, .xml)
            if (name.endsWith('.ckl') || name.endsWith('.cklb') || name.endsWith('.json') || name.endsWith('.xml')) {
                const parsed = await parseCklFile(file);
                if (parsed && parsed.findings && parsed.findings.length > 0) {
                    newChecklists.push(parsed);
                    stigCount++;
                }
            }
            // ACAS CSV
            else if (name.endsWith('.csv')) {
                try {
                    const text = await file.text();
                    const wb = XLSX.read(text, { type: 'string' });
                    const sheet = wb.Sheets[wb.SheetNames[0]];
                    const json = XLSX.utils.sheet_to_json(sheet);
                    newAcasRows.push(...json);
                    acasCount++;
                } catch (err) {
                    console.error("Error reading ACAS CSV in bulk folder", err);
                }
            }
        }

        if (newChecklists.length > 0) {
            if (activeTab === 'controls') {
                setUploadedChecklists(prev => [...prev, ...newChecklists]);
            } else {
                setPoamChecklists(prev => [...prev, ...newChecklists]);
            }
        }
        if (newAcasRows.length > 0) {
            setAcasData(prev => [...prev, ...newAcasRows]);
        }

        if (stigCount > 0 || acasCount > 0) {
            if (activeTab === 'controls') {
                alert(`Bulk Upload Complete!\n\n- Loaded ${stigCount} STIG checklists.`);
            } else {
                alert(`Bulk Upload Complete!\n\n- Loaded ${stigCount} STIG checklists\n- Loaded ${acasCount} ACAS scan files\n\nAll findings will be consolidated into the POA&M.`);
            }
        } else {
            alert("No valid STIG checklists or ACAS CSV files found in the selected folder.");
        }

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

    // Stats calculation (Dynamic based on mode)
    const stats = useMemo(() => {
        if (activeTab === 'copy' && editFile) {
            return {
                passed: editFile.findings.filter(f => f.status === 'NotAFinding').length,
                failed: editFile.findings.filter(f => f.status === 'Open').length,
                manual: editFile.findings.filter(f => f.status === 'Not_Applicable').length,
                pending: editFile.findings.filter(f => f.status === 'Not_Reviewed').length
            };
        }
        return {
            passed: Array.from(results.values()).filter(r => r.status === 'pass').length,
            failed: Array.from(results.values()).filter(r => r.status === 'fail').length,
            manual: Array.from(results.values()).filter(r => r.status === 'notapplicable').length,
            pending: rules.length - results.size
        };
    }, [results, rules.length, activeTab, editFile]);

    const { passed, failed, manual, pending } = stats;

    const total = (activeTab === 'copy' && editFile) ? editFile.findings.length : rules.length;
    const scanned = (activeTab === 'copy' && editFile) ? editFile.findings.filter(f => f.status !== 'Not_Reviewed').length : results.size;

    // Severity counts (Dynamic based on mode)
    const severityCounts = useMemo(() => {
        if (activeTab === 'copy' && editFile) {
            return {
                high: editFile.findings.filter(f => (f.severity || '').toLowerCase() === 'high' || (f.severity || '').toLowerCase() === 'cat i').length,
                medium: editFile.findings.filter(f => (f.severity || '').toLowerCase() === 'medium' || (f.severity || '').toLowerCase() === 'cat ii').length,
                low: editFile.findings.filter(f => (f.severity || '').toLowerCase() === 'low' || (f.severity || '').toLowerCase() === 'cat iii').length
            };
        }
        return {
            high: rules.filter(r => r.severity === 'high').length,
            medium: rules.filter(r => r.severity === 'medium').length,
            low: rules.filter(r => r.severity === 'low').length
        };
    }, [rules, activeTab, editFile]);

    const { high: highCount, medium: mediumCount, low: lowCount } = severityCounts;

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

    const handleAcasUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (!e.target.files) return;
        const files = Array.from(e.target.files);
        const newRows: any[] = [];
        for (const file of files) {
            try {
                const text = await file.text();
                const wb = XLSX.read(text, { type: 'string' });
                const sheet = wb.Sheets[wb.SheetNames[0]];
                const json = XLSX.utils.sheet_to_json(sheet);
                newRows.push(...json);
            } catch (err) { console.error("Error reading ACAS CSV", err); }
        }
        setAcasData(prev => [...prev, ...newRows]);
    };

    const generatePoamProject = () => {
        console.group("🚀 Starting POA&M Generation");
        console.log("Input Checklists:", poamChecklists.length);
        console.log("Input ACAS Entries:", acasData.length);

        if (poamChecklists.length === 0 && acasData.length === 0) {
            console.warn("⚠️ No data loaded (Checklists or ACAS), aborting generation.");
            console.groupEnd();
            return;
        }

        const POAM_HEADERS = [
            'POA&M Item ID', 'Control Vulnerability Description', 'Controls / APs', 'Office/Org', 'Security Checks',
            'Resources Required', 'Scheduled Completion Date', 'Milestone ID', 'Milestone with Completion Dates',
            'Milestone Changes', 'Source Identifying Vulnerability', 'Status', 'Comments', 'Raw Severity',
            'Devices Affected', 'Mitigations', 'Severity', 'Relevance of Threat', 'Likelihood', 'Impact',
            'Impact Description', 'Residual Risk Level', 'Recommendations', 'Identified in CFO Audit or other review',
            'Personnel Resources: Cost Code'
        ];

        let poamId = 1;
        const allRows: any[] = [];

        // Date Helpers
        const getDateOut = (days: number) => {
            const d = new Date();
            d.setDate(d.getDate() + days);
            return `${d.getMonth() + 1}/${d.getDate()}/${d.getFullYear()}`;
        };

        // Helper to extract NIST
        const extractNist = (text: any) => {
            if (!text) return '';
            const match = String(text).match(/NIST SP 800-53 Revision 4\s*::\s*([A-Z0-9\-]+)/);
            return match ? match[1] : '';
        };
        const extractCci = (text: any) => {
            if (!text) return '';
            const match = String(text).match(/(CCI-\d+)/);
            return match ? match[0] : String(text).trim();
        };

        // Process STIGs
        console.group("Processing STIG Checklists");
        poamChecklists.forEach((checklist, cIdx) => {
            console.log(`[STIG ${cIdx + 1}/${poamChecklists.length}] processing: ${checklist.filename}`);

            let openFound = 0;
            let skipped = 0;

            checklist.findings.forEach((finding, fIdx) => {
                // DEBUG: Log the first few findings to check their structure and status
                if (fIdx < 3) {
                    console.log(`  - Finding #${fIdx} [${finding.ruleId}]: Status='${finding.status}', Severity='${finding.severity}'`);
                }

                if (finding.status !== 'Open') {
                    skipped++;
                    return;
                }
                openFound++;

                // Sensing CAT and calculating dates
                let cat: keyof typeof poamConfig.milestones = 'cat3';
                let maxDays = 90;
                const s = String(finding.severity).toLowerCase();
                if (s.includes('high') || s.includes('cat i') || s === 'i' || s === '1') { cat = 'cat1'; maxDays = 30; }
                else if (s.includes('medium') || s.includes('cat ii') || s === 'ii' || s === '2') { cat = 'cat2'; maxDays = 60; }

                const milestoneDates = poamConfig.milestones[cat].map((m, idx) => {
                    if (m.date) {
                        const [y, mm, dd] = m.date.split('-');
                        return `${parseInt(mm)}/${parseInt(dd)}/${y}`;
                    }
                    const offsets = [0, 14, 21, maxDays];
                    return getDateOut(offsets[idx]);
                });

                const controlVulnDesc = finding.title || '';

                // Lookup NIST Controls using our Dictionary
                const nistControls = new Set<string>();
                if (finding.ccis && finding.ccis.length > 0) {
                    finding.ccis.forEach(c => {
                        const mapped = cciMap[c];
                        if (mapped) {
                            // Extract base control or full control? POAM usually wants specific like AC-2(1).
                            // But usually just the primary designation.
                            nistControls.add(mapped);
                        }
                    });
                } else {
                    // Fallback to rules lookup
                    const rule = rules.find(r => r.vulnId === finding.vulnId);
                    if (rule && rule.ccis) {
                        rule.ccis.forEach(c => {
                            const mapped = cciMap[c];
                            if (mapped) nistControls.add(mapped);
                        });
                    }
                }
                const nistControl = Array.from(nistControls).join('; ');

                const cciNumber = finding.ccis?.[0] || '';
                const comments = `${cciNumber}\n${finding.findingDetails || ''}`.trim();
                const securityChecks = `${finding.ruleId || ''}\n${finding.vulnId || ''}\n${finding.groupId || ''}`.trim();

                // Generate 4 rows for this finding (one per milestone)
                poamConfig.milestones[cat].forEach((m, idx) => {
                    const row: any = {};
                    POAM_HEADERS.forEach(h => row[h] = ''); // Init empty

                    row['Milestone ID'] = m.id;
                    row['Milestone with Completion Dates'] = `${m.text} ${milestoneDates[idx]}`;

                    if (idx === 0) {
                        row['POA&M Item ID'] = poamId;
                        row['Control Vulnerability Description'] = controlVulnDesc;
                        row['Controls / APs'] = nistControl;
                        row['Office/Org'] = poamConfig.officeOrg;
                        row['Security Checks'] = securityChecks;
                        row['Resources Required'] = poamConfig.resourcesRequired;
                        row['Scheduled Completion Date'] = milestoneDates[3]; // Milestone 4 date
                        row['Source Identifying Vulnerability'] = "Evaluate STIG: " + checklist.stigName;
                        row['Status'] = poamConfig.status;
                        row['Comments'] = comments;
                        row['Raw Severity'] = finding.severity;
                        row['Devices Affected'] = checklist.hostname;
                        row['Severity'] = finding.severity;
                        row['Relevance of Threat'] = finding.severity;
                        row['Likelihood'] = finding.severity;
                        row['Impact'] = finding.severity;
                        row['Residual Risk Level'] = finding.severity;
                        row['Recommendations'] = finding.fixText;
                    }
                    allRows.push(row);
                });
                poamId++;
            });
            console.log(`- Result: ${openFound} 'Open' findings processed, ${skipped} skipped.`);
        });
        console.groupEnd();

        // Process ACAS
        if (acasData.length > 0) {
            console.group("Processing ACAS Data");
            console.log(`Processing ${acasData.length} ACAS rows...`);
            let acasProcessed = 0;

            acasData.forEach((r, idx) => {
                if (idx < 3) console.log(`  - ACAS Row #${idx}:`, r);

                const severity = r['Severity'] || r['C'];
                // Optional: Filter logic for ACAS could go here

                let cat: keyof typeof poamConfig.milestones = 'cat3';
                let maxDays = 90;
                const s = String(severity).toLowerCase();
                if (s.includes('high') || s.includes('critical') || s === 'i' || s === '1') { cat = 'cat1'; maxDays = 30; }
                else if (s.includes('medium') || s === 'ii' || s === '2') { cat = 'cat2'; maxDays = 60; }

                const milestoneDates = poamConfig.milestones[cat].map((m, idx) => {
                    if (m.date) {
                        const [y, mm, dd] = m.date.split('-');
                        return `${parseInt(mm)}/${parseInt(dd)}/${y}`;
                    }
                    const offsets = [0, 14, 21, maxDays];
                    return getDateOut(offsets[idx]);
                });

                const controlVulnDesc = r['Synopsis'] || r['F'] || '';
                const controlsAps = r['Control Family'] || r['I'] || '';
                const securityChecks = `Plugin ID: ${r['Plugin'] || r['A'] || ''}`;
                const recommendations = r['Steps to Remediate'] || r['H'] || '';
                const devicesAffected = r['DNS Name'] || r['D'] || '';
                const comments = r['Description'] || r['G'] || '';
                const mitigations = r['Mitigation'] || r['J'] || '';

                poamConfig.milestones[cat].forEach((m, idx) => {
                    const row: any = {};
                    POAM_HEADERS.forEach(h => row[h] = '');

                    row['Milestone ID'] = m.id;
                    row['Milestone with Completion Dates'] = `${m.text} ${milestoneDates[idx]}`;

                    if (idx === 0) {
                        row['POA&M Item ID'] = poamId;
                        row['Control Vulnerability Description'] = controlVulnDesc;
                        row['Controls / APs'] = controlsAps;
                        row['Office/Org'] = poamConfig.officeOrg;
                        row['Security Checks'] = securityChecks;
                        row['Resources Required'] = poamConfig.resourcesRequired;
                        row['Scheduled Completion Date'] = milestoneDates[3];
                        row['Source Identifying Vulnerability'] = "ACAS";
                        row['Status'] = poamConfig.status;
                        row['Comments'] = comments;
                        row['Raw Severity'] = severity;
                        row['Devices Affected'] = devicesAffected;
                        row['Mitigations'] = mitigations;
                        row['Severity'] = severity;
                        row['Relevance of Threat'] = severity;
                        row['Likelihood'] = severity;
                        row['Impact'] = severity;
                        row['Residual Risk Level'] = severity;
                        row['Recommendations'] = recommendations;
                    }
                    allRows.push(row);
                });
                poamId++;
                acasProcessed++;
            });
            console.log(`- Result: ${acasProcessed} ACAS items processed.`);
            console.groupEnd();
        }

        console.log(`✅ Generation Complete. Total Rows Created: ${allRows.length}`);
        if (allRows.length > 0) {
            console.log("Sample Row:", allRows[0]);
        } else {
            console.warn("⚠️ No rows were generated! Check if findings have 'Open' status.");
        }

        console.groupEnd();

        if (allRows.length === 0) {
            alert("Report generation skipped: No 'Open' findings found in the loaded checklists/scans.");
            return;
        }

        const ws = XLSX.utils.json_to_sheet(allRows);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, "POA&M");
        XLSX.writeFile(wb, "POA&M_Generated.xlsx");
    };

    const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
        if (!e.target.files) return;
        const files = Array.from(e.target.files);

        // --- Tools Logic ---
        if (activeTab === 'tools') {
            const newFiles: { file: File; originalName: string; newName: string }[] = [];
            for (const f of files) {
                newFiles.push({
                    file: f,
                    originalName: f.name,
                    newName: f.name
                });
            }
            // Reset files if user uploads new ones? Or append? User request implies "upload... and save".
            // Let's append if they drag more.
            setRenameFiles(prev => {
                // Determine names based on CURRENT prefix/suffix state immediately to avoid lag
                const mapped = newFiles.map(item => ({
                    ...item,
                    newName: `${renamePrefix}${item.originalName}${renameSuffix}`
                }));
                return [...prev, ...mapped];
            });
            return;
        }

        let successCount = 0;
        let failCount = 0;

        for (const file of files) {
            const parsed = await parseCklFile(file);
            if (parsed && parsed.findings.length > 0) {
                setUploadedChecklists(prev => {
                    // Robust duplicate check: ensure unique combination of filename and hostname
                    if (prev.find(p => p.filename === parsed.filename && p.hostname === parsed.hostname)) return prev;
                    return [...prev, parsed];
                });
                successCount++;
            } else {
                failCount++;
                console.warn(`File ${file.name} contained 0 valid findings or failed to parse.`);
            }
        }

        if (failCount > 0) {
            alert(`Loaded ${successCount} checklists. Failed to load ${failCount} files (invalid format or no content).`);
        }

        // Reset input value to allow re-selecting the same file if needed
        e.target.value = '';
    };

    // Tools Rename Logic Actions
    const executeRenameDownload = async () => {
        if (renameFiles.length === 0) return;

        const zip = new JSZip();
        renameFiles.forEach(item => {
            zip.file(item.newName, item.file);
        });

        const content = await zip.generateAsync({ type: 'blob' });

        const link = document.createElement('a');
        link.href = URL.createObjectURL(content);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        link.download = `renamed_files_${timestamp}.zip`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        alert(`Successfully bundled ${renameFiles.length} files with new names!`);
    };

    // Tools Effect for Live Updates
    useEffect(() => {
        if (activeTab === 'tools' && renameFiles.length > 0) {
            setRenameFiles(prev => prev.map(item => ({
                ...item,
                newName: `${renamePrefix}${item.originalName}${renameSuffix}`
            })));
        }
    }, [renamePrefix, renameSuffix]);

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
                            <Target className="size-5" strokeWidth={2.5} />
                        </div>
                        <span className="font-semibold text-lg tracking-tight">STIG Ops</span>
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
                    <SidebarItem icon={<FileEdit size={18} />} label="Checklist Editor" active={activeTab === 'copy'} onClick={() => setActiveTab('copy')} darkMode={darkMode} />
                    <SidebarItem icon={<FolderOpen size={18} />} label="Evidence Gallery" active={activeTab === 'evidence'} onClick={() => { setActiveTab('evidence'); loadEvidence(); }} darkMode={darkMode} />
                    <SidebarItem icon={<FileSpreadsheet size={18} />} label="Reports" active={activeTab === 'report'} onClick={() => setActiveTab('report')} darkMode={darkMode} />
                    <SidebarItem icon={<GitCompare size={18} />} label="Compare" active={activeTab === 'compare'} onClick={() => setActiveTab('compare')} darkMode={darkMode} />
                    <SidebarItem icon={<FileWarning size={18} />} label="POA&M" active={activeTab === 'poam'} onClick={() => setActiveTab('poam')} darkMode={darkMode} />
                    <SidebarItem icon={<Shield size={18} />} label="Controls" active={activeTab === 'controls'} onClick={() => setActiveTab('controls')} darkMode={darkMode} />

                    {/* Tools Dropdown */}
                    <div className="mb-1">
                        <button
                            onClick={() => setIsToolsOpen(!isToolsOpen)}
                            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all mb-0.5 group ${isToolsOpen || activeTab === 'tools'
                                ? (darkMode ? 'bg-gray-800/50 text-white' : 'bg-gray-100/50 text-gray-900')
                                : (darkMode ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-500 hover:bg-white/60 hover:text-gray-900')
                                }`}
                        >
                            <div className={`transition-colors ${activeTab === 'tools' ? (darkMode ? 'text-blue-400' : 'text-blue-600') : 'text-gray-400 group-hover:text-gray-500'}`}>
                                <Wrench size={18} />
                            </div>
                            <span className="text-sm font-medium">Tools</span>
                            <ChevronDown size={14} className={`ml-auto transition-transform text-gray-400 ${isToolsOpen ? 'rotate-180' : ''}`} />
                        </button>

                        {isToolsOpen && (
                            <div className="pl-4 space-y-0.5 mt-1">
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('rename'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'rename'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Save As (Bulk Rename)
                                </button>
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('heatmap'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'heatmap'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Risk Heatmap
                                </button>
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('analyzer'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'analyzer'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    STIG Analyzer
                                </button>
                            </div>
                        )}
                    </div>

                    <div className={`pt-4 mt-4 border-t ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                        <div className={`text-xs font-semibold px-4 mb-2 uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Filter by Severity</div>
                        <button onClick={() => { setSelectedSeverity(null); setSelectedStatus(null); }} className={`w-full text-left px-4 py-2 text-sm rounded-lg transition-colors ${!selectedSeverity && !selectedStatus
                            ? (darkMode ? 'bg-gray-700 shadow-sm font-medium text-white' : 'bg-white shadow-sm font-medium')
                            : (darkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-600 hover:bg-white/50')}`}>
                            all controls ({editFile && activeTab === 'copy' ? editFile.findings.length : total})
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
                    <div className={`text-xs font-semibold uppercase tracking-wide ${darkMode ? 'text-gray-400' : 'text-gray-400'}`}>Current Status</div>
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
                {/* Privacy Banner */}
                <div className={`px-4 py-2.5 text-center text-xs font-medium border-b sticky top-0 z-20 ${darkMode ? 'bg-blue-900/20 text-blue-200 border-blue-900/30 backdrop-blur-sm' : 'bg-blue-50 text-blue-700 border-blue-100 backdrop-blur-sm'}`}>
                    <p className="flex items-center justify-center gap-2 max-w-5xl mx-auto">
                        <ShieldCheck size={14} className="shrink-0" />
                        <span>Privacy Notice: All data processing is performed locally. No files are uploaded to any server or database.</span>
                    </p>
                </div>

                <div className={`${activeTab === 'copy' || (activeTab === 'tools' && toolsMode === 'analyzer') ? 'w-full px-6' : 'max-w-5xl mx-auto'} p-10`}>

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

                            {/* My Workspace Section */}
                            <div className="mt-12 mb-6 pt-6 border-t border-gray-100">
                                <h2 className="text-2xl font-semibold tracking-tight mb-2">My Workspace</h2>
                                <p className="text-gray-500 mb-6">Upload and manage your own STIG checklists. Edit findings, add comments, and export updates.</p>

                                <div className={`p-8 rounded-2xl border-2 border-dashed mb-8 text-center transition-all ${darkMode ? 'border-gray-700 bg-gray-800/50 hover:bg-gray-800' : 'border-gray-200 bg-gray-50 hover:bg-gray-100'}`}>
                                    <div className="max-w-md mx-auto">
                                        <div className={`size-14 mx-auto mb-4 rounded-xl flex items-center justify-center ${darkMode ? 'bg-gray-700 text-blue-400' : 'bg-white shadow text-blue-600'}`}>
                                            <Upload size={24} />
                                        </div>
                                        <h3 className={`text-lg font-medium mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>Upload Checklist to Work On</h3>
                                        <p className={`text-sm mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                            Select a .ckl or .cklb file to open it in the editor. You can modify status, comments, and details.
                                        </p>
                                        <label className="inline-block">
                                            <span className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-full font-medium cursor-pointer shadow-lg shadow-blue-600/20 active:scale-95 transition-all flex items-center gap-2">
                                                <FileEdit size={18} /> Select Checklist File
                                            </span>
                                            <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" onChange={handleFileUpload} />
                                        </label>
                                    </div>
                                </div>

                                {uploadedChecklists.length > 0 && (
                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                        {uploadedChecklists.map(ckl => (
                                            <div key={ckl.id} className={`group relative p-6 rounded-2xl border transition-all hover:shadow-lg ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                <div className="flex items-start justify-between mb-4">
                                                    <div className={`p-3 rounded-xl ${darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600'}`}>
                                                        <FileText size={24} />
                                                    </div>
                                                    <button
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            setUploadedChecklists(prev => prev.filter(c => c.id !== ckl.id));
                                                        }}
                                                        className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-red-900/30 text-gray-500 hover:text-red-400' : 'hover:bg-red-50 text-gray-400 hover:text-red-500'}`}
                                                    >
                                                        <Trash2 size={18} />
                                                    </button>
                                                </div>

                                                <h3 className={`font-semibold text-lg mb-1 truncate ${darkMode ? 'text-gray-200' : 'text-gray-900'}`} title={ckl.filename}>{ckl.filename}</h3>
                                                <p className={`text-sm mb-4 truncate ${darkMode ? 'text-gray-500' : 'text-gray-500'}`}>{ckl.hostname}</p>

                                                <div className="flex gap-2 mb-6">
                                                    <span className={`px-2.5 py-1 rounded text-xs font-medium ${darkMode ? 'bg-red-900/30 text-red-400' : 'bg-red-50 text-red-600'}`}>
                                                        {ckl.findings.filter(f => f.status === 'Open').length} Open
                                                    </span>
                                                    <span className={`px-2.5 py-1 rounded text-xs font-medium ${darkMode ? 'bg-green-900/30 text-green-400' : 'bg-green-50 text-green-600'}`}>
                                                        {ckl.findings.filter(f => f.status === 'NotAFinding' || f.status === 'Not_A_Finding').length} Pass
                                                    </span>
                                                </div>

                                                <button
                                                    onClick={() => {
                                                        const fileToEdit = JSON.parse(JSON.stringify(ckl)); // Deep clone
                                                        setEditFile(fileToEdit);
                                                        setEditMode('edit');
                                                        setActiveTab('copy');
                                                    }}
                                                    className="w-full bg-black hover:bg-gray-800 text-white px-4 py-3 rounded-xl font-medium transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <FileEdit size={16} /> Open Editor
                                                </button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
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
                                            onChange={handleFileUpload}
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
                                    <div className={`grid grid-cols-5 gap-4 p-4 rounded-xl ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
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
                                        <div
                                            className={`text-center p-2 rounded-lg transition-colors cursor-pointer ${darkMode ? 'hover:bg-gray-700/50' : 'hover:bg-gray-100'}`}
                                            onClick={() => setShowHostModal(true)}
                                        >
                                            <div className="text-2xl font-bold text-blue-500">
                                                {new Set(uploadedChecklists.map(c => c.hostname)).size}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Unique Hosts</div>
                                        </div>
                                        <div
                                            className={`text-center p-2 rounded-lg transition-colors cursor-pointer ${darkMode ? 'hover:bg-gray-700/50' : 'hover:bg-gray-100'}`}
                                            onClick={() => setShowStigModal(true)}
                                        >
                                            <div className="text-2xl font-bold text-purple-500">
                                                {new Set(uploadedChecklists.map(c => c.stigName)).size}
                                            </div>
                                            <div className={`text-xs uppercase ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Unique STIGs</div>
                                        </div>
                                    </div>

                                    {/* Summary Table */}
                                    {reportSummary.length > 0 && (
                                        <div className={`rounded-xl border mb-6 transition-all ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                            {/* Collapsible Header */}
                                            <div
                                                className={`px-4 py-3 flex items-center justify-between cursor-pointer border-b ${darkMode ? 'border-gray-700 hover:bg-gray-700/50' : 'border-gray-100 hover:bg-gray-50'}`}
                                                onClick={() => setIsSummaryExpanded(!isSummaryExpanded)}
                                            >
                                                <div className="flex items-center gap-2">
                                                    <FileSpreadsheet className={`size-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                                                    <span className={`font-semibold text-sm uppercase tracking-wide ${darkMode ? 'text-gray-200' : 'text-gray-700'}`}>Current Environment Summary</span>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={async (e) => {
                                                            e.stopPropagation();
                                                            setCopying(true);
                                                            const table = document.getElementById('summary-table');
                                                            if (table) {
                                                                try {
                                                                    const canvas = await html2canvas(table, {
                                                                        backgroundColor: darkMode ? '#1f2937' : '#ffffff',
                                                                        scale: 2 // Retain high quality
                                                                    });
                                                                    canvas.toBlob(blob => {
                                                                        if (blob) {
                                                                            navigator.clipboard.write([
                                                                                new ClipboardItem({ 'image/png': blob })
                                                                            ]).then(() => {
                                                                                setCopying(false);
                                                                            }).catch(err => {
                                                                                console.error('Copy failed', err);
                                                                                setCopying(false);
                                                                            });
                                                                        }
                                                                    });
                                                                } catch (err) {
                                                                    console.error('Capture failed', err);
                                                                    setCopying(false);
                                                                }
                                                            }
                                                        }}
                                                        className={`p-1.5 rounded-lg transition-colors flex items-center gap-1.5 text-xs font-medium ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-500'}`}
                                                    >
                                                        {copying ? <CheckCircle2 size={14} className="text-green-500" /> : <Copy size={14} />}
                                                        {copying ? 'Copied Image!' : 'Copy as Image'}
                                                    </button>
                                                    <button className={`p-1 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-400'}`}>
                                                        {isSummaryExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                                                    </button>
                                                </div>
                                            </div>

                                            {/* Table Content */}
                                            {isSummaryExpanded && (
                                                <div className="overflow-x-auto w-full rounded-b-xl relative">
                                                    <table id="summary-table" className={`w-full text-sm text-left whitespace-nowrap ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                        <thead className={`text-xs uppercase ${darkMode ? 'bg-gray-800/50 text-gray-400' : 'bg-gray-50 text-gray-700'}`}>
                                                            <tr>
                                                                <th className={`px-4 py-3 font-medium border-r dark:border-gray-700 sticky left-0 z-10 drop-shadow-sm min-w-[200px] ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`} rowSpan={2}>STIG Name</th>
                                                                <th className="px-4 py-3 text-center font-medium border-r dark:border-gray-700" rowSpan={2}>Instances</th>
                                                                <th className="px-4 py-3 text-center font-medium border-r dark:border-gray-700" rowSpan={2}>Controls</th>
                                                                <th className="px-4 py-2 text-center border-r dark:border-gray-700 font-medium text-red-500 bg-red-50/50 dark:bg-red-900/10" colSpan={5}>CAT I</th>
                                                                <th className="px-4 py-2 text-center border-r dark:border-gray-700 font-medium text-amber-500 bg-amber-50/50 dark:bg-amber-900/10" colSpan={5}>CAT II</th>
                                                                <th className="px-4 py-2 text-center font-medium text-blue-500 bg-blue-50/50 dark:bg-blue-900/10" colSpan={5}>CAT III</th>
                                                            </tr>
                                                            <tr>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-red-50/50 dark:bg-red-900/10">%</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-red-50/50 dark:bg-red-900/10">Total</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-red-50/50 dark:bg-red-900/10">NaF</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-red-50/50 dark:bg-red-900/10">N/A</th>
                                                                <th className="px-2 py-2 text-center border-r dark:border-gray-700 w-12 text-xs opacity-70 bg-red-50/50 dark:bg-red-900/10">Open</th>

                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-amber-50/50 dark:bg-amber-900/10">%</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-amber-50/50 dark:bg-amber-900/10">Total</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-amber-50/50 dark:bg-amber-900/10">NaF</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-amber-50/50 dark:bg-amber-900/10">N/A</th>
                                                                <th className="px-2 py-2 text-center border-r dark:border-gray-700 w-12 text-xs opacity-70 bg-amber-50/50 dark:bg-amber-900/10">Open</th>

                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-blue-50/50 dark:bg-blue-900/10">%</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-blue-50/50 dark:bg-blue-900/10">Total</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-blue-50/50 dark:bg-blue-900/10">NaF</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-blue-50/50 dark:bg-blue-900/10">N/A</th>
                                                                <th className="px-2 py-2 text-center w-12 text-xs opacity-70 bg-blue-50/50 dark:bg-blue-900/10">Open</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                                                            {reportSummary.map((row, i) => (
                                                                <tr key={i} className={`transition-colors ${darkMode ? 'bg-gray-800 hover:bg-gray-700/30' : 'bg-white hover:bg-gray-50'}`}>
                                                                    <td
                                                                        className="px-4 py-3 font-medium border-r dark:border-gray-700 sticky left-0 bg-inherit z-10 cursor-pointer hover:text-blue-500 hover:underline border-b dark:border-gray-700"
                                                                        title="Click to view Chart"
                                                                        onClick={() => setSelectedStigChart(row)}
                                                                    >
                                                                        {row.name}
                                                                    </td>
                                                                    <td className="px-4 py-3 text-center border-r dark:border-gray-700">{row.instances}</td>
                                                                    <td className="px-4 py-3 text-center border-r dark:border-gray-700">{row.controls}</td>

                                                                    <td className="px-2 py-3 text-center font-medium bg-red-50/30 dark:bg-red-900/5">{row.cat1.pct}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-red-50/30 dark:bg-red-900/5">{row.cat1.total}</td>
                                                                    <td className="px-2 py-3 text-center text-green-600 bg-red-50/30 dark:bg-red-900/5">{row.cat1.naf}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-red-50/30 dark:bg-red-900/5">{row.cat1.na}</td>
                                                                    <td className={`px-2 py-3 text-center font-bold border-r dark:border-gray-700 bg-red-50/30 dark:bg-red-900/5 ${row.cat1.open > 0 ? 'text-red-500' : 'text-gray-300'}`}>{row.cat1.open}</td>

                                                                    <td className="px-2 py-3 text-center font-medium bg-amber-50/30 dark:bg-amber-900/5">{row.cat2.pct}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-amber-50/30 dark:bg-amber-900/5">{row.cat2.total}</td>
                                                                    <td className="px-2 py-3 text-center text-green-600 bg-amber-50/30 dark:bg-amber-900/5">{row.cat2.naf}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-amber-50/30 dark:bg-amber-900/5">{row.cat2.na}</td>
                                                                    <td className={`px-2 py-3 text-center font-bold border-r dark:border-gray-700 bg-amber-50/30 dark:bg-amber-900/5 ${row.cat2.open > 0 ? 'text-amber-500' : 'text-gray-300'}`}>{row.cat2.open}</td>

                                                                    <td className="px-2 py-3 text-center font-medium bg-blue-50/30 dark:bg-blue-900/5">{row.cat3.pct}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-blue-50/30 dark:bg-blue-900/5">{row.cat3.total}</td>
                                                                    <td className="px-2 py-3 text-center text-green-600 bg-blue-50/30 dark:bg-blue-900/5">{row.cat3.naf}</td>
                                                                    <td className="px-2 py-3 text-center text-gray-400 bg-blue-50/30 dark:bg-blue-900/5">{row.cat3.na}</td>
                                                                    <td className={`px-2 py-3 text-center font-bold bg-blue-50/30 dark:bg-blue-900/5 ${row.cat3.open > 0 ? 'text-blue-500' : 'text-gray-300'}`}>{row.cat3.open}</td>
                                                                </tr>
                                                            ))}
                                                        </tbody>
                                                    </table>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Pie Chart Modal */}
                                    {selectedStigChart && (
                                        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" onClick={() => setSelectedStigChart(null)}>
                                            <div className={`w-full max-w-lg p-6 rounded-2xl shadow-xl ${darkMode ? 'bg-gray-800 text-white' : 'bg-white text-gray-900'}`} onClick={(e) => e.stopPropagation()}>
                                                <div className="flex items-center justify-between mb-6">
                                                    <div>
                                                        <h3 className="text-xl font-bold">{selectedStigChart.name}</h3>
                                                        <div className="text-sm opacity-60">Compliance Overview</div>
                                                    </div>
                                                    <button onClick={() => setSelectedStigChart(null)} className="p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                                                        <XCircle className="size-6 text-gray-400" />
                                                    </button>
                                                </div>

                                                <div className="grid grid-cols-2 gap-4 mb-6">
                                                    <div className={`p-4 rounded-xl text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-50'}`}>
                                                        <div className="text-xs uppercase tracking-wide opacity-70 mb-1">CAT I Compliance</div>
                                                        <div className="text-4xl font-bold text-red-500">{selectedStigChart.cat1.pct}</div>
                                                        <div className="text-xs mt-1 text-gray-400">{selectedStigChart.cat1.open} Open Findings</div>
                                                    </div>
                                                    <div className={`p-4 rounded-xl text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-50'}`}>
                                                        <div className="text-xs uppercase tracking-wide opacity-70 mb-1">CAT II Compliance</div>
                                                        <div className="text-4xl font-bold text-amber-500">{selectedStigChart.cat2.pct}</div>
                                                        <div className="text-xs mt-1 text-gray-400">{selectedStigChart.cat2.open} Open Findings</div>
                                                    </div>
                                                </div>

                                                <div className="space-y-3">
                                                    <div className="flex items-center gap-3 p-3 rounded-lg border border-red-200 bg-red-50 dark:bg-red-900/20 dark:border-red-800">
                                                        <div className="size-10 rounded-full bg-red-100 dark:bg-red-800 flex items-center justify-center text-red-600 dark:text-red-200 font-bold">I</div>
                                                        <div className="flex-1">
                                                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                                                <div className="h-full bg-red-500" style={{ width: selectedStigChart.cat1.pct }}></div>
                                                            </div>
                                                        </div>
                                                        <div className="w-12 text-right font-medium">{selectedStigChart.cat1.pct}</div>
                                                    </div>
                                                    <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-200 bg-amber-50 dark:bg-amber-900/20 dark:border-amber-800">
                                                        <div className="size-10 rounded-full bg-amber-100 dark:bg-amber-800 flex items-center justify-center text-amber-600 dark:text-amber-200 font-bold">II</div>
                                                        <div className="flex-1">
                                                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                                                <div className="h-full bg-amber-500" style={{ width: selectedStigChart.cat2.pct }}></div>
                                                            </div>
                                                        </div>
                                                        <div className="w-12 text-right font-medium">{selectedStigChart.cat2.pct}</div>
                                                    </div>
                                                    <div className="flex items-center gap-3 p-3 rounded-lg border border-blue-200 bg-blue-50 dark:bg-blue-900/20 dark:border-blue-800">
                                                        <div className="size-10 rounded-full bg-blue-100 dark:bg-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-200 font-bold">III</div>
                                                        <div className="flex-1">
                                                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                                                <div className="h-full bg-blue-500" style={{ width: selectedStigChart.cat3.pct }}></div>
                                                            </div>
                                                        </div>
                                                        <div className="w-12 text-right font-medium">{selectedStigChart.cat3.pct}</div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    )}

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

                            {/* Detail Modals for Stats */}
                            {showHostModal && (
                                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" onClick={() => setShowHostModal(false)}>
                                    <div className={`w-full max-w-md p-6 rounded-2xl shadow-xl ${darkMode ? 'bg-gray-800' : 'bg-white'}`} onClick={(e) => e.stopPropagation()}>
                                        <div className="flex items-center justify-between mb-4">
                                            <h3 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Unique Hosts</h3>
                                            <button onClick={() => setShowHostModal(false)} className="p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                                                <XCircle className="size-5 text-gray-400" />
                                            </button>
                                        </div>
                                        <div className="max-h-60 overflow-y-auto space-y-2">
                                            {Array.from(new Set(uploadedChecklists.map(c => c.hostname))).sort().map(host => (
                                                <div key={host} className={`p-3 rounded-lg text-sm font-mono ${darkMode ? 'bg-gray-700/50 text-gray-300' : 'bg-gray-50 text-gray-700'}`}>
                                                    {host}
                                                </div>
                                            ))}
                                        </div>
                                        <div className="mt-4 pt-4 border-t border-gray-100 dark:border-gray-700 text-center">
                                            <span className="text-xs text-gray-500">{new Set(uploadedChecklists.map(c => c.hostname)).size} Total Hosts</span>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {showStigModal && (
                                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" onClick={() => setShowStigModal(false)}>
                                    <div className={`w-full max-w-md p-6 rounded-2xl shadow-xl ${darkMode ? 'bg-gray-800' : 'bg-white'}`} onClick={(e) => e.stopPropagation()}>
                                        <div className="flex items-center justify-between mb-4">
                                            <h3 className={`text-lg font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Unique STIGs</h3>
                                            <button onClick={() => setShowStigModal(false)} className="p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                                                <XCircle className="size-5 text-gray-400" />
                                            </button>
                                        </div>
                                        <div className="max-h-60 overflow-y-auto space-y-2">
                                            {Array.from(new Set(uploadedChecklists.map(c => c.stigName))).sort().map(stig => (
                                                <div key={stig} className={`p-3 rounded-lg text-sm ${darkMode ? 'bg-gray-700/50 text-gray-300' : 'bg-gray-50 text-gray-700'}`}>
                                                    {stig}
                                                </div>
                                            ))}
                                        </div>
                                        <div className="mt-4 pt-4 border-t border-gray-100 dark:border-gray-700 text-center">
                                            <span className="text-xs text-gray-500">{new Set(uploadedChecklists.map(c => c.stigName)).size} Total STIGs</span>
                                        </div>
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
                    ) : activeTab === 'copy' ? (
                        <div className="h-[calc(100vh-100px)] flex flex-col">
                            <div className="flex-none mb-4 flex items-center justify-between">
                                <div>
                                    <h1 className="text-2xl font-semibold tracking-tight">
                                        {editMode === 'edit' && editFile ? `Editing: ${editFile.filename}` : 'Edit & Transfer'}
                                    </h1>
                                    <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>
                                        {editMode === 'edit' ? 'Edit a checklist directly with find & replace, then export.' : 'Transfer data between two checklists.'}
                                    </p>
                                </div>
                                <div className={`flex rounded-lg p-1 ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                                    <button onClick={() => setEditMode('edit')}
                                        className={`px-4 py-2 text-sm font-medium rounded-md transition-all ${editMode === 'edit'
                                            ? (darkMode ? 'bg-gray-700 text-white shadow' : 'bg-white text-gray-900 shadow')
                                            : (darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-600 hover:text-gray-900')}`}>
                                        <FileEdit size={14} className="inline mr-2" />Edit
                                    </button>
                                    <button onClick={() => setEditMode('copy')}
                                        className={`px-4 py-2 text-sm font-medium rounded-md transition-all ${editMode === 'copy'
                                            ? (darkMode ? 'bg-gray-700 text-white shadow' : 'bg-white text-gray-900 shadow')
                                            : (darkMode ? 'text-gray-400 hover:text-gray-200' : 'text-gray-600 hover:text-gray-900')}`}>
                                        <Copy size={14} className="inline mr-2" />Copy
                                    </button>
                                </div>
                            </div>

                            {editMode === 'copy' ? (
                                <>

                                    <div className="flex-1 min-h-0 grid grid-cols-2 gap-6">
                                        {/* Left Panel: Source */}
                                        <div className={`flex flex-col rounded-2xl border overflow-hidden ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                            <div className={`p-3 border-b flex items-center justify-between ${darkMode ? 'border-gray-700 bg-gray-900/50' : 'border-gray-100 bg-gray-50'}`}>
                                                <div className="flex items-center gap-2">
                                                    <div className="p-1.5 rounded-lg bg-blue-100 text-blue-600">
                                                        <div className="font-bold text-xs uppercase">Source</div>
                                                    </div>
                                                    {copySource && (
                                                        <div className="text-sm">
                                                            <div className={`font-semibold ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{copySource.filename}</div>
                                                            <div className="text-xs text-gray-500">{copySource.hostname}</div>
                                                        </div>
                                                    )}
                                                </div>
                                                {copySource && (
                                                    <button
                                                        onClick={() => setCopySource(null)}
                                                        className="text-xs text-red-500 hover:text-red-600 font-medium underline px-2"
                                                    >
                                                        Change File
                                                    </button>
                                                )}
                                            </div>

                                            {/* Source Find/Replace */}
                                            {copySource && (
                                                <div className="px-3 pb-2 flex items-center gap-2">
                                                    <div className="flex items-center flex-1 gap-1 bg-white dark:bg-black/20 p-1 rounded-lg border border-gray-200 dark:border-gray-600">
                                                        <input
                                                            type="text"
                                                            placeholder="Find..."
                                                            className="bg-transparent text-xs px-2 py-1 w-full outline-none"
                                                            value={sourceFindText}
                                                            onChange={e => setSourceFindText(e.target.value)}
                                                        />
                                                        <div className="w-px h-4 bg-gray-300 dark:bg-gray-600"></div>
                                                        <input
                                                            type="text"
                                                            placeholder="Replace..."
                                                            className="bg-transparent text-xs px-2 py-1 w-full outline-none"
                                                            value={sourceReplaceText}
                                                            onChange={e => setSourceReplaceText(e.target.value)}
                                                        />
                                                        <button
                                                            onClick={() => {
                                                                if (!copySource || !sourceFindText) return;
                                                                const newSource = JSON.parse(JSON.stringify(copySource));
                                                                let count = 0;
                                                                newSource.findings.forEach((f: any) => {
                                                                    if (f.comments && f.comments.includes(sourceFindText)) {
                                                                        f.comments = f.comments.split(sourceFindText).join(sourceReplaceText);
                                                                        count++;
                                                                    }
                                                                    if (f.findingDetails && f.findingDetails.includes(sourceFindText)) {
                                                                        f.findingDetails = f.findingDetails.split(sourceFindText).join(sourceReplaceText);
                                                                        count++;
                                                                    }
                                                                });
                                                                setCopySource(newSource);
                                                                alert(`Replaced in ${count} fields.`);
                                                            }}
                                                            disabled={!sourceFindText}
                                                            className="px-2 py-1 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 rounded text-xs font-medium whitespace-nowrap disabled:opacity-50"
                                                        >
                                                            Go
                                                        </button>
                                                    </div>
                                                </div>
                                            )}

                                            <div className="flex-1 overflow-hidden relative">
                                                {!copySource ? (
                                                    <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center">
                                                        <div className={`mx-auto size-12 mb-3 opacity-50 ${darkMode ? 'text-gray-600' : 'text-gray-300'}`}>
                                                            <FileSpreadsheet size={48} />
                                                        </div>
                                                        <h3 className={`font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Upload Master Checklist</h3>
                                                        <label className="inline-block mt-3">
                                                            <span className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-full text-sm font-medium cursor-pointer inline-flex items-center gap-2">
                                                                <Upload size={16} /> Choose Source
                                                            </span>
                                                            <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" onChange={(e) => {
                                                                if (e.target.files && e.target.files[0]) handleCopyUpload(e.target.files[0], 'source');
                                                            }} />
                                                        </label>
                                                    </div>
                                                ) : (
                                                    <div className="absolute inset-0 overflow-auto">
                                                        <table className={`w-full text-sm text-left ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            <thead className={`uppercase sticky top-0 z-10 ${darkMode ? 'bg-gray-900 text-gray-400' : 'bg-gray-50 text-gray-700'}`}>
                                                                <tr>
                                                                    <th className="px-3 py-2 w-32">Rule ID</th>
                                                                    <th className="px-3 py-2 w-24">Status</th>
                                                                    <th className="px-3 py-2">Finding Details</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody className={`divide-y ${darkMode ? 'divide-gray-700' : 'divide-gray-200'}`}>
                                                                {copySource.findings.map((f, i) => (
                                                                    <tr key={i} className={`group hover:bg-gray-50 dark:hover:bg-gray-700/30 align-top`}>
                                                                        <td className="px-3 py-2 font-mono text-[10px] whitespace-nowrap">{f.ruleId || f.vulnId}</td>
                                                                        <td className="px-3 py-2">
                                                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${f.status === 'Open' ? 'bg-red-100 text-red-700' :
                                                                                f.status === 'NotAFinding' ? 'bg-green-100 text-green-700' :
                                                                                    'bg-gray-100 text-gray-600'
                                                                                }`}>{f.status}</span>
                                                                        </td>
                                                                        <td className="px-3 py-2">
                                                                            {expandedSourceIdx === i ? (
                                                                                <div className="flex flex-col gap-2">
                                                                                    <textarea
                                                                                        className={`w-full text-xs p-3 rounded border resize-y min-h-[150px] ${darkMode ? 'bg-gray-900 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900'}`}
                                                                                        value={f.findingDetails || ''}
                                                                                        onChange={e => {
                                                                                            const newSource = JSON.parse(JSON.stringify(copySource));
                                                                                            newSource.findings[i].findingDetails = e.target.value;
                                                                                            setCopySource(newSource);
                                                                                        }}
                                                                                    />
                                                                                    <button
                                                                                        onClick={() => setExpandedSourceIdx(null)}
                                                                                        className="text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded font-medium self-end"
                                                                                    >
                                                                                        Done
                                                                                    </button>
                                                                                </div>
                                                                            ) : (
                                                                                <div
                                                                                    className="line-clamp-2 cursor-pointer hover:text-blue-600 hover:underline"
                                                                                    title="Click to expand and edit"
                                                                                    onClick={() => setExpandedSourceIdx(i)}
                                                                                >
                                                                                    {f.findingDetails || <span className="opacity-30 italic">Click to add details</span>}
                                                                                </div>
                                                                            )}
                                                                        </td>
                                                                    </tr>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        {/* Right Panel: Target */}
                                        <div className={`flex flex-col rounded-2xl border overflow-hidden ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                            <div className={`p-3 border-b flex flex-col gap-2 ${darkMode ? 'border-gray-700 bg-gray-900/50' : 'border-gray-100 bg-gray-50'}`}>
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-2">
                                                        <div className="p-1.5 rounded-lg bg-purple-100 text-purple-600">
                                                            <div className="font-bold text-xs uppercase">Target</div>
                                                        </div>
                                                        {copyTarget && (
                                                            <div className="text-sm">
                                                                <div className={`font-semibold ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>{copyTarget.filename}</div>
                                                                <div className="text-xs text-gray-500">{copyTarget.hostname}</div>
                                                            </div>
                                                        )}
                                                    </div>
                                                    {copyTarget && (
                                                        <button
                                                            onClick={() => setCopyTarget(null)}
                                                            className="text-xs text-red-500 hover:text-red-600 font-medium underline px-2"
                                                        >
                                                            Change File
                                                        </button>
                                                    )}
                                                </div>

                                                {/* Tools Bar */}
                                                {copyTarget && (
                                                    <div className="flex items-center gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                                                        <div className="flex items-center flex-1 gap-2 bg-white dark:bg-black/20 p-1 rounded-lg border border-gray-200 dark:border-gray-600">
                                                            <input
                                                                type="text"
                                                                placeholder="Find..."
                                                                className="bg-transparent text-xs px-2 py-1 w-full outline-none"
                                                                value={findText}
                                                                onChange={e => setFindText(e.target.value)}
                                                            />
                                                            <div className="w-px h-4 bg-gray-300 dark:bg-gray-600 mx-1"></div>
                                                            <input
                                                                type="text"
                                                                placeholder="Replace..."
                                                                className="bg-transparent text-xs px-2 py-1 w-full outline-none"
                                                                value={replaceText}
                                                                onChange={e => setReplaceText(e.target.value)}
                                                            />
                                                            <button
                                                                onClick={executeFindReplace}
                                                                disabled={!findText}
                                                                className="px-3 py-1 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 rounded text-xs font-medium whitespace-nowrap disabled:opacity-50"
                                                            >
                                                                Replace All
                                                            </button>
                                                        </div>

                                                        {/* Comment+ Toolbar */}
                                                        <div className="flex items-center gap-1 bg-green-50 dark:bg-green-900/20 p-1 rounded-lg border border-green-200 dark:border-green-800">
                                                            <span className="text-[10px] font-bold text-green-700 dark:text-green-400 px-2">+</span>
                                                            <input
                                                                type="text"
                                                                placeholder="Prepend text to all details..."
                                                                className="bg-transparent text-xs px-2 py-1 flex-1 outline-none min-w-[150px]"
                                                                value={commentPlusText}
                                                                onChange={e => setCommentPlusText(e.target.value)}
                                                            />
                                                            <button
                                                                onClick={() => {
                                                                    if (!copyTarget || !commentPlusText) return;
                                                                    const newTarget = JSON.parse(JSON.stringify(copyTarget));
                                                                    newTarget.findings.forEach((f: any) => {
                                                                        const existing = f.findingDetails || '';
                                                                        f.findingDetails = `${commentPlusText}\n\n${existing}`.trim();
                                                                    });
                                                                    setCopyTarget(newTarget);
                                                                    setCommentPlusText('');
                                                                    alert(`Prepended to all ${newTarget.findings.length} findings.`);
                                                                }}
                                                                disabled={!commentPlusText}
                                                                className="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-[10px] font-bold whitespace-nowrap disabled:opacity-50"
                                                            >
                                                                Apply All
                                                            </button>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>

                                            <div className="flex-1 overflow-hidden relative">
                                                {!copyTarget ? (
                                                    <div className="absolute inset-0 flex flex-col items-center justify-center p-6 text-center">
                                                        <div className={`mx-auto size-12 mb-3 opacity-50 ${darkMode ? 'text-gray-600' : 'text-gray-300'}`}>
                                                            <FileText size={48} />
                                                        </div>
                                                        <h3 className={`font-medium mb-1 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Upload Target Checklist</h3>
                                                        <label className="inline-block mt-3">
                                                            <span className="bg-purple-600 hover:bg-purple-700 text-white px-5 py-2 rounded-full text-sm font-medium cursor-pointer inline-flex items-center gap-2">
                                                                <Upload size={16} /> Choose Target
                                                            </span>
                                                            <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" onChange={(e) => {
                                                                if (e.target.files && e.target.files[0]) handleCopyUpload(e.target.files[0], 'target');
                                                            }} />
                                                        </label>
                                                    </div>
                                                ) : (
                                                    <div className="absolute inset-0 overflow-auto">
                                                        <table className={`w-full text-sm text-left ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            <thead className={`uppercase sticky top-0 z-10 ${darkMode ? 'bg-gray-900 text-gray-400' : 'bg-gray-50 text-gray-700'}`}>
                                                                <tr>
                                                                    <th className="px-3 py-2 w-32">Rule ID</th>
                                                                    <th className="px-3 py-2 w-24">Status</th>
                                                                    <th className="px-3 py-2">Finding Details</th>
                                                                </tr>
                                                            </thead>
                                                            <tbody className={`divide-y ${darkMode ? 'divide-gray-700' : 'divide-gray-200'}`}>
                                                                {copyTarget.findings.map((f, i) => (
                                                                    <tr key={i} className={`group hover:bg-gray-50 dark:hover:bg-gray-700/30 align-top`}>
                                                                        <td className="px-3 py-2 font-mono text-[10px] whitespace-nowrap">{f.ruleId || f.vulnId}</td>
                                                                        <td className="px-3 py-2">
                                                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${f.status === 'Open' ? 'bg-red-100 text-red-700' :
                                                                                f.status === 'NotAFinding' ? 'bg-green-100 text-green-700' :
                                                                                    'bg-gray-100 text-gray-600'
                                                                                }`}>{f.status}</span>
                                                                        </td>
                                                                        <td className="px-3 py-2">
                                                                            {expandedTargetIdx === i ? (
                                                                                <div className="flex flex-col gap-2">
                                                                                    {/* Comment+ for single row */}
                                                                                    <div className="flex items-center gap-1 bg-green-50 dark:bg-green-900/20 p-1 rounded border border-green-200 dark:border-green-800">
                                                                                        <input
                                                                                            type="text"
                                                                                            placeholder="Prepend text..."
                                                                                            className="bg-transparent text-xs px-2 py-1 flex-1 outline-none"
                                                                                            value={commentPlusText}
                                                                                            onChange={e => setCommentPlusText(e.target.value)}
                                                                                        />
                                                                                        <button
                                                                                            onClick={() => {
                                                                                                if (!commentPlusText) return;
                                                                                                const newTarget = JSON.parse(JSON.stringify(copyTarget));
                                                                                                const existing = newTarget.findings[i].findingDetails || '';
                                                                                                newTarget.findings[i].findingDetails = `${commentPlusText}\n\n${existing}`.trim();
                                                                                                setCopyTarget(newTarget);
                                                                                                setCommentPlusText('');
                                                                                            }}
                                                                                            disabled={!commentPlusText}
                                                                                            className="px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded text-[10px] font-bold disabled:opacity-50"
                                                                                        >
                                                                                            Apply
                                                                                        </button>
                                                                                    </div>
                                                                                    <textarea
                                                                                        className={`w-full text-xs p-3 rounded border resize-y min-h-[150px] ${darkMode ? 'bg-gray-900 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900'}`}
                                                                                        value={f.findingDetails || ''}
                                                                                        onChange={e => {
                                                                                            const newTarget = JSON.parse(JSON.stringify(copyTarget));
                                                                                            newTarget.findings[i].findingDetails = e.target.value;
                                                                                            setCopyTarget(newTarget);
                                                                                        }}
                                                                                    />
                                                                                    <button
                                                                                        onClick={() => setExpandedTargetIdx(null)}
                                                                                        className="text-xs bg-purple-600 hover:bg-purple-700 text-white px-3 py-1 rounded font-medium self-end"
                                                                                    >
                                                                                        Done
                                                                                    </button>
                                                                                </div>
                                                                            ) : (
                                                                                <div
                                                                                    className="line-clamp-2 cursor-pointer hover:text-purple-600 hover:underline"
                                                                                    title="Click to expand and edit"
                                                                                    onClick={() => setExpandedTargetIdx(i)}
                                                                                >
                                                                                    {f.findingDetails || <span className="opacity-30 italic">Click to add details</span>}
                                                                                </div>
                                                                            )}
                                                                        </td>
                                                                    </tr>
                                                                ))}
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Bottom Config Panel */}
                                    {copySource && copyTarget && (
                                        <div className={`flex-none mt-4 p-4 rounded-xl border flex items-center justify-between ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100 shadow-sm'}`}>
                                            <div className="flex items-center gap-6">
                                                <div className="font-semibold text-sm">Transfer:</div>
                                                <label className="flex items-center gap-2 text-sm cursor-pointer">
                                                    <input type="checkbox" className="rounded text-blue-600" checked={copyFields.status} onChange={e => setCopyFields(f => ({ ...f, status: e.target.checked }))} />
                                                    <span>Status</span>
                                                </label>
                                                <label className="flex items-center gap-2 text-sm cursor-pointer">
                                                    <input type="checkbox" className="rounded text-blue-600" checked={copyFields.comments} onChange={e => setCopyFields(f => ({ ...f, comments: e.target.checked }))} />
                                                    <span>Comments</span>
                                                </label>
                                                <label className="flex items-center gap-2 text-sm cursor-pointer">
                                                    <input type="checkbox" className="rounded text-blue-600" checked={copyFields.details} onChange={e => setCopyFields(f => ({ ...f, details: e.target.checked }))} />
                                                    <span>Details</span>
                                                </label>
                                            </div>

                                            <div className="flex items-center gap-4">
                                                {copySuccess ? (
                                                    <>
                                                        <div className="text-green-600 font-medium text-sm flex items-center gap-2"><CheckCircle2 size={16} /> {copySuccess}</div>
                                                        <button onClick={() => {
                                                            // Build a proper CKLB export
                                                            let exportData: any;

                                                            if (copyTarget.rawJson) {
                                                                // Use original JSON structure and update findings
                                                                exportData = JSON.parse(JSON.stringify(copyTarget.rawJson));

                                                                // Convert our internal status to CKLB format
                                                                const toCklbStatus = (status: string): string => {
                                                                    switch (status) {
                                                                        case 'NotAFinding': return 'not_a_finding';
                                                                        case 'Open': return 'open';
                                                                        case 'Not_Applicable': return 'not_applicable';
                                                                        case 'Not_Reviewed': return 'not_reviewed';
                                                                        default: return status.toLowerCase().replace(/\s+/g, '_');
                                                                    }
                                                                };

                                                                // Helper to find and update findings in the original structure
                                                                const updateFindings = (obj: any): void => {
                                                                    if (!obj) return;
                                                                    if (Array.isArray(obj)) {
                                                                        obj.forEach((item: any) => {
                                                                            // Check if this looks like a finding
                                                                            const itemId = item.vulnId || item.vulnNum || item.Vuln_Num || item.vuln_num ||
                                                                                item.rule_id || item.group_id || item.ruleId || item.id;
                                                                            if (itemId) {
                                                                                // Find corresponding updated finding
                                                                                const updated = copyTarget.findings.find(f =>
                                                                                    f.vulnId === itemId || f.ruleId === itemId ||
                                                                                    f.vulnId === item.vulnId || f.ruleId === item.ruleId ||
                                                                                    f.vulnId === item.rule_id || f.ruleId === item.rule_id
                                                                                );
                                                                                if (updated) {
                                                                                    // Update the status (convert to CKLB format)
                                                                                    const cklbStatus = toCklbStatus(updated.status);
                                                                                    if (item.status !== undefined) item.status = cklbStatus;
                                                                                    if (item.STATUS !== undefined) item.STATUS = updated.status; // Keep original format for XML-style
                                                                                    // Update comments
                                                                                    if (updated.comments) {
                                                                                        if (item.comments !== undefined) item.comments = updated.comments;
                                                                                        if (item.COMMENTS !== undefined) item.COMMENTS = updated.comments;
                                                                                    }
                                                                                    // Update finding details
                                                                                    if (updated.findingDetails) {
                                                                                        if (item.finding_details !== undefined) item.finding_details = updated.findingDetails;
                                                                                        if (item.findingDetails !== undefined) item.findingDetails = updated.findingDetails;
                                                                                        if (item.FINDING_DETAILS !== undefined) item.FINDING_DETAILS = updated.findingDetails;
                                                                                    }
                                                                                }
                                                                            }
                                                                            updateFindings(item);
                                                                        });
                                                                    } else if (typeof obj === 'object') {
                                                                        for (const key in obj) {
                                                                            updateFindings(obj[key]);
                                                                        }
                                                                    }
                                                                };

                                                                updateFindings(exportData);
                                                            } else {
                                                                // Fallback: construct basic CKLB structure
                                                                exportData = {
                                                                    title: copyTarget.stigName,
                                                                    id: copyTarget.id,
                                                                    target_data: {
                                                                        target_type: "Computing",
                                                                        host_name: copyTarget.hostname,
                                                                        ip_address: "",
                                                                        mac_address: "",
                                                                        fqdn: "",
                                                                        comments: "",
                                                                        role: "None",
                                                                        is_web_database: false,
                                                                        technology_area: "",
                                                                        web_db_site: "",
                                                                        web_db_instance: ""
                                                                    },
                                                                    stigs: [{
                                                                        stig_name: copyTarget.stigName,
                                                                        display_name: copyTarget.stigName,
                                                                        stig_id: copyTarget.stigName,
                                                                        version: 1,
                                                                        release_info: "",
                                                                        uuid: copyTarget.id,
                                                                        reference_identifier: "",
                                                                        size: copyTarget.findings.length,
                                                                        rules: copyTarget.findings.map(f => ({
                                                                            uuid: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                                                                            stig_uuid: copyTarget.id,
                                                                            group_id: f.vulnId,
                                                                            rule_id: f.ruleId || f.vulnId,
                                                                            rule_id_src: f.ruleId || f.vulnId,
                                                                            weight: "10.0",
                                                                            classification: "UNCLASSIFIED",
                                                                            severity: f.severity || "medium",
                                                                            rule_version: f.ruleId || "",
                                                                            group_title: f.title,
                                                                            rule_title: f.title,
                                                                            fix_text: f.fixText || "",
                                                                            false_positives: "",
                                                                            false_negatives: "",
                                                                            documentable: "false",
                                                                            mitigations: "",
                                                                            potential_impacts: "",
                                                                            third_party_tools: "",
                                                                            mitigation_control: "",
                                                                            responsibility: "",
                                                                            security_override_guidance: "",
                                                                            check_content_ref: { name: "", href: "" },
                                                                            legacy_ids: [],
                                                                            ccis: f.ccis || [],
                                                                            group_tree: [{ id: f.vulnId, title: f.vulnId, description: "" }],
                                                                            createdAt: new Date().toISOString(),
                                                                            updatedAt: new Date().toISOString(),
                                                                            status: f.status === 'NotAFinding' ? 'not_a_finding' :
                                                                                f.status === 'Open' ? 'open' :
                                                                                    f.status === 'Not_Applicable' ? 'not_applicable' : 'not_reviewed',
                                                                            finding_details: f.findingDetails || "",
                                                                            comments: f.comments || "",
                                                                            severity_override: "",
                                                                            severity_justification: ""
                                                                        }))
                                                                    }],
                                                                    active: true,
                                                                    mode: 1,
                                                                    has_path: true,
                                                                    cklb_version: "2.0"
                                                                };
                                                            }

                                                            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                                                            const url = URL.createObjectURL(blob);
                                                            const a = document.createElement('a');
                                                            a.href = url;
                                                            a.download = `${copyTarget.filename.replace(/\.(ckl|cklb|xml|json)$/i, '')}_updated.cklb`;
                                                            document.body.appendChild(a);
                                                            a.click();
                                                            document.body.removeChild(a);
                                                            URL.revokeObjectURL(url);
                                                        }} className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2">
                                                            <Download size={16} /> Download
                                                        </button>
                                                    </>
                                                ) : (
                                                    <button onClick={executeCopy} className="bg-black hover:bg-gray-800 text-white px-6 py-2 rounded-lg text-sm font-bold flex items-center gap-2">
                                                        <Copy size={16} /> Transfer Data
                                                    </button>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </>
                            ) : (
                                /* EDIT MODE - Single file */
                                <div className="flex-1 min-h-0 flex flex-col">
                                    <div className={`flex-1 flex flex-col rounded-2xl border overflow-hidden ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
                                        <div className={`p-3 border-b flex flex-col gap-2 ${darkMode ? 'border-gray-700 bg-gray-900/50' : 'border-gray-100 bg-gray-50'}`}>
                                            <div className="flex items-center justify-between">

                                                <div className="flex items-center gap-2">
                                                    <div className="p-1.5 rounded-lg bg-blue-100 text-blue-600">
                                                        <div className="font-bold text-xs uppercase">Workspace</div>
                                                    </div>
                                                    {editFile && (
                                                        <div className="relative group">
                                                            <button className={`flex items-center gap-2 text-sm font-semibold px-2 py-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                                                <span className="truncate max-w-[300px]">{editFile.filename}</span>
                                                                <ChevronDown size={14} className="opacity-50" />
                                                            </button>
                                                            {/* Dropdown for switching or closing */}
                                                            <div className="absolute top-full left-0 mt-1 w-64 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-xl z-50 hidden group-hover:block animate-in fade-in zoom-in-95 duration-100">
                                                                <div className="p-2">
                                                                    <div className="text-xs font-semibold text-gray-500 mb-2 px-2">OPEN CHECKLISTS</div>
                                                                    {uploadedChecklists.map((ckl, i) => (
                                                                        <button key={i} onClick={() => setEditFile(ckl)} className={`w-full text-left px-2 py-1.5 rounded text-xs truncate ${editFile.id === ckl.id ? 'bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400' : 'hover:bg-gray-50 dark:hover:bg-gray-700 dark:text-gray-300'}`}>
                                                                            {ckl.filename}
                                                                        </button>
                                                                    ))}
                                                                    <div className="border-t my-2 border-gray-100 dark:border-gray-700"></div>
                                                                    <button onClick={() => setEditFile(null)} className="w-full text-left px-2 py-1.5 rounded text-xs text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2">
                                                                        <X size={12} /> Close Current File
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <label className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1">
                                                        <Upload size={12} /> Import Checklist
                                                        <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" multiple onChange={async (e) => {
                                                            if (e.target.files) {
                                                                const files = Array.from(e.target.files);
                                                                for (const file of files) {
                                                                    const parsed = await parseCklFile(file);
                                                                    if (parsed) {
                                                                        setUploadedChecklists(prev => [...prev, parsed]);
                                                                        setEditFile(parsed);
                                                                    }
                                                                }
                                                            }
                                                        }} />
                                                    </label>
                                                </div>
                                            </div>

                                            {/* Filters in Header */}
                                            <div className="flex items-center gap-2 flex-1 justify-end">
                                                <div className={`flex items-center rounded-md border px-2 py-1 gap-2 ${darkMode ? 'bg-gray-900 border-gray-600' : 'bg-white border-gray-300'}`}>
                                                    <Filter size={12} className="text-gray-400" />
                                                    <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className="bg-transparent text-xs font-medium outline-none w-24 dark:text-gray-200">
                                                        <option value="All">All Status</option>
                                                        <option value="Open">Open</option>
                                                        <option value="NotAFinding">Not A Finding</option>
                                                        <option value="Not_Reviewed">Pending</option>
                                                        <option value="Not_Applicable">N/A</option>
                                                    </select>
                                                    <div className="w-px h-3 bg-gray-300 dark:bg-gray-600"></div>
                                                    <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className="bg-transparent text-xs font-medium outline-none w-24 dark:text-gray-200">
                                                        <option value="All">All Severity</option>
                                                        <option value="high">High (CAT I)</option>
                                                        <option value="medium">Medium (CAT II)</option>
                                                        <option value="low">Low (CAT III)</option>
                                                    </select>
                                                </div>
                                                <div className={`flex items-center rounded-md border px-2 py-1 gap-2 w-48 ${darkMode ? 'bg-gray-900 border-gray-600' : 'bg-white border-gray-300'}`}>
                                                    <Search size={12} className="text-gray-400" />
                                                    <input
                                                        value={findText}
                                                        onChange={e => setFindText(e.target.value)}
                                                        placeholder="Search rules..."
                                                        className="bg-transparent text-xs outline-none flex-1 dark:text-gray-200"
                                                    />
                                                </div>
                                                <button
                                                    onClick={() => setShowBatchTools(!showBatchTools)}
                                                    className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 shadow-sm transition-colors ${showBatchTools ? 'bg-purple-600 text-white' : (darkMode ? 'bg-gray-800 text-gray-300 border border-gray-600' : 'bg-white text-gray-700 border border-gray-200')}`}
                                                >
                                                    <Settings size={12} /> Batch Tools
                                                </button>
                                                <label className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 shadow-sm">
                                                    <Upload size={12} /> Import
                                                    <input type="file" className="hidden" accept=".ckl,.cklb,.xml,.json" multiple onChange={async (e) => {
                                                        if (e.target.files) {
                                                            const files = Array.from(e.target.files);
                                                            for (const file of files) {
                                                                const parsed = await parseCklFile(file);
                                                                if (parsed) {
                                                                    setUploadedChecklists(prev => [...prev, parsed]);
                                                                    setEditFile(parsed);
                                                                }
                                                            }
                                                        }
                                                    }} />
                                                </label>
                                            </div>
                                        </div>

                                        {/* Batch Tools Panel */}
                                        {showBatchTools && editFile && (
                                            <div className={`p-3 border-b space-y-3 ${darkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-gray-50 border-gray-100'}`}>
                                                <div className="flex items-center gap-4 border-b pb-2 border-gray-200 dark:border-gray-700">
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-[10px] font-bold uppercase text-gray-500">Scope:</span>
                                                        <select
                                                            value={batchScope}
                                                            onChange={e => setBatchScope(e.target.value as any)}
                                                            className="bg-transparent text-xs font-bold text-blue-600 outline-none"
                                                        >
                                                            <option value="filtered">All Filtered Findings</option>
                                                            <option value="selected">Current Selected Finding Only</option>
                                                        </select>
                                                    </div>
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-[10px] font-bold uppercase text-gray-500">Target Field:</span>
                                                        <select
                                                            value={batchField}
                                                            onChange={e => setBatchField(e.target.value as any)}
                                                            className="bg-transparent text-xs font-bold text-purple-600 outline-none"
                                                        >
                                                            <option value="details">Finding Details</option>
                                                            <option value="comments">Comments</option>
                                                        </select>
                                                    </div>
                                                </div>

                                                <div className="grid grid-cols-2 gap-4">
                                                    {/* Find & Replace */}
                                                    <div className="flex items-center gap-2">
                                                        <div className="text-[10px] font-bold uppercase text-gray-400 w-12 text-right">Replace</div>
                                                        <div className={`flex items-center flex-1 rounded border px-2 py-1 gap-2 ${darkMode ? 'bg-gray-900 border-gray-600' : 'bg-white border-gray-300'}`}>
                                                            <Search size={12} className="text-gray-400" />
                                                            <input value={batchFind} onChange={e => setBatchFind(e.target.value)} placeholder="Find..." className="bg-transparent text-xs outline-none w-20" />
                                                            <div className="w-px h-3 bg-gray-300 dark:bg-gray-600" />
                                                            <input value={batchReplace} onChange={e => setBatchReplace(e.target.value)} placeholder="Replace..." className="bg-transparent text-xs outline-none flex-1" />
                                                            <button
                                                                onClick={() => {
                                                                    if (!batchFind) return;
                                                                    const newFile = JSON.parse(JSON.stringify(editFile));
                                                                    let count = 0;
                                                                    newFile.findings.forEach((f: any, idx: number) => {
                                                                        const isTarget = batchScope === 'selected'
                                                                            ? idx === expandedEditIdx
                                                                            : ((filterStatus === 'All' || f.status === filterStatus) &&
                                                                                (filterSeverity === 'All' || f.severity === filterSeverity) &&
                                                                                (!findText || f.title.toLowerCase().includes(findText.toLowerCase()) || (f.ruleId || '').toLowerCase().includes(findText.toLowerCase())));

                                                                        if (isTarget) {
                                                                            if (batchField === 'comments' && f.comments?.includes(batchFind)) {
                                                                                f.comments = f.comments.split(batchFind).join(batchReplace);
                                                                                count++;
                                                                            }
                                                                            if (batchField === 'details' && (f.findingDetails || f.title)?.includes(batchFind)) {
                                                                                // f might have findingDetails or we might be targeting description
                                                                                f.findingDetails = (f.findingDetails || '').split(batchFind).join(batchReplace);
                                                                                count++;
                                                                            }
                                                                        }
                                                                    });
                                                                    setEditFile(newFile);
                                                                    alert(`Replaced ${count} occurrences in ${batchField === 'details' ? 'Finding Details' : 'Comments'}.`);
                                                                }}
                                                                className="text-[10px] font-bold bg-blue-600 text-white px-2 py-0.5 rounded hover:bg-blue-700"
                                                            >
                                                                GO
                                                            </button>
                                                        </div>
                                                    </div>

                                                    {/* Prepend */}
                                                    <div className="flex items-center gap-2">
                                                        <div className="text-[10px] font-bold uppercase text-gray-400 w-12 text-right">Prepend</div>
                                                        <div className={`flex items-center flex-1 rounded border px-2 py-1 gap-2 ${darkMode ? 'bg-gray-900 border-gray-600' : 'bg-white border-gray-300'}`}>
                                                            <FileText size={12} className="text-gray-400" />
                                                            <input value={batchPrepend} onChange={e => setBatchPrepend(e.target.value)} placeholder="Add text to start..." className="bg-transparent text-xs outline-none flex-1" />
                                                            <button
                                                                onClick={() => {
                                                                    if (!batchPrepend) return;
                                                                    const newFile = JSON.parse(JSON.stringify(editFile));
                                                                    let count = 0;
                                                                    newFile.findings.forEach((f: any, idx: number) => {
                                                                        const isTarget = batchScope === 'selected'
                                                                            ? idx === expandedEditIdx
                                                                            : ((filterStatus === 'All' || f.status === filterStatus) &&
                                                                                (filterSeverity === 'All' || f.severity === filterSeverity) &&
                                                                                (!findText || f.title.toLowerCase().includes(findText.toLowerCase()) || (f.ruleId || '').toLowerCase().includes(findText.toLowerCase())));

                                                                        if (isTarget) {
                                                                            if (batchField === 'comments') {
                                                                                f.comments = `${batchPrepend}\n${f.comments || ''}`;
                                                                                count++;
                                                                            }
                                                                            if (batchField === 'details') {
                                                                                f.findingDetails = `${batchPrepend}\n${f.findingDetails || ''}`;
                                                                                count++;
                                                                            }
                                                                        }
                                                                    });
                                                                    setEditFile(newFile);
                                                                    alert(`Prepended text to ${count} finding(s).`);
                                                                }}
                                                                className="text-[10px] font-bold bg-green-600 text-white px-2 py-0.5 rounded hover:bg-green-700"
                                                            >
                                                                Add
                                                            </button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        )}

                                        {/* Main Split View */}
                                        <div className="flex-1 flex overflow-hidden">
                                            {/* Left Sidebar - List */}
                                            <div className={`w-1/3 min-w-[300px] max-w-[400px] flex flex-col border-r ${darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-white'}`}>
                                                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                                                    {editFile && editFile.findings
                                                        .map((f, idx) => ({ ...f, origIdx: idx }))
                                                        .filter(f => (filterStatus === 'All' || f.status === filterStatus) && (filterSeverity === 'All' || f.severity === filterSeverity) && (
                                                            !findText || f.title.toLowerCase().includes(findText.toLowerCase()) || (f.ruleId || '').toLowerCase().includes(findText.toLowerCase()) || (f.vulnId || '').toLowerCase().includes(findText.toLowerCase())
                                                        ))
                                                        .map((f, i) => (
                                                            <div
                                                                key={f.origIdx}
                                                                onClick={() => setExpandedEditIdx(f.origIdx)}
                                                                className={`p-3 rounded-lg cursor-pointer border transition-all ${expandedEditIdx === f.origIdx
                                                                    ? 'bg-blue-50 border-blue-200 dark:bg-blue-900/30 dark:border-blue-700 shadow-sm ring-1 ring-blue-500/20'
                                                                    : `hover:bg-gray-50 dark:hover:bg-gray-800 border-transparent ${darkMode ? 'text-gray-300' : 'text-gray-600'}`
                                                                    }`}
                                                            >
                                                                <div className="flex items-start justify-between gap-2 mb-1">
                                                                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${f.severity === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' :
                                                                        f.severity === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' :
                                                                            'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                                                                        }`}>
                                                                        {f.severity === 'high' ? 'CAT I' : f.severity === 'medium' ? 'CAT II' : 'CAT III'}
                                                                    </span>
                                                                    <div className={`w-2 h-2 rounded-full ${f.status === 'Open' ? 'bg-red-500' :
                                                                        f.status === 'NotAFinding' ? 'bg-green-500' :
                                                                            f.status === 'Not_Applicable' ? 'bg-gray-400' : 'bg-orange-400'
                                                                        }`} />
                                                                </div>
                                                                <div className={`text-xs font-semibold line-clamp-2 mb-1 ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>{f.title}</div>
                                                                <div className="flex items-center gap-2 text-[10px] text-gray-400 font-mono">
                                                                    <span>{f.ruleId}</span>
                                                                    <span>•</span>
                                                                    <span>{f.vulnId}</span>
                                                                </div>
                                                            </div>
                                                        ))
                                                    }
                                                    {editFile && editFile.findings.length === 0 && (
                                                        <div className="text-center py-10 text-gray-400 text-xs">No findings match your filter</div>
                                                    )}
                                                </div>
                                                <div className={`p-2 border-t text-[10px] text-center ${darkMode ? 'border-gray-700 text-gray-500' : 'border-gray-100 text-gray-400'}`}>
                                                    Showing {editFile ? editFile.findings.filter(f => (filterStatus === 'All' || f.status === filterStatus) && (filterSeverity === 'All' || f.severity === filterSeverity)).length : 0} of {editFile ? editFile.findings.length : 0}
                                                </div>
                                            </div>

                                            {/* Right Main Panel - Detail Editor */}
                                            <div className={`flex-1 flex flex-col bg-gray-50 dark:bg-gray-900 overflow-hidden relative`}>
                                                {editFile && editFile.findings[expandedEditIdx ?? -1] ? (
                                                    (() => {
                                                        const f = editFile.findings[expandedEditIdx!];
                                                        return (
                                                            <div className="flex flex-col h-full">
                                                                {/* Toolbar */}
                                                                <div className={`h-14 border-b flex items-center justify-between px-6 shrink-0 ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200 shadow-sm'}`}>
                                                                    <div className="flex items-center gap-4">
                                                                        <div className="flex flex-col">
                                                                            <label className="text-[9px] uppercase font-bold text-gray-400">Severity</label>
                                                                            <select
                                                                                value={f.severity}
                                                                                onChange={e => {
                                                                                    const newFile = JSON.parse(JSON.stringify(editFile));
                                                                                    newFile.findings[expandedEditIdx!].severity = e.target.value;
                                                                                    setEditFile(newFile);
                                                                                }}
                                                                                className={`text-sm font-bold bg-transparent outline-none cursor-pointer hover:underline ${f.severity === 'high' ? 'text-red-600 dark:text-red-400' :
                                                                                    f.severity === 'medium' ? 'text-yellow-600 dark:text-yellow-400' :
                                                                                        'text-green-600 dark:text-green-400'
                                                                                    }`}
                                                                            >
                                                                                <option value="high">High (CAT I)</option>
                                                                                <option value="medium">Medium (CAT II)</option>
                                                                                <option value="low">Low (CAT III)</option>
                                                                            </select>
                                                                        </div>
                                                                        <div className="w-px h-8 bg-gray-200 dark:bg-gray-700"></div>
                                                                        <div className="flex flex-col">
                                                                            <label className="text-[9px] uppercase font-bold text-gray-400">Status</label>
                                                                            <select
                                                                                value={f.status}
                                                                                onChange={e => {
                                                                                    const newFile = JSON.parse(JSON.stringify(editFile));
                                                                                    newFile.findings[expandedEditIdx!].status = e.target.value;
                                                                                    setEditFile(newFile);
                                                                                }}
                                                                                className={`text-sm font-bold bg-transparent outline-none cursor-pointer hover:underline ${f.status === 'Open' ? 'text-red-600 dark:text-red-400' :
                                                                                    f.status === 'NotAFinding' ? 'text-green-600 dark:text-green-400' :
                                                                                        'text-gray-600 dark:text-gray-400'
                                                                                    }`}
                                                                            >
                                                                                <option value="Open">Open</option>
                                                                                <option value="NotAFinding">Not A Finding</option>
                                                                                <option value="Not_Reviewed">Not Reviewed</option>
                                                                                <option value="Not_Applicable">Not Applicable</option>
                                                                            </select>
                                                                        </div>
                                                                    </div>

                                                                    <div className="flex items-center gap-2">
                                                                        <button
                                                                            onClick={() => {
                                                                                // Find prev index in filtered list basically, but for now simple prev/next in raw list
                                                                                if ((expandedEditIdx || 0) > 0) setExpandedEditIdx((expandedEditIdx || 0) - 1);
                                                                            }}
                                                                            disabled={(expandedEditIdx || 0) <= 0}
                                                                            className="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-30 transition-colors"
                                                                        >
                                                                            <ChevronUp size={20} />
                                                                        </button>
                                                                        <button
                                                                            onClick={() => {
                                                                                if ((expandedEditIdx || 0) < editFile.findings.length - 1) setExpandedEditIdx((expandedEditIdx || 0) + 1);
                                                                            }}
                                                                            disabled={(expandedEditIdx || 0) >= editFile.findings.length - 1}
                                                                            className="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-30 transition-colors"
                                                                        >
                                                                            <ChevronDown size={20} />
                                                                        </button>
                                                                    </div>
                                                                </div>

                                                                {/* Scrollable Content */}
                                                                <div className="flex-1 overflow-y-auto p-8">
                                                                    <div className="max-w-4xl mx-auto space-y-6">

                                                                        {/* Info Cards */}
                                                                        <div className="grid grid-cols-4 gap-4">
                                                                            <div className="bg-white dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <div className="text-[10px] uppercase text-gray-500 font-bold mb-1">Group ID</div>
                                                                                <div className="text-xs font-mono dark:text-gray-200 selectable">{f.groupId}</div>
                                                                            </div>
                                                                            <div className="bg-white dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <div className="text-[10px] uppercase text-gray-500 font-bold mb-1">Rule ID</div>
                                                                                <div className="text-xs font-mono dark:text-gray-200 selectable">{f.ruleId}</div>
                                                                            </div>
                                                                            <div className="bg-white dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <div className="text-[10px] uppercase text-gray-500 font-bold mb-1">Legacy ID</div>
                                                                                <div className="text-xs font-mono dark:text-gray-200 selectable">{f.legacyId || 'N/A'}</div>
                                                                            </div>
                                                                            <div className="bg-white dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <div className="text-[10px] uppercase text-gray-500 font-bold mb-1">CCIs</div>
                                                                                <div className="text-xs font-mono dark:text-gray-200 selectable truncate" title={f.ccis?.join(', ')}>{(f.ccis?.length || 0) > 0 ? f.ccis?.[0] : 'N/A'}</div>
                                                                            </div>
                                                                        </div>

                                                                        <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                            <div className="flex items-center gap-2 mb-4">
                                                                                <div className="p-1.5 rounded-md bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300">
                                                                                    <Shield size={16} />
                                                                                </div>
                                                                                <h3 className="text-sm font-bold uppercase text-gray-700 dark:text-gray-200">Rule Title</h3>
                                                                            </div>
                                                                            <div className="text-sm dark:text-gray-300 leading-relaxed selectable">{f.title}</div>
                                                                        </div>

                                                                        <div className="grid grid-cols-2 gap-6">
                                                                            <div className="col-span-2 bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <h3 className="text-xs font-bold uppercase text-gray-500 mb-3">Discussion</h3>
                                                                                <div className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap leading-relaxed selectable">{f.description}</div>
                                                                            </div>

                                                                            <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <h3 className="text-xs font-bold uppercase text-green-600 dark:text-green-400 mb-3">Check Text</h3>
                                                                                <div className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap leading-relaxed selectable">{f.checkText}</div>
                                                                            </div>

                                                                            <div className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                                <h3 className="text-xs font-bold uppercase text-indigo-600 dark:text-indigo-400 mb-3">Fix Text</h3>
                                                                                <div className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap leading-relaxed selectable">{f.fixText}</div>
                                                                            </div>
                                                                        </div>

                                                                        {/* Editor Areas */}
                                                                        <div className="space-y-4 pt-4 border-t dark:border-gray-800">
                                                                            <div className="flex flex-col gap-2">
                                                                                <label className="text-xs font-bold uppercase text-gray-500 flex items-center gap-2">
                                                                                    <FileEdit size={12} /> Finding Details / Evidence
                                                                                </label>
                                                                                <textarea
                                                                                    className={`w-full min-h-[150px] p-4 rounded-xl resize-y outline-none transition-all ring-1 focus:ring-2 ${darkMode ? 'bg-gray-800 border-transparent text-gray-100 ring-gray-700 focus:ring-blue-500' : 'bg-white border-gray-200 ring-gray-200 focus:ring-blue-500 focus:border-blue-500'}`}
                                                                                    placeholder="Enter technical details, command output, or screenshots here..."
                                                                                    value={f.findingDetails || ''}
                                                                                    onChange={e => {
                                                                                        const newFile = JSON.parse(JSON.stringify(editFile));
                                                                                        newFile.findings[expandedEditIdx!].findingDetails = e.target.value;
                                                                                        setEditFile(newFile);
                                                                                    }}
                                                                                />
                                                                            </div>

                                                                            <div className="flex flex-col gap-2">
                                                                                <label className="text-xs font-bold uppercase text-gray-500 flex items-center gap-2">
                                                                                    <AlertCircle size={12} /> Comments
                                                                                </label>
                                                                                <textarea
                                                                                    className={`w-full min-h-[100px] p-4 rounded-xl resize-y outline-none transition-all ring-1 focus:ring-2 ${darkMode ? 'bg-gray-800 border-transparent text-gray-100 ring-gray-700 focus:ring-blue-500' : 'bg-white border-gray-200 ring-gray-200 focus:ring-blue-500 focus:border-blue-500'}`}
                                                                                    placeholder="General comments..."
                                                                                    value={f.comments || ''}
                                                                                    onChange={e => {
                                                                                        const newFile = JSON.parse(JSON.stringify(editFile));
                                                                                        newFile.findings[expandedEditIdx!].comments = e.target.value;
                                                                                        setEditFile(newFile);
                                                                                    }}
                                                                                />
                                                                            </div>
                                                                        </div>

                                                                    </div>
                                                                </div>
                                                            </div>
                                                        );
                                                    })()
                                                ) : (
                                                    <div className="flex flex-col items-center justify-center h-full text-gray-400 gap-4">
                                                        <div className="w-16 h-16 rounded-full bg-gray-100 dark:bg-gray-800 flex items-center justify-center">
                                                            <Target size={32} />
                                                        </div>
                                                        <div className="text-sm font-medium">Select a finding to details</div>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    {
                                        editFile && (
                                            <div className={`flex-none mt-4 p-4 rounded-xl border flex items-center justify-end ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100 shadow-sm'}`}>
                                                <button onClick={() => {
                                                    let exportData: any;
                                                    if (editFile.rawJson) {
                                                        exportData = JSON.parse(JSON.stringify(editFile.rawJson));
                                                        const toCklbStatus = (s: string) => s === 'NotAFinding' ? 'not_a_finding' : s === 'Open' ? 'open' : s === 'Not_Applicable' ? 'not_applicable' : 'not_reviewed';
                                                        const updateFindings = (obj: any): void => {
                                                            if (!obj) return;
                                                            if (Array.isArray(obj)) {
                                                                obj.forEach((item: any) => {
                                                                    const itemId = item.vulnId || item.vulnNum || item.rule_id || item.group_id || item.ruleId || item.id;
                                                                    if (itemId) {
                                                                        const updated = editFile.findings.find(f => f.vulnId === itemId || f.ruleId === itemId);
                                                                        if (updated) {
                                                                            if (item.status !== undefined) item.status = toCklbStatus(updated.status);
                                                                            if (updated.findingDetails) {
                                                                                if (item.finding_details !== undefined) item.finding_details = updated.findingDetails;
                                                                                if (item.findingDetails !== undefined) item.findingDetails = updated.findingDetails;
                                                                                if (item.FINDING_DETAILS !== undefined) item.FINDING_DETAILS = updated.findingDetails;
                                                                            }
                                                                            if (updated.comments) {
                                                                                if (item.comments !== undefined) item.comments = updated.comments;
                                                                                if (item.COMMENTS !== undefined) item.COMMENTS = updated.comments;
                                                                            }
                                                                            if (updated.severity) {
                                                                                if (item.severity !== undefined) item.severity = updated.severity;
                                                                                if (item.SEVERITY !== undefined) item.SEVERITY = updated.severity;
                                                                            }
                                                                        }
                                                                    }
                                                                    updateFindings(item);
                                                                });
                                                            } else if (typeof obj === 'object') { for (const key in obj) updateFindings(obj[key]); }
                                                        };
                                                        updateFindings(exportData);
                                                    } else { exportData = editFile; }
                                                    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
                                                    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url;
                                                    a.download = `${editFile.filename.replace(/\.(ckl|cklb|xml|json)$/i, '')}_edited.cklb`;
                                                    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
                                                }} className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg text-sm font-bold flex items-center gap-2">
                                                    <Download size={16} /> Export CKLB
                                                </button>
                                            </div>
                                        )
                                    }
                                </div>
                            )}
                        </div>
                    ) : activeTab === 'poam' ? (
                        <div className="space-y-8 max-w-2xl mx-auto">
                            <div className="text-center">
                                <h1 className="text-3xl font-semibold tracking-tight mb-2">POA&M Generator</h1>
                                <p className={darkMode ? 'text-gray-400' : 'text-gray-500'}>Generate a Plan of Action and Milestones (POA&M) document from multiple STIG checklists.</p>
                            </div>

                            <div className="flex justify-center -mt-2">
                                <label className={`cursor-pointer px-6 py-3 rounded-full text-sm font-bold shadow-lg transition-all flex items-center gap-3 border ${darkMode ? 'bg-blue-600 hover:bg-blue-500 text-white border-blue-400' : 'bg-black hover:bg-black/80 text-white border-gray-800'} active:scale-95`}>
                                    <FolderTree size={20} /> Bulk Folder Upload
                                    <input
                                        type="file"
                                        // @ts-ignore
                                        webkitdirectory=""
                                        // @ts-ignore
                                        directory=""
                                        multiple
                                        className="hidden"
                                        onChange={handleBulkFolderUpload}
                                    />
                                </label>
                            </div>

                            <div className="space-y-6">
                                {/* Configuration */}
                                <div className={`p-6 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <h3 className={`font-semibold mb-4 flex items-center gap-2 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                        <Settings size={18} /> Default Configuration
                                    </h3>
                                    <div className="grid grid-cols-2 gap-4 mb-4">
                                        <div>
                                            <label className={`block text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Office / Org</label>
                                            <input
                                                type="text"
                                                value={poamConfig.officeOrg}
                                                onChange={e => setPoamConfig({ ...poamConfig, officeOrg: e.target.value })}
                                                className={`w-full bg-transparent border rounded-lg px-3 py-2 text-sm ${darkMode ? 'border-gray-600 text-gray-200 focus:border-blue-500' : 'border-gray-300 text-gray-900 focus:border-blue-500'} focus:ring-0 outline-none transition-colors`}
                                            />
                                        </div>
                                        <div>
                                            <label className={`block text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Resources Required</label>
                                            <input
                                                type="text"
                                                value={poamConfig.resourcesRequired}
                                                onChange={e => setPoamConfig({ ...poamConfig, resourcesRequired: e.target.value })}
                                                className={`w-full bg-transparent border rounded-lg px-3 py-2 text-sm ${darkMode ? 'border-gray-600 text-gray-200 focus:border-blue-500' : 'border-gray-300 text-gray-900 focus:border-blue-500'} focus:ring-0 outline-none transition-colors`}
                                            />
                                        </div>
                                        <div>
                                            <label className={`block text-xs font-medium mb-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Default Status</label>
                                            <input
                                                type="text"
                                                value={poamConfig.status}
                                                onChange={e => setPoamConfig({ ...poamConfig, status: e.target.value })}
                                                className={`w-full bg-transparent border rounded-lg px-3 py-2 text-sm ${darkMode ? 'border-gray-600 text-gray-200 focus:border-blue-500' : 'border-gray-300 text-gray-900 focus:border-blue-500'} focus:ring-0 outline-none transition-colors`}
                                            />
                                        </div>
                                    </div>

                                    <div className="space-y-4">
                                        <div className="flex items-center justify-between border-b border-gray-100 dark:border-gray-700 pb-1">
                                            <label className={`block text-xs font-bold uppercase tracking-wider ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Milestone Templates</label>
                                            <div className="flex bg-gray-100 dark:bg-gray-700 p-0.5 rounded-lg">
                                                {(['cat1', 'cat2', 'cat3'] as const).map(cat => (
                                                    <button
                                                        key={cat}
                                                        onClick={() => setPoamActiveCat(cat)}
                                                        className={`px-3 py-1 rounded-md text-[10px] font-bold uppercase transition-all ${poamActiveCat === cat ? 'bg-white dark:bg-gray-600 text-blue-600 shadow-sm' : 'text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'}`}
                                                    >
                                                        {cat === 'cat1' ? 'CAT I' : cat === 'cat2' ? 'CAT II' : 'CAT III'}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>

                                        <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
                                            {poamConfig.milestones[poamActiveCat].map((m, idx) => (
                                                <div key={m.id} className="flex gap-2 items-start group">
                                                    <div className={`shrink-0 w-8 h-8 rounded-full flex flex-col items-center justify-center border ${darkMode ? 'border-gray-600 bg-gray-700/50 text-gray-300' : 'border-gray-200 bg-gray-50 text-gray-600'}`}>
                                                        <span className="text-[10px] font-bold">{m.id}</span>
                                                        <span className="text-[8px] opacity-70">
                                                            {m.id === 1 ? 'Day 0' : m.id === 2 ? '+14' : m.id === 3 ? '+21' : poamActiveCat === 'cat1' ? '+30' : poamActiveCat === 'cat2' ? '+60' : '+90'}
                                                        </span>
                                                    </div>
                                                    <textarea
                                                        value={m.text}
                                                        onChange={e => {
                                                            setPoamConfig(prev => ({
                                                                ...prev,
                                                                milestones: {
                                                                    ...prev.milestones,
                                                                    [poamActiveCat]: prev.milestones[poamActiveCat].map((m2, i) => i === idx ? { ...m2, text: e.target.value } : m2)
                                                                }
                                                            }));
                                                        }}
                                                        rows={2}
                                                        className={`flex-1 bg-transparent border rounded-lg px-3 py-2 text-xs leading-relaxed ${darkMode ? 'border-gray-600 text-gray-200 focus:border-blue-500' : 'border-gray-300 text-gray-900 focus:border-blue-500'} focus:ring-0 outline-none transition-all resize-none hover:border-gray-400 dark:hover:border-gray-500`}
                                                    />
                                                    <div className="flex flex-col gap-1 w-28 shrink-0">
                                                        <div className="relative group/date">
                                                            <input
                                                                type="date"
                                                                value={m.date || ""}
                                                                onChange={e => {
                                                                    setPoamConfig(prev => ({
                                                                        ...prev,
                                                                        milestones: {
                                                                            ...prev.milestones,
                                                                            [poamActiveCat]: prev.milestones[poamActiveCat].map((m2, i) => i === idx ? { ...m2, date: e.target.value } : m2)
                                                                        }
                                                                    }));
                                                                }}
                                                                className={`w-full bg-transparent border rounded-lg pl-2 pr-1 py-1 text-[10px] font-medium appearance-none ${darkMode ? 'border-gray-600 text-gray-300 hover:border-gray-500' : 'border-gray-300 text-gray-600 hover:border-gray-400'} focus:outline-none focus:border-blue-500 transition-colors`}
                                                            />
                                                            {m.date ? (
                                                                <button
                                                                    onClick={() => {
                                                                        setPoamConfig(prev => ({
                                                                            ...prev,
                                                                            milestones: {
                                                                                ...prev.milestones,
                                                                                [poamActiveCat]: prev.milestones[poamActiveCat].map((m2, i) => i === idx ? { ...m2, date: "" } : m2)
                                                                            }
                                                                        }));
                                                                    }}
                                                                    className="absolute right-1 top-1/2 -translate-y-1/2 p-0.5 hover:bg-red-50 hover:text-red-500 rounded transition-colors text-gray-400"
                                                                    title="Clear fixed date"
                                                                >
                                                                    <X size={10} />
                                                                </button>
                                                            ) : (
                                                                <Calendar className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 size-3 opacity-40" />
                                                            )}
                                                        </div>
                                                        <div className={`text-[8px] text-center font-bold uppercase tracking-tighter ${m.date ? 'text-blue-500' : darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                            {m.date ? 'Fixed Date' : 'Auto-Calc'}
                                                        </div>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 w-full">
                                    {/* STIG Upload */}
                                    <div className={`p-6 rounded-2xl border-2 border-dashed relative text-center flex flex-col items-center justify-center min-h-[250px] ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                        <FileSpreadsheet className={`size-12 mb-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                                        <h3 className={`font-medium mb-1 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>STIG Checklists</h3>
                                        {poamChecklists.length > 0 ? (
                                            <div className="w-full">
                                                <div className="text-2xl font-bold text-green-600 mb-2">{poamChecklists.length} Loaded</div>
                                                <button onClick={() => setPoamChecklists([])} className="text-xs text-red-500 hover:text-red-600 underline">Clear</button>
                                            </div>
                                        ) : (
                                            <p className={`text-xs mb-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Upload .ckl/.cklb files</p>
                                        )}
                                        <label className={`mt-4 cursor-pointer px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}>
                                            <Upload size={14} /> {poamChecklists.length > 0 ? 'Add More' : 'Upload STIGs'}
                                            <input type="file" multiple className="hidden" accept=".ckl,.cklb,.json,.xml" onChange={handlePoamUpload} />
                                        </label>
                                    </div>

                                    {/* ACAS Upload */}
                                    <div className={`p-6 rounded-2xl border-2 border-dashed relative text-center flex flex-col items-center justify-center min-h-[250px] ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                        <Database className={`size-12 mb-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                                        <h3 className={`font-medium mb-1 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>ACAS Scans</h3>
                                        {acasData.length > 0 ? (
                                            <div className="w-full">
                                                <div className="text-2xl font-bold text-blue-600 mb-2">{acasData.length} Rows</div>
                                                <button onClick={() => setAcasData([])} className="text-xs text-red-500 hover:text-red-600 underline">Clear</button>
                                            </div>
                                        ) : (
                                            <p className={`text-xs mb-4 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Upload .csv scan results</p>
                                        )}
                                        <label className={`mt-4 cursor-pointer px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}>
                                            <Upload size={14} /> {acasData.length > 0 ? 'Add More' : 'Upload CSV'}
                                            <input type="file" multiple className="hidden" accept=".csv" onChange={handleAcasUpload} />
                                        </label>
                                    </div>
                                </div>

                                {(poamChecklists.length > 0 || acasData.length > 0) && (
                                    <div className="flex justify-center pt-4">
                                        <button
                                            onClick={generatePoamProject}
                                            className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-full font-bold shadow-lg flex items-center gap-3 transition-transform active:scale-95"
                                        >
                                            <Download size={20} /> Generate Project POA&M
                                        </button>
                                    </div>
                                )}
                            </div>

                            <div className={`p-6 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-blue-50 border-blue-100'}`}>
                                <h4 className={`font-medium mb-2 flex items-center gap-2 ${darkMode ? 'text-blue-400' : 'text-blue-800'}`}>
                                    <Info size={18} /> How it works
                                </h4>
                                <ul className={`list-disc list-inside text-sm space-y-1 ${darkMode ? 'text-gray-400' : 'text-blue-700'}`}>
                                    <li>Reads all <strong>Open</strong> findings from your checklist.</li>
                                    <li>Maps STIG Severity to standard CAT I/II/III levels.</li>
                                    <li>Auto-calculates milestone dates (Today, +14d, +21d) and scheduled completion (+30/60/90d).</li>
                                    <li>Populates standard POA&M columns including CCIs, descriptions, and comments.</li>
                                    <li>Outputs a formatted Excel file ready for submission or review.</li>
                                </ul>
                            </div>
                        </div>
                    ) : activeTab === 'controls' ? (
                        <div className="space-y-8 max-w-6xl mx-auto h-full flex flex-col">
                            {/* Controls Header */}
                            <div>
                                <h2 className={`text-2xl font-bold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Security Controls</h2>
                                <p className={darkMode ? 'text-gray-400' : 'text-gray-600'}>
                                    Map your STIG results to NIST SP 800-53 controls (Rev 4 & 5).
                                </p>
                            </div>

                            {/* Upload Section: Checklist Only */}
                            <div className={`p-10 rounded-2xl border-2 border-dashed relative text-center flex flex-col items-center justify-center min-h-[250px] ${darkMode ? 'border-gray-600 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                <FolderOpen className={`size-16 mb-4 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                                <h3 className={`font-semibold text-xl mb-2 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>Upload Checklists</h3>
                                <p className={`max-w-md mx-auto text-sm mb-6 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                    Upload your .ckl files to automatically map results to NIST SP 800-53 controls.
                                </p>

                                {uploadedChecklists.length > 0 && (
                                    <div className="mb-6 w-full max-w-md">
                                        <div className="flex items-center justify-between bg-green-50 px-4 py-3 rounded-lg border border-green-100">
                                            <div className="flex items-center gap-3">
                                                <div className="size-8 rounded-full bg-green-100 flex items-center justify-center text-green-600">
                                                    <Check size={16} strokeWidth={3} />
                                                </div>
                                                <div className="text-left">
                                                    <div className="font-semibold text-green-800">{uploadedChecklists.length} Files Loaded</div>
                                                    <div className="text-xs text-green-600">{uploadedChecklists.reduce((acc, c) => acc + c.findings.length, 0)} Total Findings</div>
                                                </div>
                                            </div>
                                            <button onClick={() => setUploadedChecklists([])} className="p-2 hover:bg-green-100 rounded-full text-green-700 transition-colors">
                                                <Trash2 size={16} />
                                            </button>
                                        </div>
                                    </div>
                                )}

                                <div className="flex gap-3 justify-center">
                                    <label className={`cursor-pointer px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2 shadow-sm ${darkMode ? 'bg-blue-600 hover:bg-blue-700 text-white' : 'bg-black hover:bg-gray-800 text-white'}`}>
                                        <Upload size={18} /> Upload Files
                                        <input type="file" multiple className="hidden" accept=".ckl,.cklb,.xml,.json" onChange={async (e) => {
                                            if (e.target.files) {
                                                const files = Array.from(e.target.files);
                                                for (const file of files) {
                                                    const parsed = await parseCklFile(file);
                                                    if (parsed) setUploadedChecklists(prev => [...prev, parsed]);
                                                }
                                            }
                                        }} />
                                    </label>
                                    <label className={`cursor-pointer px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2 ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}>
                                        <FolderTree size={18} /> Upload Folder
                                        <input
                                            type="file"
                                            // @ts-ignore
                                            webkitdirectory=""
                                            // @ts-ignore
                                            directory=""
                                            multiple
                                            className="hidden"
                                            onChange={handleBulkFolderUpload}
                                        />
                                    </label>
                                </div>
                            </div>

                            {/* Revision Toggle Removed - Single Standard */}
                            <div className="flex justify-center mb-6 items-center gap-4">
                                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${darkMode ? 'bg-blue-900/30 border-blue-800 text-blue-300' : 'bg-blue-50 border-blue-100 text-blue-600'}`}>
                                    Mapped to NIST SP 800-53
                                </span>
                                <div className="flex gap-2">
                                    <button
                                        onClick={() => {
                                            const header = ['Control', 'Associated CCIs', 'Group IDs', 'Open Findings', 'Status'];
                                            const rows = controlsData.map(row => [
                                                row.control,
                                                Array.from(row.ccis).join('; '),
                                                Array.from(row.groupIds || []).join('; '),
                                                row.openCount.toString(),
                                                row.status
                                            ]);

                                            // Create CSV content
                                            const csvContent = [
                                                header.join(','),
                                                ...rows.map(r => r.map(c => `"${c}"`).join(',')) // Quote fields
                                            ].join('\n');

                                            // Download File
                                            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                                            const link = document.createElement('a');
                                            if (link.download !== undefined) {
                                                const url = URL.createObjectURL(blob);
                                                link.setAttribute('href', url);
                                                link.setAttribute('download', `controls_export_${new Date().toISOString().split('T')[0]}.csv`);
                                                link.style.visibility = 'hidden';
                                                document.body.appendChild(link);
                                                link.click();
                                                document.body.removeChild(link);
                                            }
                                        }}
                                        className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}
                                    >
                                        <FileSpreadsheet size={14} /> Export CSV
                                    </button>
                                    <button
                                        onClick={async () => {
                                            const element = document.getElementById('controls-grid');
                                            if (!element) return;

                                            try {
                                                // Clone to capture full height even if scrolled
                                                const clone = element.cloneNode(true) as HTMLElement;

                                                // Force full height and remove scroll on clone
                                                clone.style.height = 'auto';
                                                clone.style.maxHeight = 'none';
                                                clone.style.overflow = 'visible';
                                                clone.style.position = 'absolute';
                                                clone.style.top = '-9999px';
                                                clone.style.left = '0';
                                                clone.style.width = `${element.offsetWidth}px`; // Maintain width
                                                clone.style.background = darkMode ? '#1f2937' : '#ffffff'; // Ensure background matches

                                                document.body.appendChild(clone);

                                                const canvas = await html2canvas(clone, {
                                                    backgroundColor: darkMode ? '#1f2937' : '#ffffff',
                                                    windowHeight: clone.scrollHeight,
                                                    height: clone.scrollHeight
                                                });

                                                document.body.removeChild(clone);

                                                canvas.toBlob(blob => {
                                                    if (blob) {
                                                        navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
                                                        alert('Full table image copied to clipboard!');
                                                    }
                                                });
                                            } catch (e) {
                                                console.error('Copy image failed', e);
                                                alert('Failed to copy image.');
                                            }
                                        }}
                                        className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold transition-all ${darkMode ? 'bg-gray-700 hover:bg-gray-600 text-white' : 'bg-white border border-gray-200 hover:bg-gray-50 text-gray-700'}`}
                                    >
                                        <ImageIcon size={14} /> Copy Image
                                    </button>
                                </div>
                            </div>

                            {/* Summary Cards */}
                            <div className="grid grid-cols-4 gap-4">
                                <div className={`p-4 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}>
                                    <div className="text-gray-500 text-xs font-medium uppercase mb-1">Total Controls</div>
                                    <div className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{controlsStats.total}</div>
                                </div>
                                <div className={`p-4 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}>
                                    <div className="text-green-500 text-xs font-medium uppercase mb-1">Compliant</div>
                                    <div className="text-2xl font-bold text-green-600">{controlsStats.passed}</div>
                                </div>
                                <div className={`p-4 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}>
                                    <div className="text-red-500 text-xs font-medium uppercase mb-1">Non-Compliant</div>
                                    <div className="text-2xl font-bold text-red-600">{controlsStats.failed}</div>
                                </div>
                                <div className={`p-4 rounded-xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-100'}`}>
                                    <div className="text-gray-400 text-xs font-medium uppercase mb-1">No Data</div>
                                    <div className="text-2xl font-bold text-gray-400">{controlsStats.noData}</div>
                                </div>
                            </div>

                            {/* Controls Grid */}
                            <div id="controls-grid" className={`rounded-xl border overflow-hidden flex flex-col ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`} style={{ maxHeight: '600px' }}>
                                <div className={`grid grid-cols-12 gap-4 p-4 border-b font-semibold text-xs uppercase tracking-wider ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-400' : 'bg-gray-50 border-gray-100 text-gray-500'}`}>
                                    <div className="col-span-2">Control</div>
                                    <div className="col-span-4">Associated CCIs</div>
                                    <div className="col-span-2">Group IDs</div>
                                    <div className="col-span-2 text-center">Open Findings</div>
                                    <div className="col-span-2 text-center">Status</div>
                                </div>
                                <div className="overflow-y-auto flex-1">
                                    {controlsData.map((row, idx) => (
                                        <div key={idx} className={`grid grid-cols-12 gap-4 p-4 border-b last:border-0 text-sm items-center hover:bg-gray-50/5 ${darkMode ? 'border-gray-700 text-gray-300' : 'border-gray-100 text-gray-700'}`}>
                                            <div className="col-span-2 font-mono font-medium">{row.control}</div>
                                            <div className="col-span-4">
                                                <div className="flex flex-wrap gap-1">
                                                    {row.ccis.map(((cci: string) => (
                                                        <span key={cci} className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${darkMode ? 'bg-gray-700 text-gray-400' : 'bg-gray-100 text-gray-500'}`}>
                                                            {cci}
                                                        </span>
                                                    )))}
                                                </div>
                                            </div>
                                            <div className="col-span-2">
                                                <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto custom-scrollbar">
                                                    {(row.groupIds as string[] || []).map((gid) => (
                                                        <span key={gid} className={`text-[10px] px-1.5 py-0.5 rounded font-mono border ${darkMode ? 'bg-blue-900/20 border-blue-900 text-blue-300' : 'bg-blue-50 border-blue-100 text-blue-600'}`}>
                                                            {gid}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                            <div className="col-span-2 text-center font-mono">
                                                {row.openCount > 0 ? (
                                                    <span className="text-red-500 font-bold">{row.openCount}</span>
                                                ) : (
                                                    <span className="text-gray-400">-</span>
                                                )}
                                            </div>
                                            <div className="col-span-2 text-center">
                                                <span className={`px-2 py-1 rounded text-xs font-semibold uppercase ${row.status === 'Fail' ? 'bg-red-100 text-red-600' :
                                                    row.status === 'Pass' ? 'bg-green-100 text-green-600' :
                                                        'bg-gray-100 text-gray-500'
                                                    }`}>
                                                    {row.status}
                                                </span>
                                            </div>
                                        </div>
                                    ))}
                                    {controlsData.length === 0 && (
                                        <div className="p-10 text-center text-gray-400">
                                            No controls mapped yet. Upload a checklist to see results.
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : activeTab === 'tools' ? (
                        <div className="space-y-6">
                            <h1 className="text-3xl font-semibold tracking-tight mb-8">Tools & Utilities</h1>

                            <div className={`grid gap-6 ${toolsMode === 'analyzer' ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-4'}`}>
                                {/* Tools Sidebar/Menu */}
                                {toolsMode !== 'analyzer' && (
                                    <div className="space-y-2">
                                        <button
                                            onClick={() => setToolsMode('rename')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${toolsMode === 'rename'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <Save size={18} />
                                            <div className="font-medium">Save As (Bulk Rename)</div>
                                        </button>
                                        <button
                                            onClick={() => setToolsMode('heatmap')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${toolsMode === 'heatmap'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <Target size={18} />
                                            <div className="font-medium">Risk Heatmap</div>
                                        </button>
                                        <button
                                            onClick={() => setToolsMode('analyzer')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600'}`}
                                        >
                                            <GitCompare size={18} />
                                            <div className="font-medium">STIG Analyzer</div>
                                        </button>
                                    </div>
                                )}

                                {/* Tool Content */}
                                <div className={toolsMode === 'analyzer' ? '' : 'md:col-span-3'}>
                                    {toolsMode === 'rename' && (
                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <div className="p-3 bg-blue-100 text-blue-600 rounded-xl">
                                                    <Save size={24} />
                                                </div>
                                                <div>
                                                    <h2 className="text-xl font-semibold">Bulk File Renamer</h2>
                                                    <p className="text-sm text-gray-500">Add prefixes or suffixes to multiple files instantly.</p>
                                                </div>
                                            </div>

                                            <div className="w-full relative group cursor-pointer mb-8">
                                                <div className={`absolute inset-0 rounded-xl bg-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity border-2 border-dashed border-blue-500/50`} />
                                                <div className={`relative z-10 p-10 rounded-xl border-2 border-dashed text-center transition-colors ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                                    <div className="size-16 mx-auto bg-blue-50 text-blue-600 rounded-2xl flex items-center justify-center mb-4 shadow-sm">
                                                        <FolderOpen size={30} />
                                                    </div>
                                                    <h3 className="text-lg font-medium mb-1">Drag files or folder here</h3>
                                                    <p className="text-sm text-gray-500 mb-4">Supports uploading folders directly</p>
                                                    <label className="inline-block relative">
                                                        <span className="bg-black hover:bg-gray-800 text-white px-6 py-2.5 rounded-full text-sm font-medium transition-all shadow-lg active:scale-95 cursor-pointer">
                                                            Browse Files
                                                        </span>
                                                        <input
                                                            type="file"
                                                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                                                            multiple
                                                            // @ts-ignore
                                                            webkitdirectory=""
                                                            directory=""
                                                            onChange={handleFileUpload}
                                                        />
                                                    </label>
                                                </div>
                                            </div>

                                            {renameFiles.length > 0 && (
                                                <div className="space-y-6">
                                                    <div className="grid grid-cols-2 gap-4">
                                                        <div>
                                                            <label className="block text-xs font-semibold uppercase text-gray-500 mb-1.5">Add to Start (Prefix)</label>
                                                            <div className="relative">
                                                                <input
                                                                    type="text"
                                                                    value={renamePrefix}
                                                                    onChange={e => setRenamePrefix(e.target.value)}
                                                                    placeholder="e.g. 2024_"
                                                                    className={`w-full px-4 py-2.5 rounded-xl border outline-none transition-all ${darkMode ? 'bg-gray-900 border-gray-700 focus:border-blue-500' : 'bg-white border-gray-200 focus:border-blue-500'}`}
                                                                />
                                                            </div>
                                                        </div>
                                                        <div>
                                                            <label className="block text-xs font-semibold uppercase text-gray-500 mb-1.5">Add to End (Suffix)</label>
                                                            <div className="relative">
                                                                <input
                                                                    type="text"
                                                                    value={renameSuffix}
                                                                    onChange={e => setRenameSuffix(e.target.value)}
                                                                    placeholder="e.g. _reviewed"
                                                                    className={`w-full px-4 py-2.5 rounded-xl border outline-none transition-all ${darkMode ? 'bg-gray-900 border-gray-700 focus:border-blue-500' : 'bg-white border-gray-200 focus:border-blue-500'}`}
                                                                />
                                                            </div>
                                                        </div>
                                                    </div>

                                                    <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                        <div className={`px-4 py-2 border-b text-xs font-semibold uppercase flex justify-between ${darkMode ? 'bg-gray-800 border-gray-700 text-gray-400' : 'bg-gray-50 border-gray-100 text-gray-500'}`}>
                                                            <span>Original Name</span>
                                                            <span>New Name Preview</span>
                                                        </div>
                                                        <div className="max-h-60 overflow-y-auto divide-y dark:divide-gray-800">
                                                            {renameFiles.map((file, idx) => (
                                                                <div key={idx} className="px-4 py-2.5 flex items-center justify-between text-sm">
                                                                    <span className={darkMode ? 'text-gray-400' : 'text-gray-600'}>{file.originalName}</span>
                                                                    <ArrowRight size={14} className="text-gray-300" />
                                                                    <span className={`font-mono font-medium ${darkMode ? 'text-green-400' : 'text-green-600'}`}>{file.newName}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>

                                                    <div className="flex justify-end pt-4 border-t border-gray-100 dark:border-gray-700">
                                                        <button
                                                            onClick={executeRenameDownload}
                                                            className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-full font-bold shadow-lg shadow-green-600/20 active:scale-95 transition-all flex items-center gap-2"
                                                        >
                                                            <Download size={20} />
                                                            Download All ({renameFiles.length})
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {toolsMode === 'heatmap' && (
                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <div className="p-3 bg-red-100 text-red-600 rounded-xl">
                                                    <Target size={24} />
                                                </div>
                                                <div>
                                                    <h2 className="text-xl font-semibold">Risk Heatmap</h2>
                                                    <p className="text-sm text-gray-500">Visualize compliance risk by NIST control family.</p>
                                                </div>
                                            </div>

                                            {/* Upload Zone */}
                                            <div className="w-full relative group cursor-pointer mb-8">
                                                <div className={`absolute inset-0 rounded-xl bg-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity border-2 border-dashed border-red-500/50`} />
                                                <div className={`relative z-10 p-8 rounded-xl border-2 border-dashed text-center transition-colors ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                                    <div className="size-14 mx-auto bg-red-50 text-red-600 rounded-2xl flex items-center justify-center mb-3 shadow-sm">
                                                        <Upload size={26} />
                                                    </div>
                                                    <h3 className="text-base font-medium mb-1">Upload Checklists for Analysis</h3>
                                                    <p className="text-sm text-gray-500 mb-3">{heatmapChecklists.length} checklist(s) loaded</p>
                                                    <label className="inline-block relative">
                                                        <span className="bg-red-600 hover:bg-red-700 text-white px-5 py-2 rounded-full text-sm font-medium transition-all shadow-lg active:scale-95 cursor-pointer">
                                                            Choose Files
                                                        </span>
                                                        <input
                                                            type="file"
                                                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                                                            multiple
                                                            accept=".ckl,.cklb,.json,.xml"
                                                            // @ts-ignore
                                                            webkitdirectory=""
                                                            directory=""
                                                            onChange={async (e) => {
                                                                const files = e.target.files;
                                                                if (!files) return;
                                                                const newChecklists: typeof heatmapChecklists = [];
                                                                for (const file of Array.from(files)) {
                                                                    const name = file.name.toLowerCase();
                                                                    if (name.endsWith('.ckl') || name.endsWith('.cklb') || name.endsWith('.json') || name.endsWith('.xml')) {
                                                                        const parsed = await parseCklFile(file);
                                                                        if (parsed) newChecklists.push(parsed as any);
                                                                    }
                                                                }
                                                                setHeatmapChecklists(prev => [...prev, ...newChecklists]);
                                                                e.target.value = '';
                                                            }}
                                                        />
                                                    </label>
                                                    {heatmapChecklists.length > 0 && (
                                                        <button
                                                            onClick={() => setHeatmapChecklists([])}
                                                            className="ml-3 text-sm text-gray-500 hover:text-red-500"
                                                        >
                                                            Clear All
                                                        </button>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Visual Heatmap Grid */}
                                            {heatmapData.length > 0 ? (
                                                <div className="space-y-6">
                                                    {/* Legend */}
                                                    <div className="flex items-center justify-center gap-6 text-xs">
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-4 h-4 rounded bg-green-500" />
                                                            <span className="text-gray-500">0 Open</span>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-4 h-4 rounded bg-yellow-400" />
                                                            <span className="text-gray-500">Low Risk</span>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-4 h-4 rounded bg-orange-500" />
                                                            <span className="text-gray-500">Medium Risk</span>
                                                        </div>
                                                        <div className="flex items-center gap-2">
                                                            <div className="w-4 h-4 rounded bg-red-600" />
                                                            <span className="text-gray-500">High Risk</span>
                                                        </div>
                                                    </div>

                                                    {/* Heatmap Grid */}
                                                    <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                        {/* Header */}
                                                        <div className={`grid gap-1 p-2 ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`} style={{ gridTemplateColumns: '100px repeat(3, 1fr)' }}>
                                                            <div className="text-xs font-semibold uppercase text-gray-500 pl-2">Family</div>
                                                            <div className="text-xs font-semibold uppercase text-center text-red-500">CAT I</div>
                                                            <div className="text-xs font-semibold uppercase text-center text-orange-500">CAT II</div>
                                                            <div className="text-xs font-semibold uppercase text-center text-blue-500">CAT III</div>
                                                        </div>

                                                        {/* Heatmap Rows */}
                                                        <div className="p-2 space-y-1">
                                                            {heatmapData.map((row, idx) => {
                                                                const getHeatCellStyle = (open: number, total: number) => {
                                                                    if (total === 0) return { bg: 'bg-gray-100', text: 'text-gray-400' };
                                                                    const pct = total > 0 ? open / total : 0;
                                                                    if (open === 0) return { bg: 'bg-green-500', text: 'text-white' };
                                                                    if (pct < 0.25) return { bg: 'bg-yellow-400', text: 'text-yellow-900' };
                                                                    if (pct < 0.5) return { bg: 'bg-orange-500', text: 'text-white' };
                                                                    return { bg: 'bg-red-600', text: 'text-white' };
                                                                };

                                                                const cat1Style = getHeatCellStyle(row.cat1.open, row.cat1.open + row.cat1.naf + row.cat1.nr);
                                                                const cat2Style = getHeatCellStyle(row.cat2.open, row.cat2.open + row.cat2.naf + row.cat2.nr);
                                                                const cat3Style = getHeatCellStyle(row.cat3.open, row.cat3.open + row.cat3.naf + row.cat3.nr);

                                                                return (
                                                                    <div key={idx} className="grid gap-1" style={{ gridTemplateColumns: '100px repeat(3, 1fr)' }}>
                                                                        <div className={`flex items-center pl-2 py-3 text-sm font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                                            {row.family}
                                                                        </div>
                                                                        <div className={`${cat1Style.bg} ${cat1Style.text} rounded-lg py-4 text-center font-bold text-lg transition-all hover:scale-105 cursor-default shadow-sm`} title={`${row.cat1.open} Open / ${row.cat1.naf} NAF / ${row.cat1.nr} NR`}>
                                                                            {row.cat1.open}
                                                                        </div>
                                                                        <div className={`${cat2Style.bg} ${cat2Style.text} rounded-lg py-4 text-center font-bold text-lg transition-all hover:scale-105 cursor-default shadow-sm`} title={`${row.cat2.open} Open / ${row.cat2.naf} NAF / ${row.cat2.nr} NR`}>
                                                                            {row.cat2.open}
                                                                        </div>
                                                                        <div className={`${cat3Style.bg} ${cat3Style.text} rounded-lg py-4 text-center font-bold text-lg transition-all hover:scale-105 cursor-default shadow-sm`} title={`${row.cat3.open} Open / ${row.cat3.naf} NAF / ${row.cat3.nr} NR`}>
                                                                            {row.cat3.open}
                                                                        </div>
                                                                    </div>
                                                                );
                                                            })}
                                                        </div>
                                                    </div>

                                                    {/* Summary Stats */}
                                                    <div className="grid grid-cols-4 gap-4">
                                                        <div className={`p-4 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-gray-50'}`}>
                                                            <div className="text-2xl font-bold text-gray-900 dark:text-white">{heatmapData.length}</div>
                                                            <div className="text-xs text-gray-500 uppercase">Control Families</div>
                                                        </div>
                                                        <div className={`p-4 rounded-xl text-center bg-red-50`}>
                                                            <div className="text-2xl font-bold text-red-600">{heatmapData.reduce((acc, r) => acc + r.cat1.open, 0)}</div>
                                                            <div className="text-xs text-red-500 uppercase">CAT I Open</div>
                                                        </div>
                                                        <div className={`p-4 rounded-xl text-center bg-orange-50`}>
                                                            <div className="text-2xl font-bold text-orange-600">{heatmapData.reduce((acc, r) => acc + r.cat2.open, 0)}</div>
                                                            <div className="text-xs text-orange-500 uppercase">CAT II Open</div>
                                                        </div>
                                                        <div className={`p-4 rounded-xl text-center bg-blue-50`}>
                                                            <div className="text-2xl font-bold text-blue-600">{heatmapData.reduce((acc, r) => acc + r.cat3.open, 0)}</div>
                                                            <div className="text-xs text-blue-500 uppercase">CAT III Open</div>
                                                        </div>
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className="p-10 text-center text-gray-400 border-2 border-dashed rounded-xl">
                                                    Upload checklists to generate the risk heatmap.
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* STIG Analyzer Panel */}
                                    {toolsMode === 'analyzer' && (
                                        <div id="analyzer-panel-content" className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <button
                                                    onClick={() => setToolsMode('rename')}
                                                    className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-600'}`}
                                                    title="Back to Tools"
                                                >
                                                    <ChevronLeft size={20} />
                                                </button>
                                                <div className="p-3 bg-purple-100 text-purple-600 rounded-xl">
                                                    <GitCompare size={24} />
                                                </div>
                                                <div className="flex-1">
                                                    <h2 className="text-xl font-semibold">STIG Version Analyzer</h2>
                                                    <p className="text-sm text-gray-500">Compare old and new STIG checklists to migrate statuses and comments.</p>
                                                </div>
                                            </div>

                                            {/* Dual Upload Zone */}
                                            <div className="grid grid-cols-2 gap-4 mb-6">
                                                {/* Old STIG */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${analyzerOldChecklist ? 'border-green-500 bg-green-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">Old STIG (Source)</div>
                                                    {analyzerOldChecklist ? (
                                                        <div>
                                                            <div className="text-sm font-medium truncate">{analyzerOldChecklist.filename}</div>
                                                            <div className="text-xs text-gray-500">{analyzerOldChecklist.findings.length} findings</div>
                                                            <button onClick={() => setAnalyzerOldChecklist(null)} className="text-xs text-red-500 hover:underline mt-1">Remove</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-10 mx-auto bg-gray-100 text-gray-400 rounded-xl flex items-center justify-center mb-2">
                                                                <Upload size={20} />
                                                            </div>
                                                            <span className="text-sm text-gray-500">Upload old checklist</span>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".ckl,.cklb,.json,.xml"
                                                                onChange={async (e) => {
                                                                    const file = e.target.files?.[0];
                                                                    if (file) {
                                                                        const parsed = await parseCklFile(file);
                                                                        if (parsed) setAnalyzerOldChecklist(parsed as any);
                                                                    }
                                                                    e.target.value = '';
                                                                }}
                                                            />
                                                        </label>
                                                    )}
                                                </div>

                                                {/* New STIG */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${analyzerNewChecklist ? 'border-blue-500 bg-blue-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">New STIG (Target)</div>
                                                    {analyzerNewChecklist ? (
                                                        <div>
                                                            <div className="text-sm font-medium truncate">{analyzerNewChecklist.filename}</div>
                                                            <div className="text-xs text-gray-500">{analyzerNewChecklist.findings.length} findings</div>
                                                            <button onClick={() => setAnalyzerNewChecklist(null)} className="text-xs text-red-500 hover:underline mt-1">Remove</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-10 mx-auto bg-gray-100 text-gray-400 rounded-xl flex items-center justify-center mb-2">
                                                                <Upload size={20} />
                                                            </div>
                                                            <span className="text-sm text-gray-500">Upload new checklist</span>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".ckl,.cklb,.json,.xml"
                                                                onChange={async (e) => {
                                                                    const file = e.target.files?.[0];
                                                                    if (file) {
                                                                        const parsed = await parseCklFile(file);
                                                                        if (parsed) setAnalyzerNewChecklist(parsed as any);
                                                                    }
                                                                    e.target.value = '';
                                                                }}
                                                            />
                                                        </label>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Tabs */}
                                            {analyzerOldChecklist && analyzerNewChecklist && (
                                                <>
                                                    <div className="flex gap-2 mb-4">
                                                        <button
                                                            onClick={() => { setAnalyzerTab('notreviewed'); setAnalyzerSelectedIds(new Set()); }}
                                                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${analyzerTab === 'notreviewed'
                                                                ? 'bg-purple-600 text-white'
                                                                : (darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600')}`}
                                                        >
                                                            Not Reviewed ({analyzerData.notReviewed.length})
                                                        </button>
                                                        <button
                                                            onClick={() => { setAnalyzerTab('newids'); setAnalyzerSelectedIds(new Set()); }}
                                                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${analyzerTab === 'newids'
                                                                ? 'bg-green-600 text-white'
                                                                : (darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600')}`}
                                                        >
                                                            New IDs ({analyzerData.newIds.length})
                                                        </button>
                                                        <button
                                                            onClick={() => { setAnalyzerTab('droppedids'); setAnalyzerSelectedIds(new Set()); }}
                                                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${analyzerTab === 'droppedids'
                                                                ? 'bg-red-600 text-white'
                                                                : (darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600')}`}
                                                        >
                                                            Dropped IDs ({analyzerData.droppedIds.length})
                                                        </button>
                                                        <button
                                                            onClick={() => { setAnalyzerTab('reviewed'); setAnalyzerSelectedIds(new Set()); }}
                                                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${analyzerTab === 'reviewed'
                                                                ? 'bg-blue-600 text-white'
                                                                : (darkMode ? 'bg-gray-700 text-gray-300' : 'bg-gray-100 text-gray-600')}`}
                                                        >
                                                            Reviewed ({analyzerShowAllReviewed ? analyzerNewChecklist?.findings.filter(f => f.status !== 'Not_Reviewed').length : analyzerEditedIds.size})
                                                        </button>

                                                        {/* Report Controls (Image, Excel, CKLB) */}
                                                        <div className="ml-auto flex gap-2">
                                                            {(() => {
                                                                const handleExportExcel = () => {
                                                                    if (!analyzerData) return;
                                                                    const wb = XLSX.utils.book_new();

                                                                    // 1. Summary
                                                                    const summaryData = [
                                                                        { Metric: 'Total Old Findings', Value: analyzerData.totalOld },
                                                                        { Metric: 'Total New Findings', Value: analyzerData.totalNew },
                                                                        { Metric: 'Not Reviewed', Value: analyzerData.notReviewed.length },
                                                                        { Metric: 'New IDs', Value: analyzerData.newIds.length },
                                                                        { Metric: 'Dropped IDs', Value: analyzerData.droppedIds.length },
                                                                        { Metric: 'Reviewed (Edited)', Value: analyzerEditedIds.size },
                                                                    ];
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summaryData), "Summary");

                                                                    // 2. Not Reviewed
                                                                    const notReviewedData = analyzerData.notReviewed.map(r => ({
                                                                        GroupID: r.vulnId,
                                                                        Severity: r.oldFinding.severity,
                                                                        OldStatus: r.oldFinding.status,
                                                                        OldDetails: r.oldFinding.findingDetails || r.oldFinding.comments || '',
                                                                        NewStatus: 'Not_Reviewed'
                                                                    }));
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(notReviewedData), "Not Reviewed");

                                                                    // 3. All Findings (Source of Truth)
                                                                    const allData = analyzerNewChecklist?.findings.map(f => ({
                                                                        GroupID: f.vulnId,
                                                                        RuleID: f.ruleId,
                                                                        Severity: f.severity,
                                                                        Status: f.status,
                                                                        Details: f.findingDetails,
                                                                        Comments: f.comments,
                                                                        Edited: analyzerEditedIds.has(f.vulnId) ? 'Yes' : 'No'
                                                                    })) || [];
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(allData), "All Findings");

                                                                    // 4. New IDs
                                                                    const newIdsData = analyzerData.newIds.map(r => ({
                                                                        GroupID: r.vulnId,
                                                                        Severity: r.finding.severity,
                                                                        Title: r.finding.title,
                                                                        Status: r.finding.status
                                                                    }));
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(newIdsData), "New IDs");

                                                                    // 5. Dropped IDs
                                                                    const droppedIdsData = analyzerData.droppedIds.map(r => ({
                                                                        GroupID: r.vulnId,
                                                                        Severity: r.finding.severity,
                                                                        Title: r.finding.title,
                                                                        Status: r.finding.status
                                                                    }));
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(droppedIdsData), "Dropped IDs");

                                                                    XLSX.writeFile(wb, `stig_analyzer_report_${new Date().toISOString().split('T')[0]}.xlsx`);
                                                                };

                                                                const handleCopyImage = async () => {
                                                                    const element = document.getElementById('analyzer-panel-content');
                                                                    if (!element) return;
                                                                    try {
                                                                        const canvas = await html2canvas(element as HTMLElement);
                                                                        canvas.toBlob(blob => {
                                                                            if (blob) {
                                                                                navigator.clipboard.write([
                                                                                    new ClipboardItem({ 'image/png': blob })
                                                                                ]);
                                                                                alert('Analyzer view copied to clipboard!');
                                                                            }
                                                                        });
                                                                    } catch (err) {
                                                                        console.error('Failed to capture image', err);
                                                                        alert('Failed to copy image.');
                                                                    }
                                                                };

                                                                const handleExportCKLB = () => {
                                                                    if (!analyzerNewChecklist) return;
                                                                    // Export as CKLB JSON
                                                                    const exportData = {
                                                                        ...analyzerNewChecklist.rawJson,
                                                                        stigs: analyzerNewChecklist.rawJson?.stigs?.map((stig: any) => ({
                                                                            ...stig,
                                                                            uuid: stig.uuid || self.crypto.randomUUID(),
                                                                            rules: stig.rules?.map((rule: any) => {
                                                                                const finding = analyzerNewChecklist.findings.find(f => f.vulnId === rule.group_id || f.ruleId === rule.rule_id);
                                                                                if (finding) {
                                                                                    const { reviews, ...rest } = rule;
                                                                                    return {
                                                                                        ...rest,
                                                                                        uuid: rest.uuid || self.crypto.randomUUID(),
                                                                                        status: (() => {
                                                                                            const s = (finding.status || '').toLowerCase().replace(/[^a-z]/g, '');
                                                                                            if (s.includes('open')) return 'open';
                                                                                            if (s.includes('notafinding')) return 'not_a_finding';
                                                                                            if (s.includes('notapplicable')) return 'not_applicable';
                                                                                            return 'not_reviewed';
                                                                                        })(),
                                                                                        finding_details: finding.findingDetails || rule.finding_details,
                                                                                        comments: finding.comments || rule.comments
                                                                                    };
                                                                                }
                                                                                return { ...rule, uuid: rule.uuid || self.crypto.randomUUID() };
                                                                            })
                                                                        })),
                                                                        target_data: {
                                                                            ...analyzerNewChecklist.rawJson?.target_data,
                                                                            uuid: analyzerNewChecklist.rawJson?.target_data?.uuid || self.crypto.randomUUID()
                                                                        }
                                                                    };
                                                                    const cklbData = JSON.stringify(exportData, null, 2);

                                                                    const blob = new Blob([cklbData], { type: 'application/json' });
                                                                    const url = URL.createObjectURL(blob);
                                                                    const a = document.createElement('a');
                                                                    a.href = url;
                                                                    a.download = `stig_analyzer_export_${new Date().toISOString().split('T')[0]}.cklb`;
                                                                    document.body.appendChild(a);
                                                                    a.click();
                                                                    document.body.removeChild(a);
                                                                    URL.revokeObjectURL(url);
                                                                };

                                                                return (
                                                                    <>
                                                                        <button
                                                                            onClick={handleCopyImage}
                                                                            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors text-xs font-medium border ${darkMode ? 'border-gray-700 hover:bg-gray-800 text-gray-300' : 'border-gray-200 hover:bg-gray-50 text-gray-600'}`}
                                                                            title="Copy Analyzer View to Clipboard"
                                                                        >
                                                                            <Camera size={14} />
                                                                            Copy
                                                                        </button>
                                                                        <button
                                                                            onClick={handleExportExcel}
                                                                            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors text-xs font-medium border ${darkMode ? 'border-gray-700 hover:bg-gray-800 text-green-400' : 'border-gray-200 hover:bg-gray-50 text-green-600'}`}
                                                                            title="Export Full Report to Excel"
                                                                        >
                                                                            <FileSpreadsheet size={14} />
                                                                            Report
                                                                        </button>
                                                                        <button
                                                                            onClick={handleExportCKLB}
                                                                            className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-xs font-medium"
                                                                            title="Export CKLB for STIG Viewer"
                                                                        >
                                                                            <Download size={14} />
                                                                            CKLB
                                                                        </button>
                                                                    </>
                                                                );
                                                            })()}
                                                        </div>
                                                    </div>

                                                    {/* Controls Row */}
                                                    {analyzerData.notReviewed.length > 0 && (
                                                        <div className="space-y-3">
                                                            {/* Select All and Copy Button */}
                                                            <div className="flex items-center justify-between flex-wrap gap-2">
                                                                <label className="flex items-center gap-2 text-sm cursor-pointer">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={analyzerSelectedIds.size === analyzerData.notReviewed.length && analyzerData.notReviewed.length > 0}
                                                                        onChange={(e) => {
                                                                            if (e.target.checked) {
                                                                                setAnalyzerSelectedIds(new Set(analyzerData.notReviewed.map(r => r.vulnId)));
                                                                            } else {
                                                                                setAnalyzerSelectedIds(new Set());
                                                                            }
                                                                        }}
                                                                        className="rounded"
                                                                    />
                                                                    Select All ({analyzerData.notReviewed.length})
                                                                </label>
                                                                <div className="flex items-center gap-2">
                                                                    <div className="flex gap-2">
                                                                        <button
                                                                            onClick={() => {
                                                                                if (analyzerSelectedIds.size === 0) return;
                                                                                setAnalyzerNewChecklist(prev => {
                                                                                    if (!prev) return prev;
                                                                                    const updated = { ...prev, findings: [...prev.findings] };
                                                                                    updated.findings = updated.findings.map(f => {
                                                                                        if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                            const oldF = analyzerData.notReviewed.find(r => r.vulnId === f.vulnId)?.oldFinding;
                                                                                            if (oldF) {
                                                                                                return {
                                                                                                    ...f,
                                                                                                    status: oldF.status
                                                                                                };
                                                                                            }
                                                                                        }
                                                                                        return f;
                                                                                    });
                                                                                    return updated;
                                                                                });
                                                                                setAnalyzerEditedIds(prev => {
                                                                                    const next = new Set(prev);
                                                                                    analyzerSelectedIds.forEach(id => next.add(id));
                                                                                    return next;
                                                                                });
                                                                                setAnalyzerSelectedIds(new Set());
                                                                            }}
                                                                            disabled={analyzerSelectedIds.size === 0}
                                                                            className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${analyzerSelectedIds.size > 0
                                                                                ? 'bg-blue-600 hover:bg-blue-700 text-white'
                                                                                : 'bg-gray-200 text-gray-400 cursor-not-allowed'}`}
                                                                        >
                                                                            Copy Status
                                                                        </button>
                                                                        <button
                                                                            onClick={() => {
                                                                                if (analyzerSelectedIds.size === 0) return;
                                                                                setAnalyzerNewChecklist(prev => {
                                                                                    if (!prev) return prev;
                                                                                    const updated = { ...prev, findings: [...prev.findings] };
                                                                                    updated.findings = updated.findings.map(f => {
                                                                                        if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                            const oldF = analyzerData.notReviewed.find(r => r.vulnId === f.vulnId)?.oldFinding;
                                                                                            if (oldF) {
                                                                                                let newFindingDetails = f.findingDetails || '';
                                                                                                if (analyzerCustomComment) {
                                                                                                    newFindingDetails = `${analyzerCustomComment}\n\n${newFindingDetails}`;
                                                                                                }
                                                                                                if (oldF.findingDetails) {
                                                                                                    newFindingDetails = `${oldF.findingDetails}\n\n---\n${newFindingDetails}`;
                                                                                                }
                                                                                                return {
                                                                                                    ...f,
                                                                                                    findingDetails: newFindingDetails.trim(),
                                                                                                    comments: oldF.comments || f.comments
                                                                                                };
                                                                                            }
                                                                                        }
                                                                                        return f;
                                                                                    });
                                                                                    return updated;
                                                                                });
                                                                                setAnalyzerSelectedIds(new Set());
                                                                                setAnalyzerCustomComment('');
                                                                            }}
                                                                            disabled={analyzerSelectedIds.size === 0}
                                                                            className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${analyzerSelectedIds.size > 0
                                                                                ? 'bg-indigo-600 hover:bg-indigo-700 text-white'
                                                                                : 'bg-gray-200 text-gray-400 cursor-not-allowed'}`}
                                                                        >
                                                                            Copy Details
                                                                        </button>
                                                                        <button
                                                                            onClick={() => {
                                                                                if (analyzerSelectedIds.size === 0) return;
                                                                                setAnalyzerNewChecklist(prev => {
                                                                                    if (!prev) return prev;
                                                                                    const updated = { ...prev, findings: [...prev.findings] };
                                                                                    updated.findings = updated.findings.map(f => {
                                                                                        if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                            const oldF = analyzerData.notReviewed.find(r => r.vulnId === f.vulnId)?.oldFinding;
                                                                                            if (oldF) {
                                                                                                let newFindingDetails = f.findingDetails || '';
                                                                                                if (analyzerCustomComment) {
                                                                                                    newFindingDetails = `${analyzerCustomComment}\n\n${newFindingDetails}`;
                                                                                                }
                                                                                                if (oldF.findingDetails) {
                                                                                                    newFindingDetails = `${oldF.findingDetails}\n\n---\n${newFindingDetails}`;
                                                                                                }
                                                                                                return {
                                                                                                    ...f,
                                                                                                    status: oldF.status,
                                                                                                    findingDetails: newFindingDetails.trim(),
                                                                                                    comments: oldF.comments || f.comments
                                                                                                };
                                                                                            }
                                                                                        }
                                                                                        return f;
                                                                                    });
                                                                                    return updated;
                                                                                });
                                                                                setAnalyzerSelectedIds(new Set());
                                                                                setAnalyzerCustomComment('');
                                                                            }}
                                                                            disabled={analyzerSelectedIds.size === 0}
                                                                            className={`px-3 py-2 rounded-lg text-xs font-medium transition-colors ${analyzerSelectedIds.size > 0
                                                                                ? 'bg-purple-600 hover:bg-purple-700 text-white'
                                                                                : 'bg-gray-200 text-gray-400 cursor-not-allowed'}`}
                                                                        >
                                                                            Copy Both
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                            </div>

                                                            {/* Custom Finding Details Input */}
                                                            <div className={`p-3 rounded-lg border ${darkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                                <label className="text-xs font-semibold uppercase text-gray-500 block mb-2">Add Custom Comment to <span className="text-blue-500">NEW</span> Finding Details</label>
                                                                <textarea
                                                                    value={analyzerCustomComment}
                                                                    onChange={(e) => setAnalyzerCustomComment(e.target.value)}
                                                                    placeholder="Enter additional comments to add on top of existing finding details..."
                                                                    className={`w-full p-2 rounded-lg border text-sm resize-none ${darkMode ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200'}`}
                                                                    rows={2}
                                                                />
                                                            </div>

                                                            {/* Find and Replace */}
                                                            <div className={`p-3 rounded-lg border ${darkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                                <label className="text-xs font-semibold uppercase text-gray-500 block mb-2">Find & Replace in <span className="text-blue-500">NEW</span> Finding Details</label>
                                                                <div className="flex gap-2 items-center">
                                                                    <input
                                                                        type="text"
                                                                        value={analyzerFindText}
                                                                        onChange={(e) => setAnalyzerFindText(e.target.value)}
                                                                        placeholder="Find text..."
                                                                        className={`flex-1 p-2 rounded-lg border text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200'}`}
                                                                    />
                                                                    <span className="text-gray-400">→</span>
                                                                    <input
                                                                        type="text"
                                                                        value={analyzerReplaceText}
                                                                        onChange={(e) => setAnalyzerReplaceText(e.target.value)}
                                                                        placeholder="Replace with..."
                                                                        className={`flex-1 p-2 rounded-lg border text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200'}`}
                                                                    />
                                                                    <button
                                                                        onClick={() => {
                                                                            if (!analyzerFindText) return;
                                                                            setAnalyzerNewChecklist(prev => {
                                                                                if (!prev) return prev;
                                                                                const updated = { ...prev, findings: [...prev.findings] };
                                                                                updated.findings = updated.findings.map(f => {
                                                                                    // If selection exists, only update selected. Otherwise update ALL.
                                                                                    if (analyzerSelectedIds.size > 0 && !analyzerSelectedIds.has(f.vulnId)) {
                                                                                        return f;
                                                                                    }
                                                                                    return {
                                                                                        ...f,
                                                                                        findingDetails: (f.findingDetails || '').replaceAll(analyzerFindText, analyzerReplaceText)
                                                                                    };
                                                                                });
                                                                                return updated;
                                                                            });
                                                                        }}
                                                                        disabled={!analyzerFindText}
                                                                        className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${analyzerFindText
                                                                            ? 'bg-blue-600 hover:bg-blue-700 text-white'
                                                                            : 'bg-gray-200 text-gray-400 cursor-not-allowed'}`}
                                                                    >
                                                                        Replace
                                                                    </button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Table */}
                                                    <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                        <div className={`grid grid-cols-12 gap-2 p-3 text-xs font-semibold uppercase ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-50 text-gray-500'}`}>
                                                            <div className="col-span-1"></div>
                                                            <div className="col-span-1 text-center cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'severity', dir: prev.key === 'severity' && prev.dir === 'desc' ? 'asc' : 'desc' }))}>CAT {analyzerSort.key === 'severity' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                            <div className="col-span-2 cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'vulnId', dir: prev.key === 'vulnId' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Group ID {analyzerSort.key === 'vulnId' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                            <div className="col-span-2 cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'status', dir: prev.key === 'status' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Old Status {analyzerSort.key === 'status' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                            <div className="col-span-2">Old Finding Details</div>
                                                            <div className="col-span-1 text-center">→</div>
                                                            <div className="col-span-3">New Status</div>
                                                        </div>
                                                        <div className="max-h-[400px] overflow-y-auto divide-y dark:divide-gray-800">
                                                            {analyzerData.notReviewed
                                                                .slice()
                                                                .sort((a, b) => {
                                                                    const dir = analyzerSort.dir === 'asc' ? 1 : -1;
                                                                    if (analyzerSort.key === 'vulnId') return a.vulnId.localeCompare(b.vulnId) * dir;
                                                                    if (analyzerSort.key === 'severity') {
                                                                        const levels: any = { high: 3, medium: 2, low: 1 };
                                                                        return ((levels[a.oldFinding.severity] || 0) - (levels[b.oldFinding.severity] || 0)) * dir;
                                                                    }
                                                                    if (analyzerSort.key === 'status') return (a.oldFinding.status || '').localeCompare(b.oldFinding.status || '') * dir;
                                                                    return 0;
                                                                })
                                                                .map((row, idx) => (
                                                                    <div key={idx} className="border-b dark:border-gray-800">
                                                                        <div
                                                                            className="grid grid-cols-12 gap-2 p-3 items-center text-sm hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer"
                                                                            onClick={() => {
                                                                                const newSet = new Set(analyzerExpandedRows);
                                                                                if (newSet.has(row.vulnId)) newSet.delete(row.vulnId);
                                                                                else newSet.add(row.vulnId);
                                                                                setAnalyzerExpandedRows(newSet);
                                                                            }}
                                                                        >
                                                                            <div className="col-span-1" onClick={(e) => e.stopPropagation()}>
                                                                                <input
                                                                                    type="checkbox"
                                                                                    checked={analyzerSelectedIds.has(row.vulnId)}
                                                                                    onChange={(e) => {
                                                                                        const newSet = new Set(analyzerSelectedIds);
                                                                                        if (e.target.checked) newSet.add(row.vulnId);
                                                                                        else newSet.delete(row.vulnId);
                                                                                        setAnalyzerSelectedIds(newSet);
                                                                                    }}
                                                                                    className="rounded"
                                                                                />
                                                                            </div>
                                                                            <div className="col-span-1 text-center font-bold text-xs text-gray-500">
                                                                                {row.oldFinding.severity === 'high' ? 'I' : row.oldFinding.severity === 'medium' ? 'II' : 'III'}
                                                                            </div>
                                                                            <div className="col-span-2 font-mono text-xs flex items-center gap-1">
                                                                                <ChevronDown size={14} className={`transition-transform ${analyzerExpandedRows.has(row.vulnId) ? 'rotate-180' : ''}`} />
                                                                                {row.vulnId}
                                                                            </div>
                                                                            <div className="col-span-2">
                                                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${row.oldFinding.status === 'Open' ? 'bg-red-100 text-red-700' : row.oldFinding.status === 'NotAFinding' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                                                                                    {row.oldFinding.status}
                                                                                </span>
                                                                            </div>
                                                                            <div className="col-span-2 text-xs text-gray-500 truncate" title={row.oldFinding.findingDetails || row.oldFinding.comments}>
                                                                                {(row.oldFinding.findingDetails || row.oldFinding.comments || '-').slice(0, 50)}...
                                                                            </div>
                                                                            <div className="col-span-1 text-center text-gray-400">→</div>
                                                                            <div className="col-span-3">
                                                                                <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-700">
                                                                                    Not_Reviewed
                                                                                </span>
                                                                            </div>
                                                                        </div>
                                                                        {/* Expanded Details */}
                                                                        {analyzerExpandedRows.has(row.vulnId) && (
                                                                            <div className={`p-4 grid grid-cols-2 gap-4 text-xs ${darkMode ? 'bg-gray-800/30' : 'bg-gray-50'}`}>
                                                                                <div>
                                                                                    <div className="font-semibold text-gray-500 uppercase mb-2">Old Finding Details</div>
                                                                                    <div className={`p-3 rounded-lg max-h-40 overflow-y-auto whitespace-pre-wrap ${darkMode ? 'bg-gray-900 text-gray-300' : 'bg-white text-gray-700 border'}`}>
                                                                                        {row.oldFinding.findingDetails || row.oldFinding.comments || 'No finding details'}
                                                                                    </div>
                                                                                </div>
                                                                                <div>
                                                                                    <div className="font-semibold text-gray-500 uppercase mb-2">New Finding Details</div>
                                                                                    <textarea
                                                                                        value={row.newFinding.findingDetails || ''}
                                                                                        onChange={(e) => {
                                                                                            const val = e.target.value;
                                                                                            setAnalyzerNewChecklist(prev => {
                                                                                                if (!prev) return prev;
                                                                                                const newFindings = [...prev.findings];
                                                                                                const idx = newFindings.findIndex(f => f.vulnId === row.vulnId);
                                                                                                if (idx !== -1) {
                                                                                                    newFindings[idx] = { ...newFindings[idx], findingDetails: val };
                                                                                                }
                                                                                                return { ...prev, findings: newFindings };
                                                                                            });
                                                                                        }}
                                                                                        className={`w-full p-3 rounded-lg text-xs resize-none h-40 border focus:ring-2 focus:ring-blue-500 outline-none transition-all ${darkMode ? 'bg-gray-900 text-gray-300 border-gray-700' : 'bg-white text-gray-700 border-gray-200 focus:border-blue-500'}`}
                                                                                        placeholder="Enter finding details..."
                                                                                    />
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                            {analyzerData.notReviewed.length === 0 && (
                                                                <div className="p-8 text-center text-gray-400">
                                                                    No "Not Reviewed" findings in the new checklist that have status in the old checklist.
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}

                                            {/* Reviewed Tab */}
                                            {analyzerTab === 'reviewed' && (
                                                <div className="space-y-4">
                                                    <div className="flex justify-between items-center px-1">
                                                        <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">
                                                            {analyzerShowAllReviewed ? "All Findings (Not_Reviewed excluded)" : "Findings Edited This Session"}
                                                        </span>
                                                        <button
                                                            onClick={() => setAnalyzerShowAllReviewed(!analyzerShowAllReviewed)}
                                                            className="text-xs text-blue-500 hover:text-blue-600 font-medium"
                                                        >
                                                            {analyzerShowAllReviewed ? 'Show Only My Edits' : 'Show All Processed'}
                                                        </button>
                                                    </div>
                                                    <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                        <div className={`grid grid-cols-12 gap-2 p-3 text-xs font-semibold uppercase ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-50 text-gray-500'}`}>
                                                            <div className="col-span-1 flex items-center justify-center">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={(() => {
                                                                        const visible = analyzerNewChecklist?.findings.filter(f => analyzerShowAllReviewed ? f.status !== 'Not_Reviewed' : analyzerEditedIds.has(f.vulnId)) || [];
                                                                        return visible.length > 0 && visible.every(f => analyzerSelectedIds.has(f.vulnId));
                                                                    })()}
                                                                    onChange={(e) => {
                                                                        const visible = analyzerNewChecklist?.findings.filter(f => analyzerShowAllReviewed ? f.status !== 'Not_Reviewed' : analyzerEditedIds.has(f.vulnId)) || [];
                                                                        if (e.target.checked) {
                                                                            setAnalyzerSelectedIds(new Set(visible.map(f => f.vulnId)));
                                                                        } else {
                                                                            setAnalyzerSelectedIds(new Set());
                                                                        }
                                                                    }}
                                                                    className="rounded"
                                                                />
                                                            </div>
                                                            <div
                                                                className="col-span-1 text-center cursor-pointer hover:text-blue-500"
                                                                onClick={() => setAnalyzerSort(prev => ({ key: 'severity', dir: prev.key === 'severity' && prev.dir === 'desc' ? 'asc' : 'desc' }))}
                                                            >
                                                                CAT {analyzerSort.key === 'severity' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                            </div>
                                                            <div
                                                                className="col-span-2 cursor-pointer hover:text-blue-500"
                                                                onClick={() => setAnalyzerSort(prev => ({ key: 'vulnId', dir: prev.key === 'vulnId' && prev.dir === 'asc' ? 'desc' : 'asc' }))}
                                                            >
                                                                Group ID {analyzerSort.key === 'vulnId' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                            </div>
                                                            <div
                                                                className="col-span-2 cursor-pointer hover:text-blue-500"
                                                                onClick={() => setAnalyzerSort(prev => ({ key: 'status', dir: prev.key === 'status' && prev.dir === 'asc' ? 'desc' : 'asc' }))}
                                                            >
                                                                Status {analyzerSort.key === 'status' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                            </div>
                                                            <div className="col-span-6">Finding Details</div>
                                                        </div>
                                                        <div className="max-h-[600px] overflow-y-auto divide-y dark:divide-gray-800">
                                                            {analyzerNewChecklist?.findings
                                                                .filter(f => analyzerShowAllReviewed ? f.status !== 'Not_Reviewed' : analyzerEditedIds.has(f.vulnId))
                                                                .sort((a, b) => {
                                                                    const dir = analyzerSort.dir === 'asc' ? 1 : -1;
                                                                    if (analyzerSort.key === 'vulnId') return a.vulnId.localeCompare(b.vulnId) * dir;
                                                                    if (analyzerSort.key === 'severity') {
                                                                        const levels: any = { high: 3, medium: 2, low: 1 };
                                                                        return (levels[a.severity] - levels[b.severity]) * dir;
                                                                    }
                                                                    if (analyzerSort.key === 'status') return a.status.localeCompare(b.status) * dir;
                                                                    return 0;
                                                                })
                                                                .map((finding, idx) => (
                                                                    <div key={idx} className={`border-b dark:border-gray-800 ${analyzerSelectedIds.has(finding.vulnId) ? (darkMode ? 'bg-blue-900/20' : 'bg-blue-50') : ''}`}>
                                                                        <div
                                                                            className="grid grid-cols-12 gap-2 p-3 items-center text-sm hover:bg-gray-50 dark:hover:bg-gray-800/50 cursor-pointer"
                                                                            onClick={() => {
                                                                                const newSet = new Set(analyzerExpandedRows);
                                                                                if (newSet.has(finding.vulnId)) newSet.delete(finding.vulnId);
                                                                                else newSet.add(finding.vulnId);
                                                                                setAnalyzerExpandedRows(newSet);
                                                                            }}
                                                                        >
                                                                            <div className="col-span-1 flex justify-center" onClick={(e) => e.stopPropagation()}>
                                                                                <input
                                                                                    type="checkbox"
                                                                                    checked={analyzerSelectedIds.has(finding.vulnId)}
                                                                                    onChange={(e) => {
                                                                                        const newSet = new Set(analyzerSelectedIds);
                                                                                        if (e.target.checked) newSet.add(finding.vulnId);
                                                                                        else newSet.delete(finding.vulnId);
                                                                                        setAnalyzerSelectedIds(newSet);
                                                                                    }}
                                                                                    className="rounded"
                                                                                />
                                                                            </div>
                                                                            <div className="col-span-1 text-center font-bold text-xs text-gray-500">
                                                                                {finding.severity === 'high' ? 'I' : finding.severity === 'medium' ? 'II' : 'III'}
                                                                            </div>
                                                                            <div className="col-span-2 font-mono text-xs flex items-center gap-1">
                                                                                <ChevronDown size={14} className={`transition-transform ${analyzerExpandedRows.has(finding.vulnId) ? 'rotate-180' : ''}`} />
                                                                                {finding.vulnId}
                                                                            </div>
                                                                            <div className="col-span-2">
                                                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${finding.status === 'Open' ? 'bg-red-100 text-red-700' : finding.status === 'NotAFinding' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                                                                                    {finding.status}
                                                                                </span>
                                                                            </div>
                                                                            <div className="col-span-6 text-xs text-gray-500 truncate" title={finding.findingDetails}>
                                                                                {(finding.findingDetails || '-').slice(0, 80)}...
                                                                            </div>
                                                                        </div>
                                                                        {analyzerExpandedRows.has(finding.vulnId) && (
                                                                            <div className={`p-4 space-y-4 text-xs ${darkMode ? 'bg-gray-800/30' : 'bg-gray-50'}`}>
                                                                                <div>
                                                                                    <div className="font-semibold text-gray-500 uppercase mb-2">Finding Details (Editable)</div>
                                                                                    <textarea
                                                                                        value={finding.findingDetails || ''}
                                                                                        onChange={(e) => {
                                                                                            const val = e.target.value;
                                                                                            setAnalyzerEditedIds(prev => new Set(prev).add(finding.vulnId));
                                                                                            setAnalyzerNewChecklist(prev => {
                                                                                                if (!prev) return prev;
                                                                                                const newFindings = [...prev.findings];
                                                                                                const idx = newFindings.findIndex(f => f.vulnId === finding.vulnId);
                                                                                                if (idx !== -1) {
                                                                                                    newFindings[idx] = { ...newFindings[idx], findingDetails: val };
                                                                                                }
                                                                                                return { ...prev, findings: newFindings };
                                                                                            });
                                                                                        }}
                                                                                        className={`w-full p-3 rounded-lg text-xs resize-none h-32 border focus:ring-2 focus:ring-blue-500 outline-none transition-all ${darkMode ? 'bg-gray-900 text-gray-300 border-gray-700' : 'bg-white text-gray-700 border-gray-200 focus:border-blue-500'}`}
                                                                                        placeholder="Finding details..."
                                                                                    />
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                ))}
                                                            {(analyzerNewChecklist?.findings.filter(f => analyzerShowAllReviewed ? f.status !== 'Not_Reviewed' : analyzerEditedIds.has(f.vulnId)).length || 0) === 0 && (
                                                                <div className="p-8 text-center text-gray-400">
                                                                    {analyzerShowAllReviewed ? "No processed findings found." : "No findings edited in this session."}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}

                                            {/* New IDs Tab */}
                                            {analyzerTab === 'newids' && (
                                                <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                    <div className={`grid grid-cols-6 gap-2 p-3 text-xs font-semibold uppercase ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-50 text-gray-500'}`}>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'vulnId', dir: prev.key === 'vulnId' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Group ID {analyzerSort.key === 'vulnId' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'severity', dir: prev.key === 'severity' && prev.dir === 'desc' ? 'asc' : 'desc' }))}>CAT {analyzerSort.key === 'severity' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                        <div className="col-span-3">Title</div>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'status', dir: prev.key === 'status' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Status {analyzerSort.key === 'status' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                    </div>
                                                    <div className="max-h-96 overflow-y-auto divide-y dark:divide-gray-800">
                                                        {analyzerData.newIds
                                                            .slice()
                                                            .sort((a, b) => {
                                                                const dir = analyzerSort.dir === 'asc' ? 1 : -1;
                                                                if (analyzerSort.key === 'vulnId') return a.vulnId.localeCompare(b.vulnId) * dir;
                                                                if (analyzerSort.key === 'severity') {
                                                                    const levels: any = { high: 3, medium: 2, low: 1 };
                                                                    return ((levels[a.finding.severity] || 0) - (levels[b.finding.severity] || 0)) * dir;
                                                                }
                                                                if (analyzerSort.key === 'status') return (a.finding.status || '').localeCompare(b.finding.status || '') * dir;
                                                                return 0;
                                                            })
                                                            .map((row, idx) => (
                                                                <div key={idx} className="grid grid-cols-6 gap-2 p-3 items-center text-sm">
                                                                    <div className="font-mono text-xs">{row.vulnId}</div>
                                                                    <div className="font-bold text-xs text-gray-500">
                                                                        {row.finding.severity === 'high' ? 'I' : row.finding.severity === 'medium' ? 'II' : 'III'}
                                                                    </div>
                                                                    <div className="col-span-3 text-xs truncate" title={row.finding.title}>{row.finding.title}</div>
                                                                    <div>
                                                                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-700">
                                                                            {row.finding.status}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        {analyzerData.newIds.length === 0 && (
                                                            <div className="p-8 text-center text-gray-400">
                                                                No new Group IDs found in the new checklist.
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Dropped IDs Tab */}
                                            {analyzerTab === 'droppedids' && (
                                                <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                    <div className={`grid grid-cols-6 gap-2 p-3 text-xs font-semibold uppercase ${darkMode ? 'bg-gray-800 text-gray-400' : 'bg-gray-50 text-gray-500'}`}>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'vulnId', dir: prev.key === 'vulnId' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Group ID {analyzerSort.key === 'vulnId' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'severity', dir: prev.key === 'severity' && prev.dir === 'desc' ? 'asc' : 'desc' }))}>CAT {analyzerSort.key === 'severity' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                        <div className="col-span-3">Title</div>
                                                        <div className="cursor-pointer hover:text-blue-500" onClick={() => setAnalyzerSort(prev => ({ key: 'status', dir: prev.key === 'status' && prev.dir === 'asc' ? 'desc' : 'asc' }))}>Old Status {analyzerSort.key === 'status' && (analyzerSort.dir === 'asc' ? '↑' : '↓')}</div>
                                                    </div>
                                                    <div className="max-h-96 overflow-y-auto divide-y dark:divide-gray-800">
                                                        {analyzerData.droppedIds
                                                            .slice()
                                                            .sort((a, b) => {
                                                                const dir = analyzerSort.dir === 'asc' ? 1 : -1;
                                                                if (analyzerSort.key === 'vulnId') return a.vulnId.localeCompare(b.vulnId) * dir;
                                                                if (analyzerSort.key === 'severity') {
                                                                    const levels: any = { high: 3, medium: 2, low: 1 };
                                                                    return ((levels[a.finding.severity] || 0) - (levels[b.finding.severity] || 0)) * dir;
                                                                }
                                                                if (analyzerSort.key === 'status') return (a.finding.status || '').localeCompare(b.finding.status || '') * dir;
                                                                return 0;
                                                            })
                                                            .map((row, idx) => (
                                                                <div key={idx} className="grid grid-cols-6 gap-2 p-3 items-center text-sm">
                                                                    <div className="font-mono text-xs">{row.vulnId}</div>
                                                                    <div className="font-bold text-xs text-gray-500">
                                                                        {row.finding.severity === 'high' ? 'I' : row.finding.severity === 'medium' ? 'II' : 'III'}
                                                                    </div>
                                                                    <div className="col-span-3 text-xs truncate" title={row.finding.title}>{row.finding.title}</div>
                                                                    <div>
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${row.finding.status === 'Open' ? 'bg-red-100 text-red-700' : row.finding.status === 'NotAFinding' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                                                                            {row.finding.status}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        {analyzerData.droppedIds.length === 0 && (
                                                            <div className="p-8 text-center text-gray-400">
                                                                No Group IDs were dropped from the old checklist.
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}
                                        </>
                                    )}

                                    {(!analyzerOldChecklist || !analyzerNewChecklist) && (
                                        <div className="p-8 text-center text-gray-400 border-2 border-dashed rounded-xl">
                                            Upload both old and new STIG checklists to begin analysis.
                                        </div>
                                    )}
                                    {/* DEBUG INFO */}
                                    <div className="mt-8 p-4 bg-gray-100 dark:bg-gray-900 rounded border border-red-500 overflow-auto max-h-96">
                                        <h3 className="font-bold text-red-500 mb-2">DEBUG: Raw JSON Structure (For Troubleshooting - Copy this config)</h3>
                                        <p className="text-xs text-gray-500 mb-2">If your export is failing, upload a WORKING file here, look at this debug info, and verify if the structure (especially "status" fields) matches what you expect.</p>
                                        <pre className="text-xs font-mono whitespace-pre-wrap text-left select-all">
                                            {analyzerNewChecklist?.rawJson ? JSON.stringify({
                                                keys: Object.keys(analyzerNewChecklist.rawJson),
                                                stigKeys: Object.keys(analyzerNewChecklist.rawJson.stigs?.[0] || {}),
                                                ruleSample: analyzerNewChecklist.rawJson.stigs?.[0]?.rules?.[0],
                                                targetData: analyzerNewChecklist.rawJson.target_data
                                            }, null, 2) : 'No New Checklist Raw JSON available.'}
                                        </pre>
                                    </div>
                                </div>
                                    )}
                            </div>
                        </div>
                        </div>
                ) : null
                    }


                {/* Removed Source Preview Modal - details now inline */}

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
            </main >
        </div >
    );
}

// Helper Components
function SidebarItem({ icon, label, active, onClick, darkMode }: { icon: any, label: string, active: boolean, onClick: () => void, darkMode: boolean }) {
    return (
        <button
            onClick={onClick}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-all mb-0.5 group ${active
                ? (darkMode ? 'bg-gray-800 text-white font-medium shadow-sm' : 'bg-white text-black font-medium shadow-sm')
                : (darkMode ? 'text-gray-400 hover:bg-gray-800 hover:text-gray-200' : 'text-gray-500 hover:bg-white/60 hover:text-gray-900')
                }`}
        >
            <div className={`transition-colors ${active ? (darkMode ? 'text-blue-400' : 'text-blue-600') : 'text-gray-400 group-hover:text-gray-500'}`}>
                {icon}
            </div>
            <span className="text-sm">{label}</span>
            {active && <div className={`ml-auto size-1.5 rounded-full ${darkMode ? 'bg-blue-500' : 'bg-blue-600'}`} />}
        </button>
    );
}

export default App;

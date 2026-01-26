import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
    Trash2, Upload, AlertCircle, Check, X, Search, FileEdit, FolderOpen, FolderTree, FileSpreadsheet, Database, Info, Calendar, Terminal, ChevronRight, ChevronDown, ChevronUp, Copy, Maximize2, Minimize2, XCircle, RotateCw, Play, Shield, Camera, Target, Download, Settings, Image as ImageIcon,
    ShieldCheck, LayoutGrid, Loader2, AlertTriangle, RefreshCw, FileText, Eye, ClipboardList, Monitor, Globe, Moon, Sun, GitCompare, FileWarning, Server, Users, PieChart, CheckCircle2, Filter, FolderClosed,
    Wrench, Save, ArrowRight, ChevronLeft, FolderPlus, Cpu, ExternalLink, Book, Network, Zap, Link, Hash, Code, FileCode, Wallet, Activity
} from 'lucide-react';
import { parseStigXML, generateCheckCommand, evaluateCheckResult, ParsedStigRule, parseCklFile } from './utils/stig-parser';
import * as XLSX from 'xlsx';
import html2canvas from 'html2canvas';
import JSZip from 'jszip';
import NetworkDiagram from './components/NetworkDiagram';
import WebScanner from './components/WebScanner';
import CodeScanner from './components/CodeScanner';
import { analyzeContract, validateAddress, decodeFunctionSelector, parseABI, formatWei, chainInfo, attackVectors, VulnerabilityResult, ContractAnalysis } from './blockchain';

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
    findingDetails?: string;
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
    const [activeTab, setActiveTab] = useState<'scan' | 'checklist' | 'results' | 'report' | 'compare' | 'settings' | 'help' | 'tools' | 'codescan' | 'analyzer' | 'master_copy' | 'copy' | 'evidence' | 'poam' | 'controls' | 'network' | 'webscan' | 'blockchain'>(isElectron ? 'scan' : 'checklist');
    const [evidenceList, setEvidenceList] = useState<any[]>([]);
    const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
    const [selectedStatus, setSelectedStatus] = useState<string | null>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [stigInfo, setStigInfo] = useState({ version: 'Loading...', ruleCount: 0, stigId: 'win11' });
    const [selectedRule, setSelectedRule] = useState<ParsedStigRule | null>(null);
    const [availableChecklists, setAvailableChecklists] = useState<StigChecklist[]>([]);
    const [darkMode, setDarkMode] = useState(false);

    // Evidence Capture Modal State
    const [showEvidenceModal, setShowEvidenceModal] = useState(false);
    const [evidenceModalRule, setEvidenceModalRule] = useState<ParsedStigRule | null>(null);
    const [evidenceFolderName, setEvidenceFolderName] = useState('');
    const [evidenceScreenshot, setEvidenceScreenshot] = useState<string | null>(null);

    // Evidence Type Selection Modal State
    const [showEvidenceTypeModal, setShowEvidenceTypeModal] = useState(false);
    const [showUsernameModal, setShowUsernameModal] = useState(false);
    const [scanUsername, setScanUsername] = useState<string>('');
    const detailEvidenceCardRef = React.useRef<HTMLDivElement>(null);
    const virtualEvidenceRef = React.useRef<HTMLDivElement>(null); // NEW: For capturing virtual tools

    // Auto-Capture Virtual Evidence when Modal triggers
    useEffect(() => {
        if (showEvidenceModal && evidenceModalRule && !evidenceScreenshot) {
            // Short timeout to ensure DOM render
            const timer = setTimeout(async () => {
                if (virtualEvidenceRef.current) {
                    try {
                        const canvas = await html2canvas(virtualEvidenceRef.current, {
                            backgroundColor: null, // Transparent wrapper
                            scale: 1.5 // Higher quality
                        });
                        setEvidenceScreenshot(canvas.toDataURL('image/png'));
                    } catch (e) {
                        console.error("Virtual capture failed:", e);
                    }
                }
            }, 500);
            return () => clearTimeout(timer);
        }
    }, [showEvidenceModal, evidenceModalRule]);

    // Tools State
    const [toolsMode, setToolsMode] = useState<'rename' | 'heatmap' | 'analyzer' | 'extractor' | 'reportanalyzer' | 'master_copy'>('rename');
    const [isToolsOpen, setIsToolsOpen] = useState(false);
    const [showDocsModal, setShowDocsModal] = useState(false);
    const [selectedDocSection, setSelectedDocSection] = useState<string>('intro');
    const [renameFiles, setRenameFiles] = useState<{ file: File; originalName: string; newName: string }[]>([]);
    const [renamePrefix, setRenamePrefix] = useState('');
    const [renameSuffix, setRenameSuffix] = useState('');
    const [heatmapChecklists, setHeatmapChecklists] = useState<typeof uploadedChecklists>([]);

    // Master Copy Tool State
    const [masterCopySource, setMasterCopySource] = useState<typeof uploadedChecklists[0] | null>(null);
    const [masterCopyTarget, setMasterCopyTarget] = useState<typeof uploadedChecklists[0] | null>(null);
    const [masterCopyBatchFiles, setMasterCopyBatchFiles] = useState<typeof uploadedChecklists>([]);
    const [masterCopyTab, setMasterCopyTab] = useState<'all' | 'notreviewed' | 'open' | 'reviewed' | 'newids' | 'droppedids' | 'done'>('notreviewed');
    const [masterCopySelectedIds, setMasterCopySelectedIds] = useState<Set<string>>(new Set());
    const [masterCopySearch, setMasterCopySearch] = useState('');
    const [masterCopyReplace, setMasterCopyReplace] = useState('');
    const [masterCopyEditedIds, setMasterCopyEditedIds] = useState<Set<string>>(new Set());
    const [masterCopyDoneIds, setMasterCopyDoneIds] = useState<Set<string>>(new Set());
    const [masterCopyExpandedId, setMasterCopyExpandedId] = useState<string | null>(null);
    const [showDoneToast, setShowDoneToast] = useState(false);
    const [masterCopySort, setMasterCopySort] = useState<{ key: string, dir: 'asc' | 'desc' }>({ key: 'severity', dir: 'desc' });


    // Extractor state
    const [extractorFiles, setExtractorFiles] = useState<File[]>([]);
    const [extractorOptions, setExtractorOptions] = useState({
        catI: false,
        catII: false,
        catIII: false,
        ruleId: false,
        groupId: false,
    });
    const [extractorProcessing, setExtractorProcessing] = useState(false);

    // Blockchain State
    const [blockchainMode, setBlockchainMode] = useState<'analyzer' | 'address' | 'decoder' | 'abi' | 'converter' | 'attacks'>('analyzer');
    const [contractCode, setContractCode] = useState('');
    const [contractAnalysis, setContractAnalysis] = useState<ContractAnalysis | null>(null);
    const [addressInput, setAddressInput] = useState('');
    const [addressValidation, setAddressValidation] = useState<{ valid: boolean; type: string; checksum?: boolean } | null>(null);
    const [txDataInput, setTxDataInput] = useState('');
    const [decodedFunction, setDecodedFunction] = useState<{ selector: string; name?: string } | null>(null);
    const [abiInput, setAbiInput] = useState('');
    const [parsedAbi, setParsedAbi] = useState<{ functions: string[]; events: string[]; errors: string[] } | null>(null);
    const [weiInput, setWeiInput] = useState('');
    const [convertedValues, setConvertedValues] = useState<{ wei: string; gwei: string; ether: string } | null>(null);
    const [selectedChain, setSelectedChain] = useState(1);
    const [selectedAttack, setSelectedAttack] = useState<typeof attackVectors[0] | null>(null);
    const [attackLabMode, setAttackLabMode] = useState<'learn' | 'scan'>('learn');
    const [scannerCode, setScannerCode] = useState('');
    const [scanResults, setScanResults] = useState<ContractAnalysis | null>(null);

    // Report Analyzer State
    const [reportBaseData, setReportBaseData] = useState<{
        filename: string;
        rows: Array<Record<string, string>>;
        headers: string[];
    } | null>(null);
    const [reportComparisonFiles, setReportComparisonFiles] = useState<typeof uploadedChecklists>([]);
    const [reportAnalysisResults, setReportAnalysisResults] = useState<Array<{
        groupId: string;
        ruleId: string;
        stigName: string;
        oldSeverity: string;
        newSeverity: string;
        severityChanged: boolean;
        title: string;
        checkText: string;
        fixText: string;
        description: string;
        status: string;
        findingDetails: string;
        comments: string;
        // Keep original CSV row data for reference
        originalCsvRow: Record<string, string>;
    }> | null>(null);
    const [reportProcessing, setReportProcessing] = useState(false);
    const [reportFilterSeverityChange, setReportFilterSeverityChange] = useState(false);

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

    // Master Copy computed data
    const masterCopyData = useMemo(() => {
        if (!masterCopySource || !masterCopyTarget) {
            return { notReviewed: [], openFindings: [], newIds: [], droppedIds: [], totalOld: 0, totalNew: 0 };
        }

        const totalOld = masterCopySource.findings.length;
        const totalNew = masterCopyTarget.findings.length;

        const oldMap = new Map(masterCopySource.findings.map(f => [f.vulnId, f]));
        const newMap = new Map(masterCopyTarget.findings.map(f => [f.vulnId, f]));

        // Not Reviewed in new checklist but has data in old
        const notReviewed = masterCopyTarget.findings
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

        // Open Findings in new (target) checklist
        const openFindings = masterCopyTarget.findings
            .filter(f => {
                const status = f.status?.toLowerCase().replace(/[\s_]/g, '') || '';
                return status === 'open' || status === 'fail';
            })
            .map(f => ({
                vulnId: f.vulnId,
                newFinding: f,
                oldFinding: oldMap.get(f.vulnId) // Optional
            }));

        // New Group IDs (in new but not in old)
        const newIds = masterCopyTarget.findings
            .filter(f => !oldMap.has(f.vulnId))
            .map(f => ({ vulnId: f.vulnId, finding: f }));

        // Dropped IDs (in old but not in new)
        const droppedIds = masterCopySource.findings
            .filter(f => !newMap.has(f.vulnId))
            .map(f => ({ vulnId: f.vulnId, finding: f }));

        // All Findings
        const allFindings = masterCopyTarget.findings.map(f => ({
            vulnId: f.vulnId,
            newFinding: f,
            oldFinding: oldMap.get(f.vulnId)
        }));

        // Done Findings
        const doneFindings = masterCopyTarget.findings
            .filter(f => masterCopyDoneIds.has(f.vulnId))
            .map(f => ({
                vulnId: f.vulnId,
                newFinding: f,
                oldFinding: oldMap.get(f.vulnId)
            }));

        return { notReviewed, openFindings, newIds, droppedIds, totalOld, totalNew, allFindings, doneFindings };
    }, [masterCopySource, masterCopyTarget, masterCopyDoneIds]);

    // Sorted Data for Master Copy
    const sortedMasterCopy = useMemo(() => {
        let findings: any[] = [];
        if (masterCopyTab === 'notreviewed') findings = masterCopyData.notReviewed;
        else if (masterCopyTab === 'open') findings = masterCopyData.openFindings;
        else if (masterCopyTab === 'newids') findings = masterCopyData.newIds;
        else if (masterCopyTab === 'droppedids') findings = masterCopyData.droppedIds;
        else if (masterCopyTab === 'reviewed') {
            // "Reviewed" means status is NOT 'Not_Reviewed'
            if (!masterCopyTarget) return [];
            findings = masterCopyTarget.findings
                .filter(f => (f.status || '').toLowerCase().replace(/[\s_]/g, '') !== 'notreviewed')
                .map(f => ({
                    vulnId: f.vulnId,
                    newFinding: f,
                    // Look up old just in case we want to show it, though irrelevant for sorting logic usually
                    oldFinding: masterCopySource?.findings.find(of => of.vulnId === f.vulnId)
                }));

        } else if (masterCopyTab === 'done') {
            findings = masterCopyData.doneFindings;
        } else if (masterCopyTab === 'all') {
            findings = masterCopyData.allFindings;
        }

        if (!masterCopySort.key) return findings;

        return findings.sort((a, b) => {
            let valA: any = '';
            let valB: any = '';

            // Handle different object structures (some have newFinding/oldFinding, some just finding)
            const getField = (obj: any, source: 'new' | 'old') => {
                if (obj.newFinding) return source === 'new' ? obj.newFinding : obj.oldFinding;
                if (obj.finding) return obj.finding;
                if (obj.vulnId) return obj; // Fallback
                return {};
            };

            const itemA = getField(a, 'new');
            const itemB = getField(b, 'new');

            // For severity sort, prefer OLD severity if available in not_reviewed tab? 
            // Analyzer logic uses oldFinding severity. Let's stick to NEW finding severity for Master Copy as it is the "Master" we are editing.
            // EXCEPT for Not Reviewed, where new finding has no data usually? 
            // Actually, in Not Reviewed, the NEW finding exists but is unreviewed. The user wants to compare with OLD.
            // Let's use Old Finding for Severity sorting in Not Reviewed tab, else New Finding.
            const useOldSev = masterCopyTab === 'notreviewed';
            const sortItemA = useOldSev ? (a.oldFinding || itemA) : itemA;
            const sortItemB = useOldSev ? (b.oldFinding || itemB) : itemB;

            if (masterCopySort.key === 'groupid') {
                valA = a.vulnId;
                valB = b.vulnId;
            } else if (masterCopySort.key === 'severity') {
                const sevMap: Record<string, number> = { 'high': 3, 'cat i': 3, 'medium': 2, 'cat ii': 2, 'low': 1, 'cat iii': 1 };
                valA = sevMap[(sortItemA?.severity || '').toLowerCase()] || 0;
                valB = sevMap[(sortItemB?.severity || '').toLowerCase()] || 0;
            } else if (masterCopySort.key === 'status') {
                valA = sortItemA?.status || '';
                valB = sortItemB?.status || '';
            }

            if (valA < valB) return masterCopySort.dir === 'asc' ? -1 : 1;
            if (valA > valB) return masterCopySort.dir === 'asc' ? 1 : -1;
            return 0;
        });
    }, [masterCopyData, masterCopyTab, masterCopySort, masterCopySource, masterCopyTarget]);

    // Map for fast lookup of Old Findings in Reviewed Tab
    const oldFindingsMap = useMemo(() => {
        if (!analyzerOldChecklist) return new Map();
        return new Map(analyzerOldChecklist.findings.map((f: any) => [f.vulnId, f]));
    }, [analyzerOldChecklist]);

    const [filterStatus, setFilterStatus] = useState<string>('All');

    // Sorted Data for Analyzer Tabs
    const sortedNotReviewed = useMemo(() => {
        if (!analyzerData?.notReviewed) return [];
        const sorted = [...analyzerData.notReviewed];
        if (!analyzerSort.key) return sorted;

        return sorted.sort((a, b) => {
            let valA: any = '';
            let valB: any = '';

            if (analyzerSort.key === 'groupid') {
                valA = a.vulnId;
                valB = b.vulnId;
            } else if (analyzerSort.key === 'severity') {
                const sevMap: Record<string, number> = { 'high': 3, 'cat i': 3, 'medium': 2, 'cat ii': 2, 'low': 1, 'cat iii': 1 };
                valA = sevMap[(a.oldFinding.severity || '').toLowerCase()] || 0;
                valB = sevMap[(b.oldFinding.severity || '').toLowerCase()] || 0;
            } else if (analyzerSort.key === 'status') {
                valA = a.oldFinding.status || '';
                valB = b.oldFinding.status || '';
            }

            if (valA < valB) return analyzerSort.dir === 'asc' ? -1 : 1;
            if (valA > valB) return analyzerSort.dir === 'asc' ? 1 : -1;
            return 0;
        });
    }, [analyzerData, analyzerSort]);

    const sortedReviewed = useMemo(() => {
        if (!analyzerNewChecklist || !analyzerTab) return [];
        // Filter based on Toggle
        let findings = analyzerNewChecklist.findings.filter(f => {
            // "Reviewed" means status is NOT 'Not_Reviewed' (already processed) OR we edited it specifically
            if (analyzerShowAllReviewed) {
                return (f.status || '').toLowerCase().replace(/[\s_]/g, '') !== 'notreviewed';
            } else {
                return analyzerEditedIds.has(f.vulnId);
            }
        });

        // Sort
        return findings.sort((a, b) => {
            let valA: any = '';
            let valB: any = '';

            if (analyzerSort.key === 'groupid') {
                valA = a.vulnId;
                valB = b.vulnId;
            } else if (analyzerSort.key === 'severity') {
                const sevMap: Record<string, number> = { 'high': 3, 'cat i': 3, 'medium': 2, 'cat ii': 2, 'low': 1, 'cat iii': 1 };
                valA = sevMap[(a.severity || '').toLowerCase()] || 0;
                valB = sevMap[(b.severity || '').toLowerCase()] || 0;
            } else if (analyzerSort.key === 'status') {
                valA = a.status || '';
                valB = b.status || '';
            }

            if (valA < valB) return analyzerSort.dir === 'asc' ? -1 : 1;
            if (valA > valB) return analyzerSort.dir === 'asc' ? 1 : -1;
            return 0;
        });
    }, [analyzerNewChecklist, analyzerTab, analyzerEditedIds, analyzerShowAllReviewed, analyzerSort]);

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
    // Load available checklists on mount
    useEffect(() => {
        const init = async () => {
            try {
                // Determine if we should wait for checklists before loading file
                await loadChecklists();
                // Default to Edge STIG for agent scanning (can be changed via dropdown)
                await loadStigFile('edge');
            } catch (e) {
                console.error("Initialization error:", e);
                // Ensure we don't get stuck
                setIsLoading(false);
            }
        };

        init();

        // Safety timeout: If IPC hangs or something fails silently, force app to load after 5s
        const safetyTimer = setTimeout(() => {
            setIsLoading(current => {
                if (current) {
                    console.warn("Forcing loading completion due to timeout");
                    return false;
                }
                return current;
            });
        }, 5000);

        return () => clearTimeout(safetyTimer);
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

    // Run a single check - launches visible PowerShell window
    const runCheck = async (rule: ParsedStigRule): Promise<CheckResult> => {
        const command = generateCheckCommand(rule);
        if (!command) {
            const result: CheckResult = {
                ruleId: rule.vulnId,
                status: 'notapplicable',
                output: 'Manual check required - no automated check available',
                command: 'N/A'
            };
            setResults(prev => new Map(prev).set(rule.vulnId, result));
            return result;
        }

        setResults(prev => new Map(prev).set(rule.vulnId, {
            ruleId: rule.vulnId,
            status: 'running',
            command
        }));

        try {
            // Launch PowerShell window visibly with the command
            // @ts-ignore
            const res = await window.ipcRenderer.invoke('run-command-visible', {
                command: command,
                ruleId: rule.vulnId,
                ruleTitle: rule.title
            });

            // Handle the output
            let output = res.output?.trim() || '';
            let passed = false;

            if (res.success) {
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

            const result: CheckResult = {
                ruleId: rule.vulnId,
                status: passed ? 'pass' : 'fail',
                output,
                command,
                timestamp: new Date()
            };

            setResults(prev => new Map(prev).set(rule.vulnId, result));
            return result;

        } catch (e: any) {
            const result: CheckResult = {
                ruleId: rule.vulnId,
                status: 'error',
                output: e.toString(),
                command
            };
            setResults(prev => new Map(prev).set(rule.vulnId, result));
            return result;
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

    // Auto-Capture Batch Evidence (Agentic Mode)
    const [isBatchCapturing, setIsBatchCapturing] = useState(false);

    // Agent State
    interface AgentState {
        status: 'idle' | 'working' | 'complete' | 'stopped';
        currentRuleId: string;
        currentAction: string;
        logs: string[];
        progress: number;
        total: number;
    }
    const [agentState, setAgentState] = useState<AgentState>({
        status: 'idle',
        currentRuleId: '',
        currentAction: 'Waiting for orders...',
        logs: [],
        progress: 0,
        total: 0
    });

    // Cancellation ref for stopping scans
    const scanCancelledRef = useRef(false);

    const addAgentLog = (msg: string) => {
        setAgentState(prev => ({
            ...prev,
            logs: [...prev.logs.slice(-4), `> ${msg}`] // Keep last 5 logs
        }));
    };

    const stopScan = () => {
        scanCancelledRef.current = true;
        setIsBatchCapturing(false);
        setAgentState(prev => ({
            ...prev,
            status: 'stopped',
            currentAction: 'Scan cancelled by user'
        }));
        addAgentLog('Scan cancelled by user');
    };

    const runAgent = async () => {
        // Reset cancellation flag
        scanCancelledRef.current = false;

        // Filter rules that CAN be automated - focus on Edge STIG registry checks
        const rulesToProcess = filteredRules.filter(r => {
            // For Edge STIG, focus on registry checks that have automated checks
            return r.automatedCheck?.type !== 'manual' && r.automatedCheck?.type === 'registry';
        });
        const total = rulesToProcess.length;

        if (total === 0) {
            alert("No automated registry checks found. Make sure you've loaded the Edge STIG.");
            return;
        }

        // Show evidence type selection modal and wait for user selection
        let evidenceTypeForScan: 'powershell' | 'regedit' | 'both' = 'powershell';

        const evidenceTypePromise = new Promise<'powershell' | 'regedit' | 'both' | null>((resolve) => {
            // Store the resolve function so the modal can call it
            (window as any).__evidenceTypeResolver = resolve;
            setShowEvidenceTypeModal(true);
        });

        const evidenceType = await evidenceTypePromise;

        if (!evidenceType) {
            setShowEvidenceTypeModal(false);
            return; // User cancelled
        }

        evidenceTypeForScan = evidenceType;
        setShowEvidenceTypeModal(false);

        // Prompt for username
        const usernamePromise = new Promise<string | null>((resolve) => {
            (window as any).__usernameResolver = resolve;
            setShowUsernameModal(true);
        });

        const username = await usernamePromise;

        if (!username || username.trim() === '') {
            setShowUsernameModal(false);
            return; // User cancelled or didn't enter username
        }

        const scanUsernameValue = username.trim(); // Store in local variable for use in finding details
        setScanUsername(scanUsernameValue);
        setShowUsernameModal(false);

        setIsBatchCapturing(true);

        setAgentState({
            status: 'working',
            currentRuleId: 'INIT',
            currentAction: 'Launching Admin PowerShell...',
            logs: ['Initializing Agent...', 'Loading Edge STIG Rules...', 'Preparing PowerShell Interface...'],
            progress: 0,
            total
        });

        // Launch PowerShell window first (user will need to accept UAC)
        addAgentLog('Requesting admin PowerShell window...');
        try {
            // @ts-ignore
            const launchResult = await window.ipcRenderer.invoke('launch-admin-powershell');
            if (!launchResult.success) {
                alert(`Failed to launch PowerShell: ${launchResult.error}`);
                setIsBatchCapturing(false);
                setAgentState(prev => ({ ...prev, status: 'idle' }));
                return;
            }
            addAgentLog('PowerShell window launched. Please position it on the left side.');
            // Give user time to position window and accept UAC
            await new Promise(r => setTimeout(r, 3000));
        } catch (e: any) {
            console.error('Error launching PowerShell:', e);
            addAgentLog(`Error: ${e.message}`);
        }

        // Create folder name with STIG name and date: "Edge_STIG_V2R3_2024-01-15"
        const today = new Date();
        const dateStr = today.toISOString().split('T')[0]; // YYYY-MM-DD format
        const stigName = stigInfo.version.replace(/[^a-zA-Z0-9]/g, '_') || 'Edge_STIG';
        const safeFolder = `${stigName}_${dateStr}`;

        // Process all commands - start with first one
        let processedCount = 0;
        const firstRule = rulesToProcess[0];
        if (!firstRule) {
            addAgentLog('No rules to process');
            setIsBatchCapturing(false);
            setAgentState(prev => ({ ...prev, status: 'idle' }));
            return;
        }

        addAgentLog(`Processing first command: ${firstRule.vulnId}`);
        addAgentLog('Waiting 5 seconds for PowerShell to be ready...');
        await new Promise(r => setTimeout(r, 5000)); // Give PowerShell time to initialize

        // Check if scan was cancelled during wait
        if (scanCancelledRef.current) {
            addAgentLog('⚠️ Scan cancelled - stopping processing');
            setIsBatchCapturing(false);
            setAgentState(prev => ({
                ...prev,
                status: 'stopped',
                currentAction: 'Scan cancelled by user'
            }));
            return;
        }

        // Update agent state for first rule
        processedCount++;
        setAgentState(prev => ({
            ...prev,
            currentRuleId: firstRule.vulnId,
            currentAction: `Checking: ${firstRule.vulnId} - ${firstRule.title.substring(0, 50)}...`,
            progress: processedCount,
            logs: [...prev.logs.slice(-3), `Processing: ${firstRule.vulnId} (${firstRule.severity})`]
        }));

        // Get the command to execute
        const command = generateCheckCommand(firstRule);
        if (!command) {
            addAgentLog(`ERROR: No automated check available for ${firstRule.vulnId}`);
            setIsBatchCapturing(false);
            setAgentState(prev => ({ ...prev, status: 'idle' }));
            return;
        }

        addAgentLog(`Command: ${command}`);
        addAgentLog('Writing command to queue file...');

        try {
            // Execute command in PowerShell and capture screenshot
            // @ts-ignore
            const execResult = await window.ipcRenderer.invoke('execute-command-with-screenshot', {
                command: command,
                groupId: firstRule.vulnId,
                evidenceType: evidenceTypeForScan
            });

            addAgentLog(`Execution completed. Success: ${execResult.success}`);
            if (execResult.error) {
                addAgentLog(`Error: ${execResult.error}`);
            }
            if (execResult.output) {
                addAgentLog(`Output: ${execResult.output.substring(0, 100)}...`);
            }

            // Wait longer to ensure PowerShell has time to process
            await new Promise(r => setTimeout(r, 2000));

            // Check if we got valid results
            if (!execResult.success) {
                addAgentLog(`❌ FIRST COMMAND FAILED - STOPPING`);
                addAgentLog(`Reason: ${execResult.error || 'Unknown error'}`);
                addAgentLog(`Check the PowerShell window to see if commands are executing.`);
                setIsBatchCapturing(false);
                setAgentState(prev => ({ ...prev, status: 'stopped', currentAction: 'First command failed - check PowerShell window' }));
                return;
            }

            // Check if we got output
            if (!execResult.output || execResult.output.trim().length === 0) {
                addAgentLog(`⚠️ WARNING: Command executed but no output received`);
                addAgentLog(`This might mean the command didn't run in PowerShell.`);
            } else {
                addAgentLog(`✅ SUCCESS: Command executed and got output!`);
            }

            // Evaluate the result
            const passed = evaluateCheckResult(firstRule, execResult.output || '');
            const status = passed ? 'pass' : 'fail';

            addAgentLog(`Result: ${status.toUpperCase()} - ${passed ? 'Compliant' : 'Non-Compliant'}`);

            // Generate finding details text
            const dateStr = new Date().toLocaleString();
            // If passed (compliant) = "isn't a finding", if failed (non-compliant) = "is a finding"
            const findingStatus = passed ? "isn't" : "is";
            const findingDetails = `[${dateStr}] - [${scanUsernameValue}] - STRIX Scan was run, the following command was run: ${command} and this was the output ${execResult.output || '(no output)'}\nAccording to the Check Text, this ${findingStatus} a finding. Reference Evidence in ${safeFolder}`;

            // Save evidence with screenshot
            if (execResult.screenshot) {
                addAgentLog(`✅ Screenshot captured (${Math.round(execResult.screenshot.length / 1024)}KB)`);

                // @ts-ignore
                await window.ipcRenderer.invoke('save-evidence', {
                    ruleId: firstRule.vulnId,
                    ruleTitle: firstRule.title,
                    command: command,
                    output: execResult.output || '',
                    status: status,
                    captureScreenshot: false,
                    screenshotDataUrl: execResult.screenshot,
                    folder: safeFolder,
                    findingDetails: findingDetails
                });

                addAgentLog(`✅ Evidence saved for ${firstRule.vulnId}`);
            } else {
                addAgentLog(`❌ Screenshot capture failed - this is a problem!`);
            }

            // Update the results map for UI
            setResults(prev => new Map(prev).set(firstRule.vulnId, {
                ruleId: firstRule.vulnId,
                status: status,
                output: execResult.output || '',
                command: command,
                timestamp: new Date(),
                findingDetails: findingDetails
            }));

            // Confirm first command worked before proceeding
            if (!execResult.success || !execResult.screenshot) {
                addAgentLog(`❌ FIRST COMMAND HAD ISSUES - Stopping`);
                addAgentLog(`Success: ${execResult.success}, Screenshot: ${execResult.screenshot ? 'Yes' : 'No'}`);
                setIsBatchCapturing(false);
                setAgentState(prev => ({ ...prev, status: 'stopped' }));
                await loadEvidence(); // Refresh gallery even on failure
                return;
            }

            // First command successful - continue!
            addAgentLog(`✅ FIRST COMMAND SUCCESSFUL - Processing remaining ${total - 1} commands...`);

        } catch (e: any) {
            console.error(`Error processing ${firstRule.vulnId}:`, e);
            addAgentLog(`❌ CRITICAL ERROR: ${e.message}`);
            setIsBatchCapturing(false);
            setAgentState(prev => ({ ...prev, status: 'stopped' }));
            await loadEvidence(); // Refresh gallery even on error
            return;
        }

        // Process remaining commands automatically - this loop should execute!
        addAgentLog(`🔄 Starting batch processing of ${rulesToProcess.length - 1} remaining commands...`);

        for (let ruleIndex = 1; ruleIndex < rulesToProcess.length; ruleIndex++) {
            // Check if scan was cancelled
            if (scanCancelledRef.current) {
                addAgentLog('⚠️ Scan cancelled - stopping processing');
                setIsBatchCapturing(false);
                setAgentState(prev => ({
                    ...prev,
                    status: 'stopped',
                    currentAction: 'Scan cancelled by user'
                }));
                return;
            }

            const rule = rulesToProcess[ruleIndex];
            processedCount++;

            addAgentLog(`\n--- Processing command ${processedCount}/${total}: ${rule.vulnId} ---`);

            // Update agent state
            setAgentState(prev => ({
                ...prev,
                currentRuleId: rule.vulnId,
                currentAction: `Checking: ${rule.vulnId} - ${rule.title.substring(0, 50)}...`,
                progress: processedCount,
                logs: [...prev.logs.slice(-4), `Processing: ${rule.vulnId} (${rule.severity})`]
            }));

            // Get the command to execute
            const command = generateCheckCommand(rule);
            if (!command) {
                addAgentLog(`Skipping ${rule.vulnId}: No automated check available`);
                continue;
            }

            addAgentLog(`Executing: ${command.substring(0, 60)}...`);

            try {
                // @ts-ignore
                const execResult = await window.ipcRenderer.invoke('execute-command-with-screenshot', {
                    command: command,
                    groupId: rule.vulnId,
                    evidenceType: evidenceTypeForScan
                });

                await new Promise(r => setTimeout(r, 1500));

                if (execResult.success) {
                    const passed = evaluateCheckResult(rule, execResult.output || '');
                    const status = passed ? 'pass' : 'fail';

                    addAgentLog(`${rule.vulnId}: ${status.toUpperCase()}`);

                    // Generate finding details text
                    const dateStr = new Date().toLocaleString();
                    // If passed (compliant) = "isn't a finding", if failed (non-compliant) = "is a finding"
                    const findingStatus = passed ? "isn't" : "is";
                    const findingDetails = `[${dateStr}] - [${scanUsernameValue}] - STRIX Scan was run, the following command was run: ${command} and this was the output ${execResult.output || '(no output)'}\nAccording to the Check Text, this ${findingStatus} a finding. Reference Evidence in ${safeFolder}`;

                    // Save evidence with screenshot
                    if (execResult.screenshot) {
                        // @ts-ignore
                        await window.ipcRenderer.invoke('save-evidence', {
                            ruleId: rule.vulnId,
                            ruleTitle: rule.title,
                            command: command,
                            output: execResult.output || '',
                            status: status,
                            captureScreenshot: false,
                            screenshotDataUrl: execResult.screenshot,
                            folder: safeFolder,
                            findingDetails: findingDetails
                        });
                        addAgentLog(`Screenshot saved for ${rule.vulnId}`);
                    } else {
                        addAgentLog(`⚠️ No screenshot for ${rule.vulnId}`);
                    }

                    // Update results map
                    setResults(prev => new Map(prev).set(rule.vulnId, {
                        ruleId: rule.vulnId,
                        status: status,
                        output: execResult.output || '',
                        command: command,
                        timestamp: new Date(),
                        findingDetails: findingDetails
                    }));
                } else {
                    addAgentLog(`❌ Error: ${execResult.error || 'Unknown error'}`);

                    // Generate finding details for error case
                    const dateStr = new Date().toLocaleString();
                    const findingDetails = `[${dateStr}] - [${scanUsernameValue}] - STRIX Scan was run, the following command was run: ${command} and this was the output ${execResult.output || 'Command execution failed'}\nAccording to the Check Text, this is a finding (error occurred). Reference Evidence in ${safeFolder}`;

                    // Save with error status even if screenshot failed
                    if (execResult.screenshot) {
                        // @ts-ignore
                        await window.ipcRenderer.invoke('save-evidence', {
                            ruleId: rule.vulnId,
                            ruleTitle: rule.title,
                            command: command,
                            output: execResult.output || 'Command execution failed',
                            status: 'error',
                            captureScreenshot: false,
                            screenshotDataUrl: execResult.screenshot,
                            folder: safeFolder,
                            findingDetails: findingDetails
                        });
                    }
                }

            } catch (e: any) {
                addAgentLog(`❌ Exception: ${e.message}`);
            }

            // Small delay between commands
            await new Promise(r => setTimeout(r, 1000));
        }

        setAgentState(prev => ({
            ...prev,
            status: 'complete',
            currentAction: `Scan Complete! ${processedCount}/${total} checks processed`,
            currentRuleId: 'DONE'
        }));

        setIsBatchCapturing(false);

        // Refresh evidence gallery to show all saved screenshots
        await loadEvidence();

        addAgentLog(`✅ Scan complete! ${processedCount} checks processed.`);
        addAgentLog(`Evidence saved to folder: ${safeFolder}`);
    };


    // Open Evidence Capture Modal
    // Open Evidence Capture Modal
    const openEvidenceModal = async (rule: ParsedStigRule) => {
        setEvidenceScreenshot(null); // Clear previous screenshot
        setEvidenceModalRule(rule);
        setEvidenceFolderName(stigInfo.version.replace(/[^a-zA-Z0-9]/g, '_')); // Default folder name
        setShowEvidenceModal(true);
    };

    // Capture evidence for a single rule
    const captureEvidence = async (rule: ParsedStigRule, skipReload = false, folder?: string, screenshotDataUrl?: string) => {
        const result = results.get(rule.vulnId);
        const command = generateCheckCommand(rule);

        // Format: VulnID_CCI (e.g., V-253254_CCI-000366)
        const cciPart = rule.ccis && rule.ccis.length > 0 ? `_${rule.ccis[0]}` : '';
        const ruleIdForFile = `${rule.vulnId}${cciPart}`;

        await window.ipcRenderer.invoke('save-evidence', {
            ruleId: ruleIdForFile,
            ruleTitle: rule.title,
            command: command || 'Manual check',
            output: result?.output || 'No output captured - run check first',
            status: result?.status || 'pending',
            captureScreenshot: false,
            screenshotDataUrl: screenshotDataUrl || null,
            folder: folder || '' // Optional folder for organization
        });
        if (!skipReload) {
            loadEvidence();
        }
    };

    // Confirm and capture from modal
    const confirmCaptureEvidence = async () => {
        if (evidenceModalRule) {
            await captureEvidence(evidenceModalRule, false, evidenceFolderName, evidenceScreenshot || undefined);
            setShowEvidenceModal(false);
            setEvidenceModalRule(null);
            setEvidenceScreenshot(null);
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

    // Clear all evidence
    const clearEvidence = async () => {
        if (window.confirm('Are you sure you want to delete ALL evidence? This cannot be undone.')) {
            await window.ipcRenderer.invoke('clear-evidence');
            setEvidenceList([]);
        }
    };

    // Delete single evidence item
    const deleteEvidenceItem = async (ruleId: string, folder?: string) => {
        if (window.confirm(`Delete evidence for ${ruleId}?`)) {
            await window.ipcRenderer.invoke('delete-evidence', { ruleId, folder });
            await loadEvidence();
        }
    };

    // Create new evidence folder
    const [showNewFolderModal, setShowNewFolderModal] = useState(false);
    const [newFolderName, setNewFolderName] = useState('');
    const createEvidenceFolder = async () => {
        if (newFolderName.trim()) {
            await window.ipcRenderer.invoke('create-evidence-folder', newFolderName.trim());
            setShowNewFolderModal(false);
            setNewFolderName('');
            await loadEvidence();
        }
    };

    // Delete Evidence Folder
    const deleteEvidenceFolder = async (folderName: string) => {
        if (window.confirm(`Are you sure you want to PERMANENTLY delete the folder "${folderName}" and all its contents?`)) {
            const result = await window.ipcRenderer.invoke('delete-evidence-folder', folderName);
            if (result.success) {
                await loadEvidence();
            } else {
                alert(`Error deleting folder: ${result.error}`);
            }
        }
    };

    // Collapsed Folders State
    const [collapsedFolders, setCollapsedFolders] = useState<Set<string>>(new Set());
    const toggleFolder = (folderName: string) => {
        setCollapsedFolders(prev => {
            const next = new Set(prev);
            if (next.has(folderName)) next.delete(folderName);
            else next.add(folderName);
            return next;
        });
    };

    // Helper to merge images vertically
    const mergeImages = async (images: string[]): Promise<string | null> => {
        if (!images.length) return null;

        const loadedButtonImages = await Promise.all(images.map(src => new Promise<HTMLImageElement>((resolve, reject) => {
            const img = new Image();
            img.onload = () => resolve(img);
            img.onerror = reject;
            img.src = src;
        })));

        const width = Math.max(...loadedButtonImages.map(img => img.width));
        const height = loadedButtonImages.reduce((acc, img) => acc + img.height + 20, 0); // 20px padding

        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;

        // Fill white background
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, width, height);

        let yOffset = 0;
        loadedButtonImages.forEach((img) => {
            ctx.drawImage(img, 0, yOffset);
            yOffset += img.height + 20;
        });

        return canvas.toDataURL('image/png');
    };

    // Export Evidence as Word Doc (HTML with .doc extension)
    const exportToWord = async () => {
        if (evidenceList.length === 0) return;

        const content: string[] = [];

        // CSS Styles for Word
        content.push(`
            <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
            <head>
                <meta charset="utf-8">
                <style>
                    body { font-family: 'Calibri', sans-serif; }
                    h1 { color: #2E74B5; font-size: 24pt; border-bottom: 2px solid #2E74B5; padding-bottom: 10px; }
                    h2 { color: #1F4D78; font-size: 18pt; margin-top: 20px; background-color: #f2f2f2; padding: 5px; }
                    h3 { font-size: 14pt; color: #444; border-bottom: 1px solid #ddd; margin-top: 15px; }
                    .item { border: 1px solid #ddd; padding: 10px; margin-bottom: 20px; }
                    .meta { font-size: 10pt; color: #666; margin-bottom: 10px; }
                    .status { font-weight: bold; color: white; padding: 2px 6px; border-radius: 4px; }
                    .pass { background-color: #2e7d32; }
                    .fail { background-color: #d32f2f; }
                    .code { background-color: #f5f5f5; font-family: 'Consolas', monospace; padding: 10px; border: 1px solid #ccc; white-space: pre-wrap; font-size: 9pt; }
                    img { max-width: 600px; height: auto; border: 1px solid #999; margin-top: 10px; display: block; }
                </style>
            </head>
            <body>
                <h1>STIG Evidence Report</h1>
                <p>Generated: ${new Date().toLocaleString()}</p>
                <p>Total Items: ${evidenceList.length}</p>
        `);

        // Group by folder
        const grouped: Record<string, typeof evidenceList> = {};
        evidenceList.forEach(item => {
            const folder = item.folder || 'General Evidence';
            if (!grouped[folder]) grouped[folder] = [];
            grouped[folder].push(item);
        });

        // Loop folders
        for (const folder of Object.keys(grouped).sort()) {
            content.push(`<h2>📁 ${folder}</h2>`);

            for (const item of grouped[folder]) {
                const statusColor = item.status === 'pass' ? 'pass' : item.status === 'fail' ? 'fail' : 'code';
                content.push(`
                    <div class="item">
                        <h3>${item.ruleId} - ${item.ruleTitle}</h3>
                        <div class="meta">
                            Status: <span class="status ${statusColor}">${item.status.toUpperCase()}</span> | 
                            Time: ${item.timestampReadable}
                        </div>
                        
                        <p><strong>Command:</strong></p>
                        <div class="code">${item.command}</div>
                        
                        <p><strong>Output:</strong></p>
                        <div class="code">${item.output}</div>
                `);

                // Embed screenshot if exists
                if (item.screenshotPath) {
                    try {
                        const result = await window.ipcRenderer.invoke('read-file-base64', item.screenshotPath);
                        if (result.success && result.data) {
                            content.push(`
                                <p><strong>Evidence Screenshot:</strong></p>
                                <img src="data:image/png;base64,${result.data}" width="600" />
                                <br/>
                                <small style="color:#999; font-size:8pt;">Source: ${item.screenshotPath}</small>
                            `);
                        } else {
                            content.push(`<p style="color:red;"><em>Failed to load image: ${result.error || 'Unknown error'}</em></p>`);
                        }
                    } catch (e) {
                        content.push(`<p style="color:red;"><em>Error loading image: ${e}</em></p>`);
                    }
                }

                content.push(`</div>`);
            }
        }

        content.push(`</body></html>`);

        // Create Blob and Download
        const blob = new Blob([content.join('')], { type: 'application/msword' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `STIG_Evidence_Report_${new Date().toISOString().split('T')[0]}.doc`;
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
                setUploadedChecklists(prev => [...prev, ...newChecklists as any]);
            } else {
                setPoamChecklists(prev => [...prev, ...newChecklists as any]);
            }
        }
        if (newAcasRows.length > 0) {
            setAcasData(prev => [...prev, ...newAcasRows as any]);
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
                        <div className={`size-10 rounded-xl flex items-center justify-center shadow-lg overflow-hidden ${darkMode ? 'bg-slate-800' : 'bg-slate-900'}`}>
                            <img src="/strix-logo.svg" alt="STRIX" className="size-9" />
                        </div>
                        <div className="flex flex-col">
                            <span className="font-bold text-lg tracking-tight">STRIX</span>
                            <span className={`text-[10px] -mt-1 ${darkMode ? 'text-cyan-400' : 'text-cyan-600'}`}>Security Platform</span>
                        </div>
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
                    <SidebarItem icon={<Network size={18} />} label="Network Diagram" active={activeTab === 'network'} onClick={() => setActiveTab('network')} darkMode={darkMode} />
                    <SidebarItem icon={<Globe size={18} />} label="Web Scanner" active={activeTab === 'webscan'} onClick={() => setActiveTab('webscan')} darkMode={darkMode} />
                    <SidebarItem icon={<Code size={18} />} label="Code Scanner" active={activeTab === 'codescan'} onClick={() => setActiveTab('codescan')} darkMode={darkMode} />
                    <SidebarItem icon={<Link size={18} />} label="Blockchain" active={activeTab === 'blockchain'} onClick={() => setActiveTab('blockchain')} darkMode={darkMode} />

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
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('master_copy'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'master_copy'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Master Copy
                                </button>
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('extractor'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'extractor'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Extractor
                                </button>
                                <button
                                    onClick={() => { setActiveTab('tools'); setToolsMode('reportanalyzer'); }}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${activeTab === 'tools' && toolsMode === 'reportanalyzer'
                                        ? (darkMode ? 'bg-gray-800 text-blue-400 font-medium' : 'bg-white text-blue-600 font-medium shadow-sm')
                                        : (darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50')
                                        }`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Report Analyzer
                                </button>
                                <button
                                    onClick={() => setShowDocsModal(true)}
                                    className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50'}`}
                                >
                                    <div className="size-1 rounded-full bg-current opacity-50" />
                                    Docs
                                </button>

                                {/* Useful Links Section */}
                                <div className="mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
                                    <div className="px-3 mb-2">
                                        <h3 className="text-xs font-semibold uppercase text-gray-500">Useful Links</h3>
                                    </div>
                                    <a
                                        href="https://i-assure.com/products/rmf-templates/"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50'}`}
                                    >
                                        <ExternalLink size={14} />
                                        <span>RMF Templates</span>
                                    </a>
                                    <a
                                        href="https://patches.csd.disa.mil/"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50'}`}
                                    >
                                        <ExternalLink size={14} />
                                        <span>DoD Repo</span>
                                    </a>
                                    <a
                                        href="https://www.archives.gov/cui/registry/category-detail/personnel-records"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50'}`}
                                    >
                                        <ExternalLink size={14} />
                                        <span>CUI</span>
                                    </a>
                                    <a
                                        href="https://nam10.safelinks.protection.outlook.com/?url=https%3A%2F%2Fspork.navsea.navy.mil%2Fnswc-crane-division%2Fevaluate-stig%2F-%2Freleases&data=05%7C02%7Crgaertner%40deloitte.com%7Ca651e843956d42bd3fdf08de53a40e1b%7C36da45f1dd2c4d1faf135abe46b99921%7C0%7C0%7C639040161322443506%7CUnknown%7CTWFpbGZsb3d8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbCIsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=pEcXKOoMlDLpKyu%2Btm%2BYkvrDSltyJ%2FmyCkDLyVAvXAI%3D&reserved=0"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${darkMode ? 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50' : 'text-gray-500 hover:text-gray-900 hover:bg-white/50'}`}
                                    >
                                        <ExternalLink size={14} />
                                        <span>Evaluate STIG</span>
                                    </a>
                                </div>
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
                                    <div className="flex items-center gap-3 mb-1">
                                        <select
                                            value={stigInfo.stigId}
                                            onChange={(e) => loadStigFile(e.target.value)}
                                            className={`text-xl font-semibold tracking-tight cursor-pointer px-3 py-2 rounded-lg border transition-colors ${darkMode ? 'text-white bg-gray-800 border-gray-700 hover:border-gray-600' : 'text-gray-900 bg-gray-50 border-gray-200 hover:border-gray-400'}`}
                                        >
                                            {Object.entries(STIG_PATHS).map(([id, info]) => (
                                                <option key={id} value={id} className="text-gray-900 text-base">
                                                    {info.name}
                                                </option>
                                            ))}
                                        </select>
                                    </div>
                                    <p className={`pl-3 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
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
                                        onClick={runAgent}
                                        disabled={isBatchCapturing || rules.length === 0}
                                        className="bg-black hover:bg-black/80 disabled:bg-gray-300 disabled:cursor-not-allowed text-white px-4 py-2.5 rounded-full text-sm font-medium transition-all flex items-center gap-2 shadow-lg"
                                    >
                                        {isBatchCapturing ? <Loader2 className="size-4 animate-spin" /> : <Cpu className="size-4" />}
                                        {isBatchCapturing ? 'Scanning...' : 'Run Scan'}
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

                                                    {result?.findingDetails && (
                                                        <div className="mt-3 bg-blue-50 rounded-lg p-3 text-xs border border-blue-100">
                                                            <div className="flex justify-between text-blue-600 mb-1 pb-1 border-b border-blue-200 font-semibold">
                                                                <span>Finding Details</span>
                                                            </div>
                                                            <pre className="whitespace-pre-wrap text-gray-700 text-xs leading-relaxed">{result.findingDetails}</pre>
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
                                    <button
                                        onClick={() => setShowNewFolderModal(true)}
                                        className="bg-blue-50 hover:bg-blue-100 text-blue-600 border border-blue-200 px-4 py-2 rounded-full text-sm font-medium flex items-center gap-2 transition-colors"
                                    >
                                        <FolderPlus size={16} /> New Folder
                                    </button>
                                    <button
                                        onClick={clearEvidence}
                                        disabled={evidenceList.length === 0}
                                        className="bg-red-50 hover:bg-red-100 disabled:bg-gray-100 text-red-600 disabled:text-gray-400 border border-red-200 disabled:border-gray-200 px-4 py-2 rounded-full text-sm font-medium flex items-center gap-2 transition-colors"
                                    >
                                        <Trash2 size={16} /> Clear All
                                    </button>
                                    <button onClick={exportToWord} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-full text-sm font-medium flex items-center gap-2">
                                        <FileText size={16} /> Export Doc
                                    </button>
                                    <button onClick={loadEvidence} className="p-2 hover:bg-gray-100 rounded-lg text-gray-500">
                                        <RefreshCw size={18} />
                                    </button>
                                </div>
                            </div>

                            {/* Evidence List - Grouped by Folder */}
                            <div className="space-y-6">
                                {(() => {
                                    // Group evidence by folder
                                    const grouped: Record<string, typeof evidenceList> = {};
                                    evidenceList.forEach(item => {
                                        const folder = item.folder || 'Ungrouped';
                                        if (!grouped[folder]) grouped[folder] = [];
                                        grouped[folder].push(item);
                                    });

                                    const folders = Object.keys(grouped).sort();

                                    if (folders.length === 0) {
                                        return (
                                            <div className="py-20 text-center text-gray-400 border-2 border-dashed border-gray-200 rounded-xl">
                                                <Camera className="mx-auto size-12 mb-4 opacity-20" />
                                                <p className="font-medium text-lg">No evidence captured yet</p>
                                                <p className="text-sm mt-1">Run a check and click the camera icon to capture evidence</p>
                                            </div>
                                        );
                                    }

                                    return folders.map(folder => {
                                        const isCollapsed = collapsedFolders.has(folder);
                                        return (
                                            <div key={folder} className="border border-gray-200 rounded-xl overflow-hidden">
                                                <div
                                                    className="bg-gray-100 px-5 py-3 border-b border-gray-200 flex items-center justify-between cursor-pointer hover:bg-gray-200 transition-colors"
                                                    onClick={() => toggleFolder(folder)}
                                                >
                                                    <div className="flex items-center gap-3">
                                                        {isCollapsed ? <ChevronRight size={18} className="text-gray-500" /> : <ChevronDown size={18} className="text-gray-500" />}
                                                        <FolderOpen size={18} className="text-gray-500" />
                                                        <span className="font-medium text-gray-700">{folder}</span>
                                                        <span className="text-xs bg-gray-200 text-gray-600 px-2 py-0.5 rounded-full">{grouped[folder].length} items</span>
                                                    </div>
                                                    {folder !== 'Ungrouped' && (
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); deleteEvidenceFolder(folder); }}
                                                            className="p-1.5 text-gray-400 hover:text-red-500 hover:bg-white rounded-lg transition-colors"
                                                            title="Delete Folder"
                                                        >
                                                            <Trash2 size={16} />
                                                        </button>
                                                    )}
                                                </div>
                                                {!isCollapsed && (
                                                    <div className="divide-y divide-gray-100">
                                                        {grouped[folder].map((item, idx) => (
                                                            <div key={idx} className="bg-white hover:bg-gray-50 transition-all group">
                                                                <div className="flex items-center justify-between px-5 py-3">
                                                                    <div className="flex items-center gap-3">
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${item.status === 'pass' ? 'bg-green-100 text-green-700' :
                                                                            item.status === 'fail' ? 'bg-red-100 text-red-600' :
                                                                                'bg-gray-100 text-gray-600'
                                                                            }`}>{item.status}</span>
                                                                        <span className="font-mono text-sm font-medium text-gray-700">{item.ruleId}</span>
                                                                    </div>
                                                                    <div className="flex items-center gap-3">
                                                                        <div className="text-xs text-gray-400 font-mono">
                                                                            {item.timestampReadable}
                                                                        </div>
                                                                        <button
                                                                            onClick={() => deleteEvidenceItem(item.ruleId, item.folder)}
                                                                            className="p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors opacity-0 group-hover:opacity-100"
                                                                            title="Delete Evidence"
                                                                        >
                                                                            <Trash2 size={14} />
                                                                        </button>
                                                                    </div>
                                                                </div>

                                                                <div className="px-5 pb-4">
                                                                    <div className="text-sm font-medium text-gray-700 mb-3">{item.ruleTitle}</div>

                                                                    <div className="space-y-3">
                                                                        {/* Screenshot Image - MOST IMPORTANT */}
                                                                        {item.screenshotPath && (
                                                                            <div>
                                                                                <div className="text-xs font-semibold text-gray-400 uppercase mb-1">PowerShell Screenshot</div>
                                                                                <div className="border-2 border-gray-200 rounded-lg overflow-hidden bg-gray-900">
                                                                                    <img
                                                                                        src={item.screenshotUrl || `file://${item.screenshotPath}`}
                                                                                        alt={`Screenshot for ${item.ruleId}`}
                                                                                        className="w-full h-auto"
                                                                                        onError={(e) => {
                                                                                            // Fallback: try reading file directly
                                                                                            if (isElectron && item.screenshotPath) {
                                                                                                window.ipcRenderer.invoke('read-file-base64', item.screenshotPath).then((result: any) => {
                                                                                                    if (result.success) {
                                                                                                        (e.target as HTMLImageElement).src = `data:image/png;base64,${result.data}`;
                                                                                                    }
                                                                                                });
                                                                                            }
                                                                                        }}
                                                                                    />
                                                                                </div>
                                                                            </div>
                                                                        )}

                                                                        <div>
                                                                            <div className="text-xs font-semibold text-gray-400 uppercase mb-1">Command</div>
                                                                            <div className="bg-gray-900 text-green-400 font-mono text-xs p-3 rounded-lg overflow-x-auto">
                                                                                <pre className="whitespace-pre-wrap">{item.command}</pre>
                                                                            </div>
                                                                        </div>

                                                                        <div>
                                                                            <div className="text-xs font-semibold text-gray-400 uppercase mb-1">Output</div>
                                                                            <div className="bg-gray-50 font-mono text-xs p-3 rounded-lg border border-gray-100 max-h-32 overflow-auto">
                                                                                <pre className="whitespace-pre-wrap text-gray-700">{item.output}</pre>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    });
                                })()}
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
                                                    {/* Duplicate Import Button Removed */}
                                                </div>
                                            </div>

                                            {/* Filters in Header */}
                                            <div className="flex items-center gap-2 flex-1 justify-end">
                                                <div className={`flex items-center rounded-md border px-2 py-1 gap-2 ${darkMode ? 'bg-gray-900 border-gray-600' : 'bg-white border-gray-300'}`}>
                                                    <Filter size={12} className="text-gray-400" />
                                                    <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} className={`bg-transparent text-xs font-medium outline-none w-24 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                                                        <option value="All">All Status</option>
                                                        <option value="Open">Open</option>
                                                        <option value="NotAFinding">Not A Finding</option>
                                                        <option value="Not_Reviewed">Pending</option>
                                                        <option value="Not_Applicable">N/A</option>
                                                    </select>
                                                    <div className="w-px h-3 bg-gray-300 dark:bg-gray-600"></div>
                                                    <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} className={`bg-transparent text-xs font-medium outline-none w-24 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}>
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
                                                        className={`bg-transparent text-xs outline-none flex-1 ${darkMode ? 'text-gray-200' : 'text-gray-900'}`}
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
                                            <div className={`flex-1 flex flex-col ${darkMode ? 'bg-gray-900' : 'bg-gray-50'} overflow-hidden relative`}>
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
                                                    <div className="flex flex-col items-center justify-center h-full text-gray-400 gap-4 opacity-70">
                                                        <div className={`w-20 h-20 rounded-2xl flex items-center justify-center mb-2 ${darkMode ? 'bg-gray-800' : 'bg-white border shadow-sm'}`}>
                                                            <Target size={40} className="opacity-50" />
                                                        </div>
                                                        <h3 className="text-lg font-semibold">No Finding Selected</h3>
                                                        <p className="text-sm max-w-xs text-center leading-relaxed">Select a finding from the list on the left to view and edit details, status, and comments.</p>
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
                                                {(['cat1', 'cat2', 'cat3'] as const).map(cat => {
                                                    const isActive = poamActiveCat === cat;
                                                    return (
                                                        <button
                                                            key={cat}
                                                            onClick={() => setPoamActiveCat(cat)}
                                                            className={`px-3 py-1 rounded-md text-[10px] font-bold uppercase transition-all focus:outline-none ${isActive
                                                                ? 'bg-white dark:bg-gray-600 text-blue-600 dark:text-blue-400 shadow-sm'
                                                                : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                                                                }`}
                                                        >
                                                            {cat === 'cat1' ? 'CAT I' : cat === 'cat2' ? 'CAT II' : 'CAT III'}
                                                        </button>
                                                    );
                                                })}
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

                            <div className={`grid gap-6 ${toolsMode === 'analyzer' || toolsMode === 'reportanalyzer' || toolsMode === 'master_copy' ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-4'}`}>
                                {/* Tools Sidebar/Menu */}
                                {toolsMode !== 'analyzer' && toolsMode !== 'reportanalyzer' && toolsMode !== 'master_copy' && (
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
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${(toolsMode as string) === 'analyzer'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <GitCompare size={18} />
                                            <div className="font-medium">STIG Analyzer</div>
                                        </button>
                                        <button
                                            onClick={() => setToolsMode('master_copy')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${(toolsMode as string) === 'master_copy'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <Copy size={18} />
                                            <div className="font-medium">Master Copy</div>
                                        </button>
                                        <button
                                            onClick={() => setToolsMode('extractor')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${toolsMode === 'extractor'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <Download size={18} />
                                            <div className="font-medium">Extractor</div>
                                        </button>
                                        <button
                                            onClick={() => setToolsMode('reportanalyzer')}
                                            className={`w-full text-left px-4 py-3 rounded-xl flex items-center gap-3 transition-colors ${(toolsMode as string) === 'reportanalyzer'
                                                ? (darkMode ? 'bg-blue-600 text-white shadow-lg' : 'bg-black text-white shadow-lg')
                                                : (darkMode ? 'hover:bg-gray-800 text-gray-400' : 'hover:bg-gray-100 text-gray-600')}`}
                                        >
                                            <FileWarning size={18} />
                                            <div className="font-medium">Report Analyzer</div>
                                        </button>
                                    </div>
                                )}

                                {/* Tool Content */}
                                <div className={toolsMode === 'analyzer' || toolsMode === 'reportanalyzer' || toolsMode === 'master_copy' ? '' : 'md:col-span-3'}>
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
                                                {/* Hostname Display */}
                                                {(analyzerOldChecklist?.hostname || analyzerNewChecklist?.hostname) && (
                                                    <div className={`px-4 py-2 rounded-lg text-sm font-medium border ${darkMode ? 'bg-gray-800 border-gray-700 text-gray-300' : 'bg-gray-50 border-gray-200 text-gray-600'}`}>
                                                        <span className="text-gray-400 mr-2 uppercase text-xs tracking-wider">Host:</span>
                                                        {analyzerOldChecklist?.hostname || analyzerNewChecklist?.hostname}
                                                    </div>
                                                )}
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
                                                    <div className="flex flex-col gap-4 mb-6">
                                                        <div className="flex bg-gray-100 dark:bg-gray-800 p-1 rounded-xl">
                                                            <button
                                                                onClick={() => { setAnalyzerTab('notreviewed'); setAnalyzerSelectedIds(new Set()); }}
                                                                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${analyzerTab === 'notreviewed' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                                                            >
                                                                Not Reviewed ({analyzerData.notReviewed.length})
                                                            </button>
                                                            <button
                                                                onClick={() => { setAnalyzerTab('reviewed'); setAnalyzerSelectedIds(new Set()); }}
                                                                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${analyzerTab === 'reviewed' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                                                            >
                                                                Reviewed ({analyzerShowAllReviewed ? (analyzerNewChecklist?.findings.filter(f => f.status !== 'Not_Reviewed').length || 0) : analyzerEditedIds.size})
                                                            </button>
                                                            <button
                                                                onClick={() => { setAnalyzerTab('newids'); setAnalyzerSelectedIds(new Set()); }}
                                                                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${analyzerTab === 'newids' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                                                            >
                                                                New IDs ({analyzerData.newIds.length})
                                                            </button>
                                                            <button
                                                                onClick={() => { setAnalyzerTab('droppedids'); setAnalyzerSelectedIds(new Set()); }}
                                                                className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${analyzerTab === 'droppedids' ? 'bg-white shadow text-purple-600' : 'text-gray-500 hover:text-gray-700'}`}
                                                            >
                                                                Dropped IDs ({analyzerData.droppedIds.length})
                                                            </button>
                                                        </div>
                                                    </div>

                                                    {/* Report Controls (Image, Excel, CKLB) */}
                                                    <div className="ml-auto flex gap-2">
                                                        {(() => {
                                                            const handleExportExcel = () => {
                                                                if (!analyzerData) return;
                                                                const wb = XLSX.utils.book_new();

                                                                // 1. Not Reviewed Sheet
                                                                const notReviewedData = analyzerData.notReviewed.map(r => ({
                                                                    GroupID: r.vulnId,
                                                                    RuleID: r.oldFinding.ruleId,
                                                                    Title: r.oldFinding.title,
                                                                    Severity: r.oldFinding.severity,
                                                                    OldStatus: r.oldFinding.status,
                                                                    NewStatus: 'Not_Reviewed',
                                                                    Discussion: r.oldFinding.description,
                                                                    CheckText: r.oldFinding.checkText,
                                                                    FixText: r.oldFinding.fixText
                                                                }));
                                                                XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(notReviewedData), "Not Reviewed");

                                                                // 2. Reviewed Sheet
                                                                const reviewedFindings = analyzerNewChecklist?.findings.filter((f: any) =>
                                                                    analyzerEditedIds.has(f.vulnId) ||
                                                                    (f.status !== 'Not_Reviewed')
                                                                ) || [];

                                                                const reviewedData = reviewedFindings.map((f: any) => ({
                                                                    GroupID: f.vulnId,
                                                                    RuleID: f.ruleId,
                                                                    Title: f.title,
                                                                    Severity: f.severity,
                                                                    Status: f.status,
                                                                    Details: f.findingDetails,
                                                                    Comments: f.comments,
                                                                    Discussion: f.description,
                                                                    CheckText: f.checkText,
                                                                    FixText: f.fixText
                                                                }));
                                                                XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(reviewedData), "Reviewed");

                                                                // 3. New IDs Sheet
                                                                const newIdsData = analyzerData.newIds.map(r => ({
                                                                    GroupID: r.vulnId,
                                                                    RuleID: r.finding.ruleId,
                                                                    Title: r.finding.title,
                                                                    Severity: r.finding.severity,
                                                                    Status: r.finding.status,
                                                                    Discussion: r.finding.description
                                                                }));
                                                                XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(newIdsData), "New IDs");

                                                                // 4. Dropped IDs Sheet
                                                                const droppedIdsData = analyzerData.droppedIds.map(r => ({
                                                                    GroupID: r.vulnId,
                                                                    RuleID: r.finding.ruleId,
                                                                    Title: r.finding.title,
                                                                    Severity: r.finding.severity,
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
                                                                    <button onClick={handleCopyImage} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors text-xs font-medium border ${darkMode ? 'border-gray-700 hover:bg-gray-800 text-gray-300' : 'border-gray-200 hover:bg-gray-50 text-gray-600'}`} title="Copy Analyzer View to Clipboard"><Camera size={14} /> Copy</button>
                                                                    <button onClick={handleExportExcel} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors text-xs font-medium border ${darkMode ? 'border-gray-700 hover:bg-gray-800 text-green-400' : 'border-gray-200 hover:bg-gray-50 text-green-600'}`} title="Export Full Report to Excel"><FileSpreadsheet size={14} /> Report</button>
                                                                    <button onClick={handleExportCKLB} className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-xs font-medium" title="Export CKLB for STIG Viewer"><Download size={14} /> CKLB</button>
                                                                </>
                                                            );
                                                        })()}
                                                    </div>
                                                </>
                                            )}

                                            {/* Controls Row - Only for Not Reviewed */}
                                            {analyzerData.notReviewed.length > 0 && analyzerTab === 'notreviewed' && (
                                                <div className="sticky top-0 z-10 flex items-center justify-between bg-white dark:bg-gray-800 p-3 rounded-lg border border-gray-200 dark:border-gray-700 mb-4 shadow-sm">
                                                    <div className="flex items-center gap-4">
                                                        <label className="flex items-center gap-2 text-sm font-medium cursor-pointer select-none">
                                                            <input
                                                                type="checkbox"
                                                                checked={analyzerData.notReviewed.length > 0 && analyzerSelectedIds.size === analyzerData.notReviewed.length}
                                                                onChange={(e) => {
                                                                    if (e.target.checked) setAnalyzerSelectedIds(new Set(analyzerData.notReviewed.map(r => r.vulnId)));
                                                                    else setAnalyzerSelectedIds(new Set());
                                                                }}
                                                                className="rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                                                            />
                                                            Select All
                                                        </label>
                                                        <div className="h-4 w-px bg-gray-300 dark:bg-gray-600" />

                                                        {/* Bulk Actions */}
                                                        {analyzerSelectedIds.size > 0 ? (
                                                            <div className="flex items-center gap-2 animate-in fade-in slide-in-from-left-2 duration-200">
                                                                <span className="text-xs font-semibold text-purple-600 bg-purple-50 px-2 py-1 rounded-md">{analyzerSelectedIds.size} Selected</span>
                                                                <div className="h-4 w-px bg-gray-300 dark:bg-gray-600 mx-2" />
                                                                <button
                                                                    onClick={() => {
                                                                        if (!confirm(`Copy STATUS for ${analyzerSelectedIds.size} items?`)) return;
                                                                        setAnalyzerNewChecklist((prev: any) => {
                                                                            if (!prev) return null;
                                                                            const newFindings = prev.findings.map((f: any) => {
                                                                                if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                    const match = analyzerData.notReviewed.find(nr => nr.vulnId === f.vulnId);
                                                                                    if (match) return { ...f, status: match.oldFinding.status };
                                                                                }
                                                                                return f;
                                                                            });
                                                                            return { ...prev, findings: newFindings };
                                                                        });
                                                                        setAnalyzerEditedIds(prev => {
                                                                            const next = new Set(prev);
                                                                            analyzerSelectedIds.forEach(id => next.add(id));
                                                                            return next;
                                                                        });
                                                                        setAnalyzerSelectedIds(new Set());
                                                                    }}
                                                                    className="px-3 py-1.5 text-xs font-medium bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
                                                                >
                                                                    Copy Status
                                                                </button>
                                                                <button
                                                                    onClick={() => {
                                                                        if (!confirm(`Copy DETAILS for ${analyzerSelectedIds.size} items?`)) return;
                                                                        setAnalyzerNewChecklist((prev: any) => {
                                                                            if (!prev) return null;
                                                                            const newFindings = prev.findings.map((f: any) => {
                                                                                if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                    const match = analyzerData.notReviewed.find(nr => nr.vulnId === f.vulnId);
                                                                                    if (match) {
                                                                                        const details = match.oldFinding.findingDetails || match.oldFinding.comments || '';
                                                                                        return { ...f, findingDetails: details };
                                                                                    }
                                                                                }
                                                                                return f;
                                                                            });
                                                                            return { ...prev, findings: newFindings };
                                                                        });
                                                                        setAnalyzerEditedIds(prev => {
                                                                            const next = new Set(prev);
                                                                            analyzerSelectedIds.forEach(id => next.add(id));
                                                                            return next;
                                                                        });
                                                                        setAnalyzerSelectedIds(new Set());
                                                                    }}
                                                                    className="px-3 py-1.5 text-xs font-medium bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors shadow-sm"
                                                                >
                                                                    Copy Details
                                                                </button>
                                                                <button
                                                                    onClick={() => {
                                                                        if (!confirm(`Copy BOTH (Status & Details) for ${analyzerSelectedIds.size} items?`)) return;
                                                                        setAnalyzerNewChecklist((prev: any) => {
                                                                            if (!prev) return null;
                                                                            const newFindings = prev.findings.map((f: any) => {
                                                                                if (analyzerSelectedIds.has(f.vulnId)) {
                                                                                    const match = analyzerData.notReviewed.find(nr => nr.vulnId === f.vulnId);
                                                                                    if (match) {
                                                                                        const details = match.oldFinding.findingDetails || match.oldFinding.comments || '';
                                                                                        return { ...f, status: match.oldFinding.status, findingDetails: details };
                                                                                    }
                                                                                }
                                                                                return f;
                                                                            });
                                                                            return { ...prev, findings: newFindings };
                                                                        });
                                                                        setAnalyzerEditedIds(prev => {
                                                                            const next = new Set(prev);
                                                                            analyzerSelectedIds.forEach(id => next.add(id));
                                                                            return next;
                                                                        });
                                                                        setAnalyzerSelectedIds(new Set());
                                                                    }}
                                                                    className="px-3 py-1.5 text-xs font-medium bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors shadow-sm"
                                                                >
                                                                    Copy Both
                                                                </button>
                                                            </div>
                                                        ) : (
                                                            <div className="flex items-center gap-2 text-xs">
                                                                <span className="text-gray-500 font-medium">Sort By:</span>
                                                                {(['severity', 'groupid', 'status'] as const).map(key => (
                                                                    <button
                                                                        key={key}
                                                                        onClick={() => setAnalyzerSort(prev => ({ key, dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc' }))}
                                                                        className={`px-2 py-1 rounded capitalize transition-colors ${analyzerSort.key === key ? 'bg-purple-100 text-purple-700 font-semibold' : 'text-gray-500 hover:bg-gray-100'}`}
                                                                    >
                                                                        {key === 'groupid' ? 'Group ID' : key} {analyzerSort.key === key && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                                    </button>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="text-xs text-gray-500 font-medium">
                                                        {analyzerSelectedIds.size > 0 ? `${analyzerSelectedIds.size} selected` : `Showing ${analyzerData.notReviewed.length} items`}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Not Reviewed Tab */}
                                            {analyzerTab === 'notreviewed' && (
                                                <div className="space-y-4">
                                                    {sortedNotReviewed.map((row) => (
                                                        <div key={row.vulnId} className={`p-4 rounded-xl border transition-all ${analyzerSelectedIds.has(row.vulnId) ? 'border-purple-300 bg-purple-50/30 dark:bg-purple-900/10' : (darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200')}`}>
                                                            {/* Header */}
                                                            <div className="flex items-start justify-between mb-3">
                                                                <div className="flex items-center gap-3">
                                                                    <input
                                                                        type="checkbox"
                                                                        checked={analyzerSelectedIds.has(row.vulnId)}
                                                                        onChange={(e) => {
                                                                            const newSet = new Set(analyzerSelectedIds);
                                                                            if (e.target.checked) newSet.add(row.vulnId);
                                                                            else newSet.delete(row.vulnId);
                                                                            setAnalyzerSelectedIds(newSet);
                                                                        }}
                                                                        className="mt-1 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                                                                    />
                                                                    <button
                                                                        onClick={() => setAnalyzerExpandedRows(prev => {
                                                                            const next = new Set(prev);
                                                                            if (next.has(row.vulnId)) next.delete(row.vulnId);
                                                                            else next.add(row.vulnId);
                                                                            return next;
                                                                        })}
                                                                        className="mt-0.5 p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400"
                                                                    >
                                                                        {analyzerExpandedRows.has(row.vulnId) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                                                    </button>
                                                                    <div>
                                                                        <div className="flex items-center gap-2">
                                                                            <span className="text-sm font-mono font-bold">{row.vulnId}</span>
                                                                            <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${(row.oldFinding.severity || '').toLowerCase().includes('high') || (row.oldFinding.severity || '').toLowerCase().includes('cat i') ? 'bg-red-100 text-red-700' :
                                                                                (row.oldFinding.severity || '').toLowerCase().includes('medium') || (row.oldFinding.severity || '').toLowerCase().includes('cat ii') ? 'bg-orange-100 text-orange-700' :
                                                                                    'bg-yellow-100 text-yellow-700'
                                                                                }`}>
                                                                                {row.oldFinding.severity}
                                                                            </span>
                                                                        </div>
                                                                        <div className="text-xs text-gray-500 mt-1 max-w-md truncate">{row.oldFinding.title}</div>
                                                                    </div>
                                                                </div>

                                                                {/* Status Badge Compare */}
                                                                <div className="flex items-center gap-2">
                                                                    <div className="flex flex-col items-end">
                                                                        <span className="text-[10px] uppercase text-gray-400 font-semibold tracking-wider">Old Status</span>
                                                                        <div className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${(row.oldFinding.status || '').toLowerCase().includes('open') ? 'bg-red-50 border-red-100 text-red-600' :
                                                                            (row.oldFinding.status || '').toLowerCase().includes('notafinding') ? 'bg-green-50 border-green-100 text-green-600' :
                                                                                'bg-gray-50 border-gray-100 text-gray-600'
                                                                            }`}>
                                                                            {row.oldFinding.status}
                                                                        </div>
                                                                    </div>
                                                                    <ArrowRight size={14} className="text-gray-300 mt-4" />
                                                                    <div className="flex flex-col items-start">
                                                                        <span className="text-[10px] uppercase text-gray-400 font-semibold tracking-wider">New Status</span>
                                                                        <div className={`px-2 py-0.5 rounded text-xs font-bold uppercase border bg-gray-50 border-gray-100 text-gray-400`}>
                                                                            Not Reviewed
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            </div>

                                                            {/* Expandable Details */}
                                                            {analyzerExpandedRows.has(row.vulnId) && (
                                                                <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-900/50 rounded-lg border border-gray-100 dark:border-gray-800 text-xs text-gray-600 dark:text-gray-300 space-y-3 animate-in fade-in slide-in-from-top-1">
                                                                    <div>
                                                                        <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Rule Title</div>
                                                                        <div className="pl-2 border-l-2 border-gray-200">{row.oldFinding.title}</div>
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Vulnerability Discussion</div>
                                                                        <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{row.oldFinding.description}</div>
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Check Text (Procedure)</div>
                                                                        <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{row.oldFinding.checkText}</div>
                                                                    </div>
                                                                    <div>
                                                                        <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Fix Text</div>
                                                                        <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{row.oldFinding.fixText}</div>
                                                                    </div>
                                                                </div>
                                                            )}

                                                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                                {/* Old Data */}
                                                                <div className="text-sm">
                                                                    <div className="text-xs font-semibold text-gray-500 mb-1 uppercase tracking-wider">Old Details/Comments</div>
                                                                    <div className="p-3 bg-gray-50 dark:bg-gray-900/50 rounded-lg text-gray-600 dark:text-gray-400 max-h-32 overflow-y-auto whitespace-pre-wrap text-xs">
                                                                        {row.oldFinding.findingDetails || row.oldFinding.comments || <em className="text-gray-400">No content</em>}
                                                                    </div>
                                                                </div>

                                                                {/* New Data & Actions */}
                                                                <div className="flex flex-col gap-2">
                                                                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider">New Finding</div>
                                                                    <textarea
                                                                        className="flex-1 min-h-[80px] w-full p-2 text-sm border rounded-lg focus:ring-2 focus:ring-purple-500 dark:bg-gray-900 dark:border-gray-600"
                                                                        placeholder="New finding details..."
                                                                        value={row.newFinding.findingDetails || ''}
                                                                        onChange={(e) => {
                                                                            const val = e.target.value;
                                                                            setAnalyzerNewChecklist((prev: any) => {
                                                                                if (!prev) return null;
                                                                                const findings = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, findingDetails: val } : f);
                                                                                return { ...prev, findings };
                                                                            });
                                                                            setAnalyzerEditedIds(prev => new Set(prev).add(row.vulnId));
                                                                        }}
                                                                    />
                                                                    <div className="grid grid-cols-3 gap-2">
                                                                        <button
                                                                            onClick={() => {
                                                                                setAnalyzerNewChecklist((prev: any) => {
                                                                                    if (!prev) return null;
                                                                                    const findings = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, status: row.oldFinding.status } : f);
                                                                                    return { ...prev, findings };
                                                                                });
                                                                                setAnalyzerEditedIds(prev => new Set(prev).add(row.vulnId));
                                                                            }}
                                                                            className="px-2 py-1.5 text-xs font-medium bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 transition-colors"
                                                                        >
                                                                            Copy Status
                                                                        </button>
                                                                        <button
                                                                            onClick={() => {
                                                                                const details = row.oldFinding.findingDetails || row.oldFinding.comments || '';
                                                                                setAnalyzerNewChecklist((prev: any) => {
                                                                                    if (!prev) return null;
                                                                                    const findings = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, findingDetails: details } : f);
                                                                                    return { ...prev, findings };
                                                                                });
                                                                                setAnalyzerEditedIds(prev => new Set(prev).add(row.vulnId));
                                                                            }}
                                                                            className="px-2 py-1.5 text-xs font-medium bg-purple-50 text-purple-600 rounded-lg hover:bg-purple-100 transition-colors"
                                                                        >
                                                                            Copy Details
                                                                        </button>
                                                                        <button
                                                                            onClick={() => {
                                                                                const details = row.oldFinding.findingDetails || row.oldFinding.comments || '';
                                                                                setAnalyzerNewChecklist((prev: any) => {
                                                                                    if (!prev) return null;
                                                                                    const findings = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, status: row.oldFinding.status, findingDetails: details } : f);
                                                                                    return { ...prev, findings };
                                                                                });
                                                                                setAnalyzerEditedIds(prev => new Set(prev).add(row.vulnId));
                                                                            }}
                                                                            className="px-2 py-1.5 text-xs font-medium bg-green-50 text-green-600 rounded-lg hover:bg-green-100 transition-colors"
                                                                        >
                                                                            Copy Both
                                                                        </button>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}

                                            {/* New IDs Tab */}
                                            {analyzerTab === 'newids' && (
                                                <div className="space-y-2">
                                                    {/* Controls Row (Sort Only) */}
                                                    <div className="flex items-center justify-end mb-4">
                                                        <div className="flex items-center gap-2 text-xs">
                                                            <span className="text-gray-500 font-medium">Sort By:</span>
                                                            {(['severity', 'groupid', 'status'] as const).map(key => (
                                                                <button
                                                                    key={key}
                                                                    onClick={() => setAnalyzerSort(prev => ({ key, dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc' }))}
                                                                    className={`px-2 py-1 rounded capitalize transition-colors ${analyzerSort.key === key ? 'bg-white shadow text-green-600 font-semibold' : 'text-gray-500 hover:bg-gray-200'}`}
                                                                >
                                                                    {key === 'groupid' ? 'Group ID' : key} {analyzerSort.key === key && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                                </button>
                                                            ))}
                                                        </div>
                                                    </div>

                                                    {/* Use sorted list logic inline or assumed simple map for now - reusing sortedNotReviewed pattern but for generic list if needed. Assuming user wants simple list for now. */}
                                                    {analyzerData.newIds.map((item) => (
                                                        <div key={item.vulnId} className="p-4 rounded-xl border bg-green-50/10 border-green-100 dark:border-green-900/30 flex items-center justify-between">
                                                            <div className="flex items-center gap-4">
                                                                <div className={`text-xs font-bold uppercase w-16 text-center py-1 rounded ${(item.finding.severity || '').toLowerCase().includes('high') ? 'bg-red-100 text-red-700' :
                                                                    (item.finding.severity || '').toLowerCase().includes('medium') ? 'bg-orange-100 text-orange-700' : 'bg-yellow-100 text-yellow-700'
                                                                    }`}>{item.finding.severity}</div>
                                                                <div>
                                                                    <div className="font-mono font-bold text-sm">{item.vulnId}</div>
                                                                    <div className="text-xs text-gray-500">{item.finding.title}</div>
                                                                </div>
                                                            </div>
                                                            <div className="text-xs font-medium px-2 py-1 bg-white dark:bg-gray-800 border rounded text-gray-600">{item.finding.status}</div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}

                                            {/* Dropped IDs Tab */}
                                            {analyzerTab === 'droppedids' && (
                                                <div className="space-y-2">
                                                    {analyzerData.droppedIds.map((item) => (
                                                        <div key={item.vulnId} className="p-4 rounded-xl border bg-red-50/10 border-red-100 dark:border-red-900/30 flex items-center justify-between opacity-75">
                                                            <div className="flex items-center gap-4">
                                                                <div className="font-mono font-bold text-sm text-gray-500 line-through">{item.vulnId}</div>
                                                                <div className="text-xs text-gray-400">{item.finding.title}</div>
                                                            </div>
                                                            <div className="text-xs font-medium px-2 py-1 bg-gray-100 text-gray-500 rounded">Removed</div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}

                                            {/* Reviewed Tab */}
                                            {analyzerTab === 'reviewed' && (
                                                <div className="space-y-4">
                                                    {/* Reviewed Controls */}
                                                    <div className="flex items-center justify-between bg-blue-50/50 p-3 rounded-lg border border-blue-100 mb-4">
                                                        <div className="flex items-center gap-4">
                                                            <label className="flex items-center gap-2 text-sm font-medium cursor-pointer">
                                                                <div className={`w-8 h-4 rounded-full p-0.5 transition-colors ${analyzerShowAllReviewed ? 'bg-blue-600' : 'bg-gray-300'}`} onClick={() => setAnalyzerShowAllReviewed(!analyzerShowAllReviewed)}>
                                                                    <div className={`h-3 w-3 rounded-full bg-white shadow transition-transform ${analyzerShowAllReviewed ? 'translate-x-4' : 'translate-x-0'}`} />
                                                                </div>
                                                                <span className="text-gray-600">Show All Processed Findings</span>
                                                            </label>
                                                            <div className="h-4 w-px bg-gray-300" />
                                                            <div className="flex items-center gap-2 text-xs">
                                                                <span className="text-gray-500 font-medium">Sort By:</span>
                                                                {(['severity', 'groupid', 'status'] as const).map(key => (
                                                                    <button
                                                                        key={key}
                                                                        onClick={() => setAnalyzerSort(prev => ({ key, dir: prev.key === key && prev.dir === 'desc' ? 'asc' : 'desc' }))}
                                                                        className={`px-2 py-1 rounded capitalize transition-colors ${analyzerSort.key === key ? 'bg-white shadow text-blue-600 font-semibold' : 'text-gray-500 hover:bg-gray-200'}`}
                                                                    >
                                                                        {key === 'groupid' ? 'Group ID' : key} {analyzerSort.key === key && (analyzerSort.dir === 'asc' ? '↑' : '↓')}
                                                                    </button>
                                                                ))}
                                                            </div>
                                                        </div>
                                                        <div className="text-xs text-gray-500 font-medium">
                                                            {sortedReviewed.length} items
                                                        </div>
                                                    </div>

                                                    {/* Reviewed List */}
                                                    {sortedReviewed.map(f => {
                                                        const oldFinding = oldFindingsMap.get(f.vulnId);
                                                        return (
                                                            <div key={f.vulnId} className={`p-4 rounded-xl border transition-all ${analyzerSelectedIds.has(f.vulnId) ? 'border-purple-300 bg-purple-50/30 dark:bg-purple-900/10' : (darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200')}`}>
                                                                {/* Header */}
                                                                <div className="flex items-start justify-between mb-3">
                                                                    <div className="flex items-center gap-3">
                                                                        <input
                                                                            type="checkbox"
                                                                            checked={analyzerSelectedIds.has(f.vulnId)}
                                                                            onChange={(e) => {
                                                                                const newSet = new Set(analyzerSelectedIds);
                                                                                if (e.target.checked) newSet.add(f.vulnId);
                                                                                else newSet.delete(f.vulnId);
                                                                                setAnalyzerSelectedIds(newSet);
                                                                            }}
                                                                            className="mt-1 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
                                                                        />
                                                                        <button
                                                                            onClick={() => setAnalyzerExpandedRows(prev => {
                                                                                const next = new Set(prev);
                                                                                if (next.has(f.vulnId)) next.delete(f.vulnId);
                                                                                else next.add(f.vulnId);
                                                                                return next;
                                                                            })}
                                                                            className="mt-0.5 p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-400"
                                                                        >
                                                                            {analyzerExpandedRows.has(f.vulnId) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                                                                        </button>
                                                                        <div>
                                                                            <div className="flex items-center gap-2">
                                                                                <span className="text-sm font-mono font-bold">{f.vulnId}</span>
                                                                                <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${(f.severity || '').toLowerCase().includes('high') || (f.severity || '').toLowerCase().includes('cat i') ? 'bg-red-100 text-red-700' :
                                                                                    (f.severity || '').toLowerCase().includes('medium') || (f.severity || '').toLowerCase().includes('cat ii') ? 'bg-orange-100 text-orange-700' :
                                                                                        'bg-yellow-100 text-yellow-700'
                                                                                    }`}>
                                                                                    {f.severity}
                                                                                </span>
                                                                            </div>
                                                                            <div className="text-xs text-gray-500 mt-1 max-w-md truncate">{f.title}</div>
                                                                        </div>
                                                                    </div>

                                                                    {/* Status Badge Compare */}
                                                                    <div className="flex items-center gap-4">
                                                                        {oldFinding && (
                                                                            <div className="flex flex-col items-end opacity-60">
                                                                                <span className="text-[10px] uppercase text-gray-400 font-semibold tracking-wider">Old Status</span>
                                                                                <div className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${(oldFinding.status || '').toLowerCase().includes('open') ? 'bg-red-50 border-red-100 text-red-600' :
                                                                                    (oldFinding.status || '').toLowerCase().includes('notafinding') ? 'bg-green-50 border-green-100 text-green-600' :
                                                                                        'bg-gray-50 border-gray-100 text-gray-600'
                                                                                    }`}>
                                                                                    {oldFinding.status}
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                        {oldFinding && <ArrowRight size={14} className="text-gray-300 mt-4" />}
                                                                        <div className="flex flex-col items-start">
                                                                            <span className="text-[10px] uppercase text-gray-400 font-semibold tracking-wider">Current Status</span>
                                                                            <select
                                                                                value={f.status}
                                                                                onChange={(e) => {
                                                                                    const val = e.target.value;
                                                                                    setAnalyzerNewChecklist((prev: any) => {
                                                                                        if (!prev) return null;
                                                                                        const findings = prev.findings.map((finding: any) => finding.vulnId === f.vulnId ? { ...finding, status: val } : finding);
                                                                                        return { ...prev, findings };
                                                                                    });
                                                                                    setAnalyzerEditedIds(prev => new Set(prev).add(f.vulnId));
                                                                                }}
                                                                                className={`px-2 py-0.5 rounded text-xs font-bold uppercase border cursor-pointer outline-none focus:ring-2 focus:ring-purple-500 ${f.status.toLowerCase().includes('open') ? 'bg-red-50 border-red-100 text-red-600' :
                                                                                    f.status.toLowerCase().includes('notafinding') ? 'bg-green-50 border-green-100 text-green-600' :
                                                                                        f.status.toLowerCase().includes('not_applicable') ? 'bg-gray-50 border-gray-100 text-gray-600' :
                                                                                            'bg-gray-50 border-gray-100 text-gray-500'}`}
                                                                            >
                                                                                <option value="Open">Open</option>
                                                                                <option value="NotAFinding">NotAFinding</option>
                                                                                <option value="Not_Applicable">Not_Applicable</option>
                                                                                <option value="Not_Reviewed">Not_Reviewed</option>
                                                                            </select>
                                                                        </div>
                                                                    </div>
                                                                </div>

                                                                {/* Expandable Details */}
                                                                {analyzerExpandedRows.has(f.vulnId) && (
                                                                    <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-900/50 rounded-lg border border-gray-100 dark:border-gray-800 text-xs text-gray-600 dark:text-gray-300 space-y-3 animate-in fade-in slide-in-from-top-1">
                                                                        <div>
                                                                            <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Rule Title</div>
                                                                            <div className="pl-2 border-l-2 border-gray-200">{f.title}</div>
                                                                        </div>
                                                                        <div>
                                                                            <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Vulnerability Discussion</div>
                                                                            <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{f.description}</div>
                                                                        </div>
                                                                        <div>
                                                                            <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Check Text (Procedure)</div>
                                                                            <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{f.checkText}</div>
                                                                        </div>
                                                                        <div>
                                                                            <div className="font-semibold text-gray-900 dark:text-gray-100 mb-1">Fix Text</div>
                                                                            <div className="pl-2 border-l-2 border-gray-200 whitespace-pre-wrap">{f.fixText}</div>
                                                                        </div>
                                                                    </div>
                                                                )}

                                                                <div className="flex flex-col gap-2">
                                                                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Finding Details / Comments</div>
                                                                    <textarea
                                                                        className="flex-1 min-h-[80px] w-full p-2 text-sm border rounded-lg focus:ring-2 focus:ring-purple-500 dark:bg-gray-900 dark:border-gray-600"
                                                                        placeholder="New finding details..."
                                                                        value={f.findingDetails || f.comments || ''}
                                                                        onChange={(e) => {
                                                                            const val = e.target.value;
                                                                            setAnalyzerNewChecklist((prev: any) => {
                                                                                if (!prev) return null;
                                                                                const findings = prev.findings.map((finding: any) => finding.vulnId === f.vulnId ? { ...finding, findingDetails: val } : finding);
                                                                                return { ...prev, findings };
                                                                            });
                                                                            setAnalyzerEditedIds(prev => new Set(prev).add(f.vulnId));
                                                                        }}
                                                                    />
                                                                </div>
                                                            </div>
                                                        );
                                                    })}
                                                </div>
                                            )}


                                            {(!analyzerOldChecklist || !analyzerNewChecklist) && (
                                                <div className="p-8 text-center text-gray-400 border-2 border-dashed rounded-xl">
                                                    Upload both old and new STIG checklists to begin analysis.
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* STIG Data Extractor */}
                                    {toolsMode === 'extractor' && (
                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <div className="p-3 bg-green-100 text-green-600 rounded-xl">
                                                    <Download size={24} />
                                                </div>
                                                <div>
                                                    <h2 className="text-xl font-semibold">STIG Data Extractor</h2>
                                                    <p className="text-sm text-gray-500">Upload a folder of STIG files and extract specific information to CSV.</p>
                                                </div>
                                            </div>

                                            {/* Folder Upload */}
                                            <div className="w-full relative group cursor-pointer mb-8">
                                                <div className={`absolute inset-0 rounded-xl bg-green-500/5 opacity-0 group-hover:opacity-100 transition-opacity border-2 border-dashed border-green-500/50`} />
                                                <div className={`relative z-10 p-10 rounded-xl border-2 border-dashed text-center transition-colors ${darkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-gray-50'}`}>
                                                    <div className="size-16 mx-auto bg-green-50 text-green-600 rounded-2xl flex items-center justify-center mb-4 shadow-sm">
                                                        <FolderOpen size={30} />
                                                    </div>
                                                    <h3 className="text-lg font-medium mb-1">Upload Folder</h3>
                                                    <p className="text-sm text-gray-500 mb-4">Select a folder containing .ckl, .cklb, or .xml STIG files</p>
                                                    <label className="inline-block relative">
                                                        <span className="bg-green-600 hover:bg-green-700 text-white px-6 py-2.5 rounded-full text-sm font-medium transition-all shadow-lg active:scale-95 cursor-pointer">
                                                            Browse Folder
                                                        </span>
                                                        <input
                                                            type="file"
                                                            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                                                            multiple
                                                            // @ts-ignore
                                                            webkitdirectory=""
                                                            directory=""
                                                            onChange={(e) => {
                                                                const files = Array.from(e.target.files || []);
                                                                const stigFiles = files.filter(f =>
                                                                    f.name.endsWith('.ckl') ||
                                                                    f.name.endsWith('.cklb') ||
                                                                    f.name.endsWith('.xml') ||
                                                                    f.name.endsWith('.json')
                                                                );
                                                                setExtractorFiles(stigFiles);
                                                                if (stigFiles.length === 0 && files.length > 0) {
                                                                    alert('No STIG files (.ckl, .cklb, .xml, .json) found in the selected folder.');
                                                                }
                                                            }}
                                                            onClick={(e) => {
                                                                // Reset the input so the same folder can be selected again
                                                                (e.target as HTMLInputElement).value = '';
                                                            }}
                                                        />
                                                    </label>
                                                </div>
                                            </div>

                                            {extractorFiles.length > 0 && (
                                                <div className="mb-6">
                                                    <div className={`p-4 rounded-lg ${darkMode ? 'bg-gray-700' : 'bg-blue-50'} mb-4`}>
                                                        <p className="text-sm font-medium mb-2">
                                                            {extractorFiles.length} STIG file(s) selected
                                                        </p>
                                                        <div className="text-xs text-gray-600 dark:text-gray-400 max-h-32 overflow-y-auto">
                                                            {extractorFiles.map((f, i) => (
                                                                <div key={i} className="truncate">{f.name}</div>
                                                            ))}
                                                        </div>
                                                    </div>

                                                    {/* Extraction Options */}
                                                    <div className="mb-6">
                                                        <h3 className="text-sm font-semibold uppercase text-gray-500 mb-3">Select Information to Extract</h3>
                                                        <div className="space-y-3">
                                                            <label className="flex items-center gap-3 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={extractorOptions.catI}
                                                                    onChange={(e) => setExtractorOptions(prev => ({ ...prev, catI: e.target.checked }))}
                                                                    className="w-4 h-4 text-green-600 rounded focus:ring-green-500"
                                                                />
                                                                <span className="text-sm font-medium">CAT I (High Severity)</span>
                                                            </label>
                                                            <label className="flex items-center gap-3 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={extractorOptions.catII}
                                                                    onChange={(e) => setExtractorOptions(prev => ({ ...prev, catII: e.target.checked }))}
                                                                    className="w-4 h-4 text-green-600 rounded focus:ring-green-500"
                                                                />
                                                                <span className="text-sm font-medium">CAT II (Medium Severity)</span>
                                                            </label>
                                                            <label className="flex items-center gap-3 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={extractorOptions.catIII}
                                                                    onChange={(e) => setExtractorOptions(prev => ({ ...prev, catIII: e.target.checked }))}
                                                                    className="w-4 h-4 text-green-600 rounded focus:ring-green-500"
                                                                />
                                                                <span className="text-sm font-medium">CAT III (Low Severity)</span>
                                                            </label>
                                                            <label className="flex items-center gap-3 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={extractorOptions.ruleId}
                                                                    onChange={(e) => setExtractorOptions(prev => ({ ...prev, ruleId: e.target.checked }))}
                                                                    className="w-4 h-4 text-green-600 rounded focus:ring-green-500"
                                                                />
                                                                <span className="text-sm font-medium">SV- (Rule ID)</span>
                                                            </label>
                                                            <label className="flex items-center gap-3 cursor-pointer">
                                                                <input
                                                                    type="checkbox"
                                                                    checked={extractorOptions.groupId}
                                                                    onChange={(e) => setExtractorOptions(prev => ({ ...prev, groupId: e.target.checked }))}
                                                                    className="w-4 h-4 text-green-600 rounded focus:ring-green-500"
                                                                />
                                                                <span className="text-sm font-medium">Group ID (V- numbers)</span>
                                                            </label>
                                                        </div>
                                                    </div>

                                                    {/* Extract Button */}
                                                    <button
                                                        onClick={async () => {
                                                            if (!extractorOptions.catI && !extractorOptions.catII && !extractorOptions.catIII && !extractorOptions.ruleId && !extractorOptions.groupId) {
                                                                alert('Please select at least one option to extract.');
                                                                return;
                                                            }

                                                            if (extractorFiles.length === 0) {
                                                                alert('Please upload a folder with STIG files first.');
                                                                return;
                                                            }

                                                            setExtractorProcessing(true);
                                                            try {
                                                                const extractedData: any[] = [];
                                                                let filesProcessed = 0;
                                                                let filesWithErrors = 0;

                                                                for (const file of extractorFiles) {
                                                                    try {
                                                                        const parsed = await parseCklFile(file);
                                                                        if (!parsed) {
                                                                            filesWithErrors++;
                                                                            console.warn(`Failed to parse file: ${file.name}`);
                                                                            continue;
                                                                        }
                                                                        filesProcessed++;

                                                                        const stigName = parsed.stigName || 'Unknown STIG';

                                                                        for (const finding of parsed.findings) {
                                                                            const severity = finding.severity?.toLowerCase() || '';
                                                                            const isCatI = severity === 'high' || severity === 'cat i';
                                                                            const isCatII = severity === 'medium' || severity === 'cat ii';
                                                                            const isCatIII = severity === 'low' || severity === 'cat iii';

                                                                            // Filter by selected categories - if any categories are selected, must match at least one
                                                                            const hasCategorySelected = extractorOptions.catI || extractorOptions.catII || extractorOptions.catIII;
                                                                            if (hasCategorySelected) {
                                                                                // Check if this finding matches any of the selected categories
                                                                                const matchesSelected =
                                                                                    (extractorOptions.catI && isCatI) ||
                                                                                    (extractorOptions.catII && isCatII) ||
                                                                                    (extractorOptions.catIII && isCatIII);

                                                                                // If it doesn't match any selected category, skip it
                                                                                if (!matchesSelected) continue;
                                                                            }
                                                                            // If no categories selected, include all findings

                                                                            const row: any = {
                                                                                'STIG Name': stigName,
                                                                            };

                                                                            if (extractorOptions.ruleId) {
                                                                                row['Rule ID (SV-)'] = finding.ruleId || '';
                                                                            }
                                                                            if (extractorOptions.groupId) {
                                                                                row['Group ID (V-)'] = finding.groupId || finding.vulnId || '';
                                                                            }
                                                                            if (extractorOptions.catI || extractorOptions.catII || extractorOptions.catIII) {
                                                                                row['Severity'] = finding.severity || '';
                                                                            }

                                                                            extractedData.push(row);
                                                                        }
                                                                    } catch (fileError: any) {
                                                                        filesWithErrors++;
                                                                        console.warn(`Error processing file ${file.name}:`, fileError);
                                                                    }
                                                                }

                                                                // Generate CSV
                                                                if (extractedData.length === 0) {
                                                                    let errorMsg = 'No data found matching your criteria.\n\n';
                                                                    errorMsg += `Files processed: ${filesProcessed}\n`;
                                                                    if (filesWithErrors > 0) {
                                                                        errorMsg += `Files with errors: ${filesWithErrors}\n`;
                                                                    }
                                                                    errorMsg += '\nPlease check:\n';
                                                                    errorMsg += '- Are the files valid STIG checklists?\n';
                                                                    errorMsg += '- Do the selected categories match the findings in the files?\n';
                                                                    errorMsg += '- Try selecting different options or all options.';
                                                                    alert(errorMsg);
                                                                    setExtractorProcessing(false);
                                                                    return;
                                                                }

                                                                const headers = Object.keys(extractedData[0]);
                                                                const csvRows = [
                                                                    headers.join(','),
                                                                    ...extractedData.map(row =>
                                                                        headers.map(header => {
                                                                            const value = row[header] || '';
                                                                            // Escape commas and quotes
                                                                            if (value.includes(',') || value.includes('"') || value.includes('\n')) {
                                                                                return `"${value.replace(/"/g, '""')}"`;
                                                                            }
                                                                            return value;
                                                                        }).join(',')
                                                                    )
                                                                ];

                                                                const csvContent = csvRows.join('\n');
                                                                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                                                                const url = URL.createObjectURL(blob);
                                                                const link = document.createElement('a');
                                                                link.href = url;
                                                                link.download = `stig_extract_${new Date().toISOString().split('T')[0]}.csv`;
                                                                link.click();
                                                                URL.revokeObjectURL(url);

                                                                alert(`Successfully extracted ${extractedData.length} rows to CSV!\n\nFiles processed: ${filesProcessed}${filesWithErrors > 0 ? `\nFiles with errors: ${filesWithErrors}` : ''}`);
                                                            } catch (error: any) {
                                                                console.error('Extraction error:', error);
                                                                alert(`Error during extraction: ${error.message}\n\nPlease try uploading the folder again.`);
                                                            } finally {
                                                                setExtractorProcessing(false);
                                                            }
                                                        }}
                                                        disabled={extractorProcessing || extractorFiles.length === 0}
                                                        className="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white px-6 py-3 rounded-xl font-medium transition-all shadow-lg flex items-center justify-center gap-2"
                                                    >
                                                        {extractorProcessing ? (
                                                            <>
                                                                <Loader2 size={18} className="animate-spin" />
                                                                Processing...
                                                            </>
                                                        ) : (
                                                            <>
                                                                <Download size={18} />
                                                                Extract to CSV
                                                            </>
                                                        )}
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* Master Copy Panel */}
                                    {toolsMode === 'master_copy' && (
                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <button
                                                    onClick={() => setToolsMode('rename')}
                                                    className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-600'}`}
                                                >
                                                    <ChevronLeft size={20} />
                                                </button>
                                                <div className="p-3 bg-indigo-100 text-indigo-600 rounded-xl">
                                                    <Copy size={24} />
                                                </div>
                                                <div className="flex-1">
                                                    <h2 className="text-xl font-semibold">Master Copy Tool</h2>
                                                    <p className="text-sm text-gray-500">Edit master checklist and apply changes to multiple raw files.</p>
                                                </div>
                                            </div>

                                            {/* Upload Zones (3 Columns) */}
                                            <div className="grid grid-cols-3 gap-4 mb-6">
                                                {/* 1. Source (Old with Comments) */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${masterCopySource ? 'border-green-500 bg-green-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">1. Old Checklist (Source)</div>
                                                    {masterCopySource ? (
                                                        <div>
                                                            <div className="text-sm font-medium truncate">{masterCopySource.filename}</div>
                                                            <div className="text-xs text-gray-500">{masterCopySource.findings.length} findings • {masterCopySource.hostname}</div>
                                                            <button onClick={() => setMasterCopySource(null)} className="text-xs text-red-500 hover:underline mt-1">Remove</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-8 mx-auto bg-gray-100 text-gray-400 rounded-lg flex items-center justify-center mb-2"><Upload size={16} /></div>
                                                            <span className="text-xs text-gray-500">Upload Old STIG</span>
                                                            <input type="file" className="hidden" accept=".ckl,.cklb,.json,.xml" onChange={async (e) => { const f = e.target.files?.[0]; if (f) { const p = await parseCklFile(f); if (p) setMasterCopySource(p as any); } e.target.value = ''; }} />
                                                        </label>
                                                    )}
                                                </div>

                                                {/* 2. Target (New/Raw Master) */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${masterCopyTarget ? 'border-blue-500 bg-blue-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">2. Master Checklist (Target)</div>
                                                    {masterCopyTarget ? (
                                                        <div>
                                                            <div className="text-sm font-medium truncate">{masterCopyTarget.filename}</div>
                                                            <div className="text-xs text-gray-500">{masterCopyTarget.findings.length} findings • {masterCopyTarget.hostname}</div>
                                                            <button onClick={() => setMasterCopyTarget(null)} className="text-xs text-red-500 hover:underline mt-1">Remove</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-8 mx-auto bg-gray-100 text-gray-400 rounded-lg flex items-center justify-center mb-2"><Upload size={16} /></div>
                                                            <span className="text-xs text-gray-500">Upload Raw Checklist</span>
                                                            <input type="file" className="hidden" accept=".ckl,.cklb,.json,.xml" onChange={async (e) => { const f = e.target.files?.[0]; if (f) { const p = await parseCklFile(f); if (p) setMasterCopyTarget(p as any); } e.target.value = ''; }} />
                                                        </label>
                                                    )}
                                                </div>

                                                {/* 3. Batch (Raw Folder) */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${masterCopyBatchFiles.length > 0 ? 'border-purple-500 bg-purple-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">3. All Checklists (Batch)</div>
                                                    {masterCopyBatchFiles.length > 0 ? (
                                                        <div>
                                                            <div className="text-sm font-medium">{masterCopyBatchFiles.length} files loaded</div>
                                                            <div className="text-xs text-gray-500">Will apply Master changes to all</div>
                                                            <button onClick={() => setMasterCopyBatchFiles([])} className="text-xs text-red-500 hover:underline mt-1">Remove All</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-8 mx-auto bg-gray-100 text-gray-400 rounded-lg flex items-center justify-center mb-2"><FolderOpen size={16} /></div>
                                                            <span className="text-xs text-gray-500">Upload Folder (Raw)</span>
                                                            <input type="file" className="hidden" multiple
                                                                // @ts-ignore
                                                                webkitdirectory="" directory="" onChange={async (e) => {
                                                                    const files = Array.from(e.target.files || []);
                                                                    const valid = [];
                                                                    for (const f of files) {
                                                                        if (f.name.match(/\.(ckl|cklb|json|xml)$/i)) {
                                                                            const p = await parseCklFile(f);
                                                                            if (p) valid.push(p as any);
                                                                        }
                                                                    }
                                                                    setMasterCopyBatchFiles(valid);
                                                                    e.target.value = '';
                                                                }} />
                                                        </label>
                                                    )}
                                                </div>
                                            </div>

                                            {masterCopySource && masterCopyTarget && (
                                                <>
                                                    {/* Find & Replace Bar */}
                                                    <div className={`flex items-center gap-4 mb-6 p-4 rounded-xl border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                        <div className="flex items-center gap-2 flex-1">
                                                            <Search size={16} className="text-gray-400" />
                                                            <input
                                                                type="text"
                                                                value={masterCopySearch}
                                                                onChange={e => setMasterCopySearch(e.target.value)}
                                                                placeholder="Find in Details/Comments..."
                                                                className="flex-1 bg-transparent text-sm outline-none"
                                                            />
                                                        </div>
                                                        <ArrowRight size={16} className="text-gray-400" />
                                                        <div className="flex items-center gap-2 flex-1">
                                                            <FileEdit size={16} className="text-gray-400" />
                                                            <input
                                                                type="text"
                                                                value={masterCopyReplace}
                                                                onChange={e => setMasterCopyReplace(e.target.value)}
                                                                placeholder="Replace with..."
                                                                className="flex-1 bg-transparent text-sm outline-none"
                                                            />
                                                        </div>
                                                        <button
                                                            onClick={() => {
                                                                if (!masterCopySearch) return;
                                                                if (!confirm(`Replace instances of "${masterCopySearch}" with "${masterCopyReplace}" across ALL findings in the Master Checklist?`)) return;

                                                                setMasterCopyTarget((prev: any) => {
                                                                    if (!prev) return null;
                                                                    let count = 0;
                                                                    const newFindings = prev.findings.map((f: any) => {
                                                                        let changed = false;
                                                                        let details = f.findingDetails || '';
                                                                        let comments = f.comments || '';

                                                                        // Simple global replace
                                                                        if (details.includes(masterCopySearch)) {
                                                                            details = details.replaceAll(masterCopySearch, masterCopyReplace);
                                                                            changed = true;
                                                                        }
                                                                        if (comments.includes(masterCopySearch)) {
                                                                            comments = comments.replaceAll(masterCopySearch, masterCopyReplace);
                                                                            changed = true;
                                                                        }

                                                                        if (changed) {
                                                                            count++;
                                                                            return { ...f, findingDetails: details, comments: comments };
                                                                        }
                                                                        return f;
                                                                    });
                                                                    alert(`Replaced text in ${count} findings.`);
                                                                    return { ...prev, findings: newFindings };
                                                                });
                                                            }}
                                                            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg transition-colors"
                                                        >
                                                            Replace All
                                                        </button>
                                                    </div>

                                                    {/* Tabs */}
                                                    <div className="flex flex-wrap gap-2 mb-4">
                                                        {[
                                                            { id: 'all', label: 'All Findings', count: masterCopyData.allFindings.length },
                                                            { id: 'notreviewed', label: 'Not Reviewed', count: masterCopyData.notReviewed.length },
                                                            { id: 'open', label: 'Open Findings', count: masterCopyData.openFindings.length },
                                                            { id: 'reviewed', label: 'Reviewed', count: masterCopyTarget.findings.filter(f => !['notreviewed', 'not_reviewed'].includes((f.status || '').toLowerCase().replace(/[\s_]/g, ''))).length },
                                                            { id: 'done', label: 'Done', count: masterCopyData.doneFindings.length },
                                                            { id: 'newids', label: 'New IDs', count: masterCopyData.newIds.length },
                                                            { id: 'droppedids', label: 'Dropped IDs', count: masterCopyData.droppedIds.length }
                                                        ].map(tab => (
                                                            <button
                                                                key={tab.id}
                                                                onClick={() => { setMasterCopyTab(tab.id as any); setMasterCopySelectedIds(new Set()); }}
                                                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${masterCopyTab === tab.id
                                                                    ? 'bg-indigo-100 text-indigo-700 shadow-sm'
                                                                    : 'text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800'
                                                                    }`}
                                                            >
                                                                {tab.label} ({tab.count})
                                                            </button>
                                                        ))}
                                                    </div>

                                                    {/* Toolbar */}
                                                    <div className="flex justify-between items-center mb-4">
                                                        <div className="flex gap-2">
                                                            {(masterCopyTab === 'notreviewed' && masterCopySelectedIds.size > 0) && (
                                                                <>
                                                                    <button
                                                                        onClick={() => {
                                                                            if (!confirm(`Copy Status & Details for ${masterCopySelectedIds.size} items?`)) return;
                                                                            setMasterCopyTarget((prev: any) => {
                                                                                if (!prev) return null;
                                                                                const newFindings = prev.findings.map((f: any) => {
                                                                                    if (masterCopySelectedIds.has(f.vulnId)) {
                                                                                        const match = masterCopyData.notReviewed.find(nr => nr.vulnId === f.vulnId);
                                                                                        if (match) {
                                                                                            return {
                                                                                                ...f,
                                                                                                status: match.oldFinding.status,
                                                                                                findingDetails: match.oldFinding.findingDetails || match.oldFinding.comments || match.oldFinding.findingDetails,
                                                                                                comments: match.oldFinding.comments || match.oldFinding.findingDetails
                                                                                            };
                                                                                        }
                                                                                    }
                                                                                    return f;
                                                                                });
                                                                                return { ...prev, findings: newFindings };
                                                                            });
                                                                            setMasterCopySelectedIds(new Set());
                                                                        }}
                                                                        className="px-3 py-1.5 bg-green-600 text-white rounded text-xs font-semibold hover:bg-green-700"
                                                                    >
                                                                        Copy Both ({masterCopySelectedIds.size})
                                                                    </button>
                                                                </>
                                                            )}
                                                        </div>
                                                        <div className="flex gap-2">
                                                            {masterCopyBatchFiles.length > 0 && (
                                                                <button
                                                                    onClick={async () => {
                                                                        if (!confirm(`Apply changes from Master Checklist to ${masterCopyBatchFiles.length} batch files? This will generate a ZIP download.`)) return;

                                                                        try {
                                                                            const zip = new JSZip();
                                                                            const masterMap = new Map(masterCopyTarget.findings.map(f => [f.vulnId, f]));

                                                                            let processedCount = 0;

                                                                            for (const file of masterCopyBatchFiles) {
                                                                                // Clone raw JSON structure
                                                                                const newJson = JSON.parse(JSON.stringify(file.rawJson || {}));

                                                                                // Update findings in the JSON
                                                                                if (newJson.stigs) {
                                                                                    for (const stig of newJson.stigs) {
                                                                                        if (stig.rules) {
                                                                                            for (const rule of stig.rules) {
                                                                                                const masterFinding = masterMap.get(rule.group_id);
                                                                                                if (masterFinding) {
                                                                                                    // Copy editable fields
                                                                                                    rule.status = masterFinding.status;
                                                                                                    rule.finding_details = masterFinding.findingDetails;
                                                                                                    rule.comments = masterFinding.comments;
                                                                                                    rule.severity = masterFinding.severity;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }

                                                                                zip.file(file.filename, JSON.stringify(newJson, null, 2));
                                                                                processedCount++;
                                                                            }

                                                                            const content = await zip.generateAsync({ type: "blob" });
                                                                            const url = URL.createObjectURL(content);
                                                                            const a = document.createElement('a');
                                                                            a.href = url;
                                                                            a.download = `master_batch_export_${new Date().toISOString().split('T')[0]}.zip`;
                                                                            a.click();

                                                                            alert(`Successfully processed ${processedCount} files.`);
                                                                        } catch (e) {
                                                                            console.error(e);
                                                                            alert('Error generating batch export.');
                                                                        }
                                                                    }}
                                                                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-xs font-bold shadow-lg flex items-center gap-2"
                                                                >
                                                                    <Copy size={14} /> Apply to Batch & Download
                                                                </button>
                                                            )}
                                                            <button
                                                                onClick={() => {
                                                                    // Simple CKLB export of Master
                                                                    const data = JSON.stringify(masterCopyTarget.rawJson || {}, null, 2);
                                                                    const blob = new Blob([data], { type: 'application/json' });
                                                                    const url = URL.createObjectURL(blob);
                                                                    const a = document.createElement('a');
                                                                    a.href = url;
                                                                    a.download = `master_checklist_${new Date().toISOString().split('T')[0]}.cklb`;
                                                                    a.click();
                                                                }}
                                                                className="px-3 py-1.5 border border-gray-300 rounded text-xs font-semibold hover:bg-gray-100"
                                                            >
                                                                Export Master CKLB
                                                            </button>
                                                        </div>
                                                    </div>

                                                    {/* Data List */}
                                                    <div className="space-y-4">
                                                        {masterCopyTab === 'notreviewed' && sortedMasterCopy.length > 0 && (
                                                            <div className="flex items-center gap-2 mb-2 px-2">
                                                                <input type="checkbox" onChange={(e) => {
                                                                    if (e.target.checked) setMasterCopySelectedIds(new Set(sortedMasterCopy.map(f => f.vulnId)));
                                                                    else setMasterCopySelectedIds(new Set());
                                                                }} checked={masterCopySelectedIds.size === sortedMasterCopy.length} />
                                                                <span className="text-xs text-gray-500">Select All</span>
                                                            </div>
                                                        )}

                                                        {sortedMasterCopy.map((row) => {
                                                            const finding = row.newFinding || row.finding; // Base finding
                                                            const old = row.oldFinding;
                                                            const isSelected = masterCopySelectedIds.has(row.vulnId);
                                                            const statusChanged = old && (old.status || '').toLowerCase().replace(/[\s_]/g, '') !== (finding.status || '').toLowerCase().replace(/[\s_]/g, '');

                                                            return (
                                                                <div key={row.vulnId} className={`p-4 rounded-xl border ${isSelected ? 'border-indigo-400 bg-indigo-50' : statusChanged ? 'border-amber-400 bg-amber-50/30' : (darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200')} ${statusChanged ? 'ring-1 ring-amber-400/50' : ''}`}>
                                                                    {statusChanged && (
                                                                        <div className="flex items-center gap-1 text-[10px] font-bold text-amber-600 mb-2 bg-amber-100 w-fit px-2 py-0.5 rounded-full">
                                                                            <RefreshCw size={10} />
                                                                            STATUS CHANGED
                                                                        </div>
                                                                    )}
                                                                    {/* Header Info */}
                                                                    <div className="flex justify-between items-start mb-3">
                                                                        <div className="flex items-center gap-3">
                                                                            {masterCopyTab === 'notreviewed' && (
                                                                                <input type="checkbox" checked={isSelected} onChange={e => {
                                                                                    const next = new Set(masterCopySelectedIds);
                                                                                    if (e.target.checked) next.add(row.vulnId);
                                                                                    else next.delete(row.vulnId);
                                                                                    setMasterCopySelectedIds(next);
                                                                                }} />
                                                                            )}
                                                                            <div>
                                                                                <div className="flex items-center gap-2">
                                                                                    <span className="text-sm font-bold font-mono">{row.vulnId}</span>
                                                                                    <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded font-bold ${((finding.severity || '').toLowerCase().includes('high') || (finding.severity || '').includes('cat i')) ? 'bg-red-100 text-red-700' :
                                                                                        ((finding.severity || '').toLowerCase().includes('medium') || (finding.severity || '').includes('cat ii')) ? 'bg-orange-100 text-orange-700' : 'bg-yellow-100 text-yellow-700'
                                                                                        }`}>{finding.severity}</span>
                                                                                </div>
                                                                                <div className="text-xs text-gray-500 mt-0.5 max-w-xl truncate">{finding.title}</div>
                                                                            </div>
                                                                        </div>
                                                                        <div className="flex items-center gap-2">
                                                                            {/* Severity Editor */}
                                                                            <select
                                                                                value={finding.severity?.toLowerCase() || 'low'}
                                                                                onChange={(e) => {
                                                                                    setMasterCopyTarget((prev: any) => {
                                                                                        if (!prev) return null;
                                                                                        const updated = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, severity: e.target.value } : f);
                                                                                        return { ...prev, findings: updated };
                                                                                    });
                                                                                }}
                                                                                className="text-xs border rounded p-1 bg-white dark:bg-gray-900"
                                                                            >
                                                                                <option value="high">High / CAT I</option>
                                                                                <option value="medium">Medium / CAT II</option>
                                                                                <option value="low">Low / CAT III</option>
                                                                            </select>

                                                                            {/* Status Editor */}
                                                                            <select
                                                                                value={(finding.status || '').toLowerCase().replace(/[\s_]/g, '')}
                                                                                onChange={(e) => {
                                                                                    let val = e.target.value;
                                                                                    // Map back to standard casing if needed
                                                                                    if (val === 'open') val = 'Open';
                                                                                    if (val === 'notafinding') val = 'NotAFinding';
                                                                                    if (val === 'notapplicable') val = 'Not_Applicable';
                                                                                    if (val === 'notreviewed') val = 'Not_Reviewed';

                                                                                    setMasterCopyTarget((prev: any) => {
                                                                                        if (!prev) return null;
                                                                                        const updated = prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, status: val } : f);
                                                                                        return { ...prev, findings: updated };
                                                                                    });
                                                                                }}
                                                                                className={`text-xs border rounded p-1 font-bold ${(finding.status || '').toLowerCase().includes('open') ? 'text-red-600 bg-red-50' :
                                                                                    (finding.status || '').toLowerCase().includes('notafinding') ? 'text-green-600 bg-green-50' : 'text-gray-600'
                                                                                    }`}
                                                                            >
                                                                                <option value="notreviewed">Not Reviewed</option>
                                                                                <option value="open">Open</option>
                                                                                <option value="notafinding">Not a Finding</option>
                                                                                <option value="notapplicable">Not Applicable</option>
                                                                            </select>
                                                                        </div>
                                                                    </div>

                                                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-4">
                                                                        {/* Source / Old Side */}
                                                                        <div className={`p-4 rounded-xl border ${old ? 'bg-gray-50 dark:bg-gray-900/50 border-gray-200 dark:border-gray-700' : 'border-dashed border-gray-200'}`}>
                                                                            <div className="flex items-center justify-between mb-3">
                                                                                <div className="text-xs font-bold uppercase text-gray-400 flex items-center gap-2">
                                                                                    <div className="w-2 h-2 rounded-full bg-gray-400"></div>
                                                                                    Source (Old)
                                                                                </div>
                                                                                {old && <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${(old.status || '').toLowerCase().includes('open') ? 'bg-red-100 text-red-600' :
                                                                                    (old.status || '').toLowerCase().includes('notafinding') ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-600'
                                                                                    }`}>{old.status}</span>}
                                                                            </div>

                                                                            {old ? (
                                                                                <div className="space-y-3">
                                                                                    <div className="text-xs text-gray-600 dark:text-gray-400 bg-white dark:bg-gray-900 p-3 rounded-lg border border-gray-100 dark:border-gray-800 h-32 overflow-y-auto shadow-sm">
                                                                                        {old.findingDetails || old.comments || <span className="italic opacity-50">No details provided</span>}
                                                                                    </div>

                                                                                    <div className="flex gap-2">
                                                                                        <button
                                                                                            onClick={() => {
                                                                                                setMasterCopyTarget((prev: any) => {
                                                                                                    if (!prev) return null;
                                                                                                    return { ...prev, findings: prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, status: old.status } : f) };
                                                                                                });
                                                                                                setMasterCopyDoneIds(prev => new Set(prev).add(row.vulnId));
                                                                                                setShowDoneToast(true);
                                                                                                setTimeout(() => setShowDoneToast(false), 2000);
                                                                                            }}
                                                                                            className="flex-1 py-1.5 px-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 hover:text-blue-600 text-[10px] font-medium text-gray-600 dark:text-gray-300 rounded shadow-sm transition-all text-center"
                                                                                        >
                                                                                            Copy Status
                                                                                        </button>
                                                                                        <button
                                                                                            onClick={() => {
                                                                                                setMasterCopyTarget((prev: any) => {
                                                                                                    if (!prev) return null;
                                                                                                    return { ...prev, findings: prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, findingDetails: old.findingDetails || old.comments, comments: old.comments || old.findingDetails } : f) };
                                                                                                });
                                                                                                setMasterCopyDoneIds(prev => new Set(prev).add(row.vulnId));
                                                                                                setShowDoneToast(true);
                                                                                                setTimeout(() => setShowDoneToast(false), 2000);
                                                                                            }}
                                                                                            className="flex-1 py-1.5 px-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:border-blue-400 hover:text-blue-600 text-[10px] font-medium text-gray-600 dark:text-gray-300 rounded shadow-sm transition-all text-center"
                                                                                        >
                                                                                            Copy Details
                                                                                        </button>
                                                                                    </div>
                                                                                </div>
                                                                            ) : (
                                                                                <div className="h-32 flex items-center justify-center text-xs text-gray-400 italic">
                                                                                    No history available
                                                                                </div>
                                                                            )}
                                                                        </div>

                                                                        {/* Target / New Side */}
                                                                        <div className="p-4 rounded-xl border bg-white dark:bg-gray-900 border-indigo-100 dark:border-indigo-900/30 shadow-sm relative overflow-hidden group">
                                                                            <div className="absolute top-0 right-0 w-16 h-16 bg-gradient-to-bl from-indigo-500/10 to-transparent -mr-8 -mt-8 rounded-full pointer-events-none transition-transform group-hover:scale-150 duration-500" />

                                                                            <div className="flex items-center justify-between mb-3">
                                                                                <div className="text-xs font-bold uppercase text-indigo-500 flex items-center gap-2">
                                                                                    <div className="w-2 h-2 rounded-full bg-indigo-500 animate-pulse"></div>
                                                                                    Master Copy (New)
                                                                                </div>
                                                                                <div className="flex items-center gap-2">
                                                                                    <button
                                                                                        onClick={() => setMasterCopyExpandedId(masterCopyExpandedId === row.vulnId ? null : row.vulnId)}
                                                                                        className="text-gray-400 hover:text-indigo-500 transition-colors"
                                                                                    >
                                                                                        {masterCopyExpandedId === row.vulnId ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                                                                                    </button>
                                                                                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${(finding.status || '').toLowerCase().includes('open') ? 'bg-red-100 text-red-600' :
                                                                                        (finding.status || '').toLowerCase().includes('notafinding') ? 'bg-green-100 text-green-600' :
                                                                                            (finding.status || '').toLowerCase().includes('notreviewed') ? 'bg-gray-100 text-gray-600' : 'bg-gray-100 text-gray-600'
                                                                                        }`}>{finding.status || 'Not_Reviewed'}</span>
                                                                                </div>
                                                                            </div>

                                                                            <div className="space-y-3">
                                                                                <div>
                                                                                    <label className="text-[10px] font-medium text-gray-400 mb-1 block">FINDING DETAILS</label>
                                                                                    <textarea
                                                                                        className="w-full text-xs p-3 rounded-lg border bg-gray-50 dark:bg-gray-950 border-gray-200 dark:border-gray-700 h-32 focus:ring-2 ring-indigo-500/50 outline-none transition-all resize-none"
                                                                                        value={finding.findingDetails || finding.comments || ''}
                                                                                        placeholder="Enter technical details..."
                                                                                        onChange={(e) => {
                                                                                            setMasterCopyTarget((prev: any) => {
                                                                                                if (!prev) return null;
                                                                                                return { ...prev, findings: prev.findings.map((f: any) => f.vulnId === row.vulnId ? { ...f, findingDetails: e.target.value, comments: e.target.value } : f) };
                                                                                            });
                                                                                        }}
                                                                                    />
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    </div>

                                                                    {/* Expanded View Modal/Panel */}
                                                                    {masterCopyExpandedId === row.vulnId && (
                                                                        <div className="mt-4 p-4 bg-gray-50 dark:bg-gray-900/50 border border-indigo-100 dark:border-indigo-900/30 rounded-xl relative">
                                                                            <div className="grid grid-cols-2 gap-8">
                                                                                <div>
                                                                                    <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Check Text</h4>
                                                                                    <div className="text-xs text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 p-3 rounded border border-gray-200 dark:border-gray-700 whitespace-pre-wrap font-mono text-[10px] max-h-60 overflow-y-auto">
                                                                                        {finding.checkText || 'No check text available.'}
                                                                                    </div>
                                                                                </div>
                                                                                <div>
                                                                                    <h4 className="text-xs font-bold text-gray-500 uppercase mb-2">Fix Text</h4>
                                                                                    <div className="text-xs text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-900 p-3 rounded border border-gray-200 dark:border-gray-700 whitespace-pre-wrap font-mono text-[10px] max-h-60 overflow-y-auto">
                                                                                        {finding.fixText || 'No fix text available.'}
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            );
                                                        })}
                                                    </div>

                                                    {/* Done Toast */}
                                                    {showDoneToast && (
                                                        <div className="fixed bottom-8 right-8 bg-green-600 text-white px-6 py-3 rounded-xl shadow-xl flex items-center gap-3 animate-bounce z-50">
                                                            <div className="p-1 bg-white/20 rounded-full">
                                                                <Check size={16} />
                                                            </div>
                                                            <span className="font-bold">Marked as Done!</span>
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </div>
                                    )}

                                    {/* Report Analyzer Panel */}{/* Report Analyzer Panel */}
                                    {toolsMode === 'reportanalyzer' && (
                                        <div id="report-analyzer-panel" className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-gray-100 dark:border-gray-700">
                                                <button
                                                    onClick={() => setToolsMode('rename')}
                                                    className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-600'}`}
                                                    title="Back to Tools"
                                                >
                                                    <ChevronLeft size={20} />
                                                </button>
                                                <div className="p-3 bg-amber-100 text-amber-600 rounded-xl">
                                                    <FileWarning size={24} />
                                                </div>
                                                <div className="flex-1">
                                                    <h2 className="text-xl font-semibold">Report Analyzer</h2>
                                                    <p className="text-sm text-gray-500">Upload CSV/Excel with Group IDs, compare against CKLB folder to track severity changes.</p>
                                                </div>
                                            </div>

                                            {/* Dual Upload Zone */}
                                            <div className="grid grid-cols-2 gap-4 mb-6">
                                                {/* Base File Upload - CSV/Excel */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${reportBaseData ? 'border-green-500 bg-green-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">Base File (CSV/Excel - Old Data)</div>
                                                    {reportBaseData ? (
                                                        <div>
                                                            <div className="text-sm font-medium truncate">{reportBaseData.filename}</div>
                                                            <div className="text-xs text-gray-500">{reportBaseData.rows.length} rows • {reportBaseData.headers.length} columns</div>
                                                            <div className="text-xs text-gray-400 mt-1 truncate">Columns: {reportBaseData.headers.slice(0, 4).join(', ')}{reportBaseData.headers.length > 4 ? '...' : ''}</div>
                                                            <button onClick={() => { setReportBaseData(null); setReportAnalysisResults(null); }} className="text-xs text-red-500 hover:underline mt-1">Remove</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-10 mx-auto bg-gray-100 text-gray-400 rounded-xl flex items-center justify-center mb-2">
                                                                <FileSpreadsheet size={20} />
                                                            </div>
                                                            <span className="text-sm text-gray-500">Upload CSV or Excel file</span>
                                                            <p className="text-xs text-gray-400 mt-1">Must contain Group ID column</p>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                accept=".csv,.xlsx,.xls"
                                                                onChange={async (e) => {
                                                                    const file = e.target.files?.[0];
                                                                    if (file) {
                                                                        try {
                                                                            const arrayBuffer = await file.arrayBuffer();
                                                                            const workbook = XLSX.read(arrayBuffer, { type: 'array' });
                                                                            const sheetName = workbook.SheetNames[0];
                                                                            const worksheet = workbook.Sheets[sheetName];
                                                                            const jsonData = XLSX.utils.sheet_to_json<Record<string, string>>(worksheet, { defval: '' });

                                                                            if (jsonData.length > 0) {
                                                                                const headers = Object.keys(jsonData[0]);
                                                                                setReportBaseData({
                                                                                    filename: file.name,
                                                                                    rows: jsonData.map(row => {
                                                                                        const normalizedRow: Record<string, string> = {};
                                                                                        Object.entries(row).forEach(([key, value]) => {
                                                                                            normalizedRow[key] = String(value || '');
                                                                                        });
                                                                                        return normalizedRow;
                                                                                    }),
                                                                                    headers
                                                                                });
                                                                            } else {
                                                                                alert('The file appears to be empty or has no valid data.');
                                                                            }
                                                                        } catch (err) {
                                                                            console.error('Error parsing CSV/Excel:', err);
                                                                            alert('Failed to parse the file. Please ensure it is a valid CSV or Excel file.');
                                                                        }
                                                                    }
                                                                    e.target.value = '';
                                                                }}
                                                            />
                                                        </label>
                                                    )}
                                                </div>

                                                {/* Comparison Folder Upload - CKLB files */}
                                                <div className={`p-4 rounded-xl border-2 border-dashed text-center transition-colors ${reportComparisonFiles.length > 0 ? 'border-blue-500 bg-blue-50' : (darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50')}`}>
                                                    <div className="text-xs font-semibold uppercase text-gray-500 mb-2">Checklist Folder (CKLB - New Scans)</div>
                                                    {reportComparisonFiles.length > 0 ? (
                                                        <div>
                                                            <div className="text-sm font-medium">{reportComparisonFiles.length} CKLB files loaded</div>
                                                            <div className="text-xs text-gray-500">{reportComparisonFiles.reduce((acc, f) => acc + f.findings.length, 0)} total findings</div>
                                                            <button onClick={() => { setReportComparisonFiles([]); setReportAnalysisResults(null); }} className="text-xs text-red-500 hover:underline mt-1">Remove All</button>
                                                        </div>
                                                    ) : (
                                                        <label className="cursor-pointer">
                                                            <div className="size-10 mx-auto bg-gray-100 text-gray-400 rounded-xl flex items-center justify-center mb-2">
                                                                <FolderOpen size={20} />
                                                            </div>
                                                            <span className="text-sm text-gray-500">Upload folder with CKLB files</span>
                                                            <p className="text-xs text-gray-400 mt-1">Contains newest scan data</p>
                                                            <input
                                                                type="file"
                                                                className="hidden"
                                                                // @ts-ignore
                                                                webkitdirectory=""
                                                                directory=""
                                                                multiple
                                                                onChange={async (e) => {
                                                                    const files = Array.from(e.target.files || []);
                                                                    const stigFiles = files.filter(f =>
                                                                        f.name.endsWith('.ckl') ||
                                                                        f.name.endsWith('.cklb') ||
                                                                        f.name.endsWith('.json')
                                                                    );
                                                                    const parsed: typeof uploadedChecklists = [];
                                                                    for (const file of stigFiles) {
                                                                        const p = await parseCklFile(file);
                                                                        if (p) parsed.push(p as any);
                                                                    }
                                                                    setReportComparisonFiles(parsed);
                                                                    if (parsed.length === 0 && stigFiles.length > 0) {
                                                                        alert('No valid CKLB files found in the folder.');
                                                                    }
                                                                    e.target.value = '';
                                                                }}
                                                            />
                                                        </label>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Column Preview & Mapping Info */}
                                            {reportBaseData && reportBaseData.headers.length > 0 && (
                                                <div className={`mb-6 p-4 rounded-xl ${darkMode ? 'bg-gray-700' : 'bg-blue-50'}`}>
                                                    <div className="text-sm font-semibold mb-2">Detected Columns:</div>
                                                    <div className="flex flex-wrap gap-2">
                                                        {reportBaseData.headers.map((h, i) => (
                                                            <span key={i} className={`px-2 py-1 rounded text-xs font-medium ${h.toLowerCase().includes('group') || h.toLowerCase().includes('v-') || h.toLowerCase() === 'vuln' || h.toLowerCase() === 'vulnid'
                                                                ? 'bg-green-100 text-green-700'
                                                                : h.toLowerCase().includes('severity') || h.toLowerCase() === 'cat'
                                                                    ? 'bg-amber-100 text-amber-700'
                                                                    : 'bg-gray-100 text-gray-600'
                                                                }`}>{h}</span>
                                                        ))}
                                                    </div>
                                                    <p className="text-xs text-gray-500 mt-2">
                                                        <strong>Green</strong> = Group ID columns, <strong>Amber</strong> = Severity columns
                                                    </p>
                                                </div>
                                            )}

                                            {/* Analyze Button */}
                                            {reportBaseData && reportComparisonFiles.length > 0 && !reportAnalysisResults && (
                                                <button
                                                    onClick={async () => {
                                                        setReportProcessing(true);
                                                        try {
                                                            // Build a map of all findings from CKLB files by various IDs
                                                            const comparisonMap = new Map<string, typeof reportComparisonFiles[0]['findings'][0] & { stigName: string }>();
                                                            reportComparisonFiles.forEach(ckl => {
                                                                ckl.findings.forEach(f => {
                                                                    const findingWithStig = { ...f, stigName: ckl.stigName || '' };
                                                                    // Store by various ID formats
                                                                    if (f.ruleId) comparisonMap.set(f.ruleId.toUpperCase(), findingWithStig);
                                                                    if (f.vulnId) comparisonMap.set(f.vulnId.toUpperCase(), findingWithStig);
                                                                    if (f.groupId) comparisonMap.set(f.groupId.toUpperCase(), findingWithStig);
                                                                    // Also store without V- prefix
                                                                    if (f.vulnId?.startsWith('V-')) comparisonMap.set(f.vulnId.substring(2).toUpperCase(), findingWithStig);
                                                                });
                                                            });

                                                            // Find the Group ID and Severity columns in CSV
                                                            const headers = reportBaseData.headers;
                                                            const groupIdCol = headers.find(h =>
                                                                h.toLowerCase().includes('group') ||
                                                                h.toLowerCase().includes('v-') ||
                                                                h.toLowerCase() === 'vuln' ||
                                                                h.toLowerCase() === 'vulnid' ||
                                                                h.toLowerCase() === 'groupid' ||
                                                                h.toLowerCase() === 'group_id' ||
                                                                h.toLowerCase() === 'id'
                                                            ) || headers[0];

                                                            const severityCol = headers.find(h =>
                                                                h.toLowerCase().includes('severity') ||
                                                                h.toLowerCase() === 'cat' ||
                                                                h.toLowerCase() === 'category'
                                                            );

                                                            // Compare CSV rows with CKLB findings
                                                            const results: Array<{
                                                                groupId: string;
                                                                ruleId: string;
                                                                stigName: string;
                                                                oldSeverity: string;
                                                                newSeverity: string;
                                                                severityChanged: boolean;
                                                                title: string;
                                                                checkText: string;
                                                                fixText: string;
                                                                description: string;
                                                                status: string;
                                                                findingDetails: string;
                                                                comments: string;
                                                                originalCsvRow: Record<string, string>;
                                                            }> = [];
                                                            reportBaseData.rows.forEach(csvRow => {
                                                                let groupId = csvRow[groupIdCol] || '';
                                                                // Normalize the group ID
                                                                groupId = groupId.trim().toUpperCase();

                                                                // Try to find matching finding in CKLB files
                                                                const matchedFinding =
                                                                    comparisonMap.get(groupId) ||
                                                                    comparisonMap.get('V-' + groupId) ||
                                                                    comparisonMap.get(groupId.replace('V-', ''));

                                                                const oldSev = severityCol ? (csvRow[severityCol] || 'Unknown') : 'N/A';
                                                                const newSev = matchedFinding?.severity || 'Not Found';
                                                                const oldSevNorm = oldSev.toLowerCase().replace(/\s+/g, '');
                                                                const newSevNorm = newSev.toLowerCase().replace(/\s+/g, '');
                                                                const sevChanged = matchedFinding ? (oldSevNorm !== newSevNorm) : false;

                                                                results.push({
                                                                    groupId: groupId,
                                                                    ruleId: matchedFinding?.ruleId || '',
                                                                    stigName: matchedFinding?.stigName || '',
                                                                    oldSeverity: oldSev,
                                                                    newSeverity: newSev,
                                                                    severityChanged: sevChanged,
                                                                    title: matchedFinding?.title || '',
                                                                    checkText: matchedFinding?.checkText || '',
                                                                    fixText: matchedFinding?.fixText || '',
                                                                    description: matchedFinding?.description || '',
                                                                    status: matchedFinding?.status || 'Not Found',
                                                                    findingDetails: matchedFinding?.findingDetails || '',
                                                                    comments: matchedFinding?.comments || '',
                                                                    originalCsvRow: csvRow
                                                                });
                                                            });

                                                            setReportAnalysisResults(results);
                                                        } finally {
                                                            setReportProcessing(false);
                                                        }
                                                    }}
                                                    disabled={reportProcessing}
                                                    className="w-full bg-amber-600 hover:bg-amber-700 disabled:bg-gray-400 text-white px-6 py-3 rounded-xl font-medium transition-all shadow-lg flex items-center justify-center gap-2 mb-6"
                                                >
                                                    {reportProcessing ? (
                                                        <>
                                                            <Loader2 size={18} className="animate-spin" />
                                                            Analyzing...
                                                        </>
                                                    ) : (
                                                        <>
                                                            <GitCompare size={18} />
                                                            Analyze & Compare
                                                        </>
                                                    )}
                                                </button>
                                            )}

                                            {/* Results Display */}
                                            {reportAnalysisResults && (
                                                <div className="space-y-4">
                                                    {/* Summary Stats */}
                                                    <div className="grid grid-cols-4 gap-4 mb-6">
                                                        <div className={`p-4 rounded-xl text-center ${darkMode ? 'bg-gray-700' : 'bg-gray-50'}`}>
                                                            <div className="text-2xl font-bold">{reportAnalysisResults.length}</div>
                                                            <div className="text-xs text-gray-500 uppercase">CSV Rows</div>
                                                        </div>
                                                        <div className="p-4 rounded-xl text-center bg-amber-50">
                                                            <div className="text-2xl font-bold text-amber-600">{reportAnalysisResults.filter(r => r.severityChanged).length}</div>
                                                            <div className="text-xs text-amber-500 uppercase">Severity Changed</div>
                                                        </div>
                                                        <div className="p-4 rounded-xl text-center bg-green-50">
                                                            <div className="text-2xl font-bold text-green-600">{reportAnalysisResults.filter(r => r.newSeverity !== 'Not Found').length}</div>
                                                            <div className="text-xs text-green-500 uppercase">Found in CKLB</div>
                                                        </div>
                                                        <div className="p-4 rounded-xl text-center bg-red-50">
                                                            <div className="text-2xl font-bold text-red-600">{reportAnalysisResults.filter(r => r.newSeverity === 'Not Found').length}</div>
                                                            <div className="text-xs text-red-500 uppercase">Not Found</div>
                                                        </div>
                                                    </div>

                                                    {/* Filter and Export Controls */}
                                                    <div className="flex items-center justify-between mb-4">
                                                        <label className="flex items-center gap-2 text-sm font-medium cursor-pointer">
                                                            <input
                                                                type="checkbox"
                                                                checked={reportFilterSeverityChange}
                                                                onChange={(e) => setReportFilterSeverityChange(e.target.checked)}
                                                                className="rounded border-gray-300 text-amber-600 focus:ring-amber-500"
                                                            />
                                                            Show only severity changes
                                                        </label>
                                                        <div className="flex gap-2">
                                                            <button
                                                                onClick={() => {
                                                                    if (!reportAnalysisResults) return;
                                                                    const dataToExport = reportFilterSeverityChange
                                                                        ? reportAnalysisResults.filter(r => r.severityChanged)
                                                                        : reportAnalysisResults;

                                                                    const wb = XLSX.utils.book_new();
                                                                    const wsData = dataToExport.map(r => ({
                                                                        'Group ID': r.groupId,
                                                                        'Rule ID': r.ruleId,
                                                                        'STIG Name': r.stigName,
                                                                        'Title': r.title,
                                                                        'Old Severity (CSV)': r.oldSeverity,
                                                                        'New Severity (CKLB)': r.newSeverity,
                                                                        'Severity Changed': r.severityChanged ? 'Yes' : 'No',
                                                                        'Status': r.status,
                                                                        'Check Text': r.checkText,
                                                                        'Fix Text': r.fixText,
                                                                        'Description': r.description,
                                                                        'Finding Details': r.findingDetails,
                                                                        'Comments': r.comments
                                                                    }));
                                                                    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(wsData), 'Report Analysis');
                                                                    XLSX.writeFile(wb, `report_analysis_${new Date().toISOString().split('T')[0]}.xlsx`);
                                                                }}
                                                                className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium flex items-center gap-2"
                                                            >
                                                                <FileSpreadsheet size={16} />
                                                                Export Excel
                                                            </button>
                                                            <button
                                                                onClick={() => {
                                                                    setReportAnalysisResults(null);
                                                                    setReportBaseData(null);
                                                                    setReportComparisonFiles([]);
                                                                }}
                                                                className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg text-sm font-medium"
                                                            >
                                                                Reset
                                                            </button>
                                                        </div>
                                                    </div>

                                                    {/* Results Table */}
                                                    <div className={`rounded-xl border overflow-hidden ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                        <div className={`grid gap-2 p-3 border-b font-semibold text-xs uppercase tracking-wider ${darkMode ? 'bg-gray-800 border-gray-700 text-gray-400' : 'bg-gray-50 border-gray-100 text-gray-500'}`} style={{ gridTemplateColumns: '100px 1fr 100px 100px 100px 80px' }}>
                                                            <div>Group ID</div>
                                                            <div>Title / STIG</div>
                                                            <div className="text-center">Old (CSV)</div>
                                                            <div className="text-center">New (CKLB)</div>
                                                            <div className="text-center">Status</div>
                                                            <div className="text-center">Changed</div>
                                                        </div>
                                                        <div className="max-h-[500px] overflow-y-auto">
                                                            {(reportFilterSeverityChange ? reportAnalysisResults.filter(r => r.severityChanged) : reportAnalysisResults).map((row, idx) => (
                                                                <div
                                                                    key={idx}
                                                                    className={`grid gap-2 p-3 border-b last:border-0 text-sm items-center hover:bg-gray-50/5 cursor-pointer ${darkMode ? 'border-gray-700 text-gray-300' : 'border-gray-100 text-gray-700'} ${row.severityChanged ? 'bg-amber-50/50' : ''}`}
                                                                    style={{ gridTemplateColumns: '100px 1fr 100px 100px 100px 80px' }}
                                                                    onClick={() => {
                                                                        alert(`Rule Details:\n\nGroup ID: ${row.groupId}\nRule ID: ${row.ruleId}\nSTIG: ${row.stigName}\nTitle: ${row.title}\n\nOld Severity (CSV): ${row.oldSeverity}\nNew Severity (CKLB): ${row.newSeverity}\nStatus: ${row.status}\n\nDescription:\n${row.description?.substring(0, 500) || 'N/A'}${row.description?.length > 500 ? '...' : ''}\n\nCheck Text:\n${row.checkText?.substring(0, 500) || 'N/A'}${row.checkText?.length > 500 ? '...' : ''}`);
                                                                    }}
                                                                >
                                                                    <div className="font-mono text-xs">{row.groupId}</div>
                                                                    <div className="truncate">
                                                                        <div className="font-medium truncate">{row.title || 'N/A'}</div>
                                                                        {row.stigName && <div className="text-xs text-gray-400 truncate">{row.stigName}</div>}
                                                                    </div>
                                                                    <div className="text-center">
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${row.oldSeverity.toLowerCase() === 'high' || row.oldSeverity.toLowerCase().includes('cat i') || row.oldSeverity === '1' ? 'bg-red-100 text-red-700' :
                                                                            row.oldSeverity.toLowerCase() === 'medium' || row.oldSeverity.toLowerCase().includes('cat ii') || row.oldSeverity === '2' ? 'bg-orange-100 text-orange-700' :
                                                                                row.oldSeverity.toLowerCase() === 'low' || row.oldSeverity.toLowerCase().includes('cat iii') || row.oldSeverity === '3' ? 'bg-yellow-100 text-yellow-700' :
                                                                                    'bg-gray-100 text-gray-600'
                                                                            }`}>{row.oldSeverity}</span>
                                                                    </div>
                                                                    <div className="text-center">
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${row.newSeverity === 'Not Found' ? 'bg-gray-100 text-gray-500' :
                                                                            row.newSeverity.toLowerCase() === 'high' || row.newSeverity.toLowerCase().includes('cat i') ? 'bg-red-100 text-red-700' :
                                                                                row.newSeverity.toLowerCase() === 'medium' || row.newSeverity.toLowerCase().includes('cat ii') ? 'bg-orange-100 text-orange-700' :
                                                                                    'bg-yellow-100 text-yellow-700'
                                                                            }`}>{row.newSeverity}</span>
                                                                    </div>
                                                                    <div className="text-center">
                                                                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${row.status === 'Open' ? 'bg-red-100 text-red-600' :
                                                                            row.status === 'NotAFinding' || row.status === 'Not_A_Finding' ? 'bg-green-100 text-green-600' :
                                                                                row.status === 'Not_Reviewed' ? 'bg-gray-100 text-gray-600' :
                                                                                    'bg-gray-100 text-gray-500'
                                                                            }`}>{row.status}</span>
                                                                    </div>
                                                                    <div className="text-center">
                                                                        {row.severityChanged ? (
                                                                            <span className="text-amber-600 font-bold">⚠️ Yes</span>
                                                                        ) : (
                                                                            <span className="text-gray-400">-</span>
                                                                        )}
                                                                    </div>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            )}

                                            {/* Empty State */}
                                            {!reportBaseData && reportComparisonFiles.length === 0 && (
                                                <div className="p-8 text-center text-gray-400 border-2 border-dashed rounded-xl">
                                                    <FileSpreadsheet className="mx-auto size-12 mb-4 opacity-30" />
                                                    <p className="font-medium">Upload a CSV/Excel file and a CKLB folder to begin analysis</p>
                                                    <p className="text-sm mt-2">The CSV should contain Group IDs. We'll look them up in your CKLB files to compare severities.</p>
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ) : activeTab === 'network' ? (
                        <div className="h-[calc(100vh-100px)] w-full">
                            <NetworkDiagram darkMode={darkMode} />
                        </div>
                    ) : activeTab === 'webscan' ? (
                        <div className="h-[calc(100vh-100px)] w-full">
                            <WebScanner darkMode={darkMode} />
                        </div>
                    ) : activeTab === 'codescan' ? (
                        <div className="h-[calc(100vh-100px)] w-full overflow-auto">
                            <CodeScanner darkMode={darkMode} />
                        </div>
                    ) : activeTab === 'blockchain' ? (
                        <div className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h1 className="text-3xl font-semibold tracking-tight">Blockchain Security</h1>
                                    <p className={`mt-1 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Smart contract analysis and Web3 security tools</p>
                                </div>
                                <div className="flex items-center gap-2">
                                    <select
                                        value={selectedChain}
                                        onChange={(e) => setSelectedChain(Number(e.target.value))}
                                        className={`px-3 py-2 rounded-lg text-sm border ${darkMode ? 'bg-gray-800 border-gray-700 text-white' : 'bg-white border-gray-200'}`}
                                    >
                                        {Object.entries(chainInfo).map(([id, info]) => (
                                            <option key={id} value={id}>{info.name}</option>
                                        ))}
                                    </select>
                                    {chainInfo[selectedChain]?.explorer && (
                                        <a
                                            href={chainInfo[selectedChain].explorer}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className={`px-3 py-2 rounded-lg text-sm flex items-center gap-2 ${darkMode ? 'bg-gray-800 hover:bg-gray-700 text-gray-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'}`}
                                        >
                                            <ExternalLink size={14} />
                                            Explorer
                                        </a>
                                    )}
                                </div>
                            </div>

                            {/* Tool Selection */}
                            <div className={`flex gap-2 p-1.5 rounded-xl ${darkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                                {[
                                    { id: 'analyzer', icon: <FileCode size={16} />, label: 'Contract Analyzer' },
                                    { id: 'address', icon: <Wallet size={16} />, label: 'Address Checker' },
                                    { id: 'decoder', icon: <Code size={16} />, label: 'TX Decoder' },
                                    { id: 'abi', icon: <FileText size={16} />, label: 'ABI Parser' },
                                    { id: 'converter', icon: <Hash size={16} />, label: 'Unit Converter' },
                                    { id: 'attacks', icon: <AlertTriangle size={16} />, label: 'Attack Vectors' },
                                ].map((tool) => (
                                    <button
                                        key={tool.id}
                                        onClick={() => setBlockchainMode(tool.id as any)}
                                        className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${blockchainMode === tool.id
                                            ? 'bg-purple-600 text-white shadow-lg'
                                            : darkMode
                                                ? 'text-gray-400 hover:text-white hover:bg-gray-700'
                                                : 'text-gray-600 hover:text-gray-900 hover:bg-white'
                                            }`}
                                    >
                                        {tool.icon}
                                        <span className="hidden md:inline">{tool.label}</span>
                                    </button>
                                ))}
                            </div>

                            {/* Smart Contract Analyzer */}
                            {blockchainMode === 'analyzer' && (
                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="p-3 bg-purple-100 text-purple-600 rounded-xl">
                                            <FileCode size={24} />
                                        </div>
                                        <div>
                                            <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Smart Contract Analyzer</h2>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Paste Solidity code to scan for common vulnerabilities</p>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                        <div>
                                            <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Solidity Code</label>
                                            <textarea
                                                value={contractCode}
                                                onChange={(e) => setContractCode(e.target.value)}
                                                placeholder={`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Example {
    // Paste your contract code here...
}`}
                                                rows={20}
                                                className={`w-full px-4 py-3 rounded-xl border font-mono text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300 placeholder-gray-600' : 'bg-gray-50 border-gray-200 placeholder-gray-400'}`}
                                            />
                                            <button
                                                onClick={() => {
                                                    if (contractCode.trim()) {
                                                        setContractAnalysis(analyzeContract(contractCode));
                                                    }
                                                }}
                                                disabled={!contractCode.trim()}
                                                className="mt-4 w-full px-4 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-500 text-white font-medium rounded-xl transition-colors flex items-center justify-center gap-2"
                                            >
                                                <Search size={18} />
                                                Analyze Contract
                                            </button>
                                        </div>

                                        <div>
                                            <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Analysis Results</label>
                                            {contractAnalysis ? (
                                                <div className="space-y-4">
                                                    {/* Summary */}
                                                    <div className={`p-4 rounded-xl ${contractAnalysis.vulnerabilities.some(v => v.severity === 'critical')
                                                        ? 'bg-red-500/10 border border-red-500/30'
                                                        : contractAnalysis.vulnerabilities.some(v => v.severity === 'high')
                                                            ? 'bg-orange-500/10 border border-orange-500/30'
                                                            : contractAnalysis.vulnerabilities.length > 0
                                                                ? 'bg-yellow-500/10 border border-yellow-500/30'
                                                                : 'bg-green-500/10 border border-green-500/30'
                                                        }`}>
                                                        <p className={`text-sm font-medium ${darkMode ? 'text-gray-200' : 'text-gray-800'}`}>{contractAnalysis.summary}</p>
                                                        <div className="flex gap-4 mt-2 text-xs">
                                                            <span className="text-red-500">{contractAnalysis.vulnerabilities.filter(v => v.severity === 'critical').length} Critical</span>
                                                            <span className="text-orange-500">{contractAnalysis.vulnerabilities.filter(v => v.severity === 'high').length} High</span>
                                                            <span className="text-yellow-500">{contractAnalysis.vulnerabilities.filter(v => v.severity === 'medium').length} Medium</span>
                                                            <span className="text-blue-500">{contractAnalysis.vulnerabilities.filter(v => v.severity === 'low').length} Low</span>
                                                        </div>
                                                    </div>

                                                    {/* Vulnerabilities List */}
                                                    <div className={`max-h-[400px] overflow-auto rounded-xl border ${darkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                                                        {contractAnalysis.vulnerabilities.length > 0 ? (
                                                            contractAnalysis.vulnerabilities.map((vuln, idx) => (
                                                                <div key={idx} className={`p-4 border-b last:border-b-0 ${darkMode ? 'border-gray-700' : 'border-gray-100'}`}>
                                                                    <div className="flex items-start gap-3">
                                                                        <span className={`px-2 py-1 text-xs font-bold rounded ${vuln.severity === 'critical' ? 'bg-red-500 text-white' :
                                                                            vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                                                                                vuln.severity === 'medium' ? 'bg-yellow-500 text-black' :
                                                                                    vuln.severity === 'low' ? 'bg-blue-500 text-white' :
                                                                                        'bg-gray-500 text-white'
                                                                            }`}>
                                                                            {vuln.severity.toUpperCase()}
                                                                        </span>
                                                                        <div className="flex-1">
                                                                            <h4 className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>{vuln.title}</h4>
                                                                            {vuln.line && <p className={`text-xs mt-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Line {vuln.line}</p>}
                                                                            <p className={`text-sm mt-2 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{vuln.description}</p>
                                                                            <p className={`text-sm mt-2 ${darkMode ? 'text-green-400' : 'text-green-600'}`}>
                                                                                <strong>Fix:</strong> {vuln.recommendation}
                                                                            </p>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            ))
                                                        ) : (
                                                            <div className={`p-8 text-center ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                                <CheckCircle2 size={48} className="mx-auto mb-3 text-green-500" />
                                                                <p>No obvious vulnerabilities detected</p>
                                                                <p className="text-xs mt-1">Manual review still recommended</p>
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            ) : (
                                                <div className={`h-[500px] flex items-center justify-center rounded-xl border ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-500' : 'bg-gray-50 border-gray-200 text-gray-400'}`}>
                                                    <div className="text-center">
                                                        <FileCode size={48} className="mx-auto mb-3 opacity-30" />
                                                        <p>Paste Solidity code and click Analyze</p>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Address Checker */}
                            {blockchainMode === 'address' && (
                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="p-3 bg-blue-100 text-blue-600 rounded-xl">
                                            <Wallet size={24} />
                                        </div>
                                        <div>
                                            <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Address Checker</h2>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Validate Ethereum addresses and check format</p>
                                        </div>
                                    </div>

                                    <div className="max-w-2xl">
                                        <div className="flex gap-3">
                                            <input
                                                type="text"
                                                value={addressInput}
                                                onChange={(e) => setAddressInput(e.target.value)}
                                                placeholder="0x..."
                                                className={`flex-1 px-4 py-3 rounded-xl border font-mono text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-white placeholder-gray-600' : 'bg-gray-50 border-gray-200'}`}
                                            />
                                            <button
                                                onClick={() => setAddressValidation(validateAddress(addressInput))}
                                                disabled={!addressInput}
                                                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-500 text-white font-medium rounded-xl transition-colors"
                                            >
                                                Validate
                                            </button>
                                        </div>

                                        {addressValidation && (
                                            <div className={`mt-4 p-4 rounded-xl ${addressValidation.valid ? 'bg-green-500/10 border border-green-500/30' : 'bg-red-500/10 border border-red-500/30'}`}>
                                                <div className="flex items-center gap-3">
                                                    {addressValidation.valid ? (
                                                        <CheckCircle2 className="text-green-500" size={24} />
                                                    ) : (
                                                        <XCircle className="text-red-500" size={24} />
                                                    )}
                                                    <div>
                                                        <p className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                            {addressValidation.valid ? 'Valid Address' : 'Invalid Address'}
                                                        </p>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                            {addressValidation.type}
                                                            {addressValidation.checksum !== undefined && (
                                                                <span className="ml-2">
                                                                    • Checksum: {addressValidation.checksum ? 'Valid' : 'Not checksummed'}
                                                                </span>
                                                            )}
                                                        </p>
                                                    </div>
                                                </div>
                                                {addressValidation.valid && chainInfo[selectedChain]?.explorer && (
                                                    <a
                                                        href={`${chainInfo[selectedChain].explorer}/address/${addressInput}`}
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className={`mt-3 inline-flex items-center gap-2 text-sm ${darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700'}`}
                                                    >
                                                        <ExternalLink size={14} />
                                                        View on {chainInfo[selectedChain].name}
                                                    </a>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* Transaction Decoder */}
                            {blockchainMode === 'decoder' && (
                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="p-3 bg-green-100 text-green-600 rounded-xl">
                                            <Code size={24} />
                                        </div>
                                        <div>
                                            <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Transaction Data Decoder</h2>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Decode function selectors from transaction input data</p>
                                        </div>
                                    </div>

                                    <div className="max-w-2xl">
                                        <div className="flex gap-3">
                                            <input
                                                type="text"
                                                value={txDataInput}
                                                onChange={(e) => setTxDataInput(e.target.value)}
                                                placeholder="0xa9059cbb..."
                                                className={`flex-1 px-4 py-3 rounded-xl border font-mono text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-white placeholder-gray-600' : 'bg-gray-50 border-gray-200'}`}
                                            />
                                            <button
                                                onClick={() => setDecodedFunction(decodeFunctionSelector(txDataInput))}
                                                disabled={!txDataInput}
                                                className="px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-gray-500 text-white font-medium rounded-xl transition-colors"
                                            >
                                                Decode
                                            </button>
                                        </div>

                                        {decodedFunction && (
                                            <div className={`mt-4 p-4 rounded-xl ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-gray-50 border border-gray-200'}`}>
                                                <div className="space-y-3">
                                                    <div>
                                                        <p className={`text-xs font-medium ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Function Selector</p>
                                                        <p className={`font-mono ${darkMode ? 'text-white' : 'text-gray-900'}`}>{decodedFunction.selector}</p>
                                                    </div>
                                                    {decodedFunction.name && (
                                                        <div>
                                                            <p className={`text-xs font-medium ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Function Signature</p>
                                                            <p className={`font-mono text-green-500`}>{decodedFunction.name}</p>
                                                        </div>
                                                    )}
                                                    {!decodedFunction.name && (
                                                        <p className={`text-sm ${darkMode ? 'text-yellow-400' : 'text-yellow-600'}`}>
                                                            Unknown function - check 4byte.directory or Etherscan
                                                        </p>
                                                    )}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* ABI Parser */}
                            {blockchainMode === 'abi' && (
                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="p-3 bg-orange-100 text-orange-600 rounded-xl">
                                            <FileText size={24} />
                                        </div>
                                        <div>
                                            <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>ABI Parser</h2>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Parse contract ABI to view functions, events, and errors</p>
                                        </div>
                                    </div>

                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                        <div>
                                            <label className={`block text-sm font-medium mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>Contract ABI (JSON)</label>
                                            <textarea
                                                value={abiInput}
                                                onChange={(e) => setAbiInput(e.target.value)}
                                                placeholder='[{"type":"function","name":"transfer",...}]'
                                                rows={15}
                                                className={`w-full px-4 py-3 rounded-xl border font-mono text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-300 placeholder-gray-600' : 'bg-gray-50 border-gray-200'}`}
                                            />
                                            <button
                                                onClick={() => setParsedAbi(parseABI(abiInput))}
                                                disabled={!abiInput}
                                                className="mt-4 w-full px-4 py-3 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-500 text-white font-medium rounded-xl transition-colors"
                                            >
                                                Parse ABI
                                            </button>
                                        </div>

                                        <div>
                                            {parsedAbi ? (
                                                <div className="space-y-4">
                                                    {parsedAbi.functions.length > 0 && (
                                                        <div>
                                                            <h4 className={`text-sm font-medium mb-2 flex items-center gap-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                <Play size={14} /> Functions ({parsedAbi.functions.length})
                                                            </h4>
                                                            <div className={`max-h-40 overflow-auto rounded-lg border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                                {parsedAbi.functions.map((fn, idx) => (
                                                                    <div key={idx} className={`px-3 py-2 text-xs font-mono border-b last:border-b-0 ${darkMode ? 'border-gray-700 text-green-400' : 'border-gray-100 text-green-600'}`}>
                                                                        {fn}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                    {parsedAbi.events.length > 0 && (
                                                        <div>
                                                            <h4 className={`text-sm font-medium mb-2 flex items-center gap-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                <Activity size={14} /> Events ({parsedAbi.events.length})
                                                            </h4>
                                                            <div className={`max-h-40 overflow-auto rounded-lg border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                                {parsedAbi.events.map((ev, idx) => (
                                                                    <div key={idx} className={`px-3 py-2 text-xs font-mono border-b last:border-b-0 ${darkMode ? 'border-gray-700 text-blue-400' : 'border-gray-100 text-blue-600'}`}>
                                                                        {ev}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                    {parsedAbi.errors.length > 0 && (
                                                        <div>
                                                            <h4 className={`text-sm font-medium mb-2 flex items-center gap-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                <AlertTriangle size={14} /> Errors ({parsedAbi.errors.length})
                                                            </h4>
                                                            <div className={`max-h-40 overflow-auto rounded-lg border ${darkMode ? 'bg-gray-900 border-gray-700' : 'bg-gray-50 border-gray-200'}`}>
                                                                {parsedAbi.errors.map((err, idx) => (
                                                                    <div key={idx} className={`px-3 py-2 text-xs font-mono border-b last:border-b-0 ${darkMode ? 'border-gray-700 text-red-400' : 'border-gray-100 text-red-600'}`}>
                                                                        {err}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}
                                                </div>
                                            ) : (
                                                <div className={`h-full flex items-center justify-center rounded-xl border ${darkMode ? 'bg-gray-900 border-gray-700 text-gray-500' : 'bg-gray-50 border-gray-200 text-gray-400'}`}>
                                                    <div className="text-center py-20">
                                                        <FileText size={48} className="mx-auto mb-3 opacity-30" />
                                                        <p>Paste ABI JSON and click Parse</p>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Unit Converter */}
                            {blockchainMode === 'converter' && (
                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                    <div className="flex items-center gap-3 mb-6">
                                        <div className="p-3 bg-cyan-100 text-cyan-600 rounded-xl">
                                            <Hash size={24} />
                                        </div>
                                        <div>
                                            <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Ethereum Unit Converter</h2>
                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Convert between Wei, Gwei, and Ether</p>
                                        </div>
                                    </div>

                                    <div className="max-w-xl">
                                        <div className="flex gap-3">
                                            <input
                                                type="text"
                                                value={weiInput}
                                                onChange={(e) => setWeiInput(e.target.value)}
                                                placeholder="Enter Wei amount"
                                                className={`flex-1 px-4 py-3 rounded-xl border font-mono text-sm ${darkMode ? 'bg-gray-900 border-gray-700 text-white placeholder-gray-600' : 'bg-gray-50 border-gray-200'}`}
                                            />
                                            <button
                                                onClick={() => setConvertedValues(formatWei(weiInput))}
                                                disabled={!weiInput}
                                                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-500 text-white font-medium rounded-xl transition-colors"
                                            >
                                                Convert
                                            </button>
                                        </div>

                                        {convertedValues && (
                                            <div className={`mt-4 grid grid-cols-3 gap-4`}>
                                                <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-gray-50 border border-gray-200'}`}>
                                                    <p className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Wei</p>
                                                    <p className={`font-mono text-sm truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{convertedValues.wei}</p>
                                                </div>
                                                <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-gray-50 border border-gray-200'}`}>
                                                    <p className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Gwei</p>
                                                    <p className={`font-mono text-sm truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{convertedValues.gwei}</p>
                                                </div>
                                                <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900 border border-gray-700' : 'bg-gray-50 border border-gray-200'}`}>
                                                    <p className={`text-xs font-medium mb-1 ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Ether</p>
                                                    <p className={`font-mono text-sm truncate ${darkMode ? 'text-white' : 'text-gray-900'}`}>{convertedValues.ether}</p>
                                                </div>
                                            </div>
                                        )}

                                        {/* Quick Reference */}
                                        <div className={`mt-6 p-4 rounded-xl ${darkMode ? 'bg-gray-900/50' : 'bg-gray-50'}`}>
                                            <h4 className={`text-sm font-medium mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Quick Reference</h4>
                                            <div className={`grid grid-cols-2 gap-2 text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                <span>1 Ether = 10^18 Wei</span>
                                                <span>1 Gwei = 10^9 Wei</span>
                                                <span>1 Ether = 10^9 Gwei</span>
                                                <span>Gas Price typically 10-100 Gwei</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Attack Vectors Reference */}
                            {blockchainMode === 'attacks' && (
                                <div className="space-y-6">
                                    {/* Header with Mode Toggle */}
                                    <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                        <div className="flex items-center justify-between mb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-3 bg-red-100 text-red-600 rounded-xl">
                                                    <AlertTriangle size={24} />
                                                </div>
                                                <div>
                                                    <h2 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Security Lab</h2>
                                                    <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Learn attacks & scan code for vulnerabilities</p>
                                                </div>
                                            </div>
                                            {/* Mode Toggle */}
                                            <div className={`flex rounded-xl p-1 ${darkMode ? 'bg-gray-900' : 'bg-gray-100'}`}>
                                                <button
                                                    onClick={() => setAttackLabMode('learn')}
                                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${attackLabMode === 'learn'
                                                        ? 'bg-purple-500 text-white shadow'
                                                        : darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'
                                                        }`}
                                                >
                                                    <Book size={16} />
                                                    Learn Attacks
                                                </button>
                                                <button
                                                    onClick={() => setAttackLabMode('scan')}
                                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${attackLabMode === 'scan'
                                                        ? 'bg-purple-500 text-white shadow'
                                                        : darkMode ? 'text-gray-400 hover:text-white' : 'text-gray-600 hover:text-gray-900'
                                                        }`}
                                                >
                                                    <Search size={16} />
                                                    Scan Code
                                                </button>
                                            </div>
                                        </div>
                                        <div className={`p-4 rounded-xl ${darkMode ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-yellow-50 border border-yellow-200'}`}>
                                            <p className={`text-sm flex items-start gap-2 ${darkMode ? 'text-yellow-300' : 'text-yellow-700'}`}>
                                                <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
                                                <span><strong>Warning:</strong> {attackLabMode === 'learn'
                                                    ? 'These examples are for educational purposes and authorized security testing only. Never use against systems without explicit permission.'
                                                    : 'This scanner detects common patterns but is NOT a replacement for professional audits. Always get contracts audited before deploying with real funds.'
                                                }</span>
                                            </p>
                                        </div>
                                    </div>

                                    {/* SCANNER MODE */}
                                    {attackLabMode === 'scan' && (
                                        <div className="space-y-6">
                                            {/* Code Input */}
                                            <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                <div className="flex items-center justify-between mb-4">
                                                    <h3 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Paste Solidity Code</h3>
                                                    <div className="flex items-center gap-2">
                                                        {scannerCode && (
                                                            <button
                                                                onClick={() => { setScannerCode(''); setScanResults(null); }}
                                                                className={`px-3 py-1.5 text-sm rounded-lg ${darkMode ? 'text-gray-400 hover:text-white hover:bg-gray-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'}`}
                                                            >
                                                                Clear
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => {
                                                                if (scannerCode.trim()) {
                                                                    setScanResults(analyzeContract(scannerCode));
                                                                }
                                                            }}
                                                            disabled={!scannerCode.trim()}
                                                            className={`px-4 py-2 rounded-xl font-medium flex items-center gap-2 transition-all ${scannerCode.trim()
                                                                ? 'bg-purple-500 text-white hover:bg-purple-600'
                                                                : darkMode ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-gray-200 text-gray-400 cursor-not-allowed'
                                                                }`}
                                                        >
                                                            <Search size={16} />
                                                            Scan for Vulnerabilities
                                                        </button>
                                                    </div>
                                                </div>
                                                <textarea
                                                    value={scannerCode}
                                                    onChange={(e) => setScannerCode(e.target.value)}
                                                    placeholder={`// Paste your Solidity code here...
pragma solidity ^0.8.0;

contract MyContract {
    // ...
}`}
                                                    className={`w-full h-64 p-4 rounded-xl font-mono text-sm resize-none ${darkMode
                                                        ? 'bg-gray-900 text-gray-300 border border-gray-700 placeholder-gray-600'
                                                        : 'bg-gray-50 text-gray-800 border border-gray-200 placeholder-gray-400'
                                                        }`}
                                                />
                                                <div className={`mt-2 flex items-center justify-between text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                    <span>{scannerCode.split('\n').length} lines</span>
                                                    <span>Supports Solidity 0.4.x - 0.8.x</span>
                                                </div>
                                            </div>

                                            {/* Scan Results */}
                                            {scanResults && (
                                                <div className="space-y-4">
                                                    {/* Summary */}
                                                    <div className={`p-6 rounded-2xl border ${scanResults.stats?.critical ? (darkMode ? 'bg-red-500/10 border-red-500/50' : 'bg-red-50 border-red-200') :
                                                        scanResults.stats?.high ? (darkMode ? 'bg-orange-500/10 border-orange-500/50' : 'bg-orange-50 border-orange-200') :
                                                            scanResults.vulnerabilities.length > 0 ? (darkMode ? 'bg-yellow-500/10 border-yellow-500/50' : 'bg-yellow-50 border-yellow-200') :
                                                                darkMode ? 'bg-green-500/10 border-green-500/50' : 'bg-green-50 border-green-200'
                                                        }`}>
                                                        <h3 className={`text-lg font-semibold mb-3 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Scan Results</h3>
                                                        <p className={`text-sm mb-4 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>{scanResults.summary}</p>

                                                        {/* Stats Grid */}
                                                        {scanResults.stats && (
                                                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                                                <div className={`p-3 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                                    <div className="text-2xl font-bold text-red-500">{scanResults.stats.critical}</div>
                                                                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Critical</div>
                                                                </div>
                                                                <div className={`p-3 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                                    <div className="text-2xl font-bold text-orange-500">{scanResults.stats.high}</div>
                                                                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>High</div>
                                                                </div>
                                                                <div className={`p-3 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                                    <div className="text-2xl font-bold text-yellow-500">{scanResults.stats.medium}</div>
                                                                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Medium</div>
                                                                </div>
                                                                <div className={`p-3 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                                    <div className="text-2xl font-bold text-blue-500">{scanResults.stats.low}</div>
                                                                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Low</div>
                                                                </div>
                                                                <div className={`p-3 rounded-xl text-center ${darkMode ? 'bg-gray-800' : 'bg-white'}`}>
                                                                    <div className="text-2xl font-bold text-gray-500">{scanResults.stats.info}</div>
                                                                    <div className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Info</div>
                                                                </div>
                                                            </div>
                                                        )}

                                                        {/* Code Stats */}
                                                        {scanResults.stats && (
                                                            <div className={`mt-4 pt-4 border-t flex items-center gap-6 text-sm ${darkMode ? 'border-gray-700 text-gray-400' : 'border-gray-200 text-gray-500'}`}>
                                                                <span>{scanResults.stats.lines} lines</span>
                                                                <span>{scanResults.stats.contracts} contracts</span>
                                                                <span>{scanResults.stats.functions} functions</span>
                                                                <span>{scanResults.stats.modifiers} modifiers</span>
                                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${scanResults.complexity === 'high' ? 'bg-red-500/20 text-red-400' :
                                                                    scanResults.complexity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                                        'bg-green-500/20 text-green-400'
                                                                    }`}>
                                                                    {scanResults.complexity} complexity
                                                                </span>
                                                            </div>
                                                        )}
                                                    </div>

                                                    {/* Vulnerability List */}
                                                    {scanResults.vulnerabilities.length > 0 && (
                                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                            <h3 className={`font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>
                                                                Found Issues ({scanResults.vulnerabilities.length})
                                                            </h3>
                                                            <div className="space-y-3">
                                                                {scanResults.vulnerabilities.map((vuln, idx) => (
                                                                    <div key={idx} className={`p-4 rounded-xl border-l-4 ${vuln.severity === 'critical' ? 'border-red-500 ' + (darkMode ? 'bg-red-500/10' : 'bg-red-50') :
                                                                        vuln.severity === 'high' ? 'border-orange-500 ' + (darkMode ? 'bg-orange-500/10' : 'bg-orange-50') :
                                                                            vuln.severity === 'medium' ? 'border-yellow-500 ' + (darkMode ? 'bg-yellow-500/10' : 'bg-yellow-50') :
                                                                                vuln.severity === 'low' ? 'border-blue-500 ' + (darkMode ? 'bg-blue-500/10' : 'bg-blue-50') :
                                                                                    'border-gray-400 ' + (darkMode ? 'bg-gray-700' : 'bg-gray-50')
                                                                        }`}>
                                                                        <div className="flex items-start justify-between gap-4">
                                                                            <div className="flex-1">
                                                                                <div className="flex items-center gap-2 mb-1">
                                                                                    <span className={`px-2 py-0.5 text-xs font-bold rounded ${vuln.severity === 'critical' ? 'bg-red-500 text-white' :
                                                                                        vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                                                                                            vuln.severity === 'medium' ? 'bg-yellow-500 text-black' :
                                                                                                vuln.severity === 'low' ? 'bg-blue-500 text-white' :
                                                                                                    'bg-gray-400 text-white'
                                                                                        }`}>
                                                                                        {vuln.severity.toUpperCase()}
                                                                                    </span>
                                                                                    <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{vuln.title}</h4>
                                                                                    {vuln.line && (
                                                                                        <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>Line {vuln.line}</span>
                                                                                    )}
                                                                                </div>
                                                                                <p className={`text-sm mb-2 ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>{vuln.description}</p>
                                                                                {vuln.lineContent && (
                                                                                    <pre className={`text-xs p-2 rounded mb-2 overflow-x-auto ${darkMode ? 'bg-gray-900 text-gray-400' : 'bg-white text-gray-600 border'}`}>
                                                                                        {vuln.lineContent}
                                                                                    </pre>
                                                                                )}
                                                                                <p className={`text-sm ${darkMode ? 'text-green-400' : 'text-green-600'}`}>
                                                                                    <strong>Fix:</strong> {vuln.recommendation}
                                                                                </p>
                                                                                <div className="flex items-center gap-3 mt-2">
                                                                                    {vuln.attackVector && (
                                                                                        <button
                                                                                            onClick={() => {
                                                                                                const attack = attackVectors.find(a => a.name === vuln.attackVector);
                                                                                                if (attack) {
                                                                                                    setSelectedAttack(attack);
                                                                                                    setAttackLabMode('learn');
                                                                                                }
                                                                                            }}
                                                                                            className={`text-xs px-2 py-1 rounded flex items-center gap-1 ${darkMode ? 'bg-purple-500/20 text-purple-400 hover:bg-purple-500/30' : 'bg-purple-100 text-purple-600 hover:bg-purple-200'}`}
                                                                                        >
                                                                                            <Book size={12} />
                                                                                            Learn: {vuln.attackVector}
                                                                                        </button>
                                                                                    )}
                                                                                    {vuln.cwe && (
                                                                                        <span className={`text-xs ${darkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                                                                                            {vuln.cwe}
                                                                                        </span>
                                                                                    )}
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* No Issues Found */}
                                                    {scanResults.vulnerabilities.length === 0 && (
                                                        <div className={`p-8 rounded-2xl border text-center ${darkMode ? 'bg-green-500/10 border-green-500/30' : 'bg-green-50 border-green-200'}`}>
                                                            <CheckCircle2 size={48} className="mx-auto mb-4 text-green-500" />
                                                            <h3 className={`text-lg font-semibold mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>No Obvious Vulnerabilities Found</h3>
                                                            <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                                This scanner checks for common patterns. Always get a professional audit before deploying contracts with real value.
                                                            </p>
                                                        </div>
                                                    )}
                                                </div>
                                            )}

                                            {/* Example Contracts to Test */}
                                            {!scanResults && (
                                                <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                    <h3 className={`font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Try These Examples</h3>
                                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                                        <button
                                                            onClick={() => setScannerCode(`// VULNERABLE: Reentrancy
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        
        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        
        balances[msg.sender] = 0;
    }
}`)}
                                                            className={`p-4 rounded-xl text-left transition-all hover:scale-[1.02] ${darkMode ? 'bg-gray-900 hover:bg-gray-750 border border-gray-700' : 'bg-gray-50 hover:bg-gray-100 border border-gray-200'}`}
                                                        >
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="px-2 py-0.5 text-xs font-bold rounded bg-red-500 text-white">CRITICAL</span>
                                                                <span className={`text-sm font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Reentrancy Example</span>
                                                            </div>
                                                            <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Classic vulnerable bank contract</p>
                                                        </button>

                                                        <button
                                                            onClick={() => setScannerCode(`// VULNERABLE: tx.origin authentication
pragma solidity ^0.7.0;

contract VulnerableWallet {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    function transfer(address to, uint amount) public {
        // Vulnerable: using tx.origin
        require(tx.origin == owner);
        payable(to).transfer(amount);
    }
    
    function destroy() public {
        require(tx.origin == owner);
        selfdestruct(payable(owner));
    }
}`)}
                                                            className={`p-4 rounded-xl text-left transition-all hover:scale-[1.02] ${darkMode ? 'bg-gray-900 hover:bg-gray-750 border border-gray-700' : 'bg-gray-50 hover:bg-gray-100 border border-gray-200'}`}
                                                        >
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="px-2 py-0.5 text-xs font-bold rounded bg-red-500 text-white">CRITICAL</span>
                                                                <span className={`text-sm font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Access Control Example</span>
                                                            </div>
                                                            <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>tx.origin + selfdestruct vulnerabilities</p>
                                                        </button>

                                                        <button
                                                            onClick={() => setScannerCode(`// VULNERABLE: Oracle manipulation
pragma solidity ^0.8.0;

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract VulnerableLending {
    IUniswapV2Pair public pair;
    mapping(address => uint256) public deposits;
    
    function getPrice() public view returns (uint256) {
        // Vulnerable: spot price from DEX
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        return (uint256(reserve1) * 1e18) / uint256(reserve0);
    }
    
    function borrow(uint256 collateral) external {
        uint256 price = getPrice();
        uint256 borrowAmount = (collateral * price * 80) / 100 / 1e18;
        // ... lending logic
    }
}`)}
                                                            className={`p-4 rounded-xl text-left transition-all hover:scale-[1.02] ${darkMode ? 'bg-gray-900 hover:bg-gray-750 border border-gray-700' : 'bg-gray-50 hover:bg-gray-100 border border-gray-200'}`}
                                                        >
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="px-2 py-0.5 text-xs font-bold rounded bg-red-500 text-white">CRITICAL</span>
                                                                <span className={`text-sm font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Oracle Manipulation</span>
                                                            </div>
                                                            <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>DEX spot price vulnerability</p>
                                                        </button>

                                                        <button
                                                            onClick={() => setScannerCode(`// SECURE: Well-protected contract
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    
    function deposit() external payable {
        require(msg.value > 0, "Amount must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Amount must be > 0");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Checks-effects-interactions pattern
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdraw(msg.sender, amount);
    }
}`)}
                                                            className={`p-4 rounded-xl text-left transition-all hover:scale-[1.02] ${darkMode ? 'bg-gray-900 hover:bg-gray-750 border border-gray-700' : 'bg-gray-50 hover:bg-gray-100 border border-gray-200'}`}
                                                        >
                                                            <div className="flex items-center gap-2 mb-1">
                                                                <span className="px-2 py-0.5 text-xs font-bold rounded bg-green-500 text-white">SECURE</span>
                                                                <span className={`text-sm font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`}>Secure Example</span>
                                                            </div>
                                                            <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>Well-protected vault contract</p>
                                                        </button>
                                                    </div>
                                                </div>
                                            )}
                                        </div>
                                    )}

                                    {/* LEARN MODE - Attack Cards Grid */}
                                    {attackLabMode === 'learn' && (
                                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                            {attackVectors.map((attack, idx) => (
                                                <button
                                                    key={idx}
                                                    onClick={() => setSelectedAttack(attack)}
                                                    className={`p-4 rounded-xl border text-left transition-all hover:scale-[1.02] ${selectedAttack?.name === attack.name
                                                        ? 'ring-2 ring-purple-500 ' + (darkMode ? 'bg-purple-900/20 border-purple-500' : 'bg-purple-50 border-purple-300')
                                                        : darkMode ? 'bg-gray-800 border-gray-700 hover:bg-gray-750' : 'bg-white border-gray-200 hover:bg-gray-50'
                                                        }`}
                                                >
                                                    <div className="flex items-start gap-3">
                                                        <span className={`px-2 py-1 text-xs font-bold rounded flex-shrink-0 ${attack.severity === 'critical' ? 'bg-red-500 text-white' :
                                                            attack.severity === 'high' ? 'bg-orange-500 text-white' :
                                                                'bg-yellow-500 text-black'
                                                            }`}>
                                                            {attack.severity.toUpperCase()}
                                                        </span>
                                                        <div className="flex-1 min-w-0">
                                                            <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{attack.name}</h4>
                                                            <p className={`text-xs mt-1 line-clamp-2 ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{attack.description}</p>
                                                            {(attack as any).realWorldExample && (
                                                                <p className={`text-xs mt-2 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                                                    {(attack as any).realWorldExample}
                                                                </p>
                                                            )}
                                                        </div>
                                                    </div>
                                                </button>
                                            ))}
                                        </div>
                                    )}

                                    {/* Selected Attack Detail - Only show in Learn mode */}
                                    {attackLabMode === 'learn' && selectedAttack && (
                                        <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                            <div className="flex items-start justify-between mb-6">
                                                <div className="flex items-center gap-3">
                                                    <span className={`px-3 py-1.5 text-sm font-bold rounded ${selectedAttack.severity === 'critical' ? 'bg-red-500 text-white' :
                                                        selectedAttack.severity === 'high' ? 'bg-orange-500 text-white' :
                                                            'bg-yellow-500 text-black'
                                                        }`}>
                                                        {selectedAttack.severity.toUpperCase()}
                                                    </span>
                                                    <div>
                                                        <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>{selectedAttack.name}</h3>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>{selectedAttack.description}</p>
                                                    </div>
                                                </div>
                                                <button
                                                    onClick={() => setSelectedAttack(null)}
                                                    className={`p-2 rounded-lg ${darkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100'}`}
                                                >
                                                    <X size={20} />
                                                </button>
                                            </div>

                                            {/* Real World Example */}
                                            {(selectedAttack as any).realWorldExample && (
                                                <div className={`mb-6 p-4 rounded-xl ${darkMode ? 'bg-red-500/10 border border-red-500/30' : 'bg-red-50 border border-red-200'}`}>
                                                    <p className={`text-sm font-medium ${darkMode ? 'text-red-400' : 'text-red-700'}`}>
                                                        Real World Example: {(selectedAttack as any).realWorldExample}
                                                    </p>
                                                </div>
                                            )}

                                            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                                                {/* Vulnerable Code */}
                                                {(selectedAttack as any).vulnerableCode && (
                                                    <div>
                                                        <div className="flex items-center justify-between mb-2">
                                                            <h4 className={`text-sm font-semibold flex items-center gap-2 ${darkMode ? 'text-red-400' : 'text-red-600'}`}>
                                                                <XCircle size={16} />
                                                                Vulnerable Code
                                                            </h4>
                                                            <button
                                                                onClick={() => navigator.clipboard.writeText((selectedAttack as any).vulnerableCode)}
                                                                className={`text-xs px-2 py-1 rounded flex items-center gap-1 ${darkMode ? 'text-gray-400 hover:text-white hover:bg-gray-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'}`}
                                                            >
                                                                <Copy size={12} />
                                                                Copy
                                                            </button>
                                                        </div>
                                                        <pre className={`p-4 rounded-xl text-xs overflow-auto max-h-80 ${darkMode ? 'bg-gray-900 text-red-300' : 'bg-red-50 text-red-800'}`}>
                                                            {(selectedAttack as any).vulnerableCode}
                                                        </pre>
                                                    </div>
                                                )}

                                                {/* Attack Code */}
                                                {(selectedAttack as any).attackCode && (
                                                    <div>
                                                        <div className="flex items-center justify-between mb-2">
                                                            <h4 className={`text-sm font-semibold flex items-center gap-2 ${darkMode ? 'text-orange-400' : 'text-orange-600'}`}>
                                                                <Zap size={16} />
                                                                Attack Implementation
                                                            </h4>
                                                            <button
                                                                onClick={() => navigator.clipboard.writeText((selectedAttack as any).attackCode)}
                                                                className={`text-xs px-2 py-1 rounded flex items-center gap-1 ${darkMode ? 'text-gray-400 hover:text-white hover:bg-gray-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'}`}
                                                            >
                                                                <Copy size={12} />
                                                                Copy
                                                            </button>
                                                        </div>
                                                        <pre className={`p-4 rounded-xl text-xs overflow-auto max-h-80 ${darkMode ? 'bg-gray-900 text-orange-300' : 'bg-orange-50 text-orange-800'}`}>
                                                            {(selectedAttack as any).attackCode}
                                                        </pre>
                                                    </div>
                                                )}
                                            </div>

                                            {/* Test Steps */}
                                            {(selectedAttack as any).testSteps && (
                                                <div className="mt-6">
                                                    <h4 className={`text-sm font-semibold mb-3 flex items-center gap-2 ${darkMode ? 'text-blue-400' : 'text-blue-600'}`}>
                                                        <ClipboardList size={16} />
                                                        Testing Steps (Local Testnet)
                                                    </h4>
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-blue-50'}`}>
                                                        <ol className="space-y-2">
                                                            {(selectedAttack as any).testSteps.map((step: string, i: number) => (
                                                                <li key={i} className={`text-sm flex gap-3 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                                    <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${darkMode ? 'bg-blue-500/20 text-blue-400' : 'bg-blue-100 text-blue-600'}`}>
                                                                        {i + 1}
                                                                    </span>
                                                                    {step}
                                                                </li>
                                                            ))}
                                                        </ol>
                                                    </div>
                                                </div>
                                            )}

                                            {/* Fixed Code */}
                                            {(selectedAttack as any).fixedCode && (
                                                <div className="mt-6">
                                                    <div className="flex items-center justify-between mb-2">
                                                        <h4 className={`text-sm font-semibold flex items-center gap-2 ${darkMode ? 'text-green-400' : 'text-green-600'}`}>
                                                            <CheckCircle2 size={16} />
                                                            Secure Implementation
                                                        </h4>
                                                        <button
                                                            onClick={() => navigator.clipboard.writeText((selectedAttack as any).fixedCode)}
                                                            className={`text-xs px-2 py-1 rounded flex items-center gap-1 ${darkMode ? 'text-gray-400 hover:text-white hover:bg-gray-700' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'}`}
                                                        >
                                                            <Copy size={12} />
                                                            Copy
                                                        </button>
                                                    </div>
                                                    <pre className={`p-4 rounded-xl text-xs overflow-auto max-h-80 ${darkMode ? 'bg-gray-900 text-green-300' : 'bg-green-50 text-green-800'}`}>
                                                        {(selectedAttack as any).fixedCode}
                                                    </pre>
                                                </div>
                                            )}

                                            {/* Mitigation Summary */}
                                            <div className={`mt-6 p-4 rounded-xl ${darkMode ? 'bg-green-500/10 border border-green-500/30' : 'bg-green-50 border border-green-200'}`}>
                                                <h4 className={`text-sm font-semibold mb-2 ${darkMode ? 'text-green-400' : 'text-green-700'}`}>Mitigation Summary</h4>
                                                <p className={`text-sm ${darkMode ? 'text-green-300' : 'text-green-600'}`}>{selectedAttack.mitigation}</p>
                                            </div>
                                        </div>
                                    )}

                                    {/* Getting Started Guide - Only show in Learn mode when no attack selected */}
                                    {attackLabMode === 'learn' && !selectedAttack && (
                                        <div className="space-y-6">
                                            {/* What Each Section Means */}
                                            <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Understanding the Code Sections</h3>
                                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                    <div className={`p-4 rounded-xl border-l-4 border-red-500 ${darkMode ? 'bg-gray-900' : 'bg-red-50'}`}>
                                                        <h4 className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? 'text-red-400' : 'text-red-700'}`}>
                                                            <XCircle size={18} />
                                                            Vulnerable Code
                                                        </h4>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            This is the <strong>target</strong> - a smart contract with a security flaw. You deploy this first to have something to attack. In real audits, this represents code you're reviewing.
                                                        </p>
                                                    </div>
                                                    <div className={`p-4 rounded-xl border-l-4 border-orange-500 ${darkMode ? 'bg-gray-900' : 'bg-orange-50'}`}>
                                                        <h4 className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? 'text-orange-400' : 'text-orange-700'}`}>
                                                            <Zap size={18} />
                                                            Attack Implementation
                                                        </h4>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            This is the <strong>exploit</strong> - a separate contract (or script) that exploits the vulnerability. Deploy this second and call its attack function to drain/exploit the vulnerable contract.
                                                        </p>
                                                    </div>
                                                    <div className={`p-4 rounded-xl border-l-4 border-blue-500 ${darkMode ? 'bg-gray-900' : 'bg-blue-50'}`}>
                                                        <h4 className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? 'text-blue-400' : 'text-blue-700'}`}>
                                                            <ClipboardList size={18} />
                                                            Testing Steps
                                                        </h4>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            Step-by-step instructions for running the attack in your test environment. Follow these in order to see the exploit in action.
                                                        </p>
                                                    </div>
                                                    <div className={`p-4 rounded-xl border-l-4 border-green-500 ${darkMode ? 'bg-gray-900' : 'bg-green-50'}`}>
                                                        <h4 className={`font-semibold mb-2 flex items-center gap-2 ${darkMode ? 'text-green-400' : 'text-green-700'}`}>
                                                            <CheckCircle2 size={18} />
                                                            Secure Implementation
                                                        </h4>
                                                        <p className={`text-sm ${darkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                                                            The <strong>fix</strong> - how the vulnerable code should have been written. Use this to understand what secure code looks like and to verify your fix works.
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Full Workflow */}
                                            <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Complete Testing Workflow</h3>

                                                <div className="space-y-4">
                                                    {/* Step 1 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>1</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Set Up Local Blockchain</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Install Hardhat and create a new project. This gives you a local Ethereum blockchain to test on.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`mkdir attack-lab && cd attack-lab
npm init -y
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat init  # Choose "Create a JavaScript project"`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* Step 2 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>2</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Create the Vulnerable Contract</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Copy the "Vulnerable Code" into a new file in the contracts folder.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`# Create file: contracts/VulnerableBank.sol
# Paste the "Vulnerable Code" from any attack above`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* Step 3 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>3</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Create the Attacker Contract</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Copy the "Attack Implementation" into another file. This contract will exploit the vulnerable one.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`# Create file: contracts/Attacker.sol
# Paste the "Attack Implementation" code`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* Step 4 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>4</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Write a Test Script</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Create a test that deploys both contracts and executes the attack.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`// test/Attack.js
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Reentrancy Attack", function() {
  it("should drain the vulnerable contract", async function() {
    // 1. Deploy vulnerable contract
    const Bank = await ethers.getContractFactory("VulnerableBank");
    const bank = await Bank.deploy();
    
    // 2. Fund it with some ETH (simulating other users)
    const [owner, victim, attacker] = await ethers.getSigners();
    await bank.connect(victim).deposit({ value: ethers.parseEther("10") });
    
    // 3. Deploy attacker contract
    const Attacker = await ethers.getContractFactory("ReentrancyAttacker");
    const attackContract = await Attacker.connect(attacker).deploy(bank.target);
    
    // 4. Execute attack
    console.log("Bank balance before:", await ethers.provider.getBalance(bank.target));
    await attackContract.attack({ value: ethers.parseEther("1") });
    console.log("Bank balance after:", await ethers.provider.getBalance(bank.target));
    
    // Bank should be drained!
    expect(await ethers.provider.getBalance(bank.target)).to.equal(0);
  });
});`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* Step 5 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-purple-500/20 text-purple-400' : 'bg-purple-100 text-purple-600'}`}>5</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Run the Test</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Execute the test and watch the attack succeed.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`npx hardhat test

# Expected output:
# Bank balance before: 10000000000000000000 (10 ETH)
# Bank balance after: 0
# ✓ should drain the vulnerable contract`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>

                                                    {/* Step 6 */}
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <div className="flex items-start gap-3">
                                                            <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ${darkMode ? 'bg-green-500/20 text-green-400' : 'bg-green-100 text-green-600'}`}>6</span>
                                                            <div className="flex-1">
                                                                <h4 className={`font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Test the Fix</h4>
                                                                <p className={`text-sm mb-3 ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>Replace VulnerableBank with the "Secure Implementation" and verify the attack no longer works.</p>
                                                                <pre className={`p-3 rounded-lg text-xs overflow-x-auto ${darkMode ? 'bg-gray-800 text-gray-300' : 'bg-white text-gray-700 border'}`}>{`# Replace contracts/VulnerableBank.sol with SecureBank code
# Run test again - attack should fail now!

npx hardhat test
# Expected: Transaction reverts or attack has no effect`}</pre>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>

                                            {/* Quick Reference */}
                                            <div className={`p-6 rounded-2xl border ${darkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'}`}>
                                                <h3 className={`text-lg font-semibold mb-4 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Quick Reference</h3>
                                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <h4 className={`font-medium mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Common Commands</h4>
                                                        <pre className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{`npx hardhat compile
npx hardhat test
npx hardhat node
npx hardhat console`}</pre>
                                                    </div>
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <h4 className={`font-medium mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Useful Packages</h4>
                                                        <pre className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>{`@openzeppelin/contracts
@chainlink/contracts
@uniswap/v2-periphery
dotenv`}</pre>
                                                    </div>
                                                    <div className={`p-4 rounded-xl ${darkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
                                                        <h4 className={`font-medium mb-2 ${darkMode ? 'text-white' : 'text-gray-900'}`}>Testing Resources</h4>
                                                        <p className={`text-xs ${darkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                                                            • Damn Vulnerable DeFi<br />
                                                            • Ethernaut (OpenZeppelin)<br />
                                                            • Capture the Ether<br />
                                                            • Paradigm CTF
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>

                                            <p className={`text-center text-sm ${darkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                                Click any attack card above to view detailed code examples and test the specific vulnerability.
                                            </p>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ) : null}

                    {/* Removed Source Preview Modal - details now inline */}

                    {/* DETAIL MODAL */}
                    {
                        selectedRule && (
                            <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-8" onClick={() => setSelectedRule(null)}>
                                <div className="bg-white rounded-2xl shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden" onClick={e => e.stopPropagation()}>
                                    <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-gray-50">
                                        <div className="flex items-center gap-3 flex-wrap">
                                            <span className="text-sm font-mono bg-gray-200 px-2 py-1 rounded">{selectedRule.vulnId}</span>
                                            <span className="text-sm font-mono text-gray-500">{selectedRule.stigId}</span>
                                            <span className={`text-xs uppercase font-medium px-2 py-1 rounded ${selectedRule.severity === 'high' ? 'bg-red-100 text-red-600' :
                                                selectedRule.severity === 'medium' ? 'bg-amber-100 text-amber-600' : 'bg-blue-100 text-blue-600'
                                                }`}>CAT {selectedRule.severity === 'high' ? 'I' : selectedRule.severity === 'medium' ? 'II' : 'III'}</span>
                                            {selectedRule.ccis && selectedRule.ccis.length > 0 && (
                                                <div className="flex items-center gap-1">
                                                    {selectedRule.ccis.slice(0, 3).map((cci, idx) => (
                                                        <span key={idx} className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded font-mono">{cci}</span>
                                                    ))}
                                                    {selectedRule.ccis.length > 3 && (
                                                        <span className="text-xs text-gray-400">+{selectedRule.ccis.length - 3} more</span>
                                                    )}
                                                </div>
                                            )}
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
                                            <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Check Text</h3>
                                            <div className="bg-gray-50 p-4 rounded-lg border border-gray-100 font-mono text-sm whitespace-pre-wrap text-gray-700 max-h-60 overflow-auto">
                                                {selectedRule.checkContent || 'No check content available'}
                                            </div>
                                        </div>

                                        <div>
                                            <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Fix Text</h3>
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
                                                <h3 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">Scan Evidence</h3>
                                                <div ref={detailEvidenceCardRef} className={`p-4 rounded-lg border ${results.get(selectedRule.vulnId)?.status === 'pass' ? 'bg-green-50 border-green-200' : results.get(selectedRule.vulnId)?.status === 'fail' ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-200'}`}>
                                                    {/* Status Badge */}
                                                    <div className="flex items-center gap-2 mb-3">
                                                        <span className={`uppercase font-bold text-sm px-2 py-0.5 rounded ${results.get(selectedRule.vulnId)?.status === 'pass' ? 'bg-green-600 text-white' : results.get(selectedRule.vulnId)?.status === 'fail' ? 'bg-red-600 text-white' : 'bg-gray-600 text-white'}`}>
                                                            {results.get(selectedRule.vulnId)?.status}
                                                        </span>
                                                        {results.get(selectedRule.vulnId)?.timestamp && (
                                                            <span className="text-xs text-gray-400">
                                                                {new Date(results.get(selectedRule.vulnId)!.timestamp!).toLocaleString()}
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Command Executed */}
                                                    {results.get(selectedRule.vulnId)?.command && (
                                                        <div className="mb-3">
                                                            <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Command Executed</div>
                                                            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs overflow-x-auto">
                                                                PS&gt; {results.get(selectedRule.vulnId)?.command}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Registry Path + Value (for registry checks) */}
                                                    {selectedRule.automatedCheck?.type === 'registry' && selectedRule.automatedCheck.registryPath && (
                                                        <div className="mb-3">
                                                            <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Registry Location</div>
                                                            <div className="bg-blue-50 border border-blue-100 p-3 rounded font-mono text-xs">
                                                                <div><span className="text-gray-500">Path:</span> {selectedRule.automatedCheck.registryPath}</div>
                                                                <div><span className="text-gray-500">Value:</span> {selectedRule.automatedCheck.valueName}</div>
                                                                <div><span className="text-gray-500">Expected:</span> {selectedRule.automatedCheck.expectedValue ?? 'Any'}</div>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Output Value */}
                                                    <div>
                                                        <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Actual Value / Output</div>
                                                        <pre className="bg-white border border-gray-200 p-3 rounded font-mono text-sm whitespace-pre-wrap text-gray-800 max-h-48 overflow-auto">
                                                            {results.get(selectedRule.vulnId)?.output || '(empty)'}
                                                        </pre>
                                                    </div>
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
                                                onClick={() => { openEvidenceModal(selectedRule); }}
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
                </div>
            </main>

            {/* --- Hidden Virtual Evidence Rendering Area --- */}
            {/* Using absolute positioning to keep it out of view but renderable. Opacity 0 makes it invisible but html2canvas can still capture it if we temporarily make it visible or use specific settings. */}
            <div
                ref={virtualEvidenceRef}
                className="fixed top-0 left-[-9999px] flex flex-col gap-8 p-8 bg-white"
            >
                {/* 1. PowerShell View (Always rendered if we have a command) */}
                {evidenceModalRule && results.get(evidenceModalRule.vulnId) && (
                    <VirtualPowerShell
                        command={results.get(evidenceModalRule.vulnId)?.command || ''}
                        output={results.get(evidenceModalRule.vulnId)?.output || ''}
                        isFail={results.get(evidenceModalRule.vulnId)?.status === 'fail'}
                    />
                )}

                {/* 2. Regedit View (Rendered if it's a registry check) */}
                {evidenceModalRule &&
                    evidenceModalRule.automatedCheck?.type === 'registry' &&
                    evidenceModalRule.automatedCheck.registryPath &&
                    evidenceModalRule.automatedCheck.valueName && (
                        <VirtualRegedit
                            path={evidenceModalRule.automatedCheck.registryPath}
                            valueName={evidenceModalRule.automatedCheck.valueName}
                            expected={evidenceModalRule.automatedCheck.expectedValue || ''}
                            actual={results.get(evidenceModalRule.vulnId)?.output || ''} // In basic mode, output is often the value
                            checkType={results.get(evidenceModalRule.vulnId)?.status === 'fail' ? 'mismatch' : 'match'}
                        />
                    )}
            </div>

            {/* Evidence Capture Confirmation Modal */}
            {showEvidenceModal && evidenceModalRule && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
                    onPaste={async (e) => {
                        const items = e.clipboardData.items;
                        for (let i = 0; i < items.length; i++) {
                            if (items[i].type.indexOf('image') !== -1) {
                                const blob = items[i].getAsFile();
                                if (blob) {
                                    const reader = new FileReader();
                                    reader.onload = async (event) => {
                                        if (event.target?.result) {
                                            const newImg = event.target.result as string;
                                            // Merge with existing
                                            const base = evidenceScreenshot || '';
                                            const merged = await mergeImages(base ? [base, newImg] : [newImg]);
                                            setEvidenceScreenshot(merged);
                                        }
                                    };
                                    reader.readAsDataURL(blob);
                                }
                            }
                        }
                    }}
                >
                    <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full mx-4 overflow-hidden flex flex-col max-h-[90vh]">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100 flex items-center justify-between">
                            <h3 className="text-lg font-semibold text-gray-900">Capture Evidence</h3>
                            <button onClick={() => setShowEvidenceModal(false)} className="text-gray-400 hover:text-gray-600"><XCircle size={20} /></button>
                        </div>

                        <div className="p-6 space-y-4 overflow-y-auto flex-1">
                            {/* Rule Info */}
                            <div className="bg-blue-50/50 rounded-lg p-3 border border-blue-100">
                                <div className="flex items-center gap-2 mb-1">
                                    <span className="font-mono text-xs font-bold bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">{evidenceModalRule.vulnId}</span>
                                    <span className="text-xs text-gray-500 uppercase font-bold tracking-wider">Target Folder:</span>
                                </div>
                                <input
                                    type="text"
                                    value={evidenceFolderName}
                                    onChange={(e) => setEvidenceFolderName(e.target.value)}
                                    placeholder="Folder Name"
                                    className="w-full bg-white px-2 py-1 border rounded text-sm focus:ring-2 focus:ring-blue-500 outline-none"
                                />
                            </div>

                            {/* Screenshot Preview Area */}
                            <div>
                                <div className="flex items-center justify-between mb-2">
                                    <label className="text-sm font-medium text-gray-700">Evidence Image</label>
                                    <span className="text-xs text-purple-600 bg-purple-50 px-2 py-1 rounded font-medium animate-pulse">
                                        💡 Tip: Paste (Ctrl+V) to attach Regedit/PowerShell screenshots!
                                    </span>
                                </div>
                                <div className="border-2 border-dashed border-gray-300 rounded-xl overflow-hidden bg-gray-50 min-h-[200px] flex items-center justify-center relative group">
                                    {evidenceScreenshot ? (
                                        <div className="relative w-full">
                                            <img src={evidenceScreenshot} alt="Evidence Preview" className="w-full h-auto object-contain" />
                                            <div className="absolute top-2 right-2 flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <button
                                                    onClick={() => setEvidenceScreenshot(null)}
                                                    className="bg-red-600 text-white p-1.5 rounded-lg shadow-lg hover:bg-red-700 text-xs font-bold"
                                                >
                                                    Clear Image
                                                </button>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="text-center p-8 text-gray-400">
                                            <ImageIcon size={48} className="mx-auto mb-2 opacity-20" />
                                            <p className="text-sm">No evidence captured yet.</p>
                                            <p className="text-xs mt-1">Run check to auto-capture, or Paste (Ctrl+V) an image here.</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="px-6 py-4 bg-gray-50 border-t border-gray-100 flex justify-end gap-3 shrink-0">
                            <button
                                onClick={() => { setShowEvidenceModal(false); setEvidenceModalRule(null); setEvidenceScreenshot(null); }}
                                className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-800"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={async () => {
                                    if (!evidenceModalRule) return;
                                    const rule = evidenceModalRule;
                                    const res = results.get(rule.vulnId);
                                    let rpaType: 'regedit' | 'powershell' = 'powershell';
                                    let rpaPath = '';
                                    let rpaCommand = res?.command || 'Write-Host "No Command Recorded"';

                                    if (rule.automatedCheck?.type === 'registry' && rule.automatedCheck.registryPath) {
                                        rpaType = 'regedit';
                                        rpaPath = rule.automatedCheck.registryPath;
                                    }

                                    // Guide User
                                    if (rpaType === 'regedit') {
                                        alert("GUIDED CAPTURE MODE:\n\n1. Please Open 'Registry Editor' (Regedit) manually.\n2. In Regedit, navigate to: " + rpaPath + "\n\nPress OK when Regedit is open and visible on screen.");
                                    } else {
                                        await navigator.clipboard.writeText(rpaCommand);
                                        alert("GUIDED CAPTURE MODE:\n\n1. I have COPIED the command to your clipboard.\n2. Please OPEN 'PowerShell' (Run as Administrator).\n3. PASTE the command and press Enter.\n\nPress OK when the result is visible on screen.");
                                    }

                                    // Give user a moment to put their hand back on the mouse if they want, but really we just want them to click OK, then we snap.
                                    // Actually, we need to hide the browser window or ensure it doesn't block? 
                                    // The screenshot captures PRIMARY SCREEN.
                                    // We will minimize the app? No, just alert.

                                    try {
                                        // @ts-ignore
                                        const captureRes = await window.ipcRenderer.invoke('capture-real-evidence', {
                                            type: rpaType,
                                            path: rpaPath,
                                            command: rpaCommand,
                                            manual: true // <--- NEW FLAG
                                        });

                                        if (captureRes.success && captureRes.base64) {
                                            setEvidenceScreenshot(captureRes.base64);
                                        } else {
                                            alert("Capture failed: " + (captureRes.error || "Unknown error"));
                                        }
                                    } catch (e: any) {
                                        alert("Capture failed: " + e.message);
                                    }
                                }}
                                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg"
                            >
                                Capture Evidence
                            </button>
                            <button
                                onClick={runAgent}
                                disabled={isScanning || isBatchCapturing || rules.length === 0 || filteredRules.filter(r => r.automatedCheck?.type === 'registry').length === 0}
                                className="px-4 py-2 bg-black hover:bg-black/80 text-white text-sm font-bold rounded-lg shadow-lg flex items-center gap-2 group transition-all transform active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <Cpu size={16} className={`${isBatchCapturing ? 'animate-pulse' : 'group-hover:animate-bounce'}`} />
                                {isBatchCapturing ? 'Scanning...' : 'Run Scan'}
                            </button>
                            <button
                                onClick={confirmCaptureEvidence}
                                disabled={!evidenceScreenshot}
                                className="px-6 py-2 bg-blue-600 text-white text-sm font-bold rounded-lg hover:bg-blue-700 flex items-center gap-2 shadow-lg shadow-blue-600/20 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                <Save size={16} /> Save Evidence
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Evidence Type Selection Modal */}
            {showEvidenceTypeModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-white rounded-xl shadow-2xl max-w-lg w-full mx-4 overflow-hidden">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100">
                            <h3 className="text-lg font-semibold text-gray-900">Select Evidence Type</h3>
                        </div>

                        <div className="p-6 space-y-4">
                            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                                <p className="text-sm text-yellow-800 font-medium">
                                    <strong>⚠️ Disclaimer:</strong> The AI Audit Agent will automatically capture screenshots of the selected evidence type(s) during the scan.
                                </p>
                            </div>

                            <p className="text-sm text-gray-700 mb-4">
                                Choose what type of evidence you want to gather for each registry check:
                            </p>

                            <div className="space-y-3">
                                <button
                                    onClick={() => {
                                        if ((window as any).__evidenceTypeResolver) {
                                            (window as any).__evidenceTypeResolver('powershell');
                                            (window as any).__evidenceTypeResolver = null;
                                        }
                                    }}
                                    className="w-full text-left p-4 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-all"
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="w-4 h-4 rounded-full border-2 border-gray-400"></div>
                                        <div className="flex-1">
                                            <div className="font-semibold text-gray-900">PowerShell Only</div>
                                            <div className="text-xs text-gray-600 mt-1">Capture PowerShell console with command output</div>
                                        </div>
                                    </div>
                                </button>

                                <button
                                    onClick={() => {
                                        if ((window as any).__evidenceTypeResolver) {
                                            (window as any).__evidenceTypeResolver('regedit');
                                            (window as any).__evidenceTypeResolver = null;
                                        }
                                    }}
                                    className="w-full text-left p-4 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-all"
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="w-4 h-4 rounded-full border-2 border-gray-400"></div>
                                        <div className="flex-1">
                                            <div className="font-semibold text-gray-900">Regedit Only</div>
                                            <div className="text-xs text-gray-600 mt-1">Capture Registry Editor showing the registry path</div>
                                        </div>
                                    </div>
                                </button>

                                <button
                                    onClick={() => {
                                        if ((window as any).__evidenceTypeResolver) {
                                            (window as any).__evidenceTypeResolver('both');
                                            (window as any).__evidenceTypeResolver = null;
                                        }
                                    }}
                                    className="w-full text-left p-4 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-all"
                                >
                                    <div className="flex items-center gap-3">
                                        <div className="w-4 h-4 rounded-full border-2 border-gray-400"></div>
                                        <div className="flex-1">
                                            <div className="font-semibold text-gray-900">Both (PowerShell + Regedit)</div>
                                            <div className="text-xs text-gray-600 mt-1">Capture both PowerShell console and Registry Editor side-by-side</div>
                                        </div>
                                    </div>
                                </button>
                            </div>

                            <div className="pt-4 border-t border-gray-200 flex justify-end gap-3">
                                <button
                                    onClick={() => {
                                        if ((window as any).__evidenceTypeResolver) {
                                            (window as any).__evidenceTypeResolver(null);
                                            (window as any).__evidenceTypeResolver = null;
                                        }
                                        setShowEvidenceTypeModal(false);
                                    }}
                                    className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-800"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Username Input Modal */}
            {showUsernameModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
                    <div className="bg-white rounded-xl shadow-2xl max-w-md w-full mx-4 overflow-hidden">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100">
                            <h3 className="text-lg font-semibold text-gray-900">Enter Username</h3>
                        </div>

                        <div className="p-6 space-y-4">
                            <p className="text-sm text-gray-700">
                                Please enter your username for the scan. This will be included in the finding details for each check.
                            </p>

                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-2">
                                    Username
                                </label>
                                <input
                                    type="text"
                                    value={scanUsername}
                                    onChange={(e) => setScanUsername(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' && scanUsername.trim()) {
                                            if ((window as any).__usernameResolver) {
                                                (window as any).__usernameResolver(scanUsername.trim());
                                                (window as any).__usernameResolver = null;
                                            }
                                            setShowUsernameModal(false);
                                        }
                                    }}
                                    placeholder="Enter your username"
                                    className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                                    autoFocus
                                />
                            </div>

                            <div className="pt-4 border-t border-gray-200 flex justify-end gap-3">
                                <button
                                    onClick={() => {
                                        if ((window as any).__usernameResolver) {
                                            (window as any).__usernameResolver(null);
                                            (window as any).__usernameResolver = null;
                                        }
                                        setShowUsernameModal(false);
                                        setScanUsername('');
                                    }}
                                    className="px-4 py-2 text-sm font-medium text-gray-600 hover:text-gray-800"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={() => {
                                        if (scanUsername.trim()) {
                                            if ((window as any).__usernameResolver) {
                                                (window as any).__usernameResolver(scanUsername.trim());
                                                (window as any).__usernameResolver = null;
                                            }
                                            setShowUsernameModal(false);
                                        }
                                    }}
                                    disabled={!scanUsername.trim()}
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg"
                                >
                                    Continue
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* New Evidence Folder Modal */}
            {showNewFolderModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-white rounded-xl shadow-2xl max-w-sm w-full mx-4 overflow-hidden">
                        <div className="bg-gray-50 px-6 py-4 border-b border-gray-100">
                            <h3 className="text-lg font-semibold text-gray-900">New Evidence Folder</h3>
                        </div>
                        <div className="p-6 space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">Folder Name</label>
                                <input
                                    type="text"
                                    value={newFolderName}
                                    onChange={e => setNewFolderName(e.target.value)}
                                    placeholder="e.g. Server_Audit_v1"
                                    className="w-full px-3 py-2 border rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                    autoFocus
                                />
                            </div>
                            <div className="flex justify-end gap-2 pt-2">
                                <button
                                    onClick={() => setShowNewFolderModal(false)}
                                    className="px-4 py-2 rounded-lg text-sm font-medium text-gray-600 hover:bg-gray-100"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={createEvidenceFolder}
                                    disabled={!newFolderName.trim()}
                                    className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white disabled:bg-gray-300 disabled:cursor-not-allowed"
                                >
                                    Create Folder
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* --- AGENT OVERLAY --- */}
            {agentState.status !== 'idle' && (
                <div className="fixed bottom-6 right-6 z-[100] w-[450px] shadow-2xl font-mono text-sm overflow-hidden rounded-xl border border-gray-800 bg-gray-950 text-green-500 flex flex-col animate-in slide-in-from-bottom duration-300">
                    {/* Header */}
                    <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-gray-800">
                        <div className="flex items-center gap-2">
                            <div className={`size-3 rounded-full ${agentState.status === 'working' ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`} />
                            <span className="font-bold text-gray-100">SCAN MANAGER</span>
                        </div>
                        <div className="text-xs text-gray-400">
                            {agentState.progress} / {agentState.total}
                        </div>
                    </div>

                    {/* Activity Monitor */}
                    <div className="p-4 space-y-3 bg-black/90 h-[280px] overflow-y-auto flex flex-col-reverse">

                        {/* Current Status */}
                        <div className="pt-2 border-t border-gray-800/50 mt-2">
                            <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-gray-500 mb-1">
                                Current Task
                            </div>
                            <div className="font-semibold text-green-400 text-base leading-tight">
                                {agentState.currentAction}
                            </div>
                        </div>

                        {/* Logs */}
                        <div className="space-y-1">
                            {agentState.logs.map((log, i) => (
                                <div key={i} className="text-gray-400 text-xs font-mono break-all opacity-80">
                                    {log}
                                </div>
                            ))}
                        </div>

                    </div>

                    {/* Progress Bar */}
                    <div className="h-1 bg-gray-800 w-full">
                        <div
                            className="h-full bg-green-500 transition-all duration-300 ease-out"
                            style={{ width: `${(agentState.progress / Math.max(agentState.total, 1)) * 100}%` }}
                        />
                    </div>

                    {/* Footer Controls */}
                    <div className="bg-gray-900 p-2 flex justify-between items-center text-xs text-gray-500">
                        <span>v1.0.4 AGENT</span>
                        {agentState.status === 'complete' || agentState.status === 'stopped' ? (
                            <button
                                onClick={() => {
                                    setAgentState(prev => ({ ...prev, status: 'idle' }));
                                    scanCancelledRef.current = false;
                                }}
                                className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded text-white transition-colors"
                            >
                                CLOSE
                            </button>
                        ) : agentState.status === 'working' ? (
                            <button
                                onClick={stopScan}
                                className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-white transition-colors font-medium"
                            >
                                STOP SCAN
                            </button>
                        ) : (
                            <div className="flex gap-2">
                                <span className="animate-pulse">PROCESSING...</span>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* STRIX Documentation Modal - Root Level */}
            {showDocsModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm" onClick={() => setShowDocsModal(false)}>
                    <div className={`w-full max-w-5xl h-[85vh] rounded-2xl shadow-xl flex flex-col ${darkMode ? 'bg-gray-800' : 'bg-white'}`} onClick={(e) => e.stopPropagation()}>
                        {/* Header */}
                        <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
                            <h2 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>STRIX Technical Documentation</h2>
                            <button
                                onClick={() => setShowDocsModal(false)}
                                className={`p-2 rounded-lg transition-colors ${darkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-500'}`}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        {/* Content Area */}
                        <div className="flex flex-1 overflow-hidden">
                            {/* Left Sidebar Navigation */}
                            <div className={`w-64 border-r overflow-y-auto ${darkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50'}`}>
                                <div className="p-4 space-y-1">
                                    {[
                                        { id: 'intro', label: 'Intro to STRIX' },
                                        { id: 'how-it-works', label: 'How It Works' },
                                        { id: 'getting-started', label: 'Getting Started' },
                                        { id: 'checklist-editor', label: 'Checklist Editor' },
                                        { id: 'evidence-gallery', label: 'Evidence Gallery' },
                                        { id: 'reports', label: 'Reports' },
                                        { id: 'tools', label: 'Tools & Utilities' },
                                        { id: 'technical', label: 'Technical Details' },
                                        { id: 'troubleshooting', label: 'Troubleshooting' },
                                        { id: 'faq', label: 'FAQ' },
                                    ].map((section) => (
                                        <button
                                            key={section.id}
                                            onClick={() => setSelectedDocSection(section.id)}
                                            className={`w-full text-left px-4 py-2.5 rounded-lg text-sm transition-colors ${selectedDocSection === section.id
                                                ? (darkMode ? 'bg-gray-700 text-white font-medium' : 'bg-white text-gray-900 font-medium shadow-sm')
                                                : (darkMode ? 'text-gray-400 hover:bg-gray-700/50 hover:text-gray-200' : 'text-gray-600 hover:bg-white hover:text-gray-900')
                                                }`}
                                        >
                                            {section.label}
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Right Content Area */}
                            <div className="flex-1 overflow-y-auto p-8">
                                <div className="max-w-3xl mx-auto space-y-6">
                                    {selectedDocSection === 'intro' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Introduction to STRIX</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                STRIX is a comprehensive tool designed to help security professionals manage, analyze, and document STIG (Security Technical Implementation Guide) compliance. Built with modern web technologies, STRIX provides an intuitive interface for creating checklists, capturing evidence, generating reports, and analyzing compliance data.
                                            </p>
                                            <div className="space-y-3">
                                                <h4 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Core Philosophy</h4>
                                                <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                    STRIX emphasizes privacy, local processing, and user control. All data processing is performed locally on your machine—no files are uploaded to any server or database. This ensures maximum security and compliance with sensitive government and enterprise data requirements.
                                                </p>
                                            </div>
                                            <div className="space-y-3">
                                                <h4 className={`text-xl font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Key Characteristics</h4>
                                                <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                    <li>Privacy-First Design: All processing happens locally</li>
                                                    <li>Comprehensive STIG Support: Works with multiple STIG formats (CKL, CKLB, XML, JSON)</li>
                                                    <li>Evidence Management: Built-in gallery for organizing compliance evidence</li>
                                                    <li>Advanced Reporting: Generate detailed compliance reports and POA&M documents</li>
                                                    <li>Risk Analysis: Visualize compliance risk with heatmaps and analytics</li>
                                                    <li>Cross-Platform: Available as both web application and Electron desktop app</li>
                                                </ul>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'how-it-works' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>How It Works</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                STRIX operates on a local-first architecture where all data processing occurs on your device.
                                            </p>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>1. STIG Selection</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Start by selecting a STIG checklist from the main dashboard. STRIX supports Windows 11, Windows Server 2019, SQL Server, IIS, Edge, Defender, and more.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>2. Checklist Management</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Use the Checklist Editor to review, update, and manage STIG findings. Mark rules as Pass, Fail, Not Applicable, or Not Reviewed, and add comments and evidence references.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>3. Evidence Capture</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Capture screenshots, command outputs, and other evidence directly within the application. The Evidence Gallery helps organize and reference evidence across multiple checklists.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>4. Reporting</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Generate comprehensive reports including compliance summaries, POA&M documents, and detailed findings. Export to various formats for documentation and audit purposes.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'getting-started' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Getting Started</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Step 1: Select a STIG</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        From the main dashboard, choose the STIG that matches your system. Click the "CSV" or "CKLB" button to download the checklist format you prefer.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Step 2: Load Your Checklist</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Navigate to the Checklist Editor and upload your checklist file. STRIX supports .ckl, .cklb, .json, and .xml formats.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Step 3: Review Findings</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Review each STIG rule, update statuses, and add comments. Use filters to focus on specific severity levels or statuses.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Step 4: Capture Evidence</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        For each finding, capture screenshots or command outputs as evidence. Organize evidence in the Evidence Gallery for easy reference.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Step 5: Generate Reports</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Once your checklist is complete, generate reports and POA&M documents from the Reports section.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'checklist-editor' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Checklist Editor</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                The Checklist Editor is the core of STRIX, allowing you to manage and update STIG compliance findings.
                                            </p>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Features</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>Upload and manage multiple checklists simultaneously</li>
                                                        <li>Filter by severity (CAT I, CAT II, CAT III) and status</li>
                                                        <li>Search for specific rules by ID or title</li>
                                                        <li>Bulk update statuses for multiple findings</li>
                                                        <li>Add comments and evidence references</li>
                                                        <li>Export updated checklists in multiple formats</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Status Types</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li><strong>Pass:</strong> The system complies with the STIG requirement</li>
                                                        <li><strong>Fail:</strong> The system does not comply with the requirement</li>
                                                        <li><strong>Not Applicable:</strong> The requirement does not apply to this system</li>
                                                        <li><strong>Not Reviewed:</strong> The requirement has not yet been evaluated</li>
                                                    </ul>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'evidence-gallery' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Evidence Gallery</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                The Evidence Gallery helps you organize and manage compliance evidence across all your checklists.
                                            </p>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Capturing Evidence</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Evidence can be captured in several ways:
                                                    </p>
                                                    <ul className={`list-disc list-inside space-y-2 mt-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>Screenshots: Capture full screen or specific windows</li>
                                                        <li>Command Outputs: Copy and paste command results</li>
                                                        <li>File Uploads: Attach configuration files or logs</li>
                                                        <li>Virtual Evidence: Capture registry editor views and other virtual tools</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Organization</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Evidence is organized by folder and can be tagged with rule IDs, hostnames, and custom metadata. Use the gallery to quickly find and reference evidence when updating checklists or generating reports.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'reports' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Reports</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                STRIX provides comprehensive reporting capabilities to document compliance status and generate required documentation.
                                            </p>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Report Types</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li><strong>Compliance Summary:</strong> High-level overview of compliance status</li>
                                                        <li><strong>Detailed Findings:</strong> Complete list of all findings with status and comments</li>
                                                        <li><strong>POA&M:</strong> Plan of Action and Milestones document for tracking remediation</li>
                                                        <li><strong>Risk Heatmap:</strong> Visual representation of compliance risk by control family</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Export Formats</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Reports can be exported as PDF, Excel, CSV, or HTML formats for sharing with stakeholders and auditors.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'tools' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Tools & Utilities</h3>
                                            <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                STRIX includes several utility tools to help streamline your compliance workflow.
                                            </p>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Bulk File Renamer</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Add prefixes or suffixes to multiple files at once. Useful for organizing checklist files with consistent naming conventions.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Risk Heatmap</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Upload multiple checklists to generate a visual heatmap showing compliance risk by NIST control family. Identify areas of concern at a glance.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>STIG Analyzer</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Compare old and new STIG versions to migrate statuses and comments. Automatically maps findings between versions when possible.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'technical' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Technical Details</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Architecture</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        STRIX is built with React and TypeScript, providing a modern, responsive user interface. The application can run as a web application in any modern browser or as a desktop application using Electron.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Data Storage</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        All data is stored locally in your browser's IndexedDB (web version) or local file system (Electron version). No data is transmitted to external servers.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Supported Formats</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>STIG Checklist (.ckl, .cklb)</li>
                                                        <li>STIG XML (.xml)</li>
                                                        <li>JSON exports (.json)</li>
                                                        <li>CSV exports (.csv)</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Browser Requirements</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        STRIX requires a modern browser with support for ES6+, IndexedDB, and File API. Recommended browsers include Chrome, Firefox, Edge, and Safari (latest versions).
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'troubleshooting' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Troubleshooting</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Checklist Won't Load</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>Verify the file format is supported (.ckl, .cklb, .xml, .json)</li>
                                                        <li>Check that the file is not corrupted</li>
                                                        <li>Try opening the file in a text editor to verify it's valid XML/JSON</li>
                                                        <li>Clear browser cache and try again</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Evidence Not Saving</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>Check browser storage permissions</li>
                                                        <li>Verify you have sufficient disk space</li>
                                                        <li>Try clearing browser storage and reloading</li>
                                                        <li>In Electron version, check file system permissions</li>
                                                    </ul>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Performance Issues</h4>
                                                    <ul className={`list-disc list-inside space-y-2 ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        <li>Large checklists may take time to load - be patient</li>
                                                        <li>Close other browser tabs to free up memory</li>
                                                        <li>Consider splitting very large checklists into smaller files</li>
                                                        <li>Clear old evidence and checklists if storage is full</li>
                                                    </ul>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    {selectedDocSection === 'faq' && (
                                        <div className="space-y-4">
                                            <h3 className={`text-2xl font-bold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Frequently Asked Questions</h3>
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Is my data secure?</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Yes. All data processing happens locally on your device. No files or data are uploaded to any server. Your checklists and evidence remain completely private.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Can I use STRIX offline?</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Yes. Once loaded, STRIX works completely offline. The Electron desktop version is fully offline-capable.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>How do I backup my data?</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        Export your checklists regularly using the export functions. Evidence can be downloaded from the Evidence Gallery. In Electron version, data is stored in local files that can be backed up.
                                                    </p>
                                                </div>
                                                <div>
                                                    <h4 className={`text-lg font-semibold ${darkMode ? 'text-white' : 'text-gray-900'}`}>Can I import data from other STIG tools?</h4>
                                                    <p className={`text-base leading-relaxed ${darkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                                        STRIX supports standard STIG formats (.ckl, .cklb, .xml) that are compatible with most STIG tools. You can import checklists created in other tools.
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

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

// --- Virtual Tool Mockups ---

// 1. Virtual PowerShell Component
const VirtualPowerShell = ({ command, output, isFail }: { command: string, output: string, isFail: boolean }) => {
    return (
        <div className="w-[800px] bg-[#012456] rounded-md shadow-2xl font-mono text-sm overflow-hidden flex flex-col border border-gray-600">
            {/* Title Bar */}
            <div className="bg-white flex items-center h-8 px-2 justify-between shrink-0">
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-[#012456] text-white flex items-center justify-center text-[10px] font-bold">∑</div>
                    <span className="text-xs text-black">Administrator: Windows PowerShell</span>
                </div>
                <div className="flex gap-1">
                    <div className="w-8 h-full flex items-center justify-center hover:bg-gray-200">
                        <Minimize2 size={12} className="text-black" />
                    </div>
                    <div className="w-8 h-full flex items-center justify-center hover:bg-gray-200">
                        <Maximize2 size={12} className="text-black" />
                    </div>
                    <div className="w-8 h-full flex items-center justify-center hover:bg-red-500 hover:text-white group">
                        <X size={14} className="text-black group-hover:text-white" />
                    </div>
                </div>
            </div>

            {/* Content */}
            <div className="p-2 text-white font-normal whitespace-pre-wrap leading-tight font-con">
                <div className="mb-2">Windows PowerShell</div>
                <div className="mb-4">Copyright (C) Microsoft Corporation. All rights reserved.</div>

                <div className="flex flex-col gap-1">
                    <div>
                        <span className="text-white">PS C:\Windows\system32&gt; </span>
                        <span className="text-gray-100">{command}</span>
                    </div>
                    {output && (
                        <div className={`${isFail ? 'text-red-300' : 'text-gray-300'} mt-1`}>
                            {output}
                        </div>
                    )}
                    <div className="mt-2">
                        <span className="text-white">PS C:\Windows\system32&gt; </span>
                        <span className="animate-pulse">_</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

// 2. Virtual Regedit Component
const VirtualRegedit = ({ path, valueName, expected, actual, checkType }: { path: string, valueName: string, expected: string | number, actual: any, checkType: 'missing' | 'mismatch' | 'match' }) => {
    // Parse path to get tree structure for display
    const hives = ['Computer', 'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_CURRENT_CONFIG'];
    const parts = path.replace('HKLM:', 'HKEY_LOCAL_MACHINE').split('\\');
    const currentKey = parts[parts.length - 1];

    // Determine data type display
    const isNum = typeof actual === 'number' || (typeof expected === 'number');
    const typeStr = isNum ? 'REG_DWORD' : 'REG_SZ';
    const dataStr = isNum
        ? `0x${Number(actual || 0).toString(16).padStart(8, '0')} (${actual || 0})`
        : (actual || '(value not set)');

    return (
        <div className="w-[800px] bg-white rounded-md shadow-2xl text-xs flex flex-col border border-gray-400 font-sans h-[500px] relative">
            {/* Error Popup (Overlay) if the status implies the Key Path itself was invalid/missing */}
            {checkType === 'missing' && !actual && (
                <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-10 border border-gray-400 shadow-xl bg-[#F0F0F0] p-0.5 w-80">
                    <div className="flex justify-between items-center bg-white px-2 py-1 mb-3">
                        <span>Error Opening Key</span>
                        <X size={14} className="text-gray-500 hover:bg-gray-200 cursor-pointer" />
                    </div>
                    <div className="px-4 py-2 flex gap-4">
                        <div className="text-red-600"><AlertCircle size={32} /></div>
                        <div className="text-sm">
                            {path} could not be opened.<br />
                            An error is preventing this key from being opened.<br />
                            Details: The system cannot find the file specified.
                        </div>
                    </div>
                    <div className="flex justify-center p-3">
                        <div className="bg-[#E1E1E1] border border-[#ADADAD] px-6 py-1 hover:border-[#0078D7] hover:bg-[#E5F1FB] cursor-default text-black min-w-[70px] text-center">OK</div>
                    </div>
                </div>
            )}
            {/* Title Bar */}
            <div className="bg-white flex items-center h-8 px-2 justify-between shrink-0 border-b border-gray-200">
                <div className="flex items-center gap-2">
                    <div className="w-4 h-4 bg-blue-300 border border-blue-800 mockup-reg-icon" />
                    <span className="text-xs text-black">Registry Editor</span>
                </div>
                <div className="flex gap-1">
                    <div className="w-8 h-full flex items-center justify-center hover:bg-gray-200"><Minimize2 size={12} className="text-black" /></div>
                    <div className="w-8 h-full flex items-center justify-center hover:bg-gray-200"><Maximize2 size={12} className="text-black" /></div>
                    <div className="w-8 h-full flex items-center justify-center hover:bg-red-500 group"><X size={14} className="text-black group-hover:text-white" /></div>
                </div>
            </div>

            {/* Menu Bar */}
            <div className="bg-white border-b border-gray-200 px-2 py-1 flex gap-4 text-black">
                <span>File</span><span>Edit</span><span>View</span><span>Favorites</span><span>Help</span>
            </div>

            {/* Address Bar */}
            <div className="bg-white border-b border-gray-200 px-2 py-1 flex gap-2 items-center">
                <span className="text-gray-500">Computer\{parts.join('\\')}</span>
            </div>

            <div className="flex flex-1 overflow-hidden">
                {/* Left Tree */}
                <div className="w-1/3 border-r border-gray-200 p-2 overflow-y-auto bg-white">
                    <div className="pl-0">
                        {hives.map(hive => {
                            const isActiveHive = parts[0] === hive;
                            return (
                                <div key={hive}>
                                    <div className="flex items-center gap-1 hover:bg-blue-50 px-1 py-0.5 cursor-default">
                                        <ChevronRight size={10} className={`text-gray-400 ${isActiveHive ? 'rotate-90' : ''}`} />
                                        <FolderClosed size={12} className="text-yellow-500 fill-yellow-100" />
                                        <span>{hive}</span>
                                    </div>
                                    {isActiveHive && (
                                        <div className="pl-4 border-l border-gray-300 ml-2">
                                            {/* Simplified simulation of tree path */}
                                            {parts.slice(1).map((p, idx) => (
                                                <div key={idx} className="pl-2">
                                                    <div className={`flex items-center gap-1 px-1 py-0.5 ${idx === parts.length - 2 ? 'bg-blue-100 border border-blue-200' : 'hover:bg-blue-50'}`}>
                                                        <ChevronRight size={10} className="text-gray-400 rotate-90" />
                                                        <FolderOpen size={12} className="text-yellow-500 fill-yellow-100" />
                                                        <span>{p}</span>
                                                    </div>
                                                    {idx < parts.length - 2 && <div className="pl-4 border-l border-gray-300 ml-2 h-2" />}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* Right List */}
                <div className="flex-1 bg-white overflow-y-auto">
                    <table className="w-full text-left border-collapse">
                        <thead>
                            <tr>
                                <th className="border-r border-b border-gray-200 px-2 py-1 w-1/3 font-normal text-gray-500">Name</th>
                                <th className="border-r border-b border-gray-200 px-2 py-1 w-1/4 font-normal text-gray-500">Type</th>
                                <th className="border-b border-gray-200 px-2 py-1 font-normal text-gray-500">Data</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr className="hover:bg-blue-50">
                                <td className="px-2 py-1 border-r border-gray-100 flex items-center gap-2">
                                    <div className="text-red-800 text-[10px] font-bold">ab</div>
                                    (Default)
                                </td>
                                <td className="px-2 py-1 border-r border-gray-100">REG_SZ</td>
                                <td className="px-2 py-1">(value not set)</td>
                            </tr>

                            {/* If Check is MATCH/MISMATCH (exists but wrong), show it. If MISSING, DO NOT SHOW IT in list */}
                            {checkType !== 'missing' && (
                                <tr className={`hover:bg-blue-50 bg-blue-50`}>
                                    <td className="px-2 py-1 border-r border-gray-100 flex items-center gap-2">
                                        <div className="text-blue-800 text-[10px] font-bold">01</div>
                                        {valueName}
                                    </td>
                                    <td className="px-2 py-1 border-r border-gray-100">{typeStr}</td>
                                    <td className="px-2 py-1">{dataStr}</td>
                                </tr>
                            )}
                            {/* Filler rows */}
                            {[1, 2, 3, 4, 5].map(i => (
                                <tr key={i} className="hover:bg-blue-50">
                                    <td className="px-2 py-1 border-r border-gray-100 flex items-center gap-2">
                                        <div className="text-blue-800 text-[10px] font-bold">01</div>
                                        Example_Key_{i}
                                    </td>
                                    <td className="px-2 py-1 border-r border-gray-100">REG_DWORD</td>
                                    <td className="px-2 py-1">0x0000000{i} ({i})</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Footer */}
            <div className="bg-gray-100 border-t border-gray-200 px-2 py-0.5 text-gray-500 flex justify-between">
                <span>Computer\{parts.join('\\')}</span>
            </div>
        </div>
    );
};

export default App; // End of File

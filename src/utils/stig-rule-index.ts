/**
 * STIG Rule ID (SV-) index.
 * Builds a map of Rule ID → STIG name + full rule info from:
 * - Bulk-uploaded checklists (CKL/CKLB) — preferred when provided
 * - STIG XCCDF files (fallback or when no checklists)
 */

import { STIG_PATHS } from '../stig-paths';
import { parseStigXML, parseCklFile, type ParsedChecklist } from './stig-parser';

export interface RuleIndexEntry {
    ruleId: string;       // SV-253260
    groupId: string;       // V-253260 (Group/Vuln ID)
    stigKey?: string;      // e.g. 'win11' (only from XML index)
    stigName: string;      // e.g. 'Windows 11 STIG V2R5'
    stigId: string;        // e.g. WN11-00-000031
    title: string;
    severity: string;
    description: string;
    checkContent: string;
    fixContent: string;
    ccis: string[];
}

/** Normalize Rule ID to base form SV-XXXX (strip revision suffix like r1117271_rule) */
export function normalizeRuleId(value: string): string | null {
    const m = value.trim().match(/SV-(\d+)/i);
    return m ? `SV-${m[1]}` : null;
}

/** Regex to find SV- Rule ID in cell text (handles SV-12345, SV-12345r123_rule, etc.) */
export const SV_RULE_ID_REGEX = /SV-\d+(?:r\d+_rule)?/gi;

/**
 * Build Rule ID → RuleIndexEntry map from all STIG XMLs.
 * Fetches from baseUrl + STIG path (e.g. /STIGs/ for browser).
 */
export async function buildRuleIndex(baseUrl = '/STIGs/'): Promise<Map<string, RuleIndexEntry>> {
    const map = new Map<string, RuleIndexEntry>();

    for (const [stigKey, pathInfo] of Object.entries(STIG_PATHS)) {
        const url = `${baseUrl.replace(/\/?$/, '/')}${pathInfo.path}`;
        let xml: string;
        try {
            const res = await fetch(url);
            if (!res.ok) continue;
            xml = await res.text();
        } catch {
            continue;
        }

        const rules = parseStigXML(xml);
        for (const r of rules) {
            const ruleId = r.ruleId ? (normalizeRuleId(r.ruleId) ?? r.ruleId) : null;
            if (!ruleId) continue;
            if (map.has(ruleId)) continue; // first STIG wins for shared SV- IDs
            map.set(ruleId, {
                ruleId,
                groupId: r.vulnId,
                stigKey,
                stigName: pathInfo.name,
                stigId: r.stigId,
                title: r.title,
                severity: r.severity,
                description: r.description,
                checkContent: r.checkContent,
                fixContent: r.fixContent,
                ccis: r.ccis ?? [],
            });
        }
    }

    return map;
}

/**
 * Build Rule ID → RuleIndexEntry map from bulk-uploaded checklists (CKL/CKLB).
 * Uses each checklist's stigName and each finding's ruleId, vulnId, title, description, etc.
 * First occurrence of each SV- wins (so upload order / checklist set defines the mapping).
 */
export function buildRuleIndexFromChecklists(
    checklists: ParsedChecklist[]
): Map<string, RuleIndexEntry> {
    const map = new Map<string, RuleIndexEntry>();

    for (const ckl of checklists) {
        const stigName = ckl.stigName || ckl.filename || 'Unknown STIG';
        for (const f of ckl.findings) {
            const ruleId = normalizeRuleId(f.ruleId || '');
            if (!ruleId) continue;
            if (map.has(ruleId)) continue; // first checklist wins
            map.set(ruleId, {
                ruleId,
                groupId: f.vulnId || '',
                stigName,
                stigId: '', // CKL/CKLB may not expose short STIG ID; leave empty or parse from stigName if needed
                title: f.title || '',
                severity: f.severity || '',
                description: f.description || '',
                checkContent: f.checkText || '',
                fixContent: f.fixText || '',
                ccis: f.ccis || [],
            });
        }
    }

    return map;
}

/**
 * Build Rule ID index from bulk-uploaded checklist files (CKL/CKLB).
 * Parses each file and merges findings into one map (first occurrence of each SV- wins).
 */
export async function buildRuleIndexFromChecklistFiles(
    files: File[]
): Promise<Map<string, RuleIndexEntry>> {
    const checklists: ParsedChecklist[] = [];
    for (const file of files) {
        const ckl = await parseCklFile(file);
        if (ckl) checklists.push(ckl);
    }
    return buildRuleIndexFromChecklists(checklists);
}

/**
 * Merge two indexes: checklist map first, then fill missing from XML index.
 * Use when you have bulk checklists but want to resolve any SV- not present in them.
 */
export async function buildMergedRuleIndex(
    checklistMap: Map<string, RuleIndexEntry>,
    baseUrl = '/STIGs/'
): Promise<Map<string, RuleIndexEntry>> {
    const xmlIndex = await buildRuleIndex(baseUrl);
    const merged = new Map<string, RuleIndexEntry>(checklistMap);
    for (const [ruleId, entry] of xmlIndex) {
        if (!merged.has(ruleId)) merged.set(ruleId, entry);
    }
    return merged;
}

/**
 * Look up a single Rule ID (SV-XXXX or cell value containing it).
 */
export function lookupRule(
    index: Map<string, RuleIndexEntry>,
    value: string
): RuleIndexEntry | undefined {
    const normalized = normalizeRuleId(value);
    return normalized ? index.get(normalized) : undefined;
}

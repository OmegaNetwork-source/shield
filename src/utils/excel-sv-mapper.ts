/**
 * Excel SV- Rule ID mapper.
 * Reads an Excel workbook, finds all cells containing SV- (Rule ID), looks them up
 * in the STIG rule index, and produces an enriched sheet with STIG name and full rule info.
 */

import * as XLSX from 'xlsx';
import {
    buildRuleIndex,
    buildRuleIndexFromChecklists,
    buildMergedRuleIndex,
    normalizeRuleId,
    lookupRule,
    type RuleIndexEntry,
} from './stig-rule-index';
import type { ParsedChecklist } from './stig-parser';

export interface SvMatch {
    sheetName: string;
    address: string;
    cellValue: string | number;
    ruleId: string;
}

export interface EnrichedRow {
    Sheet: string;
    Address: string;
    'Cell Value': string;
    'Rule ID': string;
    'STIG Name': string;
    'Group ID': string;
    'STIG ID': string;
    Title: string;
    Discussion: string;
    'Check Text': string;
    'Fix Text': string;
    Severity: string;
    CCIs: string;
    Status: string;
}

/** Scan a workbook for all cells that contain an SV- Rule ID. Returns one match per Rule ID per cell (if a cell has multiple SV- IDs, multiple matches). */
export function parseExcelForRuleIds(
    workbook: XLSX.WorkBook
): SvMatch[] {
    const matches: SvMatch[] = [];

    for (const sheetName of workbook.SheetNames) {
        const sheet = workbook.Sheets[sheetName];
        if (!sheet) continue;

        // Iterate cell references (A1, B2, etc.); skip !ref, !cols, etc.
        for (const ref of Object.keys(sheet)) {
            if (ref.startsWith('!')) continue;
            const cell = sheet[ref] as XLSX.CellObject | undefined;
            const raw = cell?.v;
            const cellValue = raw === undefined || raw === null ? '' : String(raw);
            const ids = cellValue.match(/SV-\d+(?:r\d+_rule)?/gi);
            if (!ids) continue;
            const normalized = new Set<string>();
            for (const id of ids) {
                const n = normalizeRuleId(id);
                if (n) normalized.add(n);
            }
            for (const ruleId of normalized) {
                matches.push({ sheetName, address: ref, cellValue: raw ?? '', ruleId });
            }
        }
    }

    return matches;
}

/** Enrich matches with rule index. Unknown Rule IDs get empty STIG fields. */
export function enrichMatches(
    matches: SvMatch[],
    index: Map<string, RuleIndexEntry>
): EnrichedRow[] {
    return matches.map((m) => {
        const info = lookupRule(index, m.ruleId);
        const cellStr = typeof m.cellValue === 'number' ? String(m.cellValue) : String(m.cellValue ?? '');
        return {
            Sheet: m.sheetName,
            Address: m.address,
            'Cell Value': cellStr,
            'Rule ID': m.ruleId,
            'STIG Name': info?.stigName ?? '',
            'Group ID': info?.groupId ?? '',
            'STIG ID': info?.stigId ?? '',
            Title: info?.title ?? '',
            Discussion: info?.description ?? '',
            'Check Text': info?.checkContent ?? '',
            'Fix Text': info?.fixContent ?? '',
            Severity: info?.severity ?? '',
            CCIs: info?.ccis?.join('; ') ?? '',
            Status: '',
        };
    });
}

/** Build an Excel workbook with one sheet containing enriched rows. */
export function buildEnrichedWorkbook(rows: EnrichedRow[]): XLSX.WorkBook {
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'SV-Mapped');
    return wb;
}

export interface MapExcelOptions {
    /** Base URL for STIG XMLs when building index (e.g. '/STIGs/'). */
    baseUrl?: string;
    /** Map built from bulk-uploaded checklists; used first for lookups. */
    checklistMap?: Map<string, RuleIndexEntry>;
    /** If true and checklistMap is provided, fill missing SV- from STIG XMLs. Default true. */
    fallbackToXml?: boolean;
}

/** Full pipeline: read Excel file (browser File), build index from checklists and/or XML, map SV- IDs, return enriched workbook and rows. */
export async function mapExcelFileToStigInfo(
    file: File,
    options: MapExcelOptions | string = '/STIGs/'
): Promise<{ workbook: XLSX.WorkBook; rows: EnrichedRow[]; matchCount: number }> {
    const opts: MapExcelOptions =
        typeof options === 'string' ? { baseUrl: options } : { baseUrl: '/STIGs/', fallbackToXml: true, ...options };

    const arrayBuffer = await file.arrayBuffer();
    const workbook = XLSX.read(arrayBuffer, { type: 'array' });
    const matches = parseExcelForRuleIds(workbook);

    let index: Map<string, RuleIndexEntry>;
    if (opts.checklistMap?.size) {
        index =
            opts.fallbackToXml !== false
                ? await buildMergedRuleIndex(opts.checklistMap, opts.baseUrl)
                : opts.checklistMap;
    } else {
        index = await buildRuleIndex(opts.baseUrl ?? '/STIGs/');
    }

    const rows = enrichMatches(matches, index);
    const outWorkbook = buildEnrichedWorkbook(rows);
    return { workbook: outWorkbook, rows, matchCount: matches.length };
}

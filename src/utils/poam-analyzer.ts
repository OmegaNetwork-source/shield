/**
 * POA&M Analyzer: compare base POA&M (eMASS, starts col B, headers row 7)
 * with new POA&M (generator, starts col A, headers row 1).
 * Match by Security Checks (SV-/V- numbers; base may have _rule suffix).
 * Use Controls/APs as secondary match when needed.
 */

import * as XLSX from 'xlsx';
import * as XLSXStyle from 'xlsx-js-style';

const POAM_SHEET_NAME = 'POA&M';
const NEW_FINDINGS_SHEET = 'New findings';
const DROPPED_FINDINGS_SHEET = 'Dropped findings';

/** eMASS-style: row 1 = dark green banner + white bold; rows 2-6 = light gray; row 7 = light gray + bold. */
const DARK_GREEN_FILL = { patternType: 'solid' as const, fgColor: { rgb: '2E7D32' } };
const LIGHT_GRAY_FILL = { patternType: 'solid' as const, fgColor: { rgb: 'D9D9D9' } };
const WHITE_FONT = { bold: true, color: { rgb: 'FFFFFF' } };
const BOLD_FONT = { bold: true };

function setCellStyle(ws: Record<string, XLSXStyle.CellObject>, ref: string, fill: { patternType: string; fgColor: { rgb: string } }, font?: { bold: boolean; color?: { rgb: string } }): void {
  const cell = ws[ref];
  const s: XLSXStyle.CellObject['s'] = { fill };
  if (font) s.font = font;
  if (cell) {
    cell.s = { ...(cell.s || {}), ...s };
  } else {
    ws[ref] = { v: '', t: 's', s };
  }
}

function applyEmassHeaderStyle(ws: XLSXStyle.WorkSheet, maxCol: number): void {
  const sheet = ws as Record<string, XLSXStyle.CellObject>;
  for (let c = 0; c <= maxCol; c++) {
    const colLetter = c < 26 ? String.fromCharCode(65 + c) : String.fromCharCode(64 + Math.floor(c / 26)) + String.fromCharCode(65 + (c % 26));
    // Row 1: dark green + white bold (banner)
    setCellStyle(sheet, `${colLetter}1`, DARK_GREEN_FILL, WHITE_FONT);
    // Rows 2-6: light gray
    for (let r = 2; r <= 6; r++) {
      const ref = `${colLetter}${r}`;
      const cell = sheet[ref];
      const s: XLSXStyle.CellObject['s'] = { fill: LIGHT_GRAY_FILL };
      if (cell) {
        cell.s = { ...(cell.s || {}), ...s };
      } else {
        sheet[ref] = { v: '', t: 's', s };
      }
    }
    // Row 7: light gray + bold (data table headers)
    setCellStyle(sheet, `${colLetter}7`, LIGHT_GRAY_FILL, BOLD_FONT);
  }
}

/** Base POA&M: headers at row 7, data from row 8, columns start at B (index 1). */
export interface BasePoamParsed {
  headerBlock: string[][]; // rows 1-6, preserve for export
  headers: string[];        // from row 7, B7, C7, ...
  dataRows: Record<string, string>[];
}

/** New POA&M: headers at row 1, data from row 2, columns start at A. */
export interface NewPoamParsed {
  headers: string[];
  dataRows: Record<string, string>[];
}

/** Extract normalized keys for matching: SV-xxxxx (strip _rule), lowercase. */
export function normalizeSecurityCheck(value: unknown): string[] {
  if (value == null || value === '') return [];
  const s = String(value);
  // Match SV- digits, optional r digits, optional V-? digits; strip _rule
  const re = /SV-(\d+(?:r\d+)?(?:V-?\d+)?)/gi;
  const keys: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    const key = ('sv-' + m[1]).toLowerCase().replace(/_rule$/i, '');
    if (!keys.includes(key)) keys.push(key);
  }
  // Also match V- digits as fallback (e.g. "V-243468")
  const vRe = /V-(\d+)/g;
  while ((m = vRe.exec(s)) !== null) {
    const key = ('v-' + m[1]).toLowerCase();
    if (!keys.includes(key)) keys.push(key);
  }
  return keys;
}

/** Normalize Controls/APs for secondary matching (trim, take first segment). */
export function normalizeControlsAps(value: unknown): string {
  if (value == null || value === '') return '';
  return String(value).trim().split(/[,;]/)[0].trim();
}

function getSheet(wb: XLSX.WorkBook, name: string): XLSX.WorkSheet | null {
  const sheetName = wb.SheetNames.find(n => n.trim() === name) || wb.SheetNames[0];
  return wb.Sheets[sheetName] || null;
}

function cellValue(sheet: XLSX.WorkSheet, row: number, col: number): string {
  const colLetter = col < 26 ? String.fromCharCode(65 + col) : String.fromCharCode(64 + Math.floor(col / 26)) + String.fromCharCode(65 + (col % 26));
  const ref = `${colLetter}${row}`;
  const cell = sheet[ref];
  if (!cell || cell.v === undefined) return '';
  return String(cell.v).trim();
}

/** Parse base POA&M: rows 1-6 = header block, row 7 = headers (B onwards), row 8+ = data. */
export function parseBasePoam(wb: XLSX.WorkBook): BasePoamParsed | null {
  const sheet = getSheet(wb, POAM_SHEET_NAME);
  if (!sheet) return null;
  const headerBlock: string[][] = [];
  for (let r = 1; r <= 6; r++) {
    const row: string[] = [];
    for (let c = 0; c < 20; c++) row.push(cellValue(sheet, r, c));
    headerBlock.push(row);
  }
  const headers: string[] = [];
  for (let c = 1; c < 30; c++) {
    const v = cellValue(sheet, 7, c);
    if (v === '' && headers.length > 0) break;
    headers.push(v || `Col${c}`);
  }
  // Base eMASS often has 3 blank rows after each finding; only count rows that have data (Security Checks or first col).
  const secColIndex = headers.findIndex(h => /security\s*checks/i.test(String(h)));
  const dataColIndex = 1; // column B = first data column (0-based sheet col)
  const secSheetCol = secColIndex >= 0 ? 1 + secColIndex : 1;
  const MAX_CONSECUTIVE_EMPTY = 20;
  let consecutiveEmpty = 0;
  const dataRows: Record<string, string>[] = [];
  for (let r = 8; r <= 5000; r++) {
    const first = cellValue(sheet, r, dataColIndex);
    const secVal = cellValue(sheet, r, secSheetCol);
    const hasData = first !== '' || secVal !== '';
    if (!hasData) {
      consecutiveEmpty++;
      if (consecutiveEmpty >= MAX_CONSECUTIVE_EMPTY) break;
      continue;
    }
    consecutiveEmpty = 0;
    const row: Record<string, string> = {};
    headers.forEach((h, i) => { row[h] = cellValue(sheet, r, i + 1); });
    dataRows.push(row);
  }
  return { headerBlock, headers, dataRows };
}

/** Parse new POA&M: row 1 = headers, row 2+ = data, columns from A. */
export function parseNewPoam(wb: XLSX.WorkBook): NewPoamParsed | null {
  const sheet = getSheet(wb, POAM_SHEET_NAME);
  if (!sheet) return null;
  const range = XLSX.utils.decode_range(sheet['!ref'] || 'A1');
  const headers: string[] = [];
  for (let c = range.s.c; c <= range.e.c; c++) {
    const v = cellValue(sheet, 1, c);
    headers.push(v || `Col${c}`);
  }
  const secColIndex = headers.findIndex(h => /security\s*checks/i.test(String(h)));
  const MAX_CONSECUTIVE_EMPTY = 20;
  let consecutiveEmpty = 0;
  const dataRows: Record<string, string>[] = [];
  for (let r = 2; r <= Math.min(range.e.r + 1, 5000); r++) {
    const row: Record<string, string> = {};
    headers.forEach((h, i) => { row[h] = cellValue(sheet, r, i); });
    const first = row[headers[0]] || '';
    const secVal = secColIndex >= 0 ? (row[headers[secColIndex]] || '') : '';
    const hasData = first !== '' || secVal !== '';
    if (!hasData) {
      consecutiveEmpty++;
      if (consecutiveEmpty >= MAX_CONSECUTIVE_EMPTY) break;
      continue;
    }
    consecutiveEmpty = 0;
    dataRows.push(row);
  }
  return { headers, dataRows };
}

/** Find column name that contains "Security Checks" or "Controls". */
function findColumnHeader(headers: string[], ...names: string[]): string | null {
  const lower = (s: string) => s.toLowerCase();
  for (const name of names) {
    const found = headers.find(h => lower(h).includes(lower(name)));
    if (found) return found;
  }
  return null;
}

/** Devices Affected: newline-separated, deduplicated (no comma, no repeated names). */
export function normalizeDevicesAffected(value: unknown): string {
  if (value == null || value === '') return '';
  const parts = String(value).split(/[,\n]+/).map(s => s.trim()).filter(Boolean);
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const p of parts) {
    if (!seen.has(p)) { seen.add(p); unique.push(p); }
  }
  return unique.join('\n');
}

/** Milestone texts for new findings (4 rows per finding). */
const MILESTONE_TEXTS = [
  'The CMP Implementation Team has identified this finding through EvaluateSTIG, and the CMP Implementation team has been notified to address this finding.',
  'The CMP Implementation team will begin testing within the USACE CMP environment to ensure this finding has been fixed.',
  'The CMP Implementation team will have implemented the new updated configuration to the USACE CMP environment.',
  'Deloitte RMF Team validates the finding has been remediated via manual assessment procedures and evidence gathering.'
];

const NEW_FINDING_MILESTONE1 = new Date(2026, 0, 29); // 1/29/2026
const formatDate = (d: Date) => `${d.getMonth() + 1}/${d.getDate()}/${d.getFullYear()}`;
const addDays = (d: Date, n: number) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };

/** Key for grouping rows by finding (first SV- or V- from Security Checks). */
function getSecurityCheckGroupKey(row: Record<string, string>, secCol: string): string {
  const keys = normalizeSecurityCheck(row[secCol] ?? '');
  return keys[0] ?? JSON.stringify(row[secCol] ?? '');
}

/** Severity -> milestone 4 offset (days): High 30, Medium 60, Low 90. */
function getMaxDaysForSeverity(severity: string): number {
  const s = String(severity || '').toLowerCase();
  if (s.includes('high') || s.includes('cat i') || s === 'i' || s === '1') return 30;
  if (s.includes('medium') || s.includes('cat ii') || s === 'ii' || s === '2') return 60;
  return 90;
}

export interface PoamComparison {
  newFindings: Record<string, string>[];
  droppedFindings: Record<string, string>[];
  /** One row per unique finding (1 finding = 4 rows in data); for UI count and table. */
  newFindingsSummary: Record<string, string>[];
  droppedFindingsSummary: Record<string, string>[];
  newFindingsUniqueCount: number;
  droppedFindingsUniqueCount: number;
  baseKeys: Set<string>;
  newKeys: Set<string>;
}

/** Compare base vs new: new findings = in new not in base, dropped = in base not in new. */
export function comparePoam(base: BasePoamParsed, newPoam: NewPoamParsed): PoamComparison {
  const baseSecCol = findColumnHeader(base.headers, 'Security Checks') || base.headers[4] || '';
  const baseCtrCol = findColumnHeader(base.headers, 'Controls / APs', 'Controls / APs') || base.headers[2] || '';
  const newSecCol = findColumnHeader(newPoam.headers, 'Security Checks') || newPoam.headers[4] || '';
  const newCtrCol = findColumnHeader(newPoam.headers, 'Controls / APs', 'Controls / APs') || newPoam.headers[2] || '';

  const baseKeys = new Set<string>();
  const baseRowKeys = new Map<number, string[]>();
  base.dataRows.forEach((row, i) => {
    const keys = normalizeSecurityCheck(row[baseSecCol]);
    const ctr = normalizeControlsAps(row[baseCtrCol]);
    keys.forEach(k => baseKeys.add(k));
    if (ctr) keys.forEach(k => baseKeys.add(k + '::' + ctr));
    baseRowKeys.set(i, keys);
  });

  const newKeys = new Set<string>();
  const newRowKeys = new Map<number, string[]>();
  newPoam.dataRows.forEach((row, i) => {
    const keys = normalizeSecurityCheck(row[newSecCol]);
    const ctr = normalizeControlsAps(row[newCtrCol]);
    keys.forEach(k => newKeys.add(k));
    if (ctr) keys.forEach(k => newKeys.add(k + '::' + ctr));
    newRowKeys.set(i, keys);
  });

  const newFindings: Record<string, string>[] = [];
  newPoam.dataRows.forEach((row, i) => {
    const keys = newRowKeys.get(i) || [];
    const ctr = normalizeControlsAps(row[newCtrCol]);
    const hasMatch = keys.some(k => baseKeys.has(k) || (ctr && baseKeys.has(k + '::' + ctr)));
    if (!hasMatch) newFindings.push(row);
  });

  const droppedFindings: Record<string, string>[] = [];
  base.dataRows.forEach((row, i) => {
    const keys = baseRowKeys.get(i) || [];
    const ctr = normalizeControlsAps(row[baseCtrCol]);
    const hasMatch = keys.some(k => newKeys.has(k) || (ctr && newKeys.has(k + '::' + ctr)));
    if (!hasMatch) droppedFindings.push(row);
  });

  // Group by Security Check so 1 finding = 4 rows; take first row per group for summary/count
  const newGroups = new Map<string, Record<string, string>>();
  newFindings.forEach(row => {
    const key = getSecurityCheckGroupKey(row, newSecCol);
    if (!newGroups.has(key)) newGroups.set(key, row);
  });
  const newFindingsSummary = Array.from(newGroups.values());

  const droppedGroups = new Map<string, Record<string, string>>();
  droppedFindings.forEach(row => {
    const keys = normalizeSecurityCheck(row[baseSecCol]);
    const key = keys[0] ?? String(row[baseSecCol] ?? '');
    if (!droppedGroups.has(key)) droppedGroups.set(key, row);
  });
  const droppedFindingsSummary = Array.from(droppedGroups.values());

  return {
    newFindings,
    droppedFindings,
    newFindingsSummary,
    droppedFindingsSummary,
    newFindingsUniqueCount: newFindingsSummary.length,
    droppedFindingsUniqueCount: droppedFindingsSummary.length,
    baseKeys,
    newKeys
  };
}

/** Map new row to base column order (by header name). */
function mapNewRowToBase(newRow: Record<string, string>, baseHeaders: string[], newHeaders: string[]): (string | number)[] {
  const out: (string | number)[] = [''];
  baseHeaders.forEach(h => {
    const newH = newHeaders.find(nh => nh.trim() === h.trim()) || newHeaders[newHeaders.indexOf(h)];
    out.push(newRow[newH] ?? newRow[h] ?? '');
  });
  return out;
}

/** Build aoa for a sheet: header block (rows 1-6), row 7 headers, then data rows (col A empty, cols B+ from base headers). */
function buildSheetAoa(
  base: BasePoamParsed,
  dataRows: Record<string, string>[],
  mapRow: (row: Record<string, string>) => (string | number)[]
): (string | number)[][] {
  const aoa: (string | number)[][] = [];
  for (let r = 0; r < base.headerBlock.length; r++) {
    aoa.push(base.headerBlock[r].map(c => c));
  }
  aoa.push(['', ...base.headers]);
  dataRows.forEach(row => aoa.push(mapRow(row)));
  return aoa;
}

/** Map one new finding row to base columns, with optional overrides and Devices Affected normalized. */
function mapNewFindingRow(
  template: Record<string, string>,
  base: BasePoamParsed,
  newPoam: NewPoamParsed,
  overrides: Partial<Record<string, string | number>>
): (string | number)[] {
  const devicesCol = findColumnHeader(base.headers, 'Devices Affected') || 'Devices Affected';
  const mapped: (string | number)[] = [''];
  base.headers.forEach(baseH => {
    if (overrides[baseH] !== undefined) {
      mapped.push(overrides[baseH] as string | number);
      return;
    }
    const newH = newPoam.headers.find(nh => nh.trim().toLowerCase() === baseH.trim().toLowerCase());
    let val = newH != null ? (template[newH] ?? '') : '';
    if (baseH === devicesCol || (typeof baseH === 'string' && baseH.toLowerCase().includes('devices affected'))) {
      val = normalizeDevicesAffected(val);
    }
    mapped.push(val);
  });
  return mapped;
}

/** Group new findings by Security Check and expand to 4 rows per finding (milestones 1-4) with text and dates. */
function expandNewFindingsToFourRows(
  newFindings: Record<string, string>[],
  base: BasePoamParsed,
  newPoam: NewPoamParsed
): (string | number)[][] {
  const newSecCol = findColumnHeader(newPoam.headers, 'Security Checks') || newPoam.headers[4] || '';
  const severityCol = findColumnHeader(newPoam.headers, 'Severity') || findColumnHeader(newPoam.headers, 'Raw Severity') || 'Severity';
  const milestoneIdCol = findColumnHeader(base.headers, 'Milestone ID') || 'Milestone ID';
  const milestoneDatesCol = findColumnHeader(base.headers, 'Milestone with Completion Dates') || 'Milestone with Completion Dates';
  const schedCol = findColumnHeader(base.headers, 'Scheduled Completion Date') || 'Scheduled Completion Date';

  const groups = new Map<string, Record<string, string>[]>();
  newFindings.forEach(row => {
    const key = getSecurityCheckGroupKey(row, newSecCol);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(row);
  });

  const rows: (string | number)[][] = [];
  groups.forEach((groupRows) => {
    const template = groupRows[0];
    const severity = template[severityCol] ?? template['Severity'] ?? template['Raw Severity'] ?? '';
    const maxDays = getMaxDaysForSeverity(severity);
    const m1 = NEW_FINDING_MILESTONE1;
    const dates = [
      formatDate(m1),
      formatDate(addDays(m1, 14)),
      formatDate(addDays(m1, 21)),
      formatDate(addDays(m1, maxDays))
    ];
    for (let i = 0; i < 4; i++) {
      if (i === 0) {
        // Row 1: full details (like POA&M generator) + Milestone 1 and its text
        const overrides: Partial<Record<string, string | number>> = {
          [milestoneIdCol]: 1,
          [milestoneDatesCol]: `${MILESTONE_TEXTS[0]} ${dates[0]}`,
          [schedCol]: dates[3]
        };
        rows.push(mapNewFindingRow(template, base, newPoam, overrides));
      } else {
        // Rows 2, 3, 4: only Milestone ID and Milestone with Completion Dates (all other fields blank)
        const blankRow: (string | number)[] = [''];
        base.headers.forEach(h => {
          if (h === milestoneIdCol) blankRow.push(i + 1);
          else if (h === milestoneDatesCol) blankRow.push(`${MILESTONE_TEXTS[i]} ${dates[i]}`);
          else blankRow.push('');
        });
        rows.push(blankRow);
      }
    }
  });
  return rows;
}

/** Export: POA&M (merged) + New findings + Dropped findings tabs; eMASS green header on rows 1-6. */
export function exportMergedPoam(
  base: BasePoamParsed,
  newPoam: NewPoamParsed,
  comparison: PoamComparison
): XLSXStyle.WorkBook {
  const wb = XLSXStyle.utils.book_new();
  const numCols = Math.max(base.headers.length + 1, 20);

  // Sheet 1: POA&M (merged)
  const mergedRows: (string | number)[][] = [];
  for (let r = 0; r < base.headerBlock.length; r++) {
    mergedRows.push(base.headerBlock[r].map(c => c));
  }
  mergedRows.push(['', ...base.headers]);
  const droppedSet = new Set<Record<string, string>>(comparison.droppedFindings);
  base.dataRows.forEach(row => {
    if (!droppedSet.has(row)) mergedRows.push(['', ...base.headers.map(h => row[h] ?? '')]);
  });
  const newFindingRows = expandNewFindingsToFourRows(comparison.newFindings, base, newPoam);
  newFindingRows.forEach(row => mergedRows.push(row));
  const wsMerged = XLSXStyle.utils.aoa_to_sheet(mergedRows);
  applyEmassHeaderStyle(wsMerged, numCols);
  XLSXStyle.utils.book_append_sheet(wb, wsMerged, POAM_SHEET_NAME);

  // Sheet 2: New findings (4 rows per finding, Devices Affected normalized)
  const newAoa: (string | number)[][] = [];
  for (let r = 0; r < base.headerBlock.length; r++) {
    newAoa.push(base.headerBlock[r].map(c => c));
  }
  newAoa.push(['', ...base.headers]);
  expandNewFindingsToFourRows(comparison.newFindings, base, newPoam).forEach(row => newAoa.push(row));
  const wsNew = XLSXStyle.utils.aoa_to_sheet(newAoa);
  applyEmassHeaderStyle(wsNew, numCols);
  XLSXStyle.utils.book_append_sheet(wb, wsNew, NEW_FINDINGS_SHEET);

  // Sheet 3: Dropped findings (base rows as-is; normalize Devices Affected for consistency)
  const devicesCol = findColumnHeader(base.headers, 'Devices Affected');
  const droppedAoa = buildSheetAoa(base, comparison.droppedFindings, row => {
    const arr = ['', ...base.headers.map(h => {
      const val = row[h] ?? '';
      if (devicesCol && h === devicesCol) return normalizeDevicesAffected(val);
      return val;
    })];
    return arr;
  });
  const wsDropped = XLSXStyle.utils.aoa_to_sheet(droppedAoa);
  applyEmassHeaderStyle(wsDropped, numCols);
  XLSXStyle.utils.book_append_sheet(wb, wsDropped, DROPPED_FINDINGS_SHEET);

  return wb;
}

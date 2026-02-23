/**
 * Detailed documentation for each RMF Python script.
 * Used by the (i) info button so users can copy this to troubleshoot with work AI.
 */

export const RMF_SCRIPT_INFO: Record<string, string> = {
  Reports: `STRIX RMF — REPORTS (Python script parity)

WHAT THE WEB APP DOES
- Accepts one or more checklist files (.ckl, .cklb, .json, .xml) or a folder of checklists.
- Groups checklists by STIG name (stigName).
- Builds a summary: per STIG, counts # of instances, total controls, and per severity (CAT I, CAT II, CAT III): % Complete, Total, Not a Finding, NA, Open.
- Severity mapping: high → CAT I, medium → CAT II, low → CAT III.
- Status mapping: Open/Fail → Open; Not a Finding/Pass → Not a Finding; Not Reviewed → Not Reviewed; N/A (Not Applicable) → NA.

HOW IT READS INPUT
- CKL (XML): Root <CHECKLIST>. <ASSET><HOST_NAME> = hostname. <STIG_REF> or <STIG_INFO><SID_NAME> = stig name. Each <VULN> = one finding. Inside each VULN: <VULN_NUM> or STIG_DATA Vuln_Num = vulnId (V-xxxx). STIG_DATA Rule_ID = ruleId (SV-xxxx). <STATUS>, <SEVERITY>, <RULE_TITLE>, <COMMENTS>, <FINDING_DETAILS>. STIG_DATA: Vuln_Discussion, Check_Content, Fix_Text, CCI_REF (list).
- CKLB (JSON): Object with stigs: [ { display_name, rules: [ { group_id, rule_id, status, severity, rule_title, comments, finding_details, vuln_discussion, check_content, fix_text, cci_ref } ] } ], target_data.host_name.

OUTPUT (Excel .xlsx)
- Sheet 1 "Summary": Row 1 headers: STIG Name, # of Instances, Total Controls, then for CAT I / CAT II / CAT III: % Comp, Total, NaF, NA, Open (repeated). Row 2 sub-headers. Data rows: one per STIG with instance count, total controls, and severity breakdown.
- One "Detail" sheet per STIG group: Headers = Hostname, Vuln ID, Rule ID, STIG ID, Severity, Classification, Status, Title, Comments, CCIs, Fix Text, Discussion. One row per finding across all instances of that STIG.
- Column widths: Hostname 20, Vuln ID 15, Rule ID 15, STIG ID 30, Severity 8, etc.

PYTHON SCRIPT MUST
1. Parse CKL (xml.etree or lxml) or CKLB (json) as above; normalize status/severity to the same values.
2. Group by stigName; compute per-STIG stats (instances, total controls, CAT I/II/III counts).
3. Build Summary sheet with exact header row structure.
4. Build one Detail sheet per STIG with columns Hostname, Vuln ID, Rule ID, STIG ID, Severity, Classification, Status, Title, Comments, CCIs, Fix Text, Discussion.
5. Write workbook to user-specified output path (.xlsx).`,

  Compare: `STRIX RMF — COMPARE (Python script parity)

WHAT THE WEB APP DOES
- Accepts two checklists: "Base" and "New".
- Builds a map of findings by vulnId (V-xxxx) for each checklist.
- Compares: (1) In base but not in new → "Removed Rule". (2) In both but status changed → "Status Change". (3) In new but not in base → "New Rule".
- Severity is normalized: high → CAT I, medium → CAT II, low → CAT III for display.
- Export: CSV with columns Type, Vuln ID, Severity, Title, Old Status, New Status.

HOW IT READS INPUT
- Same CKL/CKLB parsing as Reports. Each finding has: vulnId, ruleId, status, severity, title (and others). Matching key is vulnId.

OUTPUT
- In-app: table with Type (Removed Rule | Status Change | New Rule), Vuln ID, Severity, Title, Old Status, New Status.
- Export: CSV with header Type,Vuln ID,Severity,Title,Old Status,New Status. Title wrapped in quotes; internal quotes escaped as "".

PYTHON SCRIPT MUST
1. Parse base and new CKL/CKLB; extract findings with vulnId, status, severity, title.
2. Build baseMap and newMap keyed by vulnId.
3. For each base finding: if not in new → Removed Rule; if in new and status differs → Status Change.
4. For each new finding: if not in base → New Rule.
5. Output Excel (.xlsx) or CSV with columns Type, Vuln ID, Severity, Title, Old Status, New Status to user-specified path.`,

  "POA&M": `STRIX RMF — POA&M (Python script parity)

TWO MODES IN WEB APP

(1) GENERATE FROM CKL(S)
- Only OPEN findings are included (status === 'Open' or 'Fail').
- Findings aggregated by Security Check key = ruleId|vulnId; same finding on multiple hosts = one POA&M row with devices listed.
- NIST controls: from finding.ccis mapped via cci2nist.json (CCI-xxxxx → e.g. AC-1.3). Controls/APs column = semicolon-separated NIST IDs.
- Excel headers (row 1): POA&M Item ID, Control Vulnerability Description, Controls / APs, Office/Org, Security Checks, Resources Required, Scheduled Completion Date, Milestone ID, Milestone with Completion Dates, Milestone Changes, Source Identifying Vulnerability, Status, Comments, Raw Severity, Devices Affected, Mitigations, Severity, Relevance of Threat, Likelihood, Impact, Impact Description, Residual Risk Level, Recommendations, Identified in CFO Audit or other review, Personnel Resources: Cost Code.
- Four rows per finding: row 1 has all data; rows 2–4 have only Milestone ID (2,3,4) and Milestone with Completion Dates (default milestone texts + dates: M1, M1+14d, M1+21d, M4 by severity).
- Prompts: input path, output path, Office/Org, Resources Required, Status (defaults: Organization, TBD, Open).
- Security Checks column = ruleId + newline + vulnId + newline + groupId (trimmed).
- Severity: high/CAT I → 30 days; medium/CAT II → 60 days; low/CAT III → 90 days for milestone 4.

(2) COMPARE (BASE vs NEW POA&M)
- Base POA&M: eMASS-style. Sheet "POA&M". Rows 1–6 = header block. Row 7 = data headers from column B. Row 8+ = data. Security Checks: normalize SV-xxxxx_rule to SV-xxxxx.
- New POA&M: Row 1 = headers (column A). Row 2+ = data. Match by Security Checks; Controls/APs as secondary.
- New findings = in new not in base. Dropped = in base not in new. Export: three sheets — POA&M (merged), "New findings", "Dropped findings". Row 1 dark green + white bold; rows 2–7 light gray/bold.

PYTHON SCRIPT MUST
- Generate: Parse CKL(s), keep only Open findings, aggregate by ruleId|vulnId, map CCI→NIST via cci2nist.json. Prompt for Office/Org, Resources Required, Status. Build 4 rows per finding (row 1 full data; rows 2–4 Milestone ID + Milestone with Completion Dates). Write .xlsx with all 25 column headers.
- Compare: Parse base/new Excel; find "POA&M" sheet; match by Security Checks; produce merged workbook with three sheets.`,

  Controls: `STRIX RMF — CONTROLS (Python script parity)

WHAT THE WEB APP DOES
- Uses checklists and CCI → NIST map (cci2nist.json: { "CCI-000001": "AC-1.3", ... }).
- For each finding: get CCIs from finding.ccis or rule lookup; map each CCI to NIST; aggregate by control ID.
- Status per control: any Open → Fail; else any Not Reviewed → No Data; else Pass.
- Output: Control (NIST ID), Title, Status (Pass/Fail/No Data), severity counts. Sorted by control ID.

PYTHON SCRIPT MUST
1. Load cci2nist.json.
2. Parse checklist(s); for each finding get ccis[] and map to NIST; aggregate by control; set Pass/Fail/No Data from statuses.
3. Write Excel: Control, Title, Status, count columns to output path.`,

  'STIG Analyzer': `STRIX RMF — STIG ANALYZER (Python script parity)

WHAT THE WEB APP DOES
- Two checklists: Old and New. Categories: (1) Not Reviewed — in new, status Not_Reviewed, vulnId in old. (2) New IDs — vulnId in new not in old. (3) Dropped IDs — vulnId in old not in new. (4) Reviewed — in new, status not Not Reviewed, vulnId in old.
- Status normalized: toLowerCase, replace spaces/underscores.

OUTPUT
- Excel or table: vulnId, severity, title, old/new status, comments. Sheets or columns per category.

PYTHON SCRIPT MUST
1. Parse old and new CKL/CKLB; build maps by vulnId.
2. Not Reviewed / New IDs / Dropped IDs / Reviewed as above.
3. Write Excel to output path.`,

  'Master Copy': `STRIX RMF — MASTER COPY (Python script parity)

WHAT THE WEB APP DOES
- One source checklist, one or more targets. Match target finding to source by ruleId or vulnId. Copy from source to target: status, comments, findingDetails.
- Output: same format as input (CKLB JSON or CKL XML).

CKLB: Update stigs[].rules[].status, .comments, .finding_details from source where rule_id/group_id match.
CKL: Update <VULN> STATUS, COMMENTS, FINDING_DETAILS from source where Rule_ID/Vuln_Num match.

PYTHON SCRIPT MUST
1. Parse source and each target CKL/CKLB.
2. For each target finding, find source by ruleId or vulnId; overwrite status, comments, findingDetails.
3. Write updated target(s) to output path (.cklb or .ckl).`,

  Extractor: `STRIX RMF — EXTRACTOR (Python script parity)

WHAT THE WEB APP DOES
- One or more checklists. Options: Include CAT I (high), CAT II (medium), CAT III (low), Include Rule ID (SV-), Include Group ID (V-). Filter by selected severities; include selected columns.
- Output: Excel with Hostname, STIG Name, Severity, Rule ID, Group ID (if options set), Title, Status, Comments, Fix Text, etc.

PYTHON SCRIPT MUST
1. Parse input CKL/CKLB; filter by severities (cat1=high, cat2=medium, cat3=low).
2. Build rows with requested columns; write Excel to output path.`,

  'Report Analyzer': `STRIX RMF — REPORT ANALYZER (Python script parity)

WHAT THE WEB APP DOES
- Base = previous report (CSV/Excel) with Group ID, Rule ID, STIG Name, Severity, Title, Status. New = checklists. Match base rows to new findings by ruleId/groupId/vulnId and stigName. Compare old vs new severity and status; flag severity changes.
- Output: groupId, ruleId, stigName, oldSeverity, newSeverity, severityChanged, title, checkText, fixText, status, findingDetails, comments, plus original base row.

PYTHON SCRIPT MUST
1. Load base report (CSV/Excel); normalize column names.
2. Parse new checklist(s); build map by (ruleId or vulnId) + stigName.
3. For each base row, find matching new finding; compare severity/status; build output row.
4. Write Excel to output path.`
};

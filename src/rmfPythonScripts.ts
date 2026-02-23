/**
 * RMF Python scripts — copy-paste runnable scripts for when file uploads are blocked.
 * Run in terminal; each script prompts for input file/folder and output path.
 * Outputs: .xlsx (Excel) or .cklb as noted per script.
 */

export const RMF_PYTHON_SCRIPTS: Record<string, string> = {
  Reports: `#!/usr/bin/env python3
"""
STRIX RMF Reports — Generate Excel compliance reports from CKL/checklist files.
Prompts: input file or folder, output path (.xlsx).
Output: Excel with Summary (CURRENT ENVIRONMENT) and one Detail sheet per STIG.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def normalize_status(s):
    if not s:
        return ""
    t = s.lower().replace(" ", "").replace("_", "")
    if t in ("open", "fail", "failed"):
        return "open"
    if t in ("notafinding", "pass", "passed", "nf"):
        return "naf"
    if t in ("notapplicable", "na", "n/a"):
        return "na"
    return t

def normalize_severity(sev):
    if not sev:
        return "cat3"
    s = sev.lower()
    if s in ("high", "cat i", "i", "1"):
        return "cat1"
    if s in ("medium", "cat ii", "ii", "2"):
        return "cat2"
    return "cat3"

def parse_ckl(content, filename):
    """Parse CKL XML. Returns dict: hostname, stigName, findings list."""
    root = ET.fromstring(content)
    hostname = ""
    asset = root.find(".//ASSET")
    if asset is not None:
        hn = asset.find("HOST_NAME")
        if hn is not None and hn.text:
            hostname = hn.text.strip()
    stig_ref = root.find(".//STIG_REF")
    stig_name = "Unknown STIG"
    if stig_ref is not None and stig_ref.text:
        stig_name = stig_ref.text.strip()
    sid = root.find(".//SID_NAME")
    if sid is not None and sid.text:
        stig_name = sid.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_num = vuln.find("VULN_NUM")
        vuln_id = vuln_num.text.strip() if vuln_num is not None and vuln_num.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        comments = vuln.find("COMMENTS")
        comments_val = comments.text.strip() if comments is not None and comments.text else ""
        finding_details = vuln.find("FINDING_DETAILS")
        finding_details_val = finding_details.text.strip() if finding_details is not None and finding_details.text else ""
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        rule_id = ""
        description = ""
        check_text = ""
        fix_text = ""
        ccis = []
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID":
                rule_id = d
            elif a == "Vuln_Num":
                vuln_id = d
            elif a == "Vuln_Discussion":
                description = d
            elif a == "Check_Content":
                check_text = d
            elif a == "Fix_Text":
                fix_text = d
            elif a == "CCI_REF":
                ccis.append(d)
        findings.append({
            "vulnId": vuln_id,
            "ruleId": rule_id,
            "status": status_val,
            "severity": severity,
            "title": title,
            "comments": comments_val,
            "findingDetails": finding_details_val,
            "description": description,
            "checkText": check_text,
            "fixText": fix_text,
            "ccis": ccis,
            "classification": "UNCLASSIFIED",
        })
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def parse_cklb(content, filename):
    """Parse CKLB JSON. Returns dict: hostname, stigName, findings list."""
    data = json.loads(content)
    hostname = ""
    if isinstance(data.get("target_data"), dict) and data["target_data"].get("host_name"):
        hostname = data["target_data"]["host_name"]
    stig_name = "Unknown STIG"
    findings = []
    for stig in data.get("stigs") or []:
        if stig.get("display_name"):
            stig_name = stig["display_name"]
        for rule in stig.get("rules") or []:
            cci_ref = rule.get("cci_ref")
            ccis = [cci_ref] if isinstance(cci_ref, str) else (cci_ref or [])
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
                "comments": rule.get("comments") or "",
                "findingDetails": rule.get("finding_details") or "",
                "description": rule.get("vuln_discussion") or "",
                "checkText": rule.get("check_content") or "",
                "fixText": rule.get("fix_text") or "",
                "ccis": ccis,
                "classification": "UNCLASSIFIED",
            })
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def load_checklists(path):
    """Load all checklists from a file or folder. Searches recursively in folders."""
    path = Path(path)
    checklists = []
    if path.is_file():
        files = [path]
    else:
        files = []
        for ext in ("*.ckl", "*.cklb", "*.json", "*.xml"):
            files.extend(path.rglob(ext))
        files = list(dict.fromkeys(files))
    if not files:
        return checklists
    for f in files:
        if not f.is_file():
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            if raw.strip().startswith("{"):
                ckl = parse_cklb(raw, f.name)
            else:
                ckl = parse_ckl(raw, f.name)
            checklists.append(ckl)
        except Exception as e:
            print(f"Warning: skip {f}: {e}")
    return checklists

def main():
    print("--- STRIX RMF Reports ---")
    inp = input("Input file or folder path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\reports\\\\STIG_Report.xlsx): ").strip().strip('"').strip("'")
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checklists = load_checklists(path)
    if not checklists:
        num_files = 0
        if path.is_dir():
            for ext in ("*.ckl", "*.cklb", "*.json", "*.xml"):
                num_files += len(list(path.rglob(ext)))
        else:
            num_files = 1 if path.is_file() else 0
        if num_files == 0:
            print("No .ckl, .cklb, .json, or .xml files found in that path (folder is empty or path is wrong).")
        else:
            print("Found files but all failed to parse. Check that they are valid CKL/CKLB. See warnings above.")
        sys.exit(1)
    print(f"Loaded {len(checklists)} checklist(s).")
    stig_groups = defaultdict(list)
    for ckl in checklists:
        name = ckl.get("stigName") or "Unknown STIG"
        stig_groups[name].append(ckl)
    summary_header1 = [
        "STIG Name", "# of Instances", "Total Controls",
        "CAT I", "", "", "", "",
        "CAT II", "", "", "", "",
        "CAT III", "", "", "", ""
    ]
    summary_header2 = [
        "", "", "",
        "% Complete", "Total CAT Is", "Not a Finding", "Not Applicable", "Open",
        "% Complete", "Total CAT IIs", "Not a Finding", "Not Applicable", "Open",
        "% Complete", "Total CAT IIIs", "Not a Finding", "Not Applicable", "Open"
    ]
    grand_stats = {"cat1": {"total": 0, "naf": 0, "na": 0, "open": 0},
                   "cat2": {"total": 0, "naf": 0, "na": 0, "open": 0},
                   "cat3": {"total": 0, "naf": 0, "na": 0, "open": 0}}
    summary_rows = []
    for stig_name, group in stig_groups.items():
        instances = len(group)
        stats = {"cat1": {"total": 0, "naf": 0, "na": 0, "open": 0},
                 "cat2": {"total": 0, "naf": 0, "na": 0, "open": 0},
                 "cat3": {"total": 0, "naf": 0, "na": 0, "open": 0}}
        total_controls = 0
        for ckl in group:
            for f in ckl["findings"]:
                total_controls += 1
                cat = normalize_severity(f.get("severity"))
                stats[cat]["total"] += 1
                grand_stats[cat]["total"] += 1
                s = normalize_status(f.get("status"))
                if s == "open":
                    stats[cat]["open"] += 1
                    grand_stats[cat]["open"] += 1
                elif s == "naf":
                    stats[cat]["naf"] += 1
                    grand_stats[cat]["naf"] += 1
                elif s == "na":
                    stats[cat]["na"] += 1
                    grand_stats[cat]["na"] += 1
        def pct(st):
            if st["total"] == 0:
                return "100%"
            return str(round((st["naf"] + st["na"]) / st["total"] * 100)) + "%"
        summary_rows.append([
            stig_name, instances, total_controls,
            pct(stats["cat1"]), stats["cat1"]["total"], stats["cat1"]["naf"], stats["cat1"]["na"], stats["cat1"]["open"],
            pct(stats["cat2"]), stats["cat2"]["total"], stats["cat2"]["naf"], stats["cat2"]["na"], stats["cat2"]["open"],
            pct(stats["cat3"]), stats["cat3"]["total"], stats["cat3"]["naf"], stats["cat3"]["na"], stats["cat3"]["open"]
        ])
    def grand_pct(st):
        if st["total"] == 0:
            return "100%"
        return str(round((st["naf"] + st["na"]) / st["total"] * 100)) + "%"
    summary_rows.append([
        "Grand Total", sum(len(g) for g in stig_groups.values()), sum(sum(len(c["findings"]) for c in g) for g in stig_groups.values()),
        grand_pct(grand_stats["cat1"]), grand_stats["cat1"]["total"], grand_stats["cat1"]["naf"], grand_stats["cat1"]["na"], grand_stats["cat1"]["open"],
        grand_pct(grand_stats["cat2"]), grand_stats["cat2"]["total"], grand_stats["cat2"]["naf"], grand_stats["cat2"]["na"], grand_stats["cat2"]["open"],
        grand_pct(grand_stats["cat3"]), grand_stats["cat3"]["total"], grand_stats["cat3"]["naf"], grand_stats["cat3"]["na"], grand_stats["cat3"]["open"]
    ])
    wb = openpyxl.Workbook()
    ws_summary = wb.active
    ws_summary.title = "CURRENT ENVIRONMENT"
    for r, row in enumerate([summary_header1, summary_header2] + summary_rows, 1):
        for c, val in enumerate(row, 1):
            ws_summary.cell(row=r, column=c, value=val)
    col_widths = [40, 15, 15, 12, 10, 12, 12, 8, 12, 10, 12, 12, 8, 12, 10, 12, 12, 8]
    for i, w in enumerate(col_widths, 1):
        ws_summary.column_dimensions[get_column_letter(i)].width = w
    detail_headers = ["Hostname", "Vuln ID", "Rule ID", "STIG ID", "Severity", "Classification", "Status", "Title", "Comments", "CCIs", "Fix Text", "Discussion"]
    used_sheet_names = {"CURRENT ENVIRONMENT"}
    for stig_name, group in stig_groups.items():
        safe_name = "".join(c for c in stig_name if c not in "[]*?/\\\\:")[:31]
        name = safe_name
        idx = 1
        while name in used_sheet_names:
            name = (safe_name[:28] + " (" + str(idx) + ")")[:31]
            idx += 1
        used_sheet_names.add(name)
        ws = wb.create_sheet(title=name)
        ws.append(detail_headers)
        for ckl in group:
            for f in ckl["findings"]:
                sev = (f.get("severity") or "").lower()
                if sev == "high":
                    sev = "CAT I"
                elif sev == "medium":
                    sev = "CAT II"
                elif sev == "low":
                    sev = "CAT III"
                ws.append([
                    ckl.get("hostname", ""),
                    f.get("vulnId", ""),
                    f.get("ruleId") or "N/A",
                    ckl.get("stigName", ""),
                    sev,
                    f.get("classification", "UNCLASSIFIED"),
                    f.get("status", ""),
                    f.get("title", ""),
                    f.get("comments", ""),
                    ", ".join(f.get("ccis") or []),
                    f.get("fixText", ""),
                    f.get("description", ""),
                ])
        for i, w in enumerate([20, 15, 15, 30, 8, 15, 15, 40, 40, 20, 40, 40], 1):
            ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  Compare: `#!/usr/bin/env python3
"""
STRIX RMF Compare — Compare two checklists (base vs new) for status/compliance diffs.
Prompts: base file, new file, output path (.xlsx).
Output: Excel with Type, Vuln ID, Severity, Title, Old Status, New Status.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    hostname = ""
    asset = root.find(".//ASSET")
    if asset is not None:
        hn = asset.find("HOST_NAME")
        if hn is not None and hn.text:
            hostname = hn.text.strip()
    stig_ref = root.find(".//STIG_REF")
    stig_name = "Unknown STIG"
    if stig_ref is not None and stig_ref.text:
        stig_name = stig_ref.text.strip()
    sid = root.find(".//SID_NAME")
    if sid is not None and sid.text:
        stig_name = sid.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_num = vuln.find("VULN_NUM")
        vuln_id = vuln_num.text.strip() if vuln_num is not None and vuln_num.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        rule_id = ""
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID":
                rule_id = d
            elif a == "Vuln_Num":
                vuln_id = d
        findings.append({"vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "severity": severity, "title": title})
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    hostname = ""
    if isinstance(data.get("target_data"), dict) and data["target_data"].get("host_name"):
        hostname = data["target_data"]["host_name"]
    stig_name = "Unknown STIG"
    findings = []
    for stig in data.get("stigs") or []:
        if stig.get("display_name"):
            stig_name = stig["display_name"]
        for rule in stig.get("rules") or []:
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
            })
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def load_one(path):
    path = Path(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if raw.strip().startswith("{"):
        return parse_cklb(raw, path.name)
    return parse_ckl(raw, path.name)

def main():
    print("--- STRIX RMF Compare ---")
    base_inp = input("Base checklist path (.ckl/.cklb): ").strip().strip('"').strip("'")
    new_inp = input("New checklist path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\output\\\\Compare_Result.xlsx): ").strip().strip('"').strip("'")
    if not base_inp or not new_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    base_path, new_path = Path(base_inp), Path(new_inp)
    out_path = Path(out)
    if not base_path.exists() or not new_path.exists():
        print("Both input files must exist.")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base = load_one(base_path)
    new = load_one(new_path)
    base_map = {f["vulnId"]: f for f in base["findings"]}
    new_map = {f["vulnId"]: f for f in new["findings"]}
    diffs = []
    for vid, bf in base_map.items():
        sev = (bf["severity"] or "").lower()
        if sev == "high": sev = "CAT I"
        elif sev == "medium": sev = "CAT II"
        elif sev == "low": sev = "CAT III"
        nf = new_map.get(vid)
        if not nf:
            diffs.append({"Type": "Removed Rule", "Vuln ID": vid, "Severity": sev, "Title": bf["title"], "Old Status": bf["status"], "New Status": "N/A"})
        elif bf["status"] != nf["status"]:
            diffs.append({"Type": "Status Change", "Vuln ID": vid, "Severity": sev, "Title": bf["title"], "Old Status": bf["status"], "New Status": nf["status"]})
    for vid, nf in new_map.items():
        if vid in base_map:
            continue
        sev = (nf["severity"] or "").lower()
        if sev == "high": sev = "CAT I"
        elif sev == "medium": sev = "CAT II"
        elif sev == "low": sev = "CAT III"
        diffs.append({"Type": "New Rule", "Vuln ID": vid, "Severity": sev, "Title": nf["title"], "Old Status": "N/A", "New Status": nf["status"]})
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Comparison"
    headers = ["Type", "Vuln ID", "Severity", "Title", "Old Status", "New Status"]
    ws.append(headers)
    for d in diffs:
        ws.append([d[h] for h in headers])
    for i, w in enumerate([14, 14, 10, 45, 14, 14], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(out_path)
    print(f"Saved: {out_path} ({len(diffs)} differences)")

if __name__ == "__main__":
    main()
`,

  "POA&M": `#!/usr/bin/env python3
"""
STRIX RMF POA&M — Generate POA&M Excel from CKL(s). Only OPEN findings. Optional: place cci2nist.json for CCI->NIST.
Prompts: input file or folder, output path (.xlsx), Office/Org (e.g. your org name).
Output: Excel with POA&M sheet (eMASS-style headers).
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    hostname = ""
    asset = root.find(".//ASSET")
    if asset is not None:
        hn = asset.find("HOST_NAME")
        if hn is not None and hn.text:
            hostname = hn.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_id = vuln.find("VULN_NUM")
        vuln_id = vuln_id.text.strip() if vuln_id is not None and vuln_id.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        if status_val.lower() not in ("open", "fail", "failed"):
            continue
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        rule_id = ""
        ccis = []
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
            elif a == "CCI_REF": ccis.append(d)
        findings.append({"hostname": hostname or filename, "vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "severity": severity, "title": title, "ccis": ccis})
    return {"hostname": hostname or filename, "findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    hostname = ""
    if isinstance(data.get("target_data"), dict) and data["target_data"].get("host_name"):
        hostname = data["target_data"]["host_name"]
    findings = []
    for stig in data.get("stigs") or []:
        for rule in stig.get("rules") or []:
            s = (rule.get("status") or "").lower()
            if s not in ("open", "fail", "failed"):
                continue
            cci_ref = rule.get("cci_ref")
            ccis = [cci_ref] if isinstance(cci_ref, str) else (cci_ref or [])
            findings.append({
                "hostname": hostname or filename,
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Open",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
                "ccis": ccis,
            })
    return {"hostname": hostname or filename, "findings": findings}

def load_checklists(path):
    path = Path(path)
    checklists = []
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.ckl")) + list(path.rglob("*.cklb")) + list(path.rglob("*.json")) + list(path.rglob("*.xml"))
        files = list(dict.fromkeys(files))
    for f in files:
        if not f.is_file():
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            ckl = parse_cklb(raw, f.name) if raw.strip().startswith("{") else parse_ckl(raw, f.name)
            checklists.append(ckl)
        except Exception as e:
            print(f"Warning: skip {f}: {e}")
    return checklists

def load_cci2nist():
    for p in [Path("cci2nist.json"), Path(__file__).parent / "cci2nist.json"]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"CCI-000001": "AC-1.3", "CCI-000073": "PM-1.1", "CCI-000117": "AU-1.3", "CCI-000176": "IA-5.2"}

def main():
    print("--- STRIX RMF POA&M (Generate from CKL) ---")
    inp = input("Input file or folder path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\poam\\\\POAM.xlsx): ").strip().strip('"').strip("'")
    office_org = input("Office/Org (optional): ").strip() or "Organization"
    if not inp or not out:
        print("Input and output paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checklists = load_checklists(path)
    if not checklists:
        print("No checklists found. (Searches folder and all subfolders for .ckl, .cklb, .json.)")
        sys.exit(1)
    cci2nist = load_cci2nist()
    aggregated = defaultdict(lambda: {"finding": None, "hostnames": set(), "nist": set()})
    for ckl in checklists:
        for f in ckl["findings"]:
            key = (f.get("ruleId") or "") + "|" + (f.get("vulnId") or "")
            if key not in aggregated or aggregated[key]["finding"] is None:
                aggregated[key]["finding"] = f
            aggregated[key]["hostnames"].add(ckl.get("hostname", ""))
            for cci in f.get("ccis") or []:
                n = cci2nist.get(cci)
                if n:
                    aggregated[key]["nist"].add(n)
    headers = ["POA&M Item ID", "Control Vulnerability Description", "Controls / APs", "Office/Org", "Security Checks", "Resources Required", "Scheduled Completion Date", "Status", "Comments", "Raw Severity", "Devices Affected", "Severity"]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append(headers)
    for idx, (key, ag) in enumerate(aggregated.items(), 1):
        f = ag["finding"]
        if not f:
            continue
        sev = (f.get("severity") or "").lower()
        if sev in ("high", "cat i"): sev_disp = "High"
        elif sev in ("medium", "cat ii"): sev_disp = "Medium"
        else: sev_disp = "Low"
        security_checks = (f.get("ruleId") or "") + "\\n" + (f.get("vulnId") or "")
        devices = "\\n".join(sorted(ag["hostnames"])) if ag["hostnames"] else ""
        nist_str = "; ".join(sorted(ag["nist"])) if ag["nist"] else ""
        ws.append([idx, f.get("title", ""), nist_str, office_org, security_checks, "", "", f.get("status", ""), "", sev_disp, devices, sev_disp])
    for i, w in enumerate([10, 45, 25, 18, 25, 18, 18, 12, 30, 12, 30, 10], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(out_path)
    print(f"Saved: {out_path} ({len(aggregated)} POA&M items)")

if __name__ == "__main__":
    main()
`,

  Controls: `#!/usr/bin/env python3
"""
STRIX RMF Controls — Map findings (CCI) to NIST controls; output control summary.
Prompts: input checklist file or folder, output path (.xlsx).
Optional: place cci2nist.json (CCI -> NIST map) in same folder for full mapping.
Output: Excel with Control, Title, Status (Pass/Fail/No Data), counts.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_id = ""
        rule_id = ""
        status_val = "Not_Reviewed"
        severity = "low"
        title = ""
        ccis = []
        vuln_num = vuln.find("VULN_NUM")
        if vuln_num is not None and vuln_num.text:
            vuln_id = vuln_num.text.strip()
        status = vuln.find("STATUS")
        if status is not None and status.text:
            status_val = status.text.strip()
        rule_title = vuln.find("RULE_TITLE")
        if rule_title is not None and rule_title.text:
            title = rule_title.text.strip()
        severity_el = vuln.find("SEVERITY")
        if severity_el is not None and severity_el.text:
            severity = severity_el.text.strip()
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
            elif a == "CCI_REF": ccis.append(d)
        findings.append({"vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "severity": severity, "title": title, "ccis": ccis})
    return {"findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    findings = []
    for stig in data.get("stigs") or []:
        for rule in stig.get("rules") or []:
            cci_ref = rule.get("cci_ref")
            ccis = [cci_ref] if isinstance(cci_ref, str) else (cci_ref or [])
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
                "ccis": ccis,
            })
    return {"findings": findings}

def load_checklists(path):
    path = Path(path)
    checklists = []
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.ckl")) + list(path.rglob("*.cklb")) + list(path.rglob("*.json")) + list(path.rglob("*.xml"))
        files = list(dict.fromkeys(files))
    for f in files:
        if not f.is_file():
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            ckl = parse_cklb(raw, f.name) if raw.strip().startswith("{") else parse_ckl(raw, f.name)
            checklists.append(ckl)
        except Exception as e:
            print(f"Warning: skip {f}: {e}")
    return checklists

def load_cci2nist():
    for p in [Path("cci2nist.json"), Path(__file__).parent / "cci2nist.json"]:
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"CCI-000001": "AC-1.3", "CCI-000002": "AC-1.4", "CCI-000003": "AC-1.7", "CCI-000008": "AC-2.4", "CCI-000073": "PM-1.1", "CCI-000117": "AU-1.3", "CCI-000123": "AU-2.1", "CCI-000176": "IA-5.2"}

def main():
    print("--- STRIX RMF Controls ---")
    inp = input("Input checklist path or folder (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\output\\\\Controls.xlsx): ").strip().strip('"').strip("'")
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checklists = load_checklists(path)
    if not checklists:
        print("No checklists found. (Searches folder and all subfolders for .ckl, .cklb, .json.)")
        sys.exit(1)
    cci2nist = load_cci2nist()
    control_findings = defaultdict(list)
    for ckl in checklists:
        for f in ckl["findings"]:
            for cci in f.get("ccis") or []:
                nist = cci2nist.get(cci)
                if nist:
                    control_findings[nist].append({"status": f["status"], "title": f["title"]})
    rows = []
    for control in sorted(control_findings.keys(), key=lambda x: (x.split("-")[0], x)):
        findings = control_findings[control]
        status_norm = [ (s or "").lower().replace(" ", "").replace("_", "") for s in [x["status"] for x in findings] ]
        if any(s in ("open", "fail", "failed") for s in status_norm):
            status = "Fail"
        elif any(s in ("notreviewed", "not_reviewed") for s in status_norm):
            status = "No Data"
        else:
            status = "Pass"
        title = findings[0]["title"] if findings else ""
        rows.append({"Control": control, "Title": title, "Status": status, "Count": len(findings)})
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Controls"
    ws.append(["Control", "Title", "Status", "Finding Count"])
    for r in rows:
        ws.append([r["Control"], r["Title"], r["Status"], r["Count"]])
    for i, w in enumerate([18, 50, 12, 14], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(out_path)
    print(f"Saved: {out_path} ({len(rows)} controls)")

if __name__ == "__main__":
    main()
`,

  'STIG Analyzer': `#!/usr/bin/env python3
"""
STRIX RMF STIG Analyzer — Compare old vs new checklist (Not Reviewed, New IDs, Dropped IDs, Reviewed).
Prompts: old checklist, new checklist, output path (.xlsx).
Output: Excel with sheets per category.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_id = vuln.find("VULN_NUM")
        vuln_id = vuln_id.text.strip() if vuln_id is not None and vuln_id.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        rule_id = ""
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
        findings.append({"vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "severity": severity, "title": title})
    return {"findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    findings = []
    for stig in data.get("stigs") or []:
        for rule in stig.get("rules") or []:
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
            })
    return {"findings": findings}

def load_one(path):
    path = Path(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    return parse_cklb(raw, path.name) if raw.strip().startswith("{") else parse_ckl(raw, path.name)

def main():
    print("--- STRIX RMF STIG Analyzer ---")
    old_inp = input("Old checklist path (.ckl/.cklb): ").strip().strip('"').strip("'")
    new_inp = input("New checklist path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\output\\\\STIG_Analyzer.xlsx): ").strip().strip('"').strip("'")
    if not old_inp or not new_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    old_path, new_path = Path(old_inp), Path(new_inp)
    out_path = Path(out)
    if not old_path.exists() or not new_path.exists():
        print("Both input files must exist.")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    old_ckl = load_one(old_path)
    new_ckl = load_one(new_path)
    old_map = {f["vulnId"]: f for f in old_ckl["findings"]}
    new_map = {f["vulnId"]: f for f in new_ckl["findings"]}
    def norm(s):
        return (s or "").lower().replace(" ", "").replace("_", "")
    not_reviewed = [{"vulnId": vid, **new_map[vid]} for vid in new_map if vid in old_map and norm(new_map[vid]["status"]) == "notreviewed"]
    new_ids = [{"vulnId": vid, **new_map[vid]} for vid in new_map if vid not in old_map]
    dropped_ids = [{"vulnId": vid, **old_map[vid]} for vid in old_map if vid not in new_map]
    reviewed = [{"vulnId": vid, **new_map[vid]} for vid in new_map if vid in old_map and norm(new_map[vid]["status"]) != "notreviewed"]
    wb = openpyxl.Workbook()
    headers = ["Vuln ID", "Rule ID", "Severity", "Title", "Status"]
    for sheet_name, rows in [("Not Reviewed", not_reviewed), ("New IDs", new_ids), ("Dropped IDs", dropped_ids), ("Reviewed", reviewed)]:
        ws = wb.create_sheet(title=sheet_name[:31])
        ws.append(headers)
        for r in rows:
            ws.append([r.get("vulnId", ""), r.get("ruleId", ""), r.get("severity", ""), r.get("title", ""), r.get("status", "")])
        for i, w in enumerate([14, 14, 10, 45, 16], 1):
            ws.column_dimensions[get_column_letter(i)].width = w
    if "Sheet" in wb.sheetnames:
        wb.remove(wb["Sheet"])
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  'Master Copy': `#!/usr/bin/env python3
"""
STRIX RMF Master Copy — Copy status, comments, finding_details from source checklist into target(s).
Prompts: source checklist, target file or folder, output path (file or folder).
Output: .cklb (JSON) per target. Target structure preserved with source values merged by ruleId/vulnId.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    hostname = ""
    asset = root.find(".//ASSET")
    if asset is not None:
        hn = asset.find("HOST_NAME")
        if hn is not None and hn.text:
            hostname = hn.text.strip()
    stig_ref = root.find(".//STIG_REF")
    stig_name = "Unknown STIG"
    if stig_ref is not None and stig_ref.text:
        stig_name = stig_ref.text.strip()
    sid = root.find(".//SID_NAME")
    if sid is not None and sid.text:
        stig_name = sid.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_num = vuln.find("VULN_NUM")
        vuln_id = vuln_num.text.strip() if vuln_num is not None and vuln_num.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        comments = vuln.find("COMMENTS")
        comments_val = comments.text.strip() if comments is not None and comments.text else ""
        finding_details = vuln.find("FINDING_DETAILS")
        finding_details_val = finding_details.text.strip() if finding_details is not None and finding_details.text else ""
        rule_id = ""
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
        findings.append({"vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "comments": comments_val, "findingDetails": finding_details_val})
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    hostname = ""
    if isinstance(data.get("target_data"), dict) and data["target_data"].get("host_name"):
        hostname = data["target_data"]["host_name"]
    stig_name = "Unknown STIG"
    findings = []
    for stig in data.get("stigs") or []:
        if stig.get("display_name"):
            stig_name = stig["display_name"]
        for rule in stig.get("rules") or []:
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "comments": rule.get("comments") or "",
                "findingDetails": rule.get("finding_details") or "",
            })
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings, "raw": data}

def load_one(path):
    path = Path(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if raw.strip().startswith("{"):
        return parse_cklb(raw, path.name)
    return parse_ckl(raw, path.name)

def main():
    print("--- STRIX RMF Master Copy ---")
    src = input("Source checklist path (.ckl/.cklb): ").strip().strip('"').strip("'")
    tgt = input("Target checklist path or folder: ").strip().strip('"').strip("'")
    out = input("Output path (file or folder for .cklb): ").strip().strip('"').strip("'")
    if not src or not tgt or not out:
        print("All three paths are required.")
        sys.exit(1)
    src_path, tgt_path, out_path = Path(src), Path(tgt), Path(out)
    if not src_path.exists():
        print(f"Not found: {src_path}")
        sys.exit(1)
    source = load_one(src_path)
    source_map = {}
    for f in source["findings"]:
        source_map[f["vulnId"]] = f
        if f.get("ruleId"):
            source_map[f["ruleId"]] = f
    if tgt_path.is_file():
        target_files = [tgt_path]
    else:
        target_files = list(tgt_path.rglob("*.ckl")) + list(tgt_path.rglob("*.cklb")) + list(tgt_path.rglob("*.json")) + list(tgt_path.rglob("*.xml"))
        target_files = list(dict.fromkeys(target_files))
    out_path.mkdir(parents=True, exist_ok=True)
    for t in target_files:
        if not t.is_file():
            continue
        tgt_ckl = load_one(t)
        for f in tgt_ckl["findings"]:
            src_f = source_map.get(f["vulnId"]) or source_map.get(f.get("ruleId", ""))
            if src_f:
                f["status"] = src_f["status"]
                f["comments"] = src_f.get("comments", "")
                f["findingDetails"] = src_f.get("findingDetails", "")
        if "raw" in tgt_ckl:
            out_data = tgt_ckl["raw"]
            for stig in out_data.get("stigs") or []:
                for rule in stig.get("rules") or []:
                    vid = rule.get("group_id") or rule.get("rule_id")
                    src_f = source_map.get(rule.get("group_id", "")) or source_map.get(rule.get("rule_id", ""))
                    if src_f:
                        rule["status"] = src_f["status"]
                        rule["comments"] = src_f.get("comments", "")
                        rule["finding_details"] = src_f.get("findingDetails", "")
        else:
            out_data = {"target_data": {"host_name": tgt_ckl["hostname"]}, "stigs": [{"display_name": tgt_ckl["stigName"], "rules": [{"group_id": f["vulnId"], "rule_id": f.get("ruleId"), "status": f["status"], "comments": f.get("comments"), "finding_details": f.get("findingDetails")} for f in tgt_ckl["findings"]]}]}
        out_file = out_path / (t.stem + "_master.cklb") if out_path.is_dir() else out_path
        if out_file.suffix.lower() != ".cklb" and out_file.suffix.lower() != ".json":
            out_file = out_file.with_suffix(".cklb")
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
        print(f"Saved: {out_file}")
    print("Done.")

if __name__ == "__main__":
    main()
`,

  Extractor: `#!/usr/bin/env python3
"""
STRIX RMF Extractor — Extract findings from CKL(s); filter by severity (CAT I/II/III), include Rule ID, Group ID.
Prompts: input file or folder, output path (.xlsx). Then: include CAT I? (y/n), CAT II? (y/n), CAT III? (y/n), Rule ID? (y/n), Group ID? (y/n).
Output: Excel with selected columns.
"""
import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    hostname = ""
    asset = root.find(".//ASSET")
    if asset is not None:
        hn = asset.find("HOST_NAME")
        if hn is not None and hn.text:
            hostname = hn.text.strip()
    sid = root.find(".//SID_NAME")
    stig_name = sid.text.strip() if sid is not None and sid.text else "Unknown STIG"
    stig_ref = root.find(".//STIG_REF")
    if stig_ref is not None and stig_ref.text:
        stig_name = stig_ref.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_id = vuln.find("VULN_NUM")
        vuln_id = vuln_id.text.strip() if vuln_id is not None and vuln_id.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        comments = vuln.find("COMMENTS")
        comments_val = comments.text.strip() if comments is not None and comments.text else ""
        fix_text = ""
        rule_id = ""
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
            elif a == "Fix_Text": fix_text = d
        findings.append({"hostname": hostname or filename, "stigName": stig_name, "vulnId": vuln_id, "ruleId": rule_id, "status": status_val, "severity": severity, "title": title, "comments": comments_val, "fixText": fix_text})
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    hostname = ""
    if isinstance(data.get("target_data"), dict) and data["target_data"].get("host_name"):
        hostname = data["target_data"]["host_name"]
    stig_name = "Unknown STIG"
    findings = []
    for stig in data.get("stigs") or []:
        if stig.get("display_name"):
            stig_name = stig["display_name"]
        for rule in stig.get("rules") or []:
            findings.append({
                "hostname": hostname or filename,
                "stigName": stig_name,
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "status": rule.get("status") or "Not_Reviewed",
                "severity": rule.get("severity") or "low",
                "title": rule.get("rule_title") or "",
                "comments": rule.get("comments") or "",
                "fixText": rule.get("fix_text") or "",
            })
    return {"hostname": hostname or filename, "stigName": stig_name, "findings": findings}

def load_checklists(path):
    path = Path(path)
    checklists = []
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.ckl")) + list(path.rglob("*.cklb")) + list(path.rglob("*.json")) + list(path.rglob("*.xml"))
        files = list(dict.fromkeys(files))
    for f in files:
        if not f.is_file():
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            ckl = parse_cklb(raw, f.name) if raw.strip().startswith("{") else parse_ckl(raw, f.name)
            checklists.append(ckl)
        except Exception as e:
            print(f"Warning: skip {f}: {e}")
    return checklists

def main():
    print("--- STRIX RMF Extractor ---")
    inp = input("Input file or folder path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\output\\\\Extract.xlsx): ").strip().strip('"').strip("'")
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    cat1 = input("Include CAT I (high) findings? [Y/n]: ").strip().lower() != "n"
    cat2 = input("Include CAT II (medium) findings? [Y/n]: ").strip().lower() != "n"
    cat3 = input("Include CAT III (low) findings? [Y/n]: ").strip().lower() != "n"
    rule_id = input("Include Rule ID column? [Y/n]: ").strip().lower() != "n"
    group_id = input("Include Group ID column? [Y/n]: ").strip().lower() != "n"
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checklists = load_checklists(path)
    if not checklists:
        print("No checklists found. (Searches folder and subfolders for .ckl, .cklb, .json.)")
        sys.exit(1)
    def severity_match(sev):
        s = (sev or "").lower()
        if s in ("high", "cat i", "i"): return cat1
        if s in ("medium", "cat ii", "ii"): return cat2
        return cat3
    headers = ["Hostname", "STIG Name", "Severity", "Status", "Title", "Comments", "Fix Text"]
    if group_id:
        headers.append("Group ID")
    if rule_id:
        headers.append("Rule ID")
    rows = []
        for f in ckl["findings"]:
            if not severity_match(f.get("severity")):
                continue
            sev = (f.get("severity") or "").lower()
            if sev == "high": sev = "CAT I"
            elif sev == "medium": sev = "CAT II"
            elif sev == "low": sev = "CAT III"
            row = [ckl.get("hostname", ""), ckl.get("stigName", ""), sev, f.get("status", ""), f.get("title", ""), f.get("comments", ""), f.get("fixText", "")]
            if group_id:
                row.append(f.get("vulnId", ""))
            if rule_id:
                row.append(f.get("ruleId", ""))
            rows.append(row)
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Extract"
    ws.append(headers)
    for row in rows:
        ws.append(row)
    for i, w in enumerate([20, 30, 10, 14, 45, 30, 40] + ([14, 14] if (group_id or rule_id) else []), 1):
        ws.column_dimensions[get_column_letter(i)].width = min(w, 50)
    wb.save(out_path)
    print(f"Saved: {out_path} ({len(rows)} rows)")

if __name__ == "__main__":
    main()
`,

  'Report Analyzer': `#!/usr/bin/env python3
"""
STRIX RMF Report Analyzer — Compare base report (CSV/Excel) to new checklist(s); find severity/status changes.
Prompts: base report path, checklist file or folder, output path (.xlsx).
Output: Excel with Old Severity, New Severity, Severity Changed, Rule ID, Group ID, STIG Name, Title, Status, etc.
"""
import sys
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import openpyxl
    from openpyxl.utils import get_column_letter
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def parse_ckl(content, filename):
    root = ET.fromstring(content)
    stig_name = "Unknown STIG"
    sid = root.find(".//SID_NAME")
    if sid is not None and sid.text:
        stig_name = sid.text.strip()
    stig_ref = root.find(".//STIG_REF")
    if stig_ref is not None and stig_ref.text:
        stig_name = stig_ref.text.strip()
    findings = []
    for vuln in root.findall(".//VULN"):
        vuln_id = vuln.find("VULN_NUM")
        vuln_id = vuln_id.text.strip() if vuln_id is not None and vuln_id.text else ""
        status = vuln.find("STATUS")
        status_val = status.text.strip() if status is not None and status.text else "Not_Reviewed"
        rule_title = vuln.find("RULE_TITLE")
        title = rule_title.text.strip() if rule_title is not None and rule_title.text else ""
        severity_el = vuln.find("SEVERITY")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "low"
        rule_id = ""
        for stig_data in vuln.findall("STIG_DATA"):
            attr = stig_data.find("VULN_ATTRIBUTE")
            data = stig_data.find("ATTRIBUTE_DATA")
            if attr is None or data is None or not attr.text or not data.text:
                continue
            a, d = attr.text.strip(), data.text.strip()
            if a == "Rule_ID": rule_id = d
            elif a == "Vuln_Num": vuln_id = d
        findings.append({"vulnId": vuln_id, "ruleId": rule_id, "stigName": stig_name, "severity": severity, "status": status_val, "title": title})
    return {"stigName": stig_name, "findings": findings}

def parse_cklb(content, filename):
    data = json.loads(content)
    stig_name = "Unknown STIG"
    findings = []
    for stig in data.get("stigs") or []:
        if stig.get("display_name"):
            stig_name = stig["display_name"]
        for rule in stig.get("rules") or []:
            findings.append({
                "vulnId": rule.get("group_id") or "",
                "ruleId": rule.get("rule_id") or "",
                "stigName": stig_name,
                "severity": rule.get("severity") or "low",
                "status": rule.get("status") or "Not_Reviewed",
                "title": rule.get("rule_title") or "",
            })
    return {"stigName": stig_name, "findings": findings}

def load_checklists(path):
    path = Path(path)
    checklists = []
    if path.is_file():
        files = [path]
    else:
        files = list(path.rglob("*.ckl")) + list(path.rglob("*.cklb")) + list(path.rglob("*.json")) + list(path.rglob("*.xml"))
        files = list(dict.fromkeys(files))
    for f in files:
        if not f.is_file():
            continue
        try:
            raw = f.read_text(encoding="utf-8", errors="replace")
            ckl = parse_cklb(raw, f.name) if raw.strip().startswith("{") else parse_ckl(raw, f.name)
            checklists.append(ckl)
        except Exception as e:
            print(f"Warning: skip {f}: {e}")
    return checklists

def load_base_report(path):
    path = Path(path)
    rows = []
    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f)
            for row in r:
                rows.append({k.strip(): v for k, v in row.items()})
        return rows
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    headers = [str(ws.cell(1, c).value or "").strip() for c in range(1, ws.max_column + 1)]
    for r in range(2, ws.max_row + 1):
        row = {}
        for c, h in enumerate(headers, 1):
            val = ws.cell(r, c).value
            row[h] = str(val).strip() if val is not None else ""
        rows.append(row)
    wb.close()
    return rows

def norm_col(row, *names):
    for n in names:
        for k in row:
            if k and n.lower() in k.lower():
                return row.get(k, "")
    return ""

def main():
    print("--- STRIX RMF Report Analyzer ---")
    base_inp = input("Base report path (.csv or .xlsx): ").strip().strip('"').strip("'")
    ckl_inp = input("Checklist file or folder path (.ckl/.cklb): ").strip().strip('"').strip("'")
    out = input("Output path (e.g. C:\\\\output\\\\Report_Analyzer.xlsx): ").strip().strip('"').strip("'")
    if not base_inp or not ckl_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    base_path, ckl_path = Path(base_inp), Path(ckl_inp)
    out_path = Path(out)
    if not base_path.exists() or not ckl_path.exists():
        print("Both input paths must exist.")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = out_path.with_suffix(".xlsx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    base_rows = load_base_report(base_path)
    checklists = load_checklists(ckl_path)
    new_map = {}
    for ckl in checklists:
        for f in ckl["findings"]:
            key = (f.get("ruleId") or f.get("vulnId") or "", f.get("stigName", ""))
            new_map[key] = f
    headers = ["Rule ID", "Group ID", "STIG Name", "Title", "Old Severity", "New Severity", "Severity Changed", "Old Status", "New Status", "Status Changed"]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Report Analyzer"
    ws.append(headers)
    for row in base_rows:
        rule_id = norm_col(row, "rule id", "rule_id", "sv-")
        group_id = norm_col(row, "group id", "group_id", "vuln id", "vuln_id")
        stig_name = norm_col(row, "stig name", "stig_name", "stig")
        key = (rule_id or group_id, stig_name)
        new_f = new_map.get(key)
        old_sev = norm_col(row, "severity", "old severity")
        old_status = norm_col(row, "status", "old status")
        new_sev = (new_f.get("severity") or "") if new_f else ""
        new_status = (new_f.get("status") or "") if new_f else ""
        sev_changed = (old_sev or "").lower() != (new_sev or "").lower()
        status_changed = (old_status or "").lower() != (new_status or "").lower()
        title = (new_f.get("title") or norm_col(row, "title", "rule title")) if new_f else norm_col(row, "title", "rule title")
        ws.append([rule_id, group_id, stig_name, title, old_sev, new_sev, "Yes" if sev_changed else "No", old_status, new_status, "Yes" if status_changed else "No"])
    for i, w in enumerate([14, 14, 28, 40, 12, 12, 14, 14, 14, 14], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(out_path)
    print(f"Saved: {out_path} ({len(base_rows)} rows)")

if __name__ == "__main__":
    main()
`,
};

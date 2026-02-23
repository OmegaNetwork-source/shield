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
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF Reports ---")
    inp = input("Input file or folder path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\reports\\\\STIG_Report.xlsx): ").strip()
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if not out_path.suffix:
        out_path = out_path / "STIG_Report.xlsx"
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Parse CKL(s) from path (file or folder), build workbook, write sheets.
    wb = openpyxl.Workbook()
    wb.active.title = "Summary"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  Compare: `#!/usr/bin/env python3
"""
STRIX RMF Compare — Compare two checklists (base vs new) for status/compliance diffs.
Prompts: base file, new file, output path (.xlsx).
Output: Excel (.xlsx) with diff summary.
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF Compare ---")
    base_inp = input("Base checklist path (.ckl/.cklb): ").strip()
    new_inp = input("New checklist path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\output\\\\Compare_Result.xlsx): ").strip()
    if not base_inp or not new_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    base_path, new_path = Path(base_inp), Path(new_inp)
    out_path = Path(out)
    if not base_path.exists() or not new_path.exists():
        print("Both input files must exist.")
        sys.exit(1)
    if not out_path.suffix:
        out_path = out_path / "Compare_Result.xlsx"
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Parse both CKLs, diff by vulnId/ruleId, write Excel with status changes, new, removed.
    wb = openpyxl.Workbook()
    wb.active.title = "Comparison"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  "POA&M": `#!/usr/bin/env python3
"""
STRIX RMF POA&M — Generate or compare POA&M Excel (eMASS-style).
Prompts: mode (generate/compare), input file(s) or folder, output path (.xlsx).
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF POA&M ---")
    mode = input("Mode: (g)enerate from CKL(s) or (c)ompare two POA&M Excel files? [g/c]: ").strip().lower() or "g"
    if mode == "c":
        inp1 = input("Base POA&M Excel path: ").strip()
        inp2 = input("New POA&M Excel path: ").strip()
        inp = (inp1, inp2)
    else:
        inp = input("Input file or folder path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\poam\\\\POAM.xlsx): ").strip()
    if not out:
        print("Output path is required.")
        sys.exit(1)
    out_path = Path(out)
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Generate from CKL(s) or compare two Excel POA&M; write result.
    wb = openpyxl.Workbook()
    wb.active.title = "POA&M"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  Controls: `#!/usr/bin/env python3
"""
STRIX RMF Controls — Map findings (CCI) to NIST controls; output control summary.
Prompts: input checklist file, output path (.xlsx).
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF Controls ---")
    inp = input("Input checklist path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\output\\\\Controls.xlsx): ").strip()
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Parse CKL for CCIs, load cci2nist map, aggregate by control, write Excel.
    wb = openpyxl.Workbook()
    wb.active.title = "Controls"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  'STIG Analyzer': `#!/usr/bin/env python3
"""
STRIX RMF STIG Analyzer — Compare old vs new checklist (not reviewed, new IDs, dropped IDs, reviewed).
Prompts: old checklist, new checklist, output path (.xlsx).
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF STIG Analyzer ---")
    old_inp = input("Old checklist path (.ckl/.cklb): ").strip()
    new_inp = input("New checklist path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\output\\\\STIG_Analyzer.xlsx): ").strip()
    if not old_inp or not new_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    old_path, new_path = Path(old_inp), Path(new_inp)
    out_path = Path(out)
    if not old_path.exists() or not new_path.exists():
        print("Both input files must exist.")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Parse both CKLs, categorize Not Reviewed/New IDs/Dropped IDs/Reviewed, write Excel.
    wb = openpyxl.Workbook()
    wb.active.title = "STIG Analyzer"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  'Master Copy': `#!/usr/bin/env python3
"""
STRIX RMF Master Copy — Merge source checklist into target(s); write updated checklist(s).
Prompts: source checklist, target file or folder, output path (file or folder for .cklb).
Output: .cklb (or multiple .cklb in output folder)
"""
import sys
from pathlib import Path

def main():
    print("--- STRIX RMF Master Copy ---")
    src = input("Source checklist path (.ckl/.cklb): ").strip()
    tgt = input("Target checklist path or folder (.ckl/.cklb or folder): ").strip()
    out = input("Output path (file or folder for .cklb): ").strip()
    if not src or not tgt or not out:
        print("All three paths are required.")
        sys.exit(1)
    src_path, tgt_path, out_path = Path(src), Path(tgt), Path(out)
    if not src_path.exists():
        print(f"Not found: {src_path}")
        sys.exit(1)
    out_path.mkdir(parents=True, exist_ok=True)
    # TODO: Parse source CKL; get target file(s) from tgt_path (file or glob); merge; write .cklb to out_path.
    if out_path.is_dir() or not out_path.suffix:
        out_file = out_path / "MasterCopy.cklb" if out_path.is_dir() else out_path.parent / "MasterCopy.cklb"
    else:
        out_file = out_path
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("<?xml version=\\"1.0\\"?>\\n<CHECKLIST/>", encoding="utf-8")
    print(f"Saved: {out_file}")

if __name__ == "__main__":
    main()
`,

  Extractor: `#!/usr/bin/env python3
"""
STRIX RMF Extractor — Extract selected fields from CKL(s) (e.g. CAT I/II/III, Rule ID, Group ID).
Prompts: input file or folder, output path (.xlsx).
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF Extractor ---")
    inp = input("Input file or folder path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\output\\\\Extract.xlsx): ").strip()
    if not inp or not out:
        print("Both paths are required.")
        sys.exit(1)
    path = Path(inp)
    out_path = Path(out)
    if not path.exists():
        print(f"Not found: {path}")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Parse CKL(s), filter by cat1/cat2/cat3/rule-id/group-id, write Excel.
    wb = openpyxl.Workbook()
    wb.active.title = "Extract"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,

  'Report Analyzer': `#!/usr/bin/env python3
"""
STRIX RMF Report Analyzer — Compare base report to checklist(s); find severity/status changes.
Prompts: base report (CSV/Excel), checklist file or folder, output path (.xlsx).
Output: Excel (.xlsx)
"""
import sys
from pathlib import Path

try:
    import openpyxl
except ImportError:
    print("Install: pip install openpyxl")
    sys.exit(1)

def main():
    print("--- STRIX RMF Report Analyzer ---")
    base_inp = input("Base report path (.csv or .xlsx): ").strip()
    ckl_inp = input("Checklist file or folder path (.ckl/.cklb): ").strip()
    out = input("Output path (e.g. C:\\\\output\\\\Report_Analyzer.xlsx): ").strip()
    if not base_inp or not ckl_inp or not out:
        print("All three paths are required.")
        sys.exit(1)
    base_path, ckl_path = Path(base_inp), Path(ckl_inp)
    out_path = Path(out)
    if not base_path.exists() or not ckl_path.exists():
        print("Both input paths must exist.")
        sys.exit(1)
    if out_path.suffix.lower() != ".xlsx":
        out_path = Path(str(out_path) + ".xlsx" if not str(out_path).lower().endswith(".xlsx") else out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # TODO: Load base report; parse CKL(s); match by ruleId; compare severity/status; write Excel.
    wb = openpyxl.Workbook()
    wb.active.title = "Report Analyzer"
    wb.save(out_path)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
`,
};

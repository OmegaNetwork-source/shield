
export interface CciMapping {
    cci: string;
    rev4: string[];
    rev5: string[];
}

export interface CciMap {
    [cci: string]: CciMapping;
}

/**
 * Parses a STIG Viewer CSV export to extract CCI mappings.
 * Expected columns may vary but we look for "CCI", "Revision 4", "Revision 5" or data within the CCI column itself
 * based on the user description "Revision 4::" pattern inside fields.
 */
export function parseStigViewerCsv(content: string): CciMap {
    const lines = content.split(/\r?\n/);
    const mappings: CciMap = {};

    // Basic CSV parser that handles quoted fields
    const parseLine = (line: string): string[] => {
        const result: string[] = [];
        let current = '';
        let inQuotes = false;

        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                result.push(current.trim());
                current = '';
            } else {
                current += char;
            }
        }
        result.push(current.trim());
        return result;
    };

    // Find header index
    // We expect headers closely matching: "CCI", "Discussion", "Legacy", etc.
    // Based on user screenshot, the CCI column contains the Revision info:
    // "CCI-002421 ... NIST SP 800-53 Revision 4::SC-8 (1) NIST SP 800-53 Revision 5::SC-8 (1)"

    let headerIndex = -1;
    let cciColIndex = -1;

    for (let i = 0; i < Math.min(20, lines.length); i++) {
        const row = parseLine(lines[i]);
        const cciIdx = row.findIndex(c => c.toLowerCase() === 'cci' || c.toLowerCase().includes('cci'));
        if (cciIdx !== -1) {
            headerIndex = i;
            cciColIndex = cciIdx;
            break;
        }
    }

    if (headerIndex === -1 || cciColIndex === -1) {
        console.error("Could not find CCI column in CSV");
        return {};
    }

    // Process rows
    for (let i = headerIndex + 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        const row = parseLine(line);
        if (row.length <= cciColIndex) continue;

        const cciCell = row[cciColIndex];

        // Extract CCI ID: CCI-XXXXXX
        const cciMatch = cciCell.match(/(CCI-\d+)/);
        if (!cciMatch) continue;

        const cci = cciMatch[1];

        // Extract Rev 4
        // Pattern: "NIST SP 800-53 Revision 4::AC-2 (1)" or just "Revision 4::AC-2"
        // We'll look for "Revision 4::" and capture until newline or next "Revision" or similar delimiter
        const rev4: string[] = [];
        const rev4Matches = [...cciCell.matchAll(/Revision 4::\s*([A-Za-z0-9\-\(\)\s]+)/g)];
        rev4Matches.forEach(m => {
            // value might look like "SC-8 (1) NIST SP..." so we might need to clean it up if regex is greedy
            // The regex above stops at end of match which is safe-ish, but let's be more specific if needed
            // "Revision 4::SC-8 (1)\n" or space separated
            let ctrl = m[1].trim();
            // Heuristic cleanup: stop before "NIST" or "Revision" if matched accidentally
            const split = ctrl.split(/NIST|Revision/);
            if (split.length > 0) ctrl = split[0].trim();

            if (ctrl) rev4.push(ctrl);
        });

        // Extract Rev 5
        const rev5: string[] = [];
        const rev5Matches = [...cciCell.matchAll(/Revision 5::\s*([A-Za-z0-9\-\(\)\s]+)/g)];
        rev5Matches.forEach(m => {
            let ctrl = m[1].trim();
            const split = ctrl.split(/NIST|Revision/);
            if (split.length > 0) ctrl = split[0].trim();

            if (ctrl) rev5.push(ctrl);
        });

        mappings[cci] = {
            cci,
            rev4,
            rev5
        };
    }

    return mappings;
}

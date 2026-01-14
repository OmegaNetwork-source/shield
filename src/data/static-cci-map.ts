
// Static CCI to NIST Control Mapping
// In a full production build, this should be generated from DISA's U_CCI_List.xml

export interface CciMapping {
    cci: string;
    rev4: string[];
    rev5: string[];
}

// Sample Mapping Data (subset for demonstration)
const CCI_DATA: Record<string, { rev4: string[], rev5: string[] }> = {
    'CCI-000015': { rev4: ['AC-2 (1)'], rev5: ['AC-2 (1)'] },
    'CCI-000016': { rev4: ['AC-2 (2)'], rev5: ['AC-2 (2)'] },
    'CCI-000018': { rev4: ['AC-2 (4)'], rev5: ['AC-2 (4)'] },
    'CCI-000048': { rev4: ['AC-7 a'], rev5: ['AC-7 a'] },
    'CCI-000130': { rev4: ['AU-3', 'AU-3 (1)'], rev5: ['AU-3', 'AU-3 (1)'] },
    'CCI-000131': { rev4: ['AU-3'], rev5: ['AU-3'] },
    'CCI-000132': { rev4: ['AU-3'], rev5: ['AU-3'] },
    'CCI-000133': { rev4: ['AU-3'], rev5: ['AU-3'] },
    'CCI-000134': { rev4: ['AU-3'], rev5: ['AU-3'] },
    'CCI-000135': { rev4: ['AU-3 (1)'], rev5: ['AU-3 (1)'] },
    'CCI-000162': { rev4: ['AU-9'], rev5: ['AU-9'] },
    'CCI-000163': { rev4: ['AU-9'], rev5: ['AU-9'] },
    'CCI-000164': { rev4: ['AU-9'], rev5: ['AU-9'] },
    'CCI-000169': { rev4: ['AU-12 a'], rev5: ['AU-12 a'] }, // Audit Generation
    'CCI-000171': { rev4: ['AU-12 b'], rev5: ['AU-12 b'] },
    'CCI-000172': { rev4: ['AU-12 c'], rev5: ['AU-12 c'] },
    'CCI-000196': { rev4: ['IA-2 (1)'], rev5: ['IA-2 (1)'] }, // MFFA
    'CCI-000197': { rev4: ['IA-2 (2)'], rev5: ['IA-2 (2)'] },
    'CCI-000198': { rev4: ['IA-2 (3)'], rev5: ['IA-2 (3)'] },
    'CCI-000199': { rev4: ['IA-2 (4)'], rev5: ['IA-2 (4)'] },
    'CCI-000200': { rev4: ['IA-2 (5)'], rev5: ['IA-2 (5)'] },
    'CCI-000366': { rev4: ['CM-6 b'], rev5: ['CM-6 b'] }, // Configuration Settings
    'CCI-002235': { rev4: ['AC-6 (9)'], rev5: ['AC-6 (9)'] },
    // Common Windows CCIs
    'CCI-000381': { rev4: ['CM-7 b'], rev5: ['CM-7 b'] },
    'CCI-002314': { rev4: ['AC-17 (1)'], rev5: ['AC-17 (1)'] },
    'CCI-002322': { rev4: ['AC-17 (2)'], rev5: ['AC-17 (2)'] },
    // Add generic fallback for unknown CCIs to just show them as "Unmapped" or similar?
    // Start with this list.
};

export const ALL_CCIS = Object.keys(CCI_DATA);

export function getStaticCciMapping(cci: string): { rev4: string[], rev5: string[] } {
    if (CCI_DATA[cci]) {
        return CCI_DATA[cci];
    }
    // Fallback: If we don't have it, maybe return empty or a placeholder?
    // Returning empty array will mean it won't show up in the controls list unless we do something else.
    // However, the current logic iterates over MAPPED keys.
    // If we want to show ALL CCIs found in the uploaded checklist, we need to iterate differently.
    // But for now, let's stick to showing known mappings.
    return { rev4: [], rev5: [] };
}

// Helper to get ALL controls defined in our static map
export function getAllStaticMappings(): CciMapping[] {
    return Object.entries(CCI_DATA).map(([cci, maps]) => ({
        cci,
        ...maps
    }));
}

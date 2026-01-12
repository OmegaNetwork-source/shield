export const STIG_PATHS: Record<string, { name: string; path: string }> = {
    'win11': {
        name: 'Windows 11 STIG V2R5',
        path: 'Win 11/U_MS_Windows_11_V2R5_Manual_STIG/U_MS_Windows_11_STIG_V2R5_Manual-xccdf.xml'
    },
    'edge': {
        name: 'Microsoft Edge STIG V2R3',
        path: 'Edge/U_MS_Edge_V2R3_Manual_STIG/U_MS_Edge_V2R3_STIG_Manual-xccdf.xml'
    },
    'server2019': {
        name: 'Windows Server 2019 STIG V3R6',
        path: 'Windows Server/U_MS_Windows_Server_2019_V3R6_Manual_STIG/U_MS_Windows_Server_2019_STIG_V3R6_Manual-xccdf.xml'
    },
    'sql-db': {
        name: 'SQL Server 2022 Database STIG V1R1',
        path: 'SQL Server/U_MS_SQL_Server_2022_Database_V1R1_Manual_STIG/U_MS_SQL_Server_2022_Database_STIG_V1R1_Manual-xccdf.xml'
    },
    'sql-instance': {
        name: 'SQL Server 2022 Instance STIG V1R2',
        path: 'SQL Server/U_MS_SQL_Server_2022_Instance_V1R2_Manual_STIG/U_MS_SQL_Server_2022_Instance_STIG_V1R2_Manual-xccdf.xml'
    },
    'iis-server': {
        name: 'IIS 10.0 Server STIG V3R5',
        path: 'IIS/U_MS_IIS_10-0_Server_V3R5_Manual_STIG/U_MS_IIS_10-0_Server_STIG_V3R5_Manual-xccdf.xml'
    },
    'iis-site': {
        name: 'IIS 10.0 Site STIG V2R13',
        path: 'IIS/U_MS_IIS_10-0_Site_V2R13_Manual_STIG/U_MS_IIS_10-0_Site_STIG_V2R13_Manual-xccdf.xml'
    },
    'ad-domain': {
        name: 'Active Directory Domain STIG V3R5',
        path: 'AD Domain/U_Active_Directory_Domain_V3R5_Manual_STIG/U_Active_Directory_Domain_STIG_V3R5_Manual-xccdf.xml'
    },
    'ad-forest': {
        name: 'Active Directory Forest STIG V3R2',
        path: 'AD Forest/U_Active_Directory_Forest_V3R2_Manual_STIG/U_Active_Directory_Forest_STIG_V3R2_Manual-xccdf.xml'
    },
    'defender': {
        name: 'Defender Antivirus STIG V2R6',
        path: 'Defender/U_MS_Defender_Antivirus_V2R6_STIG_SCAP_1-3_Benchmark.xml'
    },
    'firewall': {
        name: 'Windows Firewall STIG V3R3',
        path: 'Firewall/U_Firewall_V3R3_Manual_SRG/U_Firewall_SRG_V3R3_Manual-xccdf.xml'
    }
};

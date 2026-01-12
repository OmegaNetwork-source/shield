// Windows 11 STIG V1R6 - Real Check Definitions
// Source: DISA STIG via stigaview.com

export interface StigRule {
    id: string;           // e.g. WN11-CC-000005
    vulnId: string;       // e.g. V-253350
    title: string;
    description: string;
    severity: 'high' | 'medium' | 'low';  // CAT I, II, III
    category: string;     // AU=Audit, CC=Config, SO=Security Options, etc.
    checkType: 'registry' | 'powershell' | 'auditpol' | 'secedit' | 'manual';
    check: {
        // For registry checks
        path?: string;
        valueName?: string;
        expectedValue?: string | number;
        operator?: 'eq' | 'neq' | 'gte' | 'lte' | 'exists' | 'notexists';
        // For PowerShell/auditpol checks
        command?: string;
        expectedOutput?: string;
    };
    fix?: string;
}

export const WINDOWS_11_STIG: StigRule[] = [
    // ============ COMPUTER CONFIGURATION (CC) ============
    {
        id: "WN11-CC-000005",
        vulnId: "V-253350",
        title: "Camera access from the lock screen must be disabled",
        description: "Disabling camera access from the lock screen prevents a passerby from hijacking the device camera.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
            valueName: "NoLockScreenCamera",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000007",
        vulnId: "V-253351",
        title: "Slide shows on the lock screen must be disabled",
        description: "Slide shows that are displayed on the lock screen can display unauthorized content.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
            valueName: "NoLockScreenSlideshow",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000010",
        vulnId: "V-253352",
        title: "IPv6 source routing must be configured to highest protection",
        description: "Configuring IPv6 source routing protects against spoofing.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
            valueName: "DisableIPSourceRouting",
            expectedValue: 2,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000020",
        vulnId: "V-253353",
        title: "IPv4 source routing must be configured to highest protection",
        description: "Configuring source routing protects against IP spoofing.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            valueName: "DisableIPSourceRouting",
            expectedValue: 2,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000025",
        vulnId: "V-253354",
        title: "ICMP redirects must not be allowed to override OSPF generated routes",
        description: "Allowing ICMP redirects could lead to traffic being sent to incorrect routes.",
        severity: "low",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
            valueName: "EnableICMPRedirect",
            expectedValue: 0,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000030",
        vulnId: "V-253355",
        title: "NetBIOS name release requests must be ignored",
        description: "Ignoring NetBIOS name release requests protects against denial of service attacks.",
        severity: "low",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters",
            valueName: "NoNameReleaseOnDemand",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000035",
        vulnId: "V-253356",
        title: "Insecure logons to an SMB server must be disabled",
        description: "Insecure guest logons allow unauthenticated access to shared folders.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation",
            valueName: "AllowInsecureGuestAuth",
            expectedValue: 0,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000044",
        vulnId: "V-253359",
        title: "Hardened UNC Paths must require mutual authentication",
        description: "Hardened paths ensure that network connections to critical paths are secured.",
        severity: "medium",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
            valueName: "\\\\*\\NETLOGON",
            expectedValue: "RequireMutualAuthentication=1, RequireIntegrity=1",
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000050",
        vulnId: "V-253360",
        title: "Autoplay must be turned off for non-volume devices",
        description: "Autoplay for non-volume devices could allow malicious code to run automatically.",
        severity: "high",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
            valueName: "NoAutoplayfornonVolume",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000052",
        vulnId: "V-253361",
        title: "Default Autorun behavior must be configured to prevent autorun commands",
        description: "Disabling default autorun prevents malicious code execution.",
        severity: "high",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            valueName: "NoAutorun",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-CC-000055",
        vulnId: "V-253362",
        title: "Autoplay must be disabled for all drives",
        description: "Disabling autoplay for all drives prevents malicious programs from running automatically.",
        severity: "high",
        category: "Computer Configuration",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            valueName: "NoDriveTypeAutoRun",
            expectedValue: 255,
            operator: "eq"
        }
    },

    // ============ SECURITY OPTIONS (SO) ============
    {
        id: "WN11-SO-000005",
        vulnId: "V-253432",
        title: "The built-in administrator account must be disabled",
        description: "The built-in Administrator account is a known target for attacks.",
        severity: "medium",
        category: "Security Options",
        checkType: "powershell",
        check: {
            command: "Get-LocalUser -SID *-500 | Select-Object -ExpandProperty Enabled",
            expectedOutput: "False"
        }
    },
    {
        id: "WN11-SO-000010",
        vulnId: "V-253433",
        title: "The built-in guest account must be disabled",
        description: "A system with an enabled guest account is susceptible to unauthorized access.",
        severity: "medium",
        category: "Security Options",
        checkType: "powershell",
        check: {
            command: "Get-LocalUser -SID *-501 | Select-Object -ExpandProperty Enabled",
            expectedOutput: "False"
        }
    },
    {
        id: "WN11-SO-000015",
        vulnId: "V-253434",
        title: "Local accounts with blank passwords must be restricted",
        description: "Local accounts with blank passwords are easily compromised.",
        severity: "high",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            valueName: "LimitBlankPasswordUse",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000020",
        vulnId: "V-253435",
        title: "Audit policy using subcategories must be enabled",
        description: "Subcategory auditing ensures that detailed events are captured.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            valueName: "SCENoApplyLegacyAuditPolicy",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000025",
        vulnId: "V-253436",
        title: "Outgoing secure channel traffic must be encrypted or signed",
        description: "Secure channel traffic must be encrypted to prevent eavesdropping.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
            valueName: "RequireSignOrSeal",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000030",
        vulnId: "V-253437",
        title: "Outgoing secure channel traffic must be encrypted when possible",
        description: "Encrypting secure channel traffic protects sensitive data.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
            valueName: "SealSecureChannel",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000035",
        vulnId: "V-253438",
        title: "Outgoing secure channel traffic must be signed when possible",
        description: "Signing secure channel traffic ensures data integrity.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
            valueName: "SignSecureChannel",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000050",
        vulnId: "V-253440",
        title: "Machine inactivity limit must be set to 15 minutes",
        description: "Limiting inactivity time reduces the risk of unauthorized access.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "InactivityTimeoutSecs",
            expectedValue: 900,
            operator: "lte"
        }
    },
    {
        id: "WN11-SO-000055",
        vulnId: "V-253441",
        title: "Legal notice must be displayed before login",
        description: "A legal notice warns unauthorized users of potential consequences.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "LegalNoticeText",
            operator: "exists"
        }
    },
    {
        id: "WN11-SO-000060",
        vulnId: "V-253442",
        title: "Legal notice title must be configured",
        description: "A title for the legal notice provides context to the warning.",
        severity: "low",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "LegalNoticeCaption",
            operator: "exists"
        }
    },
    {
        id: "WN11-SO-000070",
        vulnId: "V-253443",
        title: "Caching of logon credentials must be limited",
        description: "Limiting cached credentials reduces the risk if the system is compromised.",
        severity: "medium",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            valueName: "CachedLogonsCount",
            expectedValue: 10,
            operator: "lte"
        }
    },

    // ============ AUDIT POLICY (AU) ============
    {
        id: "WN11-AU-000054",
        vulnId: "V-253313",
        title: "Audit Account Lockout failures",
        description: "Account lockout failures must be audited to detect brute-force attacks.",
        severity: "medium",
        category: "Audit Policy",
        checkType: "auditpol",
        check: {
            command: "auditpol /get /subcategory:\"Account Lockout\" | Select-String 'Failure'",
            expectedOutput: "Failure"
        }
    },
    {
        id: "WN11-AU-000060",
        vulnId: "V-253314",
        title: "Audit Group Membership successes",
        description: "Group membership successes must be audited for accountability.",
        severity: "medium",
        category: "Audit Policy",
        checkType: "auditpol",
        check: {
            command: "auditpol /get /subcategory:\"Group Membership\" | Select-String 'Success'",
            expectedOutput: "Success"
        }
    },
    {
        id: "WN11-AU-000070",
        vulnId: "V-253316",
        title: "Audit Logon successes",
        description: "Successful logon events must be audited.",
        severity: "medium",
        category: "Audit Policy",
        checkType: "auditpol",
        check: {
            command: "auditpol /get /subcategory:\"Logon\" | Select-String 'Success'",
            expectedOutput: "Success"
        }
    },
    {
        id: "WN11-AU-000075",
        vulnId: "V-253317",
        title: "Audit Logon failures",
        description: "Failed logon events must be audited to detect attacks.",
        severity: "medium",
        category: "Audit Policy",
        checkType: "auditpol",
        check: {
            command: "auditpol /get /subcategory:\"Logon\" | Select-String 'Failure'",
            expectedOutput: "Failure"
        }
    },

    // ============ LSA / CREDENTIAL PROTECTION ============
    {
        id: "WN11-CC-000075",
        vulnId: "V-253366",
        title: "Credential Guard must be running on domain-joined systems",
        description: "Credential Guard protects credentials using virtualization-based security.",
        severity: "high",
        category: "Credential Protection",
        checkType: "powershell",
        check: {
            command: "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning -contains 1",
            expectedOutput: "True"
        }
    },
    {
        id: "WN11-SO-000100",
        vulnId: "V-253447",
        title: "LSA Protection must be enabled",
        description: "LSA Protection prevents credential dumping attacks like mimikatz.",
        severity: "high",
        category: "Security Options",
        checkType: "registry",
        check: {
            path: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            valueName: "RunAsPPL",
            expectedValue: 1,
            operator: "eq"
        }
    },

    // ============ WINDOWS DEFENDER / ANTIMALWARE ============
    {
        id: "WN11-EP-000310",
        vulnId: "V-253409",
        title: "Data Execution Prevention must be enabled",
        description: "DEP prevents code from running in non-executable memory regions.",
        severity: "high",
        category: "Exploit Protection",
        checkType: "powershell",
        check: {
            command: "(Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy",
            expectedOutput: "2"  // 2 = OptOut (enabled for all except specific apps)
        }
    },

    // ============ REMOTE DESKTOP ============
    {
        id: "WN11-CC-000290",
        vulnId: "V-253398",
        title: "Remote Desktop idle session time limit",
        description: "Remote Desktop sessions must disconnect after an idle timeout.",
        severity: "medium",
        category: "Remote Desktop",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            valueName: "MaxIdleTime",
            expectedValue: 900000, // 15 minutes in ms
            operator: "lte"
        }
    },
    {
        id: "WN11-CC-000295",
        vulnId: "V-253399",
        title: "Remote Desktop session time limit",
        description: "Remote Desktop sessions must be limited to prevent unauthorized access.",
        severity: "medium",
        category: "Remote Desktop",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            valueName: "MaxDisconnectionTime",
            expectedValue: 60000, // 1 minute in ms
            operator: "lte"
        }
    },
    {
        id: "WN11-CC-000300",
        vulnId: "V-253400",
        title: "Remote Desktop client connection encryption level",
        description: "Remote Desktop connections must be encrypted at High level.",
        severity: "medium",
        category: "Remote Desktop",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
            valueName: "MinEncryptionLevel",
            expectedValue: 3,  // 3 = High
            operator: "eq"
        }
    },

    // ============ UAC ============
    {
        id: "WN11-SO-000250",
        vulnId: "V-253462",
        title: "UAC must run all administrators in Admin Approval Mode",
        description: "Admin Approval Mode requires elevation for administrative tasks.",
        severity: "medium",
        category: "User Account Control",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "EnableLUA",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000255",
        vulnId: "V-253463",
        title: "UAC must elevate only signed executables",
        description: "Only signed executables should be elevated to prevent malware execution.",
        severity: "medium",
        category: "User Account Control",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "ValidateAdminCodeSignatures",
            expectedValue: 1,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000260",
        vulnId: "V-253464",
        title: "UIAccess applications must not be elevated without secure desktop",
        description: "UIAccess integrity must be enforced for elevated applications.",
        severity: "medium",
        category: "User Account Control",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "EnableUIADesktopToggle",
            expectedValue: 0,
            operator: "eq"
        }
    },
    {
        id: "WN11-SO-000265",
        vulnId: "V-253465",
        title: "Admin Approval Mode for built-in Administrator",
        description: "The built-in Administrator must run in Admin Approval Mode.",
        severity: "medium",
        category: "User Account Control",
        checkType: "registry",
        check: {
            path: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            valueName: "FilterAdministratorToken",
            expectedValue: 1,
            operator: "eq"
        }
    }
];

// Group by category for UI
export function getCategories(): string[] {
    const cats = new Set(WINDOWS_11_STIG.map(r => r.category));
    return Array.from(cats);
}

// Get count by severity
export function getSeverityCount(sev: 'high' | 'medium' | 'low'): number {
    return WINDOWS_11_STIG.filter(r => r.severity === sev).length;
}

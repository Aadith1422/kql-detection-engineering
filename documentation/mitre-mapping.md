# MITRE ATT&CK Mapping

This project contains four KQL detections mapped to MITRE ATT&CK techniques.

| Detection | MITRE ATT&CK | Data Source |
|---|---|---|
| Sensitive File Web Reconnaissance | T1595 - Active Scanning | AppRequests |
| LSASS Credential Dumping | T1003.001 - LSASS Memory | Sysmon Event ID 1 |
| Registry Persistence | T1547.001 - Registry Run Keys / Startup Folder | Sysmon Event ID 13 |
| Windows Brute Force | T1110 - Brute Force | Windows Event ID 4625 |

## Detection Coverage

### T1595 - Active Scanning

Detects repeated requests for sensitive configuration and administrative files that may indicate web reconnaissance or automated scanning.

### T1003.001 - LSASS Memory

Detects process creation activity containing the `comsvcs.dll` and `MiniDump` pattern associated with potential LSASS memory dumping.

### T1547.001 - Registry Run Keys / Startup Folder

Detects modifications to common Windows Registry Run and RunOnce locations that may be used for persistence.

### T1110 - Brute Force

Detects repeated failed Windows logon attempts for the same user within a defined time window.


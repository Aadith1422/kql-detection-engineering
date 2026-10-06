# MITRE ATT&CK Mapping

This project contains four KQL detections mapped to MITRE ATT&CK techniques.

| Detection | MITRE ATT&CK | Data Source |
|---|---|---|
| Sensitive File Web Reconnaissance | T1595.003 - Active Scanning: Wordlist Scanning | AppRequests |
| LSASS Credential Dumping | T1003.001 - OS Credential Dumping: LSASS Memory | Sysmon Event ID 1 |
| Registry Persistence | T1547.001 - Registry Run Keys / Startup Folder | Sysmon Event ID 13 |
| Windows Brute Force | T1110 - Brute Force | Windows Security Event ID 4625 |
| Windows Password Spray (Query B) | T1110.003 - Password Spraying | Windows Security Event ID 4625 |

## Detection Coverage

### T1595.003 - Wordlist Scanning

Detects repeated requests for many known sensitive configuration and
administrative paths, which suggests automated scanning with a wordlist.

### T1003.001 - LSASS Memory

Detects `rundll32.exe` calling the `comsvcs.dll` MiniDump export (by name or
ordinal), a common way to dump LSASS memory.

### T1547.001 - Registry Run Keys / Startup Folder

Detects values written under `CurrentVersion\Run` and `RunOnce`, and flags
those that point to user-writable folders.

### T1110 - Brute Force

Detects 5 or more failed logons for one account from one source within
10 minutes.

### T1110.003 - Password Spraying

Detects one source failing against 5 or more distinct accounts within
30 minutes.

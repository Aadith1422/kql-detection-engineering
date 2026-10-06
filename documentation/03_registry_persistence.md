# Detection 03 - Registry Run Keys Persistence

## Objective

Detect values written to the Windows `Run` and `RunOnce` registry keys, which
attackers use to make a program start automatically at logon.

## Data Source

Sysmon Event ID 13 - Registry Value Set (table: `SysmonRegistryEvents`)

| Field | Meaning |
|---|---|
| `TargetObject` | Full registry path of the value that was written |
| `Details` | The data written, usually the program that will run |
| `Image` | The process that made the change |

## MITRE ATT&CK

**T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**

## Detection Logic

1. Keep Event ID 13 events.
2. Keep events where `TargetObject` ends in `\CurrentVersion\Run\<value>` or
   `\CurrentVersion\RunOnce\<value>`.
3. Add `SuspiciousPath = true` when `Details` points to a folder that attackers
   commonly use because ordinary users can write to it: `\Users\Public\`,
   `\ProgramData\`, `\Temp\`, `\AppData\Roaming\`.
4. Show suspicious-path events first.

## Threshold

Any matching write generates a result. `SuspiciousPath` is used for triage.

## Validation

Test data: `test-data/SysmonRegistryEvents.csv` (7 events, simulated).

| Result | Count | Events |
|---|---|---|
| Returned by the query | 5 | 3 malicious-style, 2 legitimate |
| `SuspiciousPath = true` | 3 | `reg.exe` and PowerShell writing programs in `C:\Users\Public` and `C:\ProgramData` |
| Legitimate Run key writes | 2 | OneDrive (HKCU Run) and SecurityHealth (HKLM Run) |
| Correctly ignored | 2 | `ExampleApp` setting and `Explorer\RecentDocs` |

## False Positives

- OneDrive, Teams, security agents and updaters write Run keys legitimately.
- Software installers and deployment tools.
- Administrators configuring startup programs.

Tuning: allow-list known `Image` + `TargetObject` pairs after a baseline period.

## Investigation

1. Which process wrote the value (`Image`) and what started it (parent process)?
2. What does `Details` point to? Does the file exist, and is it signed?
3. Which user and host?
4. Was the file recently created or downloaded?
5. Is the same value present on other hosts?

## Response

If malicious:

1. Isolate the host if the program is confirmed malicious.
2. Remove the registry value and quarantine the referenced file.
3. Look for other persistence (scheduled tasks, services, Startup folder).
4. Review what the user and process did before the write.
5. Reset credentials if credential theft is suspected.

## Limitations

- Covers only the `Run` and `RunOnce` keys, not other persistence methods.
- Needs a Sysmon configuration that logs Event ID 13 for these keys.
- Attackers can use other autostart locations or write the value without using the
  registry-set API Sysmon watches.

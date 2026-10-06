# Detection 02 - LSASS Credential Dumping

## Objective

Detect processes that may attempt to dump LSASS memory
using the comsvcs.dll MiniDump technique.

## Data Source

Sysmon Event ID 1 - Process Creation

## MITRE ATT&CK

T1003.001 - LSASS Memory

## Detection Logic

The detection looks for process creation events where the
command line contains both comsvcs.dll and MiniDump.

The combination may indicate an attempt to create a memory
dump of a process such as LSASS.

## Detection Pattern

- comsvcs.dll
- MiniDump
- rundll32.exe

## Threshold

Any matching process creation event generates a detection.

## Validation

The detection produced 3 matching events in the simulated
Sysmon dataset.

The detected events used:

- rundll32.exe
- comsvcs.dll
- MiniDump

Parent processes included:

- cmd.exe
- PowerShell

## False Positive Considerations

Potential benign sources include:

- Authorized security testing
- Incident response
- Debugging
- Administrative troubleshooting

## Investigation

When an alert fires, investigate:

1. Process image
2. Command line
3. Parent process
4. User identity
5. Process ID
6. Dump file path, if available
7. Whether the activity was authorized

## Response

If malicious activity is confirmed:

1. Isolate the affected endpoint.
2. Investigate for credential theft.
3. Check for additional suspicious processes.
4. Review for lateral movement.
5. Reset potentially compromised credentials.
6. Investigate related persistence or execution activity.

## Validation Note

The detection was validated using simulated Sysmon telemetry
because a Windows endpoint was not available during the lab.

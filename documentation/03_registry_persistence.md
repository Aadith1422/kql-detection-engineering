# Detection 03 - Registry Run Keys Persistence

## Objective

Detect modifications to Windows Registry locations that may
be used to establish persistence.

## Data Source

Sysmon Event ID 13 - Registry Value Set

## MITRE ATT&CK

T1547.001 - Registry Run Keys / Startup Folder

## Detection Logic

The detection looks for Registry modifications involving
common Run and RunOnce locations.

The events are filtered for:

- CurrentVersion\Run
- CurrentVersion\RunOnce

## Persistence Locations

- CurrentVersion\Run
- CurrentVersion\RunOnce

## Threshold

Any matching Registry modification generates a detection.

## Validation

The detection produced 3 matching events in the simulated
Sysmon dataset.

The detected events modified:

- CurrentVersion\Run
- CurrentVersion\RunOnce

A benign Registry modification outside these locations was
not returned by the detection.

## False Positive Considerations

Potential benign sources include:

- Software installation
- Application updates
- Enterprise software deployment
- Administrative configuration
- Authorized system maintenance

## Investigation

When an alert fires, investigate:

1. Registry path
2. Registry value
3. Executable path
4. User identity
5. Parent process
6. Process command line
7. Whether the referenced executable is legitimate

## Response

If malicious activity is confirmed:

1. Identify the persistence mechanism.
2. Remove or disable the malicious Registry entry.
3. Investigate the referenced executable.
4. Check for additional persistence mechanisms.
5. Review the endpoint for related malicious activity.

## Validation Note

The detection was validated using simulated Sysmon Event ID 13
telemetry because a Windows endpoint was not available during
the lab.

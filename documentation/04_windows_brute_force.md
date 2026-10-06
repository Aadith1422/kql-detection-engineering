# Detection 04 - Windows Brute Force

## Objective

Detect repeated failed Windows logon attempts that may
indicate brute-force activity.

## Data Source

Windows Event ID 4625 - Failed Logon

## MITRE ATT&CK

T1110 - Brute Force

## Detection Logic

The detection counts failed logon events for each user.

The events are grouped into 10-minute windows.

An alert is generated when 3 or more failed logons occur
for the same user within the same window.

## Threshold

3 or more failed logons within 10 minutes.

This threshold is an initial baseline for the simulated
lab dataset and should be tuned against normal authentication
activity in a production environment.

## Validation

The detection produced 1 matching time window in the
simulated dataset.

The detected window contained:

- User: CORP\Administrator
- 4 failed logons

A single failed logon for CORP\Aadith was not detected
because it did not reach the threshold.

## False Positive Considerations

Potential benign sources include:

- Users entering incorrect passwords
- Expired credentials
- Service account configuration problems
- Scheduled tasks using old credentials
- Administrative troubleshooting

## Investigation

When an alert fires, investigate:

1. Username
2. Number of failed attempts
3. Time window
4. Source information, if available
5. Successful logons following the failures
6. Whether the account activity is expected

## Response

If brute-force activity is confirmed:

1. Identify the source.
2. Check whether the account was successfully compromised.
3. Investigate successful authentication events.
4. Block or restrict the source where appropriate.
5. Reset compromised credentials.
6. Review the account and endpoint for further activity.

## Validation Note

The detection was validated using simulated Event ID 4625
telemetry because a Windows endpoint was not available during
the lab.

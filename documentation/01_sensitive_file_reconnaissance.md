# Detection 01 - Sensitive File Web Reconnaissance

## Objective

Detect repeated HTTP requests for sensitive configuration,
environment, and administrative files that may indicate web
reconnaissance or automated scanning.

## Data Source

AppRequests

## MITRE ATT&CK

T1595 - Active Scanning

## Detection Logic

The detection looks for HTTP 404 responses targeting sensitive
file and administrative paths.

The events are grouped into 10-minute windows.

An alert is generated when 3 or more matching probes occur
within the same window.

## Sensitive Targets

- .env
- .git/config
- wp-config
- web.config
- config.php
- phpinfo
- server-status

## Threshold

3 or more probes within 10 minutes.

This threshold is an initial baseline derived from the Microsoft
Log Analytics demo environment and should be tuned against
production traffic.

## Validation

The detection produced 6 matching time windows in the observed
demo dataset.

The highest observed window contained:

- 59 probes
- 59 unique targets

## False Positive Considerations

Potential benign sources include:

- Security scanners
- Vulnerability assessment tools
- Automated monitoring
- Application testing
- Authorized penetration testing

## Investigation

When an alert fires, investigate:

1. Requested URLs
2. Number of unique targets
3. Time window
4. Client IP, if reliable in the environment
5. User identity, if available
6. User agent
7. Whether the requested files exist
8. Whether successful responses followed the reconnaissance

## Response

If malicious activity is confirmed:

1. Identify the source.
2. Determine whether sensitive files were successfully accessed.
3. Check for additional reconnaissance or exploitation.
4. Block or contain the source where appropriate.
5. Investigate related application logs.

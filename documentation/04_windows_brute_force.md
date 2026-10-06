# Detection 04 - Windows Brute Force and Password Spray

## Objective

Detect repeated failed Windows logons that suggest an attacker is guessing
passwords, either against one account (brute force) or across many accounts
(password spray).

## Data Source

Windows Security Event ID 4625 - An account failed to log on
(table: `SecurityEvent`, same column names as the Microsoft Sentinel table).

Event 4625 comes from the Windows **Security** log. Sysmon does not generate it.

| Field | Meaning |
|---|---|
| `TargetUserName` | Account that was attacked |
| `IpAddress` | Source of the attempt |
| `LogonType` | 2 interactive, 3 network, 10 remote interactive (RDP) |
| `SubStatus` | Failure reason, e.g. `0xC000006A` wrong password |

## MITRE ATT&CK

- **T1110 - Brute Force** (Query A)
- **T1110.003 - Brute Force: Password Spraying** (Query B)

## Detection Logic

**Query A - Brute force.** Count failures per account, source IP and host in
10-minute windows. Alert at 5 or more.

**Query B - Password spray.** Count distinct accounts failed per source IP in
30-minute windows. Alert at 5 or more distinct accounts and 5 or more attempts.

## Thresholds

| Query | Threshold | Reason |
|---|---|---|
| A | 5 failures / 10 min / account / source | Above normal mistyped passwords |
| B | 5 distinct accounts / 30 min / source | Spray tries few passwords across many accounts, so Query A misses it |

These are starting values for the simulated data and must be tuned in a real
environment.

## Validation

Test data: `test-data/WindowsSecurityEvents.csv` (simulated).

| Scenario | Source | Query A | Query B |
|---|---|---|---|
| 6 failures against `Administrator` in 6 minutes | 10.10.5.23 | **Alert** (6 failures) | No (1 account) |
| 8 failures across 6 accounts in 12 minutes | 10.10.5.77 | No (1-2 per account) | **Alert** (6 accounts) |
| 2 failures then a success for `jsmith` | 10.10.2.14 | No | No |
| 1 failure for `mlee` | 10.10.2.31 | No | No |

This shows why both queries are needed.

## False Positives

- Users mistyping passwords, or returning after a password change.
- Service accounts with expired or outdated passwords.
- Shared NAT or VPN addresses that group many users under one IP (Query B).
- Vulnerability scanners and authorized testing.

## Investigation

1. Source IP: internal or external, known or new? Check reputation.
2. Which accounts were targeted? Privileged or service accounts?
3. Failure reasons: wrong password (`0xC000006A`) vs unknown user (`0xC0000064`).
4. Was there a successful logon (4624) from the same source after the failures?
5. Logon type: network or RDP exposed to the internet?

## Response

1. Block or rate-limit the source IP.
2. If a success followed the failures, treat the account as compromised: reset
   credentials, revoke sessions, review account activity.
3. Enforce MFA and lockout policy on targeted accounts.
4. Check other hosts and accounts for the same source.

## Limitations

- Fixed time windows can split an attack that straddles a boundary.
- Does not yet correlate with successful logons (4624).
- Slow "low and slow" attacks over many hours stay under these thresholds.

# How to Reproduce

All results use simulated telemetry in a free Azure Data Explorer cluster
(dataexplorer.azure.com, Microsoft account only).

## 1. Create the tables

Run each command in the query window of your `SecurityLab` database.

```kql
.create table SysmonRegistryEvents (TimeCreated:datetime, EventID:int, Computer:string, User:string, ProcessId:int, Image:string, EventType:string, TargetObject:string, Details:string)

.create table SecurityEvent (TimeGenerated:datetime, EventID:int, Computer:string, TargetUserName:string, TargetDomainName:string, LogonType:int, IpAddress:string, Status:string, SubStatus:string)
```

## 2. Load the test data

For each table: right-click the table, choose **Get data**, then **Local file**.
Select the matching CSV and enable **Ignore the first record**.

| Table | File |
|---|---|
| `SysmonRegistryEvents` | `test-data/SysmonRegistryEvents.csv` |
| `SecurityEvent` | `test-data/WindowsSecurityEvents.csv` |

Detections 01 and 02 use the existing data, as described in their own docs.

## 3. Run and check

Open the matching file in `detections/` and run it. Compare the output with the
Validation table in the matching `documentation/` file.

# WinFoton v1.0.0

Windows DFIR triage collector. Photons penetrate glass; WinFoton penetrates Windows.

Collects host state into a categorized, hashed, zipped evidence package with an
analyst-facing HTML overview.

## Quick start

```powershell
# Elevated PowerShell (Windows PowerShell 5.1 or PS7 on Windows)
Set-ExecutionPolicy -Scope Process Bypass -Force
.\WinFoton.ps1
```

Typical engagement run:

```powershell
.\WinFoton.ps1 -CaseNumber "JDI-2026-0142" -Examiner "J. Flynn" `
               -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
```

Fast triage on a slow or low-disk box:

```powershell
.\WinFoton.ps1 -SkipEvtxExport -SkipHashing -EventLogDays 7
```



## Parameters


| Parameter              | Default      | Notes                                                              |
| ---------------------- | ------------ | ------------------------------------------------------------------ |
| `-OutputPath`          | Desktop      | Where the case folder and ZIP land                                 |
| `-CaseNumber`          | (empty)      | Written into the chain-of-custody header                           |
| `-Examiner`            | current user | Written into the chain-of-custody header                           |
| `-EventLogDays`        | 14           | Event log and file-modification window                             |
| `-MaxEventsPerLog`     | 3000         | Caps parsed events per query                                       |
| `-SkipEvtxExport`      | off          | Skip raw .evtx export (parsed CSVs still collected)                |
| `-SkipHashing`         | off          | Skip SHA-256 of process/file images — much faster, far less useful |
| `-LoadUserHives`       | off          | Mount NTUSER.DAT for users not logged on (registry write, logged)  |
| `-IncludeFileTimeline` | off          | Deeper filesystem sweep of user-writable paths                     |
| `-NoZip`               | off          | Leave the case folder uncompressed                                 |




## Output structure

```
WinFoton_<HOST>_<UTCSTAMP>Z/
  WinFoton_Report.html          <- open this from inside the extracted folder
  00_Collection/                chain_of_custody.txt, collection.log, manifest,
                                findings.csv, hashes.csv, hashes.txt, errors
  01_System/                    OS, firmware, TPM/BitLocker, time sync, disks, VSS
  02_Users_and_Access/          accounts, groups, sessions, secpol, RDP, credentials
  03_Processes_and_Volatile/    processes w/ hash+signature, tree, modules, PS history
  04_Network/                   connections, listeners, DNS, hosts, firewall, shares
  05_Persistence/               autoruns, tasks, services, WMI subs, IFEO, COM, BITS
  06_Security_Posture/          Defender status/exclusions, hardening keys, audit policy
  07_Event_Logs/                parsed CSVs by intent + time-filtered .evtx exports
  08_Filesystem/                user-writable executables, prefetch, ADS, USB, recycle
  09_Software_and_Drivers/      installed software, drivers, browser extensions, RAT check
WinFoton_<HOST>_<UTCSTAMP>Z.zip
WinFoton_<HOST>_<UTCSTAMP>Z_PACKAGE_HASH.txt
```



## Notes on evidentiary handling

- This is **live collection**. It alters the host (process creation, prefetch,
file writes, event log entries). Capture memory/disk first if either is needed.
- Collection order follows volatility: processes and network state first.
- Every artifact is SHA-256 hashed after collection (`00_Collection/hashes.csv`),
and the ZIP itself is hashed into `*_PACKAGE_HASH.txt`. Verify on receipt and at
each custody transfer.
- Findings in the report are **automated observations**, tiered by evidentiary
strength (Tier 1 observed artifact, Tier 2 supported inference). Each cites its
source artifact. Expect false positives — the pattern lists match legitimate
admin tooling as readily as attacker tooling.
- Collection failures are recorded rather than silently dropped
(`collection_errors.csv` and the report's error table) so gaps can be disclosed.



## Adding your own detections

Heuristics live in `Invoke-FindingsAnalysis`. Each one reads a cached artifact from
`$Script:Data['<task_name>']` and calls `Add-Finding` with severity, tier,
observation, why-it-matters, and artifact path. Pattern lists for command-line and
path heuristics are `$Script:SuspiciousCommandPatterns` and
`$Script:UserWritablePatterns` near the top of the file.

Adding a new collection task is one `Invoke-Collection` call inside the relevant
section function — it handles output writing, timing, manifest entry, error capture,
and caching automatically.
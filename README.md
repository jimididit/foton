# Foton

Windows DFIR, baseline comparison, and security-audit toolkit.

Foton captures host state into a hashed case **package**, then lets you compare baselines over time, run heuristics, and (later) parse artifacts — without turning a 3,000-line script into the only extension point.

**v1.0.0 live triage** still runs from the frozen reference script `WinFoton.ps1` (same behavior, historical filename). The **Foton** module (`Foton.psd1`) is the modular product; Collect will ship as `dist/Foton-Collect.ps1` once extracted.

Photons penetrate glass; Foton is meant to make Windows state legible — not to declare compromise.

## Quick start (v1 collector)

```powershell
# Windows PowerShell 5.1 or PS7 on Windows. Elevation is optional (see coverage below).
Set-ExecutionPolicy -Scope Process Bypass -Force
.\WinFoton.ps1
```

Typical **elevated** engagement:

```powershell
.\WinFoton.ps1 -CaseNumber "JDI-2026-0142" -Examiner "J. Flynn" `
               -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
```

**Work PC / no admin** (default — collects what this user can read):

```powershell
.\WinFoton.ps1 -CaseNumber "SELF-AUDIT" -OutputPath $env:USERPROFILE\Desktop
```

Refuse to run unless elevated (incident response that must include the Security log):

```powershell
.\WinFoton.ps1 -RequireAdministrator
```

Fast triage on a slow or low-disk box:

```powershell
.\WinFoton.ps1 -SkipEvtxExport -SkipHashing -EventLogDays 7
```

Open `WinFoton_Report.html` **from inside the extracted case folder** so artifact links resolve.

### Module scaffold (no collection yet)

```powershell
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
```

## Requirements

- Windows only (`WinFoton.ps1` will refuse non-Windows).
- PowerShell 5.1+ (or PowerShell 7 on Windows). No extra modules on the endpoint.
- **Administrator recommended for full coverage**, not required. Without elevation, Foton (via `WinFoton.ps1`) uses a **StandardUser** coverage profile: current-user processes, readable network state, HKCU persistence, that user's profile artifacts, and any event logs the token can read. It skips Security log, Prefetch, VSS, auditpol/secedit, and other users' files (manifest `SkippedNotElevated`, `00_Collection/collection_coverage.json`). That is a visibility gap, not a clean host. Use `-RequireAdministrator` when a thin package is unacceptable.
- Default `-OutputPath` is the **current user's Desktop**. When elevated, that is often the Administrator profile desktop.

## Parameters

| Parameter              | Default      | Notes |
| ---------------------- | ------------ | ----- |
| `-OutputPath`          | Desktop      | Case folder and ZIP land here |
| `-CaseNumber`          | (empty)      | Chain-of-custody header |
| `-Examiner`            | current user | Chain-of-custody header |
| `-EventLogDays`        | 14           | Event log **and** recently-modified system file window |
| `-MaxEventsPerLog`     | 3000         | Caps parsed events per query |
| `-SkipEvtxExport`      | off          | Skip raw `.evtx` export (parsed CSVs still collected) |
| `-SkipHashing`         | off          | Skip SHA-256 of **process/file images** via `Get-SafeHash`. The case folder is still hashed into `00_Collection/hashes.csv` |
| `-LoadUserHives`       | off          | Mount NTUSER.DAT for users not logged on (registry write, logged) |
| `-IncludeFileTimeline` | off          | Deeper recurse (depth 6 vs 3) of user-writable executable sweep — not a MACB timeline |
| `-NoZip`               | off          | Leave the case folder uncompressed |
| `-RequireAdministrator`| off          | Exit if not elevated. Default is StandardUser coverage |

## Output structure

```
WinFoton_<HOST>_<UTCSTAMP>Z/          # v1 folder prefix (Foton-Collect will use Foton_)
  WinFoton_Report.html
  00_Collection/                      chain_of_custody.txt, collection.log, collection_manifest.csv,
                                      hashes.csv, hashes.txt, collection_coverage.json;
                                      findings.csv and collection_errors.csv only if non-empty
  01_System/                          OS, firmware, TPM/BitLocker, time sync, disks, VSS
  02_Users_and_Access/                accounts, groups, sessions, secpol, RDP, credentials
  03_Processes_and_Volatile/          processes w/ hash+signature, tree, modules, PS history
  04_Network/                         connections, listeners, DNS, hosts, firewall, shares
  05_Persistence/                     autoruns, tasks, services, WMI subs, IFEO, COM, BITS
  06_Security_Posture/                Defender, hardening keys, audit policy, roots, AppLocker
  07_Event_Logs/                      parsed CSVs by intent + optional time-filtered .evtx
  08_Filesystem/                      user-writable executables, prefetch listing, ADS, USB, recycle, LNKs
  09_Software_and_Drivers/            software, drivers, browser extensions, RAT *name* presence, AppX
WinFoton_<HOST>_<UTCSTAMP>Z.zip
WinFoton_<HOST>_<UTCSTAMP>Z_PACKAGE_HASH.txt
```

See `00_Collection/collection_manifest.csv` for the full artifact list. `WinFoton-sample-report.html` is a v1 sample (historical branding).

## Evidentiary handling

- This is **live collection**. It alters the host (process creation, prefetch, file writes, event log entries). Capture memory/disk first if either is needed.
- Collection order follows volatility: processes and network state first.
- Every artifact file is SHA-256 hashed after collection (`hashes.csv`). The ZIP is hashed into `*_PACKAGE_HASH.txt`. Verify on receipt and at each custody transfer.
- Findings are **automated observations**, tiered (Tier 1 observed artifact, Tier 2 supported inference). Each cites its source artifact. Pattern lists match legitimate admin tooling as readily as attacker tooling. **An empty findings list is not a clean host.**
- Collection failures are recorded (`collection_errors.csv` when any exist, plus the report error table). Gaps must be disclosed.

## Extending Foton

Do not add detections by editing `WinFoton.ps1` going forward. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md): new collectors, baseline providers, parsers, and rules are new files under `src/`.

Until Analyze is extracted, v1 heuristics still live in `Invoke-FindingsAnalysis` inside `WinFoton.ps1` (`$Script:Data`, `Add-Finding`, pattern arrays at the top of that file).

## Docs

| Doc | For |
|-----|-----|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, package, naming |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to add a module/feature |
| [docs/MIGRATION.md](docs/MIGRATION.md) | Extract plan from the frozen v1 script |
| [docs/LAB.md](docs/LAB.md) | Host Cursor vs VMware guest (Defender, collect) |
| [AGENTS.md](AGENTS.md) | Invariants for human and AI contributors |

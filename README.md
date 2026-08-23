# Foton

Windows DFIR, baseline comparison, and security-audit toolkit.

Foton captures host state into a hashed **package**, then you parse, compare baselines, and analyze **offline**. Findings are observations, not a verdict.

**Module 1.24.0** - collect schema **1.8.0**, baseline schema **1.13.0**. Operator path: [docs/USAGE.md](docs/USAGE.md).

## What to run

| Machine | File | Result |
|---------|------|--------|
| **Endpoint** (no install) | `dist/Foton-Collect_v1.24.0_schema1.8.0.ps1` (alias `Foton-Collect.ps1`) | Case folder `Foton_<HOST>_<UTC>Z/`, `Foton_Report.html`, ZIP + `*_PACKAGE_HASH.txt` |
| **Endpoint** | `dist/Foton-Baseline_v1.24.0_schema1.13.0.ps1` (alias `Foton-Baseline.ps1`) | `FotonBaseline_<HOST>_<UTC>Z/`, `Foton_Baseline.html`, ZIP + hash |
| **Workstation** (this repo) | `Foton.cmd` or `Import-Module .\Foton.psd1` | Full command list: [docs/USAGE.md](docs/USAGE.md) |

Rebuild flatten scripts after Collect/Baseline source changes:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

Copy **only** the generated `.ps1` to the target. Do not deploy the module tree. Default `-OutputPath` is the current user’s Desktop.

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect.ps1
powershell -ExecutionPolicy Bypass -File .\Foton-Baseline.ps1
```

Typical elevated collect:

```powershell
.\Foton-Collect.ps1 -CaseNumber "CASE-0001" -Examiner "A. Examiner" `
    -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
```

Standard user (thin package; Security log / Prefetch copies / other users skipped):

```powershell
.\Foton-Collect.ps1 -CaseNumber "SELF-AUDIT"
```

Fail if not admin: `-RequireAdministrator`. Fast/low disk: `-SkipEvtxExport -SkipHashing -EventLogDays 7`.

Open **`Foton_Report.html` from inside the case folder** so links resolve.

### Workstation (offline)

```
Foton.cmd analyze  D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd parse    D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd compare  D:\Baselines\day0.json D:\Baselines\day1.json
Foton.cmd ioc      D:\Cases\Foton_...Z D:\intel\iocs.txt
Foton.cmd carve    D:\blob.bin
Foton.cmd help
```

Or `Import-Module .\Foton.psd1 -Force`. **Every public command** (purpose + example) is in [docs/USAGE.md](docs/USAGE.md). Parse writes `analysis/Foton_Parse.html` (Prefetch, LNK, jumplist, selected-ID EVTX, Amcache `InventoryApplicationFile`). Analyze writes `Foton_Report.html` and `analysis/findings.csv`. Those are different products. Re-reporting does not rewrite collect `hashes.csv`.

See `docs/CARVE.md` (MZ/PE signature scan; not NTFS). Recapture baselines after a `BaselineSchemaVersion` bump; Compare refuses a mismatch.

## Requirements

- Windows. PowerShell 5.1+ (or PowerShell 7 on Windows). No extra modules on the endpoint.
- **Administrator recommended**, not required. Unelevated runs skip Security log, Prefetch/Amcache/SRUM copies, VSS, auditpol/secedit, and other users’ files (`SkippedNotElevated`, `collection_coverage.json`). That is a visibility gap, not a clean host.
- When elevated, Desktop often means the **Administrator** profile desktop.

## Collect parameters

| Parameter | Default | Notes |
|-----------|---------|--------|
| `-OutputPath` | Desktop | Case folder and ZIP |
| `-CaseNumber` | (empty) | Chain-of-custody header |
| `-Examiner` | current user | Chain-of-custody header |
| `-EventLogDays` | 14 | Event log and recently-modified system file window |
| `-MaxEventsPerLog` | 3000 | Caps parsed events per query |
| `-SkipEvtxExport` | off | Skip raw `.evtx` (parsed CSVs still collected) |
| `-SkipHashing` | off | Skip SHA-256 of process/file images; folder still hashed |
| `-LoadUserHives` | off | Mount NTUSER.DAT for users not logged on (`finally` unload) |
| `-IncludeFileTimeline` | off | Deeper user-writable exe sweep - not a MACB timeline |
| `-NoZip` | off | Leave the case folder uncompressed |
| `-RequireAdministrator` | off | Exit if not elevated |

## Output (Collect)

```
Foton_<HOST>_<UTCSTAMP>Z/
  Foton_Report.html
  00_Collection/     custody, log, manifest, hashes, coverage.json
  01_System/ … 09_Software_and_Drivers/
  analysis/          after workstation Parse/Analyze (not on a fresh collect)
Foton_<HOST>_<UTCSTAMP>Z.zip
Foton_<HOST>_<UTCSTAMP>Z_PACKAGE_HASH.txt
```

Send the **ZIP and hash file** (or the whole folder), not HTML alone. Historical `WinFoton_*` folders still open with `Get-FotonPackage`.

## Evidentiary handling

- Live collect **alters the host**. Capture memory/disk first if needed.
- Volatility order: processes and network first.
- SHA-256 on artifacts (`hashes.csv`) and the ZIP (`*_PACKAGE_HASH.txt`).
- Findings are automated observations (Tier 1 fact, Tier 2 inference). Pattern lists match admin tools as readily as attacker tools. **Empty findings is not a clean host.**
- Failures go to the manifest / error list. Gaps must be disclosed.

## Extending Foton

Add files under `src/` - collectors, baseline providers, parsers, rules. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Docs

| Doc | For |
|-----|-----|
| [docs/USAGE.md](docs/USAGE.md) | Endpoint vs workstation; `Foton.cmd` |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, package, privilege |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | How to add a feature |
| [docs/LAB.md](docs/LAB.md) | Contributor VM |
| [docs/COVERAGE.md](docs/COVERAGE.md) | What is in vs missing |
| [docs/CARVE.md](docs/CARVE.md) | Signature scan vs NTFS |
| [docs/TODO.md](docs/TODO.md) | Will implement vs considering; public-release bar |
| [docs/MIGRATION.md](docs/MIGRATION.md) | Completed v1 → module extract |
| [AGENTS.md](AGENTS.md) | Invariants for human and AI contributors |

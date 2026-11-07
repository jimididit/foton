# Operator usage

Foton has **two machines**. Mixing them is what usually causes confusion.

| Where | What you run | What you get |
|-------|----------------|--------------|
| **Endpoint** | One Collect or Baseline flatten script | Hashed case folder or baseline folder |
| **Workstation** (release zip, Gallery module, or `legacy\powershell` in a clone) | `Foton.cmd` or `Import-Module .\Foton.psd1` | Parse, compose, analyze, compare, reports |

You do **not** copy the module tree to a target. You do **not** `Import-Module` on an engagement host.

**Versions** (from `legacy\powershell\Foton.psd1`): module **1.38.1**, collect schema **1.13.0**, baseline schema **1.14.0**. `Get-FotonVersion` prints the same after import.

1.38.x is the final PowerShell release line: security fixes only ([SECURITY.md](../SECURITY.md)). Foton v2 (C# single-file executables) is in development; this guide describes 1.38.x until v2 ships.

### Foton v2 (in development)

There is no public v2 release until `foton-collect.exe` is ported; use 1.38.x for casework. Test builds of the single-file executables (Windows 10 / Server 2016 and newer, in-box .NET Framework 4.6.2+, nothing to install) come from the **Release v2** workflow run manually: it uploads them as a workflow artifact without publishing anything.

| Executable | Runs on | Purpose |
|------------|---------|---------|
| `foton-baseline.exe` | Endpoint | Capture a baseline package (`baseline.json`, `coverage.json`, `Foton_Baseline.html`, hashes, ZIP). Same switches as the Baseline flatten |
| `foton.exe` | Workstation | `compare` two baselines (`baseline_diff.csv`, `Foton_BaselineCompare.html`); `parse` copied Prefetch, LNK, jumplists, EVTX and Amcache in a package (`analysis\parsed_records.csv`, `Foton_Parse.html`); `analyze` a package with the triage heuristics (`analysis\findings.csv` and `Foton_Report.html`); `ioc` matches an indicator list (`analysis\ioc_matches.csv`); `package` verifies hashes |

```powershell
.\foton-baseline.exe -OutputPath D:\Baselines -NoZip        # package folder (Desktop by default)
.\foton-baseline.exe -Path D:\Baselines\HOSTNAME.json       # bare snapshot JSON (+ HTML beside it)
.\foton.exe compare D:\Baselines\day0 D:\Baselines\dayN     # folders or baseline.json files
.\foton.exe compare D:\day0.json D:\dayN.json -NoHtml -NoCsv
.\foton.exe parse D:\Cases\Foton_HOSTNAME_20260823-011150Z  # case folder or ZIP; a single file prints its rows
.\foton.exe analyze D:\Cases\Foton_HOSTNAME_20260823-011150Z # re-run after parse / compose / compare to include their output
.\foton.exe ioc D:\Cases\Foton_HOSTNAME_20260823-011150Z D:\intel\iocs.txt  # sha256: / path: / text: lines, or .csv / .json
```

The executables are not Authenticode-signed yet, so SmartScreen may warn on first run. Compare the hash with `SHA256SUMS.txt`, run `gh attestation verify .\foton-baseline.exe --repo jimididit/foton`, then `Unblock-File`. v2 writes baseline schema **1.15.0**; `foton compare` accepts a 1.14.0 baseline from 1.38.x and prints which one-time format and coverage differences to expect. v2 `parse` also returns EVTX events and automatic-destinations jumplist entries that 1.38.x `Invoke-FotonParse` silently missed.

---

## 0. Getting Foton

Each [GitHub Release](https://github.com/jimididit/foton/releases) carries:

| Asset | For |
|-------|-----|
| `Foton-Collect_v<module>_schema<collect>.ps1` | Endpoint live triage (one file) |
| `Foton-Baseline_v<module>_schema<baseline>.ps1` | Endpoint baseline capture (one file) |
| `Foton-Workstation_v<module>.zip` | Analyst workstation: parse, compose, analyze, compare, without cloning the repo |
| `SHA256SUMS.txt` | Hashes of the three files above |

The workstation module is also on the PowerShell Gallery:

```powershell
Install-Module Foton -Scope CurrentUser          # or: Install-Module Foton -RequiredVersion 1.38.1
Import-Module Foton
Get-FotonVersion
# Foton.cmd ships inside the module folder:
& (Join-Path (Get-Module Foton).ModuleBase 'Foton.cmd') help
```

**Verify before use.** The scripts are not Authenticode-signed yet, so trust comes from the hash and the build provenance, not a publisher certificate:

```powershell
Get-FileHash .\Foton-Collect_v1.38.1_schema1.13.0.ps1 -Algorithm SHA256   # must match SHA256SUMS.txt
gh attestation verify .\Foton-Collect_v1.38.1_schema1.13.0.ps1 --repo jimididit/foton
```

`gh attestation verify` proves the file was built by this repository's release workflow from a specific commit. Record the hash in the case notes so the report names the exact collector build that ran.

**ExecutionPolicy.** Run the endpoint scripts with `powershell -ExecutionPolicy Bypass -File ...`: it applies to that one process and changes nothing on the target. Do not change the machine policy on an engagement host. On the workstation:

- A zip downloaded from the internet carries Mark-of-the-Web, so under `RemoteSigned` its scripts refuse to load. After verifying the hash, unblock the extracted folder: `Get-ChildItem .\Foton-1.38.1 -Recurse | Unblock-File`.
- A module installed from the Gallery is not marked, so `RemoteSigned` loads it as-is.
- Windows client defaults to `Restricted`, which blocks every script. `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` on the analyst account is enough for both.

Building from source instead (`legacy\powershell\build\Build-Release.ps1` writes the same assets to `legacy\powershell\dist\release`) is covered below.

---

## 1. Endpoint: Collect and Baseline capture

Obtain a flatten script from a [GitHub Release](https://github.com/jimididit/foton/releases) (section 0), or build on a trusted workstation from a clone, in `legacy\powershell`:

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

That writes a **versioned** leaf and an unversioned alias (same bytes) under `dist\` (generated locally; not committed):

- `dist\Foton-Collect_v1.38.1_schema1.13.0.ps1` and `dist\Foton-Collect.ps1`
- `dist\Foton-Baseline_v1.38.1_schema1.14.0.ps1` and `dist\Foton-Baseline.ps1`

Copy **one** file to the target (USB, RMM, email). Prefer the versioned leaf so the module and schema stay in the filename.

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect_v1.38.1_schema1.13.0.ps1
powershell -ExecutionPolicy Bypass -File .\Foton-Baseline_v1.38.1_schema1.14.0.ps1
```

### If antivirus blocks the collector

Endpoint security products scan PowerShell content at load through AMSI, and DFIR
tooling reads like attack tooling. If the collector is blocked, you will see a
scanner alert naming the script and PowerShell will refuse to run it with *"This
script contains malicious content and has been blocked by your antivirus software."*

Foton no longer embeds its suspicious-command pattern list in the flatten for exactly
this reason (Defender flagged it as `Trojan:PowerShell/PSAttackTool.A`), so a current
build should load cleanly. If your product still blocks it:

- Verify locally before deployment: `.\build\Test-FotonAmsiLoad.ps1 -Path .\dist\Foton-Collect.ps1`. This compiles the script through AMSI without collecting anything.
- Report it to your vendor as a false positive, and attach the package hash.
- If your engagement authority permits it, add a **scoped, temporary** exclusion for the collector path on the target, and record it in the case notes - it changes the host's security posture during collection, which belongs in the methodology disclosure.
- Do not modify the script to evade the scanner. An obfuscated collector is not defensible in a report, and the output would no longer match the published package hash.

A block is also itself an observation worth recording: it tells you the host had an
active scanner at collection time.

Default `-OutputPath` is the current user’s **Desktop**. Open `Foton_Report.html` or `Foton_Baseline.html` **inside** the new folder. Send **ZIP + `*_PACKAGE_HASH.txt`** (or the whole folder). HTML alone is not the package.

### Collect (live triage)

Writes `Foton_<HOSTNAME>_<UTC>Z\`. Alters the host. Findings in the HTML are observations, not a verdict.

| Switch | Purpose |
|--------|---------|
| `-OutputPath D:\Cases` | Case parent folder |
| `-CaseNumber CASE-0001` | Custody header |
| `-Examiner "A. Examiner"` | Custody header |
| `-EventLogDays 14` | Event / recent-file window |
| `-MaxEventsPerLog 3000` | Cap per log query |
| `-SkipEvtxExport` | Skip raw `.evtx` copies |
| `-SkipHashing` | Skip per-file SHA-256 (package still hashed) |
| `-LoadUserHives` | Load NTUSER.DAT for users not logged on (unloaded in `finally`) |
| `-IncludeFileTimeline` | Extra user-writable exe sweep (not a MACB timeline) |
| `-IncludeUsnJournal` | Also copy `$J` when possible. Default is `fsutil usn queryjournal` text only. **`$MFT` is never copied** (KAPE/ORC). |
| `-Deep` | Opt-in extended Collect. Forces `-IncludeFileTimeline` and `-IncludeUsnJournal`, and adds task-referenced script copies, PnP inventory, DriverStore FileRepository inventory (hashes for `.sys`/`.inf`/`.cat` only - not a full binary tree), and elevated `gpresult /h` HTML. Larger/slower package. Task-script copies use raised caps (10k files / 1 GiB), skip if the output volume has under 2 GiB free, refuse UNC paths (`SkippedUnc`, no remote auth), and keep drive letters in package paths so `C:\` vs `D:\` do not collide. Default Collect stays unchanged without this switch. |
| `-NoZip` | Folder only |
| `-RequireAdministrator` | Exit if not elevated |

Unelevated runs skip Security log, Prefetch/Amcache/SRUM copies, registry hive exports, VSS, auditpol/secedit, other users. That is a **visibility gap**, not a clean host.

```powershell
.\Foton-Collect.ps1 -CaseNumber "CASE-0001" -Examiner "A. Examiner" `
    -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
.\Foton-Collect.ps1 -CaseNumber "CASE-0001" -Examiner "A. Examiner" `
    -OutputPath D:\Cases -Deep
.\Foton-Collect.ps1 -CaseNumber "SELF-AUDIT"
```

On a **workstation clone** of this repo (lab only), the same collect is `Invoke-FotonTriage` with those parameters. Engagements should still ship the flatten file.

### Baseline (known-state snapshot)

Writes `FotonBaseline_<HOSTNAME>_<UTC>Z\` with `baseline.json`, hashes, optional ZIP, `Foton_Baseline.html`. Not a triage collect. Volatile fields (PIDs, live connections) are out of scope.

A baseline taken after an incident is a picture of **that** state. Compare proves change between two observations, not when or who. Schema **1.14.0** will not compare against older baseline JSON. Recapture day0 after this bump (WDAC/AppLocker policy hash).

```powershell
.\Foton-Baseline.ps1 -OutputPath D:\Baselines -NoZip
.\Foton-Baseline.ps1 -RequireAdministrator
```

---

## 2. Workstation: `Foton.cmd` (no cmdlets required)

From the extracted workstation zip folder, or `legacy\powershell` in a clone. Import happens inside the wrapper.

```
Foton.cmd help
Foton.cmd collect  D:\Cases
Foton.cmd baseline D:\Baselines
Foton.cmd baseline D:\Baselines\role-web.json
Foton.cmd compare  D:\Baselines\day0.json D:\Baselines\day1.json
Foton.cmd parse    D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd analyze  D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd ioc      D:\Cases\Foton_HOSTNAME_...Z D:\intel\iocs.txt
Foton.cmd carve    D:\blob.bin
```

| Command | Purpose | Output |
|---------|---------|--------|
| `collect` | Runs `dist\Foton-Collect.ps1` if built | Case folder (`-NoZip`) |
| `baseline` | Capture on **this** workstation | Package folder, or JSON if the path ends in `.json` |
| `compare` | Diff two baselines | Table + `Foton_BaselineCompare.html` beside the second JSON |
| `parse` | Offline Prefetch / LNK / jumplist / EVTX / Amcache | `analysis\parsed_records.csv`, `analysis\Foton_Parse.html` |
| `compose` | If EZ Tools / Hayabusa / Chainsaw are available (`-ToolPath`, `tools.json` from `tools`, or PATH), run them on copied files | `analysis\external\<tool>\` hashed CSV; inventory CSV with Version/RulesVersion. Native parse if missing |
| `tools` | One-time workstation setup: install a **pinned** catalog tool (`tools Hayabusa`), or register an existing install (`tools EZTools <folder>`, `tools Chainsaw <folder>`). `tools` alone lists every known tool: Source `Installed` / `Catalog` (pinned download) / `Registered` (existing folder), and the Location compose will run | `%LOCALAPPDATA%\Foton\tools` + `tools.json`. Does **not** change PATH |
| `analyze` | Load package, run heuristics, write HTML | Case folder: `Foton_Report.html`, `analysis\findings.csv`. ZIP: `<zip-stem>_Report.html` + `<zip-stem>_findings.csv` **beside the ZIP** |
| `ioc` | Match a text/CSV/JSON IOC list to the package | Match table (Tier 2 hits) |
| `carve` | MZ/PE signature scan of a blob (capped) | Hit table. Not NTFS unallocated |

Parse HTML is **not** findings. Analyze HTML is **not** a parsed artifact dump. Re-reporting does not rewrite collect `hashes.csv`.

Pointing `analyze`, `parse`, or `compose` at a **ZIP** extracts it to a temp folder that is not preserved, so those commands write their reports next to the ZIP instead. The report's relative artifact links (`06_Security_Posture\...`) only resolve when you analyze an **extracted case folder** - the HTML says so in its limitations section.

**Extract the ZIP before chaining these commands.** Each ZIP open extracts to a *new* temp folder, so `compose` writes `analysis\external\` into a directory that a later `analyze` never sees - the tool output is silently lost and cannot feed findings. Against a case folder the three steps accumulate correctly, in this order:

```powershell
Expand-Archive D:\Cases\Foton_HOSTNAME_...Z.zip -DestinationPath D:\Cases
.\Foton.cmd parse   D:\Cases\Foton_HOSTNAME_...Z
.\Foton.cmd compose D:\Cases\Foton_HOSTNAME_...Z
.\Foton.cmd analyze D:\Cases\Foton_HOSTNAME_...Z
```

`analyze` must run **last**: it consumes what `parse` and `compose` wrote to disk.

---

## 3. Workstation: PowerShell commands

```powershell
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
Get-Help ConvertFrom-FotonAmcache -Full
```

Every command below except `Get-FotonVersion` is meant to work on a **package** (case folder or ZIP) or an explicit file already copied off a host. Parse / Carve / Analyze never read the live registry or network.

### Package and versions

| Command | Purpose | How |
|---------|---------|-----|
| `Get-FotonVersion` | Module version, release date (shown as Updated in the banner), collect / baseline / findings schema | `Get-FotonVersion` |
| `Get-FotonPackage` | Open a case folder or ZIP; load CSVs into the session | `Get-FotonPackage -Path D:\Cases\Foton_HOSTNAME_...Z` |

Historical `WinFoton_*` folders still open.

### Collect orchestrator (lab / this box)

| Command | Purpose | How |
|---------|---------|-----|
| `Invoke-FotonTriage` | Live collect → analyze → `Foton_Report.html` → hashed package | Same switches as `Foton-Collect.ps1`. Prefer the flatten file on a real endpoint. |

```powershell
Invoke-FotonTriage -OutputPath D:\Cases -CaseNumber CASE-0001 -NoZip
```

### Baseline

| Command | Purpose | How |
|---------|---------|-----|
| `New-FotonBaseline` | Capture stable config (live host) | `-OutputPath D:\Baselines` package, or `-Path D:\Baselines\host.json` JSON only. `-NoZip`, `-NoHtml`, `-RequireAdministrator` |
| `New-FotonBaselineReport` | HTML snapshot of **one** baseline | `-Path D:\Baselines\FotonBaseline_HOSTNAME_...Z` (or `baseline.json`) |
| `Compare-FotonBaseline` | Field-level Added/Removed/Modified | `-ReferencePath day0.json -DifferencePath day1.json` (folders that contain `baseline.json` work). Refuses schema mismatch. Writes `baseline_diff.csv` + `Foton_BaselineCompare.html` beside the difference JSON (HTML unless `-NoHtml`). Mode is **Temporal** when hostnames match, else **Fleet** |
| `New-FotonBaselineCompareReport` | HTML for an existing diff (workstation) | Used when you already have change records; `Compare-FotonBaseline` writes HTML by default |

```powershell
New-FotonBaseline -OutputPath D:\Baselines -NoZip
Compare-FotonBaseline -ReferencePath D:\Baselines\day0.json -DifferencePath D:\Baselines\day1.json
New-FotonBaselineReport -Path D:\Baselines\FotonBaseline_HOSTNAME_20260822-120000Z
```

#### Temporal recipe (same host, day0 → later)

Capture at provisioning (or any known-good moment), store **off-host**, recapture later on that host, then compare. Hostnames must match for Temporal wording.

```powershell
# Day 0 (provisioning / known-good) - store off-host
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\day0 -NoZip

# Day N on the same host
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\dayN -NoZip

# Workstation
Compare-FotonBaseline `
  -ReferencePath D:\Baselines\day0\FotonBaseline_HOSTNAME_...Z `
  -DifferencePath D:\Baselines\dayN\FotonBaseline_HOSTNAME_...Z
# -> baseline_diff.csv + Foton_BaselineCompare.html beside dayN baseline.json
```

Optional: feed High-attention rows into a triage report:

```powershell
New-Item D:\Cases\Foton_HOSTNAME_...Z\analysis -ItemType Directory -Force | Out-Null
Copy-Item D:\Baselines\dayN\...\baseline_diff.csv `
  D:\Cases\Foton_HOSTNAME_...Z\analysis\baseline_diff.csv -Force
.\Foton.cmd analyze D:\Cases\Foton_HOSTNAME_...Z
```

#### Fleet recipe (host vs golden / role image)

Capture a **role** golden once (hostname will differ from candidates). Compare each host against that golden. Wording is Fleet - not a certificate that the host is clean.

```powershell
# Golden for role "web" (any representative build host)
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\golden-web -NoZip

# Candidate host
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\hosts\WEB01 -NoZip

Compare-FotonBaseline `
  -ReferencePath D:\Baselines\golden-web\FotonBaseline_...Z `
  -DifferencePath D:\Baselines\hosts\WEB01\FotonBaseline_WEB01_...Z
```

Expect noise: hostname, SIDs, domain join, local admin via LAPS, software version bumps (Info). High attention (service PathName, new Administrators member, Winlogon, IFEO, Root CA add, …) still cites provider false-positive notes - confirm against the role image, do not treat as compromise.

Schema **1.14.0** refuses older JSON. Recapture golden and day0 after a schema bump.

### Parse (offline files)

`Invoke-FotonParse` walks a package. `ConvertFrom-Foton*` is one file.

| Command | Purpose | How |
|---------|---------|-----|
| `Invoke-FotonParse` | Prefetch, LNK, jumplists, selected EVTX, `Amcache.hve` in a package or one file | `-Path D:\Cases\Foton_HOSTNAME_...Z` or `-Path D:\Cases\...\note.lnk`. Writes `analysis\parsed_records.csv` + `Foton_Parse.html` |
| `New-FotonParseReport` | HTML from parse rows (not findings) | Called by `Invoke-FotonParse`; use if you already have rows |
| `ConvertFrom-FotonPrefetch` | SCCA executable name; MAM is unsupported, not guessed | `-Path D:\Cases\...\NOTEPAD.EXE-*.pf` |
| `ConvertFrom-FotonLnk` | `LocalBasePath` from LinkInfo when present | `-Path D:\Cases\...\foo.lnk` |
| `ConvertFrom-FotonJumplist` | Automatic DestList v1–4 (path + FILETIME at offset 100); custom destinations via Shell Link CLSID | `-Path D:\Cases\...\*.automaticDestinations-ms` |
| `ConvertFrom-FotonEvtx` | Selected Event IDs only, capped | `-Path D:\Cases\...\Security.evtx` |
| `ConvertFrom-FotonAmcache` | Win10+ `InventoryApplicationFile` named values. Key last-write is not execution. Legacy `File\*` IDs unsupported | `-Path D:\Cases\...\amcache\Amcache.hve` |

```powershell
Invoke-FotonParse -Path D:\Cases\Foton_HOSTNAME_...Z
ConvertFrom-FotonAmcache -Path D:\Cases\Foton_HOSTNAME_...Z\08_Filesystem\amcache\Amcache.hve
ConvertFrom-FotonJumplist -Path D:\Cases\...\9b9cdc69de0e5dea.automaticDestinations-ms
```

SRUM ESE is **copied, not parsed**.

### Compose (EZ Tools / Hayabusa, optional)

Native `ConvertFrom-Foton*` is the air-gap fallback. Prefer a one-time `Install-FotonTool` for Hayabusa (pinned version + SHA-256 into `%LOCALAPPDATA%\Foton\tools`). Compose then finds it via `tools.json` without touching PATH.

EZ Tools and Chainsaw are not downloaded by Foton. If you already have them, register the folder once. EZ Tools unpacks several tools into subfolders (`EvtxeCmd\`, `RECmd\`, `AmcacheParser\`) that a single PATH entry does not cover; registration records each executable's full path. The SHA-256 written to `tools.json` is what Foton observed on disk, not a verification against upstream. Versions come from each executable's file version; Chainsaw has none, so registration runs `chainsaw --version` once (5-second timeout) to record it.

```powershell
Install-FotonTool -Name EZTools -Path C:\Tools\EZTools
Install-FotonTool -Name Chainsaw -Path C:\Tools\chainsaw
# or: Foton.cmd tools EZTools C:\Tools\EZTools
```

Compose resolution order stays `-ToolPath` → `tools.json` → PATH.

| Tool | What compose runs | Status when it cannot |
|------|-------------------|-----------------------|
| RECmd | `-d <hives> --bn BatchExamples\DFIRBatch.reb` (falls back to `Kroll_Batch.reb`) | `NoBatch` (RECmd exports nothing without a batch) |
| Chainsaw | `hunt` with `rules\` and/or `sigma\` + `mappings\sigma-event-logs-all.yml` beside the binary | `NoRules` (no EVTX dump; EvtxECmd covers that) |
| Hayabusa | `dfir-timeline` (or `csv-timeline`) with `-U`, so timestamps are UTC | `NotOnPath` points at `Install-FotonTool` |
| Any | stdout/stderr captured as `tool_stdout.txt` / `tool_stderr.txt` | `MissingRuntime` when the tool reports a missing .NET runtime (AmcacheParser is .NET 10 only) |

Each tool writes into a staging folder first. Compose replaces that tool's earlier output only when the run produces files, so those rows describe this run. The swap is a folder rename; if it fails (a file in the old folder is open), the row is `SwapError`, the earlier output stays as `Retained`, and the new output is left in the staging folder named in the row. When a tool does not run (`NotOnPath`, `NoInput`, `NoRules`, `NoBatch`) or runs without producing output (`ToolError`, `NoOutput`, `MissingRuntime`), earlier output is kept and listed as `Retained` with its hash, so the inventory still covers every file analyze reads. Registration asks for confirmation unless `-Force` is given and honours `-WhatIf`.

```powershell
Install-FotonTool -List
Install-FotonTool -Name Hayabusa
# Offline / air-gap:
Install-FotonTool -Name Hayabusa -ArchivePath D:\Offline\hayabusa-4.0.0-win-x64.zip -Force

Get-FotonPackage -Path D:\Cases\Foton_HOSTNAME_...Z
Invoke-FotonParse
Invoke-FotonExternalParse
Invoke-FotonAnalysis
New-FotonReport
```

Or: `Foton.cmd tools Hayabusa` then `Foton.cmd compose <case-folder>`.

Outputs land under `analysis\external\<tool>\` and are hashed. Inventory rows include **Version** and **RulesVersion** when the tool came from the Foton manifest. Missing tools are inventory rows (`NotOnPath`), not failures - Hayabusa's note names `Install-FotonTool`. Hayabusa hits are that engine's inferences (Tier 2); name the tool in the finding. **PECmd** and **EvtxECmd** CSVs also feed `Invoke-FotonAnalysis` (coverage, user-writable path references, and a short list of high-attention EventIds such as 1102/7045) - still observations that cite the tool, not a reimplementation of those parsers. Analyze reads only PECmd, EvtxECmd, and Hayabusa output. RECmd, Chainsaw, LECmd, JLECmd, and AmcacheParser output is hashed and listed in the inventory for the examiner, but does not become findings.

Analyze noise rules (apply to every package):

- Suspicious-command patterns are matched only on events that carry command text (4688, Sysmon 1, 4104, 4697, 7045, 4698, 4702). On 4673/4674 the `ExecutableInfo` is the calling image (often `lsass.exe`), not a command.
- Rows inside the collection window (from `collection.log`) are excluded from the path and pattern counts and reported as an Info methodology finding. Attribution is by time only.
- Service installs (native 7045 and EvtxECmd 4697/7045) exclude per-user service instances (`OneSyncSvc_1701f8` and similar), which Windows creates at every logon. Only instances of known Microsoft per-user templates whose image is System32 `svchost.exe` are excluded; any other `Name_<hex>` service, a template name pointing at another binary, or a row without a readable image is still counted. System32 is recognised as `%SystemRoot%`, `%windir%`, `\SystemRoot`, `<drive>:\Windows`, or the host's own `SystemDirectory` from `os_info`. The finding names the remaining services and states how many were excluded.
- Service install events do not record `ServiceDll`, so analyze looks the instance up in `services.csv` (collect schema 1.13.0+). A genuine instance has no `ServiceDll` of its own (Collect records the template's, `ServiceDllSource` = `Template:<name>`). The event counts when the instance has its own DLL, or when the DLL is outside System32, in a user-writable path, or `NotSigned`/`HashMismatch`. Instances already removed at logoff have no row and cannot be checked this way; for those, read `Services\<name>\Parameters\ServiceDll` in the collected SYSTEM hive.
- `services.csv` carries `ServiceDll`, its signature, signer, SHA-256, and a user-writable flag for svchost-hosted services. A user-writable `ServiceDll` joins the High user-writable service finding; a `NotSigned` or `HashMismatch` one raises a Medium finding. Third-party and in-house svchost services are the usual benign source.
- Profile scans skip earlier Foton package folders on the host. Each skipped folder is listed in `collection_coverage.json` (`ExcludedEarlierPackages`) and in an Info finding, because the name and marker files that identify a package can be forged.

Account findings: a 4720 followed by a 4726 for the same SID within 60 seconds is reported separately (Low, "created and deleted within a minute") - typical of provisioning or local-admin rotation scripts. Persistent accounts and additions to privileged groups stay Medium; a new account joining its default primary group (RID 513) is not a privilege change.

**Collector footprint.** Script block logging records Foton's own PowerShell, so hunt rules for suspicious scripting and for registry or credential access fire on the collection itself. On a real package this was the single largest medium-level "detection". `Invoke-FotonAnalysis` attributes such rows to the collection - by timestamp inside the collection window read from `00_Collection\collection.log`, and by rows naming a Foton function outside it - excludes them from the severity bands, and reports the count as an Info methodology finding. That exclusion is inference, not process identity: genuine host activity during the collection window is excluded too, so filter the Hayabusa CSV to that window yourself if something could have coincided.

Hayabusa notes: v4 renamed `csv-timeline` to `dfir-timeline`, and Foton probes `--help` so both generations work. Foton always passes `-w` (no wizard) and `-U` (UTC timestamps). Rules are loaded from the `rules\` folder beside the binary. Each tool is launched with its own install directory as the working directory. Catalog pin and refresh: `Install-FotonTool -List` (manifest under `src/Private/Tools/`).

Why this matters for `analyze`: **Collect already ran the heuristics on the endpoint**, so `analyze` on an untouched package reproduces `00_Collection\findings.csv` rather than adding detection, and it now says so. Parse, compose, `ioc`, and baseline compare are what add new findings - run them, then analyze again.

### Analyze, IOC, report, carve

| Command | Purpose | How |
|---------|---------|-----|
| `Invoke-FotonAnalysis` | Heuristics on the **loaded** package | `Get-FotonPackage` first, then this. Writes `analysis\findings.csv` |
| `New-FotonReport` | Triage HTML from session findings | After analysis. Default `<case>\Foton_Report.html` |
| `Invoke-FotonIocMatch` | Offline IOC list vs package strings/hashes | `-Path D:\Cases\Foton_HOSTNAME_...Z -IocPath D:\intel\iocs.txt` (also `.csv` Kind,Value and JSON `{Kind,Value}`). Kinds: `sha256`, `path`, `text` |
| `Invoke-FotonCarve` | MZ/PE magic in a blob; not NTFS | `-Path D:\blob.bin` (`-MaxBytes`, `-MaxHits`) |

```powershell
Get-FotonPackage -Path D:\Cases\Foton_HOSTNAME_...Z
Invoke-FotonAnalysis
New-FotonReport

Invoke-FotonIocMatch -Path D:\Cases\Foton_HOSTNAME_...Z -IocPath D:\intel\iocs.txt
Invoke-FotonCarve -Path D:\evidence\unalloc-sample.bin
```

---

## What we will not hide

- Live collect **changes the host**. Capture memory/disk first if that is the case plan.
- Elevated collect exports loaded registry hives (SYSTEM, SOFTWARE, DEFAULT, signed-in users' NTUSER/UsrClass) with `reg save` into the case folder. **SAM and SECURITY are not collected** (credential material); the manifest records them as `NotCollectedByDesign`. Use a full image or KAPE when a case needs them.
- A copy task whose files could not be captured shows **Partial** or **Failed** in the manifest, `collection_errors.csv`, and `collection_coverage.json` - not Good.
- Findings are **observations**, not “infected.”
- Empty findings is not a clean host.
- A post-incident baseline is a picture of that observed state-not proof of when or who.

Carve limits: [CARVE.md](CARVE.md). Vulnerability reporting: [SECURITY.md](../SECURITY.md).

# Operator usage

Foton has **two machines**. Mixing them is what usually causes confusion.

| Where | What you run | What you get |
|-------|----------------|--------------|
| **Endpoint** | One Collect or Baseline flatten script | Hashed case folder or baseline folder |
| **Workstation** (this repo) | `Foton.cmd` or `Import-Module .\Foton.psd1` | Parse, compose, analyze, compare, reports |

You do **not** copy the module tree to a target. You do **not** `Import-Module` on an engagement host.

**Versions** (from `Foton.psd1`): module **1.31.0**, collect schema **1.10.0**, baseline schema **1.14.0**. `Get-FotonVersion` prints the same after import.

---

## 1. Endpoint: Collect and Baseline capture

Obtain a flatten script from a [GitHub Release](https://github.com/jimididit/foton/releases) when available, or build on a trusted workstation:

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

That writes a **versioned** leaf and an unversioned alias (same bytes) under `dist\` (generated locally; not committed):

- `dist\Foton-Collect_v1.31.0_schema1.10.0.ps1` and `dist\Foton-Collect.ps1`
- `dist\Foton-Baseline_v1.31.0_schema1.14.0.ps1` and `dist\Foton-Baseline.ps1`

Copy **one** file to the target (USB, RMM, email). Prefer the versioned leaf so the module and schema stay in the filename.

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect_v1.31.0_schema1.10.0.ps1
powershell -ExecutionPolicy Bypass -File .\Foton-Baseline_v1.31.0_schema1.14.0.ps1
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
| `-Deep` | Opt-in extended Collect. Forces `-IncludeFileTimeline` and `-IncludeUsnJournal`, and adds task-referenced script copies, PnP inventory, DriverStore FileRepository inventory (hashes for `.sys`/`.inf`/`.cat` only — not a full binary tree), and elevated `gpresult /h` HTML. Larger/slower package. Task-script copies use raised caps (10k files / 1 GiB), skip if the output volume has under 2 GiB free, refuse UNC paths (`SkippedUnc`, no remote auth), and keep drive letters in package paths so `C:\` vs `D:\` do not collide. Default Collect stays unchanged without this switch. |
| `-NoZip` | Folder only |
| `-RequireAdministrator` | Exit if not elevated |

Unelevated runs skip Security log, Prefetch/Amcache/SRUM copies, VSS, auditpol/secedit, other users. That is a **visibility gap**, not a clean host.

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

From the repo root. Import happens inside the wrapper.

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
| `tools` | One-time workstation setup: install a **pinned** catalog tool (`tools Hayabusa`), or register an existing install (`tools EZTools <folder>`, `tools Chainsaw <folder>`) | `%LOCALAPPDATA%\Foton\tools` + `tools.json`. Does **not** change PATH |
| `analyze` | Load package, run heuristics, write HTML | Case folder: `Foton_Report.html`, `analysis\findings.csv`. ZIP: `<zip-stem>_Report.html` + `<zip-stem>_findings.csv` **beside the ZIP** |
| `ioc` | Match a text/CSV/JSON IOC list to the package | Match table (Tier 2 hits) |
| `carve` | MZ/PE signature scan of a blob (capped) | Hit table. Not NTFS unallocated |

Parse HTML is **not** findings. Analyze HTML is **not** a parsed artifact dump. Re-reporting does not rewrite collect `hashes.csv`.

Pointing `analyze`, `parse`, or `compose` at a **ZIP** extracts it to a temp folder that is not preserved, so those commands write their reports next to the ZIP instead. The report's relative artifact links (`06_Security_Posture\...`) only resolve when you analyze an **extracted case folder** — the HTML says so in its limitations section.

**Extract the ZIP before chaining these commands.** Each ZIP open extracts to a *new* temp folder, so `compose` writes `analysis\external\` into a directory that a later `analyze` never sees — the tool output is silently lost and cannot feed findings. Against a case folder the three steps accumulate correctly, in this order:

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
| `Get-FotonVersion` | Module + collect / baseline / findings schema | `Get-FotonVersion` |
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

Capture a **role** golden once (hostname will differ from candidates). Compare each host against that golden. Wording is Fleet — not a certificate that the host is clean.

```powershell
# Golden for role "web" (any representative build host)
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\golden-web -NoZip

# Candidate host
.\Foton-Baseline.ps1 -OutputPath D:\Baselines\hosts\WEB01 -NoZip

Compare-FotonBaseline `
  -ReferencePath D:\Baselines\golden-web\FotonBaseline_...Z `
  -DifferencePath D:\Baselines\hosts\WEB01\FotonBaseline_WEB01_...Z
```

Expect noise: hostname, SIDs, domain join, local admin via LAPS, software version bumps (Info). High attention (service PathName, new Administrators member, Winlogon, IFEO, Root CA add, …) still cites provider false-positive notes — confirm against the role image, do not treat as compromise.

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

EZ Tools and Chainsaw are not downloaded by Foton. If you already have them, register the folder once. EZ Tools unpacks several tools into subfolders (`EvtxeCmd\`, `RECmd\`, `AmcacheParser\`) that a single PATH entry does not cover; registration records each executable's full path. The SHA-256 written to `tools.json` is what Foton observed on disk, not a verification against upstream.

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

Outputs land under `analysis\external\<tool>\` and are hashed. Inventory rows include **Version** and **RulesVersion** when the tool came from the Foton manifest. Missing tools are inventory rows (`NotOnPath`), not failures — Hayabusa's note names `Install-FotonTool`. Hayabusa hits are that engine's inferences (Tier 2); name the tool in the finding. **PECmd** and **EvtxECmd** CSVs also feed `Invoke-FotonAnalysis` (coverage, user-writable path references, and a short list of high-attention EventIds such as 1102/7045) — still observations that cite the tool, not a reimplementation of those parsers.

EvtxECmd noise rules (apply to every package):

- Suspicious-command patterns are matched only on events that carry command text (4688, Sysmon 1, 4104, 4697, 7045, 4698, 4702). On 4673/4674 the `ExecutableInfo` is the calling image (often `lsass.exe`), not a command.
- Rows inside the collection window (from `collection.log`) are excluded from the path and pattern counts and reported as an Info methodology finding. Attribution is by time only.
- Service installs exclude per-user service instances (`OneSyncSvc_1701f8` and similar), which Windows creates at every logon. Only instances of known Microsoft per-user templates whose image is System32 `svchost.exe` are excluded; any other `Name_<hex>` service, a template name pointing at another binary, or a row without a readable image is still counted. The finding names the remaining services and states how many were excluded. Service install events do not record `ServiceDll`, so a copied template name that loads another DLL through svchost is also excluded; check `Services\<name>\Parameters\ServiceDll` in the collected SYSTEM hive when that matters.
- Profile scans skip earlier Foton package folders on the host. Each skipped folder is listed in `collection_coverage.json` (`ExcludedEarlierPackages`) and in an Info finding, because the name and marker files that identify a package can be forged.

Account findings: a 4720 followed by a 4726 for the same SID within 60 seconds is reported separately (Low, "created and deleted within a minute") - typical of provisioning or local-admin rotation scripts. Persistent accounts and additions to privileged groups stay Medium; a new account joining its default primary group (RID 513) is not a privilege change.

**Collector footprint.** Script block logging records Foton's own PowerShell, so hunt rules for suspicious scripting and for registry or credential access fire on the collection itself. On a real package this was the single largest medium-level "detection". `Invoke-FotonAnalysis` attributes such rows to the collection — by timestamp inside the collection window read from `00_Collection\collection.log`, and by rows naming a Foton function outside it — excludes them from the severity bands, and reports the count as an Info methodology finding. That exclusion is inference, not process identity: genuine host activity during the collection window is excluded too, so filter the Hayabusa CSV to that window yourself if something could have coincided.

Hayabusa notes: v4 renamed `csv-timeline` to `dfir-timeline`, and Foton probes `--help` so both generations work. Foton always passes `-w` (no wizard) and `-U` (UTC timestamps). Rules are loaded from the `rules\` folder beside the binary. Each tool is launched with its own install directory as the working directory. Catalog pin and refresh: `Install-FotonTool -List` (manifest under `src/Private/Tools/`).

Why this matters for `analyze`: **Collect already ran the heuristics on the endpoint**, so `analyze` on an untouched package reproduces `00_Collection\findings.csv` rather than adding detection, and it now says so. Parse, compose, `ioc`, and baseline compare are what add new findings — run them, then analyze again.

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
- A post-incident baseline is a picture of that observed state—not proof of when or who.

Carve limits: [CARVE.md](CARVE.md). Vulnerability reporting: [SECURITY.md](../SECURITY.md).

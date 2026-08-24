# Operator usage

Foton has **two machines**. Mixing them is what feels like too much PowerShell.

| Where | What you run | What you get |
|-------|----------------|--------------|
| **Endpoint** | One flatten script from `dist\` | Hashed case folder or baseline folder |
| **Workstation** (this repo) | `Foton.cmd` or `Import-Module .\Foton.psd1` | Parse, compare, analyze, reports |

You do **not** copy the module tree to a target. You do **not** `Import-Module` on an engagement host.

Current stamps (from `Foton.psd1`): module **1.25.0**, collect schema **1.9.0**, baseline schema **1.14.0**. `Get-FotonVersion` prints the same after import.

---

## 1. Endpoint: Collect and Baseline capture

On a trusted box, rebuild after Collect/Baseline source changes:

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

That writes a **versioned** leaf and an unversioned alias (same bytes):

- `dist\Foton-Collect_v1.25.0_schema1.9.0.ps1` and `dist\Foton-Collect.ps1`
- `dist\Foton-Baseline_v1.25.0_schema1.14.0.ps1` and `dist\Foton-Baseline.ps1`

Copy **one** file to the target (USB, RMM, email). Prefer the versioned leaf so the module and schema stay in the filename.

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect_v1.25.0_schema1.9.0.ps1
powershell -ExecutionPolicy Bypass -File .\Foton-Baseline_v1.25.0_schema1.14.0.ps1
```

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
| `-NoZip` | Folder only |
| `-RequireAdministrator` | Exit if not elevated |

Unelevated runs skip Security log, Prefetch/Amcache/SRUM copies, VSS, auditpol/secedit, other users. That is a **visibility gap**, not a clean host.

```powershell
.\Foton-Collect.ps1 -CaseNumber "CASE-0001" -Examiner "A. Examiner" `
    -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
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
| `compose` | If EZ Tools / Hayabusa / Chainsaw are on PATH, run them on copied files | `analysis\external\<tool>\` hashed CSV; inventory CSV. Native parse if missing |
| `analyze` | Load package, run heuristics, write HTML | `Foton_Report.html`, `analysis\findings.csv` |
| `ioc` | Match a text/CSV/JSON IOC list to the package | Match table (Tier 2 hits) |
| `carve` | MZ/PE signature scan of a blob (capped) | Hit table. Not NTFS unallocated |

Parse HTML is **not** findings. Analyze HTML is **not** a parsed artifact dump. Re-reporting does not rewrite collect `hashes.csv`.

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
| `Compare-FotonBaseline` | Field-level Added/Removed/Modified | `-ReferencePath day0.json -DifferencePath day1.json` (folders that contain `baseline.json` work). Refuses schema mismatch. Writes `Foton_BaselineCompare.html` unless `-NoHtml` |
| `New-FotonBaselineCompareReport` | HTML for an existing diff (workstation) | Used when you already have change records; `Compare-FotonBaseline` writes HTML by default |

```powershell
New-FotonBaseline -OutputPath D:\Baselines -NoZip
Compare-FotonBaseline -ReferencePath D:\Baselines\day0.json -DifferencePath D:\Baselines\day1.json
New-FotonBaselineReport -Path D:\Baselines\FotonBaseline_HOSTNAME_20260822-120000Z
```

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

Native `ConvertFrom-Foton*` is the air-gap fallback. If Eric Zimmerman tools or Hayabusa/Chainsaw are **already on PATH**, `Invoke-FotonExternalParse` runs them on **copied** package files only (no download, no live host).

```powershell
Get-FotonPackage -Path D:\Cases\Foton_HOSTNAME_...Z
Invoke-FotonParse
Invoke-FotonExternalParse
Invoke-FotonAnalysis
New-FotonReport
```

Outputs land under `analysis\external\<tool>\` and are hashed. Missing tools are inventory rows (`NotOnPath`), not failures. Hayabusa hits are that engine's inferences (Tier 2); name the tool in the finding. Copy `Foton-Collect.ps1` does not parse Prefetch/EVTX/hives on the endpoint.

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
- Findings are **observations**, not “infected.”
- Empty findings is not a clean host.
- A post-incident baseline is a picture of the compromised (or unknown) state.
- Until the public-release bar in [TODO.md](TODO.md) is mostly green, treat Foton as a lab/internal tool.

Coverage (in vs missing artifacts): [COVERAGE.md](COVERAGE.md). Carve limits: [CARVE.md](CARVE.md).

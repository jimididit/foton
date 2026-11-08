# Operator usage

Foton has **two machines**. Mixing them is what usually causes confusion.

| Where | What you run | What you get |
|-------|--------------|--------------|
| **Endpoint** | `foton-collect.exe` or `foton-baseline.exe` (one file each) | Hashed case folder or baseline folder (+ ZIP) |
| **Workstation** | `foton.exe` | Parse, compose, analyze, IOC match, baseline compare, carve, package verification |

Copy only the endpoint executable to a target. Parse, compose, and analyze read the copied package on the workstation and never touch the live host.

**Versions.** Every executable prints its version, collect schema, and baseline schema with `-Version`. Foton 2.1 writes collect schema **1.14.0** and baseline schema **1.17.0** (see [Formats](#formats-and-compatibility)).

**Older hosts.** The executables need Windows 10 / Server 2016 or newer. For Windows 7, 8.1, or Server 2012 R2, use the PowerShell line: [Foton 1.38.2](https://github.com/jimididit/foton/releases/tag/v1.38.2) and its [1.38.x usage guide](https://github.com/jimididit/foton/blob/v1.38.2/legacy/powershell/release-docs/docs/USAGE.md). 1.38.2 is the final PowerShell release and is no longer maintained ([SECURITY.md](../SECURITY.md)).

---

## 0. Getting Foton

Each [GitHub Release](https://github.com/jimididit/foton/releases) tagged `v2.*` carries:

| Asset | For |
|-------|-----|
| `foton-collect.exe` | Endpoint live triage |
| `foton-baseline.exe` | Endpoint baseline capture |
| `foton.exe` | Analyst workstation |
| `SHA256SUMS.txt` | Hashes of the three executables |

They run on the .NET Framework that ships with Windows (4.6.2+). Nothing is installed, and nothing is fetched at run time except by `foton tools`, which downloads a pinned, hash-checked Hayabusa release only when you ask.

**Verify before use.** The executables are not Authenticode-signed yet, so Windows SmartScreen may warn on first run. Trust comes from the hash and the build provenance, not a publisher certificate:

```powershell
Get-FileHash .\foton-collect.exe -Algorithm SHA256        # must match SHA256SUMS.txt
gh attestation verify .\foton-collect.exe --repo jimididit/foton
Unblock-File .\foton-collect.exe
```

`gh attestation verify` proves the file was built by this repository's release workflow from a specific commit. Record the hash in the case notes so the report names the exact collector build that ran.

### If antivirus blocks the collector

DFIR tooling reads like attack tooling: it enumerates credentials stores, exports registry hives, and lists persistence. If an endpoint product blocks or quarantines `foton-collect.exe`:

- Report it to your vendor as a false positive and attach the hash.
- If your engagement authority permits it, add a **scoped, temporary** exclusion for the collector path on the target and record it in the case notes. It changes the host's security posture during collection, which belongs in the methodology disclosure.
- Do not modify or repack the executable to evade the scanner. The output would no longer match the published hash, and an altered collector is not defensible in a report.

A block is itself an observation worth recording: the host had an active scanner at collection time.

---

## 1. Endpoint: Collect and Baseline capture

### Collect (live triage)

Writes `Foton_<HOSTNAME>_<UTC>Z\` (and a ZIP beside it). Alters the host. Findings in the HTML are observations, not a verdict.

| Switch | Purpose |
|--------|---------|
| `-OutputPath D:\Cases` | Case parent folder (default: the current user's Desktop) |
| `-CaseNumber CASE-0001` | Custody header |
| `-Examiner "A. Examiner"` | Custody header |
| `-EventLogDays 14` | Event / recent-file window |
| `-MaxEventsPerLog 3000` | Cap per event query |
| `-SkipEvtxExport` | Skip the time-filtered raw `.evtx` copies |
| `-SkipHashing` | Skip per-file SHA-256 (the package is still hashed) |
| `-LoadUserHives` | Load NTUSER.DAT for users not logged on (elevated only; unloaded in `finally`) |
| `-IncludeFileTimeline` | Deeper user-writable executable sweep (not a MACB timeline) |
| `-IncludeUsnJournal` | Also copy `$J` when possible. The default is `fsutil usn queryjournal` text only. **`$MFT` is never copied** (use KAPE/ORC). |
| `-Deep` | Opt-in extended Collect. Forces `-IncludeFileTimeline` and `-IncludeUsnJournal`, and adds task-referenced script copies, PnP inventory, DriverStore FileRepository inventory (hashes for `.sys`/`.inf`/`.cat` only, not a full binary tree), and elevated `gpresult /h` HTML. Task-script copies use raised caps (10k files / 1 GiB), are skipped when the output volume has under 2 GiB free, refuse non-local paths (`SkippedUnc`, no remote authentication), and keep drive letters in package paths so `C:\` and `D:\` copies do not collide. |
| `-NoZip` | Folder only |
| `-RequireAdministrator` | Exit if not elevated |
| `-Version` | Print version and schemas, collect nothing |

A standard-user run skips the Security log, Prefetch/Amcache/SRUM copies, registry hive exports, VSS, auditpol/secedit, and other users' files. Each skip is recorded (`SkippedNotElevated` in the manifest, `collection_coverage.json`). That is a **visibility gap**, not a clean host.

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "A. Examiner" -OutputPath D:\Cases -EventLogDays 30 -LoadUserHives
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "A. Examiner" -OutputPath D:\Cases -Deep
.\foton-collect.exe -CaseNumber SELF-AUDIT
```

Open `Foton_Report.html` **inside** the new folder. Send the **ZIP + `*_PACKAGE_HASH.txt`** (or the whole folder). The HTML alone is not the package.

### Baseline (known-state snapshot)

Writes `FotonBaseline_<HOSTNAME>_<UTC>Z\` with `baseline.json`, `coverage.json`, `Foton_Baseline.html`, hashes, and an optional ZIP. Not a triage collect: volatile state (PIDs, live connections, sessions) is out of scope.

| Switch | Purpose |
|--------|---------|
| `-OutputPath D:\Baselines` | Package parent folder (default: Desktop) |
| `-Path D:\Baselines\HOSTNAME.json` | Bare snapshot JSON instead of a package (HTML beside it) |
| `-NoZip`, `-NoHtml` | Skip the ZIP or the HTML |
| `-RequireAdministrator` | Exit if not elevated |
| `-Version` | Print version and schemas |

```powershell
.\foton-baseline.exe -OutputPath D:\Baselines -NoZip
.\foton-baseline.exe -Path D:\Baselines\HOSTNAME.json
```

A baseline taken after an incident is a picture of **that** state. Compare proves change between two observations, not when or who.

---

## 2. Workstation: `foton.exe`

| Verb | Purpose |
|------|---------|
| `package <case-folder-or-zip>` | Open a package and re-check every file against `00_Collection\hashes.csv`. Unsafe ZIP paths are refused |
| `parse <case-folder-zip-or-file>` | Parse copied Prefetch, LNK, jumplists, EVTX, and Amcache: `analysis\parsed_records.csv` + `Foton_Parse.html`. A single file prints its rows |
| `compose <case-folder>` | Run EZ Tools / Hayabusa / Chainsaw on the copied files: `analysis\external\` + `external_parse_inventory.csv`. Extracted folders only |
| `analyze <case-folder-or-zip>` | Run the triage heuristics: `analysis\findings.csv` + `Foton_Report.html`. Re-run after parse, compose, IOC, or compare |
| `ioc <case-folder-or-zip> <ioc-file>` | Match `sha256:` / `path:` / `text:` lines (or `.csv` Kind,Value, or JSON `{Kind,Value}`): `analysis\ioc_matches.csv` |
| `compare <reference> <difference>` | Field-level baseline diff: `baseline_diff.csv` + `Foton_BaselineCompare.html` beside the difference baseline. `-NoCsv`, `-NoHtml`, `-OutputPath <html>` |
| `tools` | List pinned and registered tools, and where compose finds them |
| `carve <blob>` | MZ/PE signature scan of a copied blob (Tier 3, not NTFS carving). `-MaxBytes`, `-MaxHits` (defaults 8 MiB / 50 hits) |

```powershell
.\foton.exe package D:\Cases\Foton_HOSTNAME_20260823-011150Z.zip
.\foton.exe parse   D:\Cases\Foton_HOSTNAME_20260823-011150Z
.\foton.exe compose D:\Cases\Foton_HOSTNAME_20260823-011150Z
.\foton.exe analyze D:\Cases\Foton_HOSTNAME_20260823-011150Z
.\foton.exe ioc     D:\Cases\Foton_HOSTNAME_20260823-011150Z D:\intel\iocs.txt
.\foton.exe carve   D:\evidence\unalloc-sample.bin -MaxBytes 67108864 -MaxHits 200
```

Why re-run `analyze`: **Collect already ran the heuristics on the endpoint**, so `analyze` on an untouched package reproduces `00_Collection\findings.csv` rather than adding detection, and says so. Parse, compose, IOC, and baseline compare add new findings; run them, then analyze again.

### Baseline compare

Mode is **Temporal** when the hostnames match, otherwise **Fleet**. Compare refuses a baseline schema it cannot read; see [Formats](#formats-and-compatibility).

**Temporal (same host, day 0 to later).** Capture at provisioning or another known-good moment, store it **off-host**, recapture later on that host, then compare:

```powershell
.\foton-baseline.exe -OutputPath D:\Baselines\day0 -NoZip     # day 0, store off-host
.\foton-baseline.exe -OutputPath D:\Baselines\dayN -NoZip     # day N, same host
.\foton.exe compare D:\Baselines\day0\FotonBaseline_HOSTNAME_...Z D:\Baselines\dayN\FotonBaseline_HOSTNAME_...Z
```

**Fleet (host against a role golden).** Capture a golden once on a representative build host, then compare each host against it. The wording is Fleet, not a certificate that the host is clean:

```powershell
.\foton-baseline.exe -OutputPath D:\Baselines\golden-web -NoZip
.\foton-baseline.exe -OutputPath D:\Baselines\hosts\WEB01 -NoZip
.\foton.exe compare D:\Baselines\golden-web\FotonBaseline_...Z D:\Baselines\hosts\WEB01\FotonBaseline_WEB01_...Z
```

Expect noise: hostname, SIDs, domain join, LAPS-managed local admin, software version bumps (Info). High-attention rows (service PathName, new Administrators member, Winlogon, IFEO, root CA added, and so on) cite the provider's false-positive notes. Confirm them against the role image; do not treat them as compromise.

To feed High-attention rows into a triage report, copy `baseline_diff.csv` into the case's `analysis\` folder and run `foton analyze` again.

### Parse

`foton parse` covers Prefetch (SCCA; compressed MAM is reported as unsupported, not guessed), LNK (`LocalBasePath` from LinkInfo), automatic and custom jumplists, selected EVTX Event IDs (capped), and Amcache `InventoryApplicationFile` (key last-write is not execution; legacy `File\*` is unsupported). SRUM is **copied, not parsed**.

### Compose (EZ Tools / Hayabusa / Chainsaw, optional)

Install the pinned Hayabusa release once, or register tools you already have. Tools live under `%LOCALAPPDATA%\Foton\tools` and are recorded in `tools.json` (the same file 1.38.x uses, so registrations carry over). PATH is never changed.

```powershell
.\foton.exe tools                                                # what is pinned, registered, and found
.\foton.exe tools Hayabusa                                       # download the pinned release, verify SHA-256, install (asks first; -Force skips)
.\foton.exe tools Hayabusa D:\Offline\hayabusa-4.0.0-win-x64.zip  # air-gapped install, same hash check
.\foton.exe tools EZTools C:\Tools\EZTools                       # register an existing folder (also Chainsaw <dir>); nothing downloaded
```

EZ Tools unpacks several tools into subfolders (`EvtxeCmd\`, `RECmd\`, `AmcacheParser\`) that a single PATH entry does not cover; registration records each executable's full path. The SHA-256 written to `tools.json` is what Foton observed on disk, not a verification against upstream. Compose looks in `tools.json` first, then PATH.

| Tool | What compose runs | Status when it cannot |
|------|-------------------|-----------------------|
| RECmd | `-d <hives> --bn BatchExamples\DFIRBatch.reb` (falls back to `Kroll_Batch.reb`) | `NoBatch` (RECmd exports nothing without a batch) |
| Chainsaw | `hunt` with `rules\` and/or `sigma\` + `mappings\sigma-event-logs-all.yml` beside the binary | `NoRules` |
| Hayabusa | `dfir-timeline` (or `csv-timeline`) with `-w` and `-U`, so there is no wizard and timestamps are UTC | `NotOnPath` points at `foton tools Hayabusa` |
| Any | stdout/stderr captured as `tool_stdout.txt` / `tool_stderr.txt` | `MissingRuntime` when the tool reports a missing .NET runtime (AmcacheParser is .NET 10 only) |

Each tool writes into a staging folder first. Compose replaces that tool's earlier output only when the run produces files, so those rows describe this run. When a tool does not run or produces nothing, earlier output is kept and listed as `Retained` with its hash, so the inventory still covers every file analyze reads. `compose` refuses a ZIP: its output belongs in the case folder, so extract the ZIP first.

Outputs land under `analysis\external\<tool>\` and are hashed. Missing tools are inventory rows (`NotOnPath`), not failures. Hayabusa hits are that engine's inferences (Tier 2) and name the tool. PECmd and EvtxECmd CSVs also feed `analyze` (coverage, user-writable path references, and a short list of high-attention Event IDs such as 1102 and 7045). RECmd, Chainsaw, LECmd, JLECmd, and AmcacheParser output is hashed and listed for the examiner but does not become findings.

### Analysis notes

- Suspicious-command patterns are matched only on events that carry command text (4688, Sysmon 1, 4104, 4697, 7045, 4698, 4702). On 4673/4674 the `ExecutableInfo` is the calling image (often `lsass.exe`), not a command.
- Rows inside the collection window (from `collection.log`) are excluded from the path and pattern counts and reported as an Info methodology finding. Attribution is by time only.
- Service installs (7045 and EvtxECmd 4697/7045) exclude per-user service instances of known Microsoft templates (`OneSyncSvc_1701f8` and similar) whose image is System32 `svchost.exe`; any other `Name_<hex>` service is still counted. Install events do not record `ServiceDll`, so analyze looks the instance up in `services.csv`. Instances already removed at logoff cannot be checked this way; read `Services\<name>\Parameters\ServiceDll` in the collected SYSTEM hive.
- A user-writable `ServiceDll` joins the High user-writable service finding; a `NotSigned` or `HashMismatch` one raises a Medium finding. Third-party and in-house svchost services are the usual benign source.
- Profile scans skip earlier Foton package folders on the host. Each skipped folder is listed in `collection_coverage.json` (`ExcludedEarlierPackages`) and in an Info finding, because the name and marker files that identify a package can be forged.
- Accounts created (4720) and deleted (4726) with the same SID within 60 seconds are reported separately (Low), which is typical of provisioning or local-admin rotation scripts. Persistent accounts and additions to privileged groups stay Medium.

**Collector footprint.** The collection is logged like any other activity: process creation for `foton-collect.exe` and the System32 tools it starts (`reg`, `wevtutil`, `auditpol`, `secedit`, and others), or script blocks for the 1.38.x PowerShell collector. Hunt rules for registry export and credential or policy access fire on it. `analyze` attributes such rows to the collection (by time inside the collection window, and by rows naming the collector outside it), excludes them from the Hayabusa severity bands, and reports the count as an Info methodology finding. That exclusion is inference, not process identity: genuine host activity during the collection window is excluded too, so filter the Hayabusa CSV to that window yourself if something could have coincided.

---

## Formats and compatibility

- **Collect schema 1.14.0.** The same files, tasks, and columns as 1.38.x (1.13.0), with timestamps in UTC, explicit statuses where 1.38.x wrote empty or misleading values (for example `AccessDenied` instead of `NotPresent` for an unreadable event log), and rows 1.38.x missed. `foton analyze` reads both.
- **Baseline schema 1.17.0.** `foton compare` accepts 1.14.0 (1.38.x), 1.15.0 (v2.0.0-alpha.1), 1.16.0 (v2.0.0), and 1.17.0 against each other and prints which one-time format and coverage differences to expect. Older baselines are refused; recapture day 0 and goldens.
- **Service `ServiceDll` (1.17.0).** A svchost-hosted service's `PathName` is the shared `svchost.exe`; the code it runs is its `ServiceDll`, so 1.17.0 records and compares that too, and a change is High attention. Against a baseline older than 1.17.0 the field is not compared (that side never captured it); recapture day 0 to compare it.
- **Cloud-only files.** Collect never reads a cloud-only file (OneDrive Files On-Demand and similar), because reading it would download it to the host: its hash reads `SkippedCloudPlaceholder`, its signature `CloudPlaceholderNotChecked`, and a copy task records `SkippedCloudPlaceholder`.
- `foton parse` also returns EVTX events and automatic-destinations jumplist entries that 1.38.x `Invoke-FotonParse` silently missed.

---

## What we will not hide

- Live collect **changes the host**. Capture memory/disk first if that is the case plan. `chain_of_custody.txt` lists the System32 tools the collector started.
- Elevated collect exports loaded registry hives (SYSTEM, SOFTWARE, DEFAULT, signed-in users' NTUSER/UsrClass) with `reg save` into the case folder. **SAM and SECURITY are not collected** (credential material); the manifest records them as `NotCollectedByDesign`. Use a full image or KAPE when a case needs them.
- A copy task whose files could not be captured shows **Partial** or **Failed** in the manifest, `collection_errors.csv`, and `collection_coverage.json`, not Success.
- Findings are **observations**, not "infected."
- Empty findings do not mean a clean host.
- A post-incident baseline is a picture of that observed state, not proof of when or who.

Carve limits: [CARVE.md](CARVE.md). Vulnerability reporting: [SECURITY.md](../SECURITY.md).

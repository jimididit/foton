# Operator usage

Foton has **two machines**. Mixing them is what usually causes confusion.

| Where | What you run | What you get |
|-------|--------------|--------------|
| **Endpoint** | `foton-collect.exe` or `foton-baseline.exe` (one file each) | Hashed case folder or baseline folder (+ ZIP) |
| **Workstation** | `foton.exe` | Parse, compose, analyze, IOC match, baseline compare, carve, package verification |

Copy only the endpoint executable to a target. Parse, compose, and analyze read the copied package on the workstation and never touch the live host.

**First time?** Start with [GETTING-STARTED.md](GETTING-STARTED.md). This page is the full reference.

**How to read the examples.** Examples are PowerShell, run from the folder holding the executables (`cd "\path\to\folder"` first).

- Paths like `"\path\to\case-folder"` are yours to fill in: replace the whole path, keep the quotes.
- Paths that start with `C:\Foton` are folders Foton creates; use them as written.
- In tables, `<case-folder>` and similar describe what a switch or verb takes; they are not meant to be pasted.

**Versions.** Every executable prints its version and the collect, baseline, and findings schemas it writes with `-Version` (see [Formats](#formats-and-compatibility)).

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

They run on the .NET Framework that ships with Windows (4.6.2+). Nothing is installed, and nothing is fetched at run time except by `foton tools`, which downloads a pinned, hash-checked Hayabusa or Chainsaw release only when you ask.

**Verify before use.** The executables are not code-signed yet, so Windows SmartScreen may warn when one is started from File Explorer. Trust comes from the hash and the build provenance, not a publisher certificate. In the folder holding the downloads, print the hash of each executable you have and compare each with its line in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\foton-collect.exe
```

The hashes come from the same release as the files, so this catches a corrupted or swapped download but not a release whose files and hash list were both replaced. `gh attestation verify` (needs the [GitHub CLI](https://cli.github.com/)) proves the file was built by this repository's release workflow from a specific commit. Run it for casework, once per file; if you cannot, record that only the hash was checked:

```powershell
gh attestation verify .\foton-collect.exe --repo jimididit/foton
```

A browser marks downloaded files as coming from the internet, which makes SmartScreen warn when you start one from File Explorer (running it from PowerShell is not affected). After both checks pass, `Unblock-File .\foton-collect.exe` removes that mark.

Record the collector's hash in the case notes so the report names the exact build that ran.

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
| `-OutputPath <folder>` | Case parent folder. Default: `C:\Foton\Cases` on the Windows drive, created readable only by SYSTEM, Administrators, and the account that runs the collection. If `C:\Foton` or `C:\Foton\Cases` already exists and is not private that way (another owner, other accounts with access, or a junction), the run stops before collecting. A folder you name is used as it is |
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

Each line below is a separate example; run the one you need, not the whole block.

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "A. Examiner"                                # standard collection to C:\Foton\Cases
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "A. Examiner" -EventLogDays 30 -LoadUserHives # longer event window, users not signed in
.\foton-collect.exe -CaseNumber CASE-0001 -Examiner "A. Examiner" -Deep                          # extended collection (larger, slower)
.\foton-collect.exe -CaseNumber CASE-0001 -OutputPath "\path\to\folder"                          # somewhere else, such as a USB drive
```

Open `Foton_Report.html` **inside** the new folder. Send the **ZIP + `*_PACKAGE_HASH.txt`** (or the whole folder). The HTML alone is not the package.

### Baseline (known-state snapshot)

Writes `FotonBaseline_<HOSTNAME>_<UTC>Z\` with `baseline.json`, `coverage.json`, `Foton_Baseline.html`, hashes, and an optional ZIP. Not a triage collect: volatile state (PIDs, live connections, sessions) is out of scope.

| Switch | Purpose |
|--------|---------|
| `-OutputPath <folder>` | Package parent folder. Default: `C:\Foton\Baselines`, created private like `C:\Foton\Cases` |
| `-Path <file.json>` | Bare snapshot JSON instead of a package (HTML beside it); its folder is created if needed |
| `-NoZip`, `-NoHtml` | Skip the ZIP or the HTML |
| `-RequireAdministrator` | Exit if not elevated |
| `-Version` | Print version and schemas |

Run one of these:

```powershell
.\foton-baseline.exe                                                            # package in C:\Foton\Baselines
.\foton-baseline.exe -NoZip                                                     # folder only
.\foton-baseline.exe -Path "\path\to\snapshot.json"                             # bare JSON
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

Check the ZIP first, extract it into a new, empty folder (right-click, **Extract All**), then run the verbs on the extracted case folder (the `Foton_...` folder that holds `00_Collection`):

```powershell
.\foton.exe package "\path\to\Foton_case.zip"
.\foton.exe parse   "\path\to\case-folder"
.\foton.exe compose "\path\to\case-folder"
.\foton.exe analyze "\path\to\case-folder"
```

Run `analyze` last: it reads what parse and compose wrote.

`ioc` takes a text file of indicators, one per line, each starting with its kind:

```text
sha256:<64 hexadecimal characters>
path:\Users\Public\
text:mimikatz
```

```powershell
.\foton.exe ioc "\path\to\case-folder" "\path\to\iocs.txt"
```

`carve` scans a file you already copied, such as an unallocated-space export from another tool:

```powershell
.\foton.exe carve "\path\to\file" -MaxBytes 67108864 -MaxHits 200
```

Why re-run `analyze`: **Collect already ran the heuristics on the endpoint**, so `analyze` on an untouched package reproduces `00_Collection\findings.csv` rather than adding detection, and says so. Parse, compose, IOC, and baseline compare add new findings; run them, then analyze again.

### Baseline compare

Mode is **Temporal** when the hostnames match, otherwise **Fleet**. Compare refuses a baseline schema it cannot read; see [Formats](#formats-and-compatibility).

**Temporal (same host, day 0 to later).** Capture at provisioning or another known-good moment, store it **off-host**, recapture later on that host, then compare:

On day 0, then again on a later day:

```powershell
.\foton-baseline.exe
```

Each run adds a `FotonBaseline_...` folder to `C:\Foton\Baselines`; copy the day 0 one off the host. Compare with the reference (earlier) baseline first and the later one second. Each argument can be a baseline folder or its `baseline.json`:

```powershell
.\foton.exe compare "\path\to\day0-baseline-folder" "\path\to\later-baseline-folder"
```

**Fleet (host against a role golden).** Capture a golden once on a representative build host, then compare each host against it. The wording is Fleet, not a certificate that the host is clean:

Run `.\foton-baseline.exe` on the golden build host and on each host, copy the baseline folders to the workstation, and compare the golden (first) against a host (second):

```powershell
.\foton.exe compare "\path\to\golden-baseline-folder" "\path\to\host-baseline-folder"
```

Expect noise: hostname, SIDs, domain join, LAPS-managed local admin, software version bumps (Info). High-attention rows (service PathName, new Administrators member, Winlogon, IFEO, root CA added, and so on) cite the provider's false-positive notes. Confirm them against the role image; do not treat them as compromise.

To feed High-attention rows into a triage report, copy `baseline_diff.csv` into the case's `analysis\` folder and run `foton analyze` again.

### Parse

`foton parse` covers Prefetch (SCCA; compressed MAM is reported as unsupported, not guessed), LNK (`LocalBasePath` from LinkInfo), automatic and custom jumplists, selected EVTX Event IDs (capped), and Amcache `InventoryApplicationFile` (key last-write is not execution; legacy `File\*` is unsupported). SRUM is **copied, not parsed**.

### Compose (EZ Tools / Hayabusa / Chainsaw, optional)

Install the pinned Hayabusa and Chainsaw releases once, and register EZ Tools you already have. Tools live under `%LOCALAPPDATA%\Foton\tools` and are recorded in `tools.json` (the same file 1.38.x uses, so registrations carry over). PATH is never changed.

```powershell
.\foton.exe tools                   # what is pinned, registered, and found
.\foton.exe tools Hayabusa -Force   # download the pinned release, verify SHA-256, install
.\foton.exe tools Chainsaw -Force   # same for Chainsaw: the release that bundles rules, Sigma rules, and mappings
```

Without `-Force`, `tools Hayabusa` and `tools Chainsaw` ask before downloading; when you paste several lines at once, the next line would be taken as the answer, so the examples pass `-Force`. On a computer without internet access, download the release ZIP elsewhere and install from it (same hash check). To register Eric Zimmerman's tools you already have, point at their folder (nothing is downloaded). Run the line you need:

```powershell
.\foton.exe tools Hayabusa "\path\to\hayabusa-4.0.0-win-x64.zip"
.\foton.exe tools Chainsaw "\path\to\chainsaw_all_platforms+rules.zip"
.\foton.exe tools EZTools "\path\to\EZTools"
```

Pinned versions: Hayabusa 4.0.0 and Chainsaw 2.17.1 (`chainsaw_all_platforms+rules.zip`; Sigma test data and repository extras in the archive are not extracted). EZ Tools are not pinned: they are published at unversioned URLs whose contents change with each update, so a hash pin would go stale. Download them with Eric Zimmerman's `Get-ZimmermanTools` (from [ericzimmerman.github.io](https://ericzimmerman.github.io/)) and register the folder.

EZ Tools unpacks several tools into subfolders (`EvtxeCmd\`, `RECmd\`, `AmcacheParser\`) that a single PATH entry does not cover; registration records each executable's full path. The SHA-256 written to `tools.json` is what Foton observed on disk, not a verification against upstream. Compose looks in `tools.json` first, then PATH.

| Tool | What compose runs | Status when it cannot |
|------|-------------------|-----------------------|
| RECmd | `-d <hives> --bn BatchExamples\DFIRBatch.reb` (falls back to `Kroll_Batch.reb`) | `NoBatch` (RECmd exports nothing without a batch) |
| Chainsaw | `hunt` with `rules\` and/or `sigma\` + `mappings\sigma-event-logs-all.yml` beside the binary | `NoRules` (install the pinned release: `foton tools Chainsaw`) |
| Hayabusa | `dfir-timeline` (or `csv-timeline`) with `-w` and `-U`, so there is no wizard and timestamps are UTC | `NotOnPath` points at `foton tools Hayabusa` |
| Any | stdout/stderr captured as `tool_stdout.txt` / `tool_stderr.txt` | `MissingRuntime` when the tool reports a missing .NET runtime (AmcacheParser is .NET 10 only) |

Each tool writes into a staging folder first. Compose replaces that tool's earlier output only when the run produces files, so those rows describe this run. When a tool does not run or produces nothing, earlier output is kept and listed as `Retained` with its hash, so the inventory still covers every file analyze reads. `compose` refuses a ZIP: its output belongs in the case folder, so extract the ZIP first.

Outputs land under `analysis\external\<tool>\` and are hashed. Missing tools are inventory rows (`NotOnPath`), not failures. Hayabusa hits are that engine's inferences (Tier 2) and name the tool. PECmd and EvtxECmd CSVs also feed `analyze` (coverage, user-writable path references, and a short list of high-attention Event IDs such as 1102 and 7045). RECmd batch output feeds it too: an Info overview (rows by hive type and category, Threat Hunting entries), a Medium finding when Autoruns, Services, or Threat Hunting values name user-writable paths, and an Info finding for keys or values RECmd recovered as deleted. RECmd reads every copied hive, including users whose hives were not loaded at collection time. Chainsaw hunt CSVs become one Info overview (detection rows and top rule titles, with rows the collection itself caused counted apart); Chainsaw's CSV carries no rule level, so read the rule before treating a title as severe. LECmd and JLECmd CSVs each become an Info overview (rows, distinct targets, and targets on removable media or network paths), a Medium finding when an executable or script target sits in a user-writable path, and a Medium finding when a target's arguments match a suspicious-command pattern. Documents in Downloads or AppData are not flagged. AmcacheParser CSVs become an Info overview (rows by CSV kind), a Medium finding for executables or scripts inventoried under user-writable paths (rows marked `IsOsComponent` are left out), and a Medium finding for drivers recorded as unsigned and not shipped with Windows. On Windows 10 and later an Amcache entry shows a file was present, not that it ran.

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
- **Long file names.** Windows tools fail on paths of 260 characters or more, and a package is extracted under other folders later. When a copied file's path inside the case folder would exceed 160 characters (Game Bar and phone-notification shortcuts in `Recent` reach 190-character names), Collect shortens the name to a prefix plus `~` and eight hex digits, keeps the extension, and says so in the copy row's note; `SourcePath` keeps the original name. `foton package` on a ZIP that still holds longer paths (Foton 2.2.0 and earlier) lists them as not extracted instead of failing; extract that ZIP to a short folder to check them.
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

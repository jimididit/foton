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

Each [GitHub Release](https://github.com/jimididit/foton/releases) (tags `v2.*` and later) carries:

| Asset | For |
|-------|-----|
| `foton-collect.exe` | Endpoint live triage |
| `foton-baseline.exe` | Endpoint baseline capture |
| `foton.exe` | Analyst workstation |
| `foton-console.exe` | Analyst workstation, in a window ([section 3](#3-workstation-window-foton-consoleexe)) |
| `SHA256SUMS.txt` | Hashes of the four executables |

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
| `-IncludeUsnJournal` | Also export the NTFS change journal (`$J`) of the system volume, elevated only: its records are read with `FSCTL_READ_USN_JOURNAL` (as `fsutil` does) into `08_Filesystem\usn\UsnJrnl_J.bin`, which MFTECmd parses as `$J`. Capped at 1 GiB, keeping the newest records. The default is `fsutil usn queryjournal` text only. **`$MFT` is never copied** (use KAPE/ORC), so journal records carry file names but not full parent paths. |
| `-Deep` | Opt-in extended Collect. Forces `-IncludeFileTimeline` and `-IncludeUsnJournal`, and adds task-referenced script copies, PnP inventory, DriverStore FileRepository inventory (hashes for `.sys`/`.inf`/`.cat` only, not a full binary tree), and elevated `gpresult /h` HTML and `gpresult /x` XML. Task-script copies use raised caps (10k files / 1 GiB), are skipped when the output volume has under 2 GiB free, refuse non-local paths (`SkippedUnc`, no remote authentication), and keep drive letters in package paths so `C:\` and `D:\` copies do not collide. |
| `-NoZip` | Folder only |
| `-RequireAdministrator` | Exit if not elevated |
| `-Profile <file>` | Collect what a profile file selects, with its switch defaults ([Collection profiles](#collection-profiles)) |
| `-Category <names>` | Collect only these categories, comma-separated (replaces a profile's list when both are given) |
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

#### Collection profiles

A profile limits a collection to the categories a case needs and can carry the switches you would otherwise type. Categories: `Processes`, `Network`, `Users`, `System`, `Persistence`, `Security`, `Software`, `EventLogs`, `Filesystem`.

```json
{
  "Name": "Persistence review",
  "Description": "Autoruns, services, tasks, and the logs that record their changes",
  "Categories": ["System", "Persistence", "Security", "EventLogs"],
  "ExcludeTasks": ["security_policy_and_log_changes"],
  "Options": { "EventLogDays": 30, "LoadUserHives": true }
}
```

Every key is optional. Without `Categories` every category is collected. `ExcludeTasks` takes task names from the Task column of `collection_manifest.csv`, plus `evtx_export` for the raw `.evtx` copies; a name that is not a Collect task stops the run before anything is collected. `Options` accepts `EventLogDays`, `MaxEventsPerLog`, `SkipEvtxExport`, `SkipHashing`, `LoadUserHives`, `IncludeFileTimeline`, `IncludeUsnJournal`, `Deep`, `NoZip`, and `RequireAdministrator`; a switch on the command line overrides the same option in the profile. A key, category, or value Foton does not recognise stops the run before anything is collected.

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -Profile "\path\to\profile.json"     # the profile's selection and switches
.\foton-collect.exe -CaseNumber CASE-0001 -Category "System,Persistence"       # two categories, every task in them
```

A task the profile leaves out is not run. Its artifact holds a one-line note, the manifest records `NotSelected`, `collection_coverage.json` lists it, and the profile is copied into the package as `00_Collection\collection_profile.json` with its SHA-256 in the chain of custody. `analyze` names the profile in an Info finding and draws no conclusion from what it left out. The custody record, coverage, manifest, hashing, and the end-of-run report always run.

To build a profile without writing JSON, use the **Profile** tab of `foton-console.exe` ([section 3](#3-workstation-window-foton-consoleexe)); it can also package the profile with `foton-collect.exe` for an endpoint.

### Baseline (known-state snapshot)

Writes `FotonBaseline_<HOSTNAME>_<UTC>Z\` with `baseline.json`, `coverage.json`, `Foton_Baseline.html`, hashes, and an optional ZIP. Not a triage collect: volatile state (PIDs, live connections, sessions) is out of scope.

| Switch | Purpose |
|--------|---------|
| `-OutputPath <folder>` | Package parent folder. Default: `C:\Foton\Baselines`, created private like `C:\Foton\Cases` |
| `-Path <file.json>` | Bare snapshot JSON instead of a package (HTML beside it); its folder is created if needed |
| `-NoZip`, `-NoHtml` | Skip the ZIP or the HTML |
| `-RequireAdministrator` | Exit if not elevated |
| `-LoadUserHives` | Load NTUSER.DAT for users not logged on, so their per-user rows are captured (elevated only; unloaded in `finally`) |
| `-Version` | Print version and schemas |

Run one of these:

```powershell
.\foton-baseline.exe                                                            # package in C:\Foton\Baselines
.\foton-baseline.exe -NoZip                                                     # folder only
.\foton-baseline.exe -Path "\path\to\snapshot.json"                             # bare JSON
.\foton-baseline.exe -LoadUserHives                                             # include users not signed in
```

Without `-LoadUserHives`, a baseline sees only the users signed in at that moment. Their per-user rows (UserAutorun, StartupApproved, ProxyConfig, CmdAutoRun) come and go between baselines as people sign in and out. `-LoadUserHives` mounts each other user's `NTUSER.DAT` under `HKEY_USERS` for the capture and unmounts it afterwards. That is a registry write on the host, recorded in the baseline header and log. Use the same choice for every baseline you plan to compare; Compare warns when only one side used it.

A baseline taken after an incident is a picture of **that** state. Compare proves change between two observations, not when or who.

---

## 2. Workstation: `foton.exe`

| Verb | Purpose |
|------|---------|
| `package <case-folder-or-zip>` | Open a package and re-check every file against `00_Collection\hashes.csv`. Unsafe ZIP paths are refused |
| `parse <case-folder-zip-or-file>` | Parse copied Prefetch, LNK, jumplists, EVTX, and Amcache: `analysis\parsed_records.csv` + `Foton_Parse.html`. A single file prints its rows |
| `compose <case-folder-or-zip>` | Run EZ Tools / Hayabusa / Chainsaw on the copied files: `analysis\external\` + `external_parse_inventory.csv` |
| `analyze <case-folder-or-zip>` | Run the triage heuristics: `analysis\findings.csv` + `Foton_Report.html`. Re-run after parse, compose, IOC, or compare |
| `ioc <case-folder-or-zip> <ioc-file>` | Match `sha256:` / `path:` / `text:` lines (or `.csv` Kind,Value, or JSON `{Kind,Value}`): `analysis\ioc_matches.csv` |
| `compare <reference> <difference>` | Field-level baseline diff: `baseline_diff.csv` + `Foton_BaselineCompare.html` beside the difference baseline. `-NoCsv`, `-NoHtml`, `-OutputPath <html>` |
| `tools` | List pinned and registered tools, and where compose finds them |
| `carve <blob>` | MZ/PE signature scan of a copied blob (Tier 3, not NTFS carving). `-MaxBytes`, `-MaxHits` (defaults 8 MiB / 50 hits) |
| `timeline <case-folder-or-zip>` | One list of the package's recorded times, sorted by UTC, each with what that time means: `analysis\timeline.csv` + `timeline_sources.csv`. `-From`, `-To` (UTC date or `"yyyy-MM-dd HH:mm:ss"`), `-All` ([Timeline](#timeline)) |
| `notes <case-folder-or-zip>` | List each finding's review status and the examiner notes in `analysis\examiner_notes.json` (`-Json` for scripts), or set one: `-Key <key>` (a finding or note key it lists, or at least 8 characters of one) or `-Artifact <file> -Row <n>`, with `-Status`, `-Text`, `-Examiner` ([Examiner notes](#examiner-notes)) |
| `bundle collect` / `bundle baseline` | Build a folder to carry to an endpoint: the collector `foton.exe` carries (the one released with it), `RUN.txt` with the command, and `SHA256SUMS.txt`. `collect` takes `-Profile <profile.json>` (without one, every category); `baseline` takes `-LoadUserHives`. Both take `-OutputPath <folder>` (default `C:\Foton\Bundles`) |
| `search <case-folder-or-zip> <text>` | Find a text (case-insensitive) in every CSV, JSON, text, log, XML, and HTML file of the package; `-Regex` for a regular expression. Hits name the file and CSV row and column, or line: `analysis\search_<UTC>.csv` + `.txt` ([Search](#search)) |
| `handoff <case-folder-or-zip>` | Write the review for another examiner: `Foton_Handoff_<case>_<UTC>` under `C:\Foton\Handoffs` (or `-OutputPath <folder>`) with findings, examiner notes, `Foton_Handoff.html`, custody and `hashes.csv` copies, `HANDOFF.txt`, and `SHA256SUMS.txt`. Exit 2 when the package does not verify ([Handoff](#handoff)) |
| `cases` | List the case and baseline packages in `C:\Foton\Cases`, `C:\Foton\Baselines`, and each `-Path <folder>`: host, time, case number, examiner, elevated, profile, finding counts, and which of parse, compose, and analyze have run. `-Json` for scripts. Read-only and does not hash; use `package` to verify |

`package`, `parse`, `compose`, `analyze`, and `ioc` take the package ZIP or a case folder (the `Foton_...` folder that holds `00_Collection`). The first of them run on a ZIP extracts it once, beside the ZIP, into a folder named like the ZIP with `-extracted` at the end. Later verbs reuse that folder and write their outputs into it, so the report ends up in `...-extracted\Foton_...\Foton_Report.html`. Foton needs write access to the folder holding the ZIP.

Each verb re-hashes the ZIP before reusing the folder. If the ZIP was replaced, or the folder was not left by a finished Foton extraction, the verb stops and names the folder; Foton never deletes it, so move or remove it yourself.

`foton package` on a ZIP checks the files inside the ZIP against its `hashes.csv`, so later outputs in the folder do not affect the result. It then checks the folder too, because parse, compose, and analyze read from it: a collected file that changed there is reported (exit code 2), except `Foton_Report.html`, which `analyze` rewrites.

Check the ZIP first, then run the other verbs on the same ZIP:

```powershell
.\foton.exe package "\path\to\Foton_case.zip"
.\foton.exe parse   "\path\to\Foton_case.zip"
.\foton.exe compose "\path\to\Foton_case.zip"
.\foton.exe analyze "\path\to\Foton_case.zip"
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
| AppCompatCacheParser | `-f <hives\machine\SYSTEM> --nl` (Shimcache; the `reg save` export has no transaction logs) | `NoInput` when the package has no SYSTEM hive (standard-user collect) |
| SBECmd | `-d <hives\users> --nl` (shellbags, one CSV per NTUSER.DAT / UsrClass.dat) | `NoInput` when the package has no user hives |
| SrumECmd | `-f <srum\SRUDB.dat> -r <hives\machine\SOFTWARE>` (when present) with its temporary database copy in the staging folder | `NoInput` when the package has no SRUM copy (standard-user collect) |
| MFTECmd | `-f <usn\UsnJrnl_J.bin>` (the change journal exported with `-IncludeUsnJournal`) | `NoInput` when the collection did not include the journal (no `-IncludeUsnJournal` or `-Deep`; the `usn_journal` task alone records journal metadata) |
| Chainsaw | `hunt` with `rules\` and/or `sigma\` + `mappings\sigma-event-logs-all.yml` beside the binary | `NoRules` (install the pinned release: `foton tools Chainsaw`) |
| Hayabusa | `dfir-timeline` (or `csv-timeline`) with `-w` and `-U`, so there is no wizard and timestamps are UTC | `NotOnPath` points at `foton tools Hayabusa` |
| Any | stdout/stderr captured as `tool_stdout.txt` / `tool_stderr.txt` | `MissingRuntime` when the tool reports a missing .NET runtime (AmcacheParser is .NET 10 only) |

Each tool writes into a staging folder first. Compose replaces that tool's earlier output only when the run produces files, so those rows describe this run. When a tool does not run or produces nothing, earlier output is kept and listed as `Retained` with its hash, so the inventory still covers every file analyze reads. On a ZIP, compose works in the ZIP's `-extracted` folder like every other verb.

Outputs land under `analysis\external\<tool>\` and are hashed. Missing tools are inventory rows (`NotOnPath`), not failures; a tool unchecked in the console's **Compose runs** list is `NotSelected`. Hayabusa hits are that engine's inferences (Tier 2) and name the tool. PECmd and EvtxECmd CSVs also feed `analyze` (coverage, user-writable path references, and a short list of high-attention Event IDs such as 1102 and 7045). RECmd batch output feeds it too: an Info overview (rows by hive type and category, Threat Hunting entries), a Medium finding when Autoruns, Services, or Threat Hunting values name user-writable paths, and an Info finding for keys or values RECmd recovered as deleted. RECmd reads every copied hive, including users whose hives were not loaded at collection time. Chainsaw hunt CSVs become one Info overview (detection rows and top rule titles, with rows the collection itself caused counted apart); Chainsaw's CSV carries no rule level, so read the rule before treating a title as severe. LECmd and JLECmd CSVs each become an Info overview (rows, distinct targets, and targets on removable media or network paths), a Medium finding when an executable or script target sits in a user-writable path, and a Medium finding when a target's arguments match a suspicious-command pattern. Documents in Downloads or AppData are not flagged. AmcacheParser CSVs become an Info overview (rows by CSV kind), a Medium finding for executables or scripts inventoried under user-writable paths (rows marked `IsOsComponent` are left out), and a Medium finding for drivers recorded as unsigned and not shipped with Windows. On Windows 10 and later an Amcache entry shows a file was present, not that it ran. AppCompatCacheParser (Shimcache) CSVs become an Info overview (entries per control set, how many are marked Executed) and a Medium finding for executables or scripts in user-writable paths; the Executed flag is the tool's reading of an insert flag, not proof of execution. SBECmd (shellbags) CSVs become one Info overview: folders browsed per user hive, phone and camera (MTP) entries, network paths, archive contents, and drive letters other than the system drive. A drive letter alone does not say whether the volume was removable. SrumECmd (SRUM) CSVs become an Info overview (rows per table, distinct apps, the dates covered) and a Medium finding for executables in user-writable paths that used the network, with bytes sent and received; SRUM counts bytes per app per hour, not destinations. MFTECmd (USN journal) CSVs become an Info overview (creates, deletes, and renames in the period covered) and an Info list of executables or scripts created, by name only: without `$MFT` the journal has no folder paths. Journal rows inside the collection window are counted apart, because the collector writes its own output to the volume.

EZ Tools registered with Foton 2.4.0 or earlier list six tools; run `.\foton.exe tools EZTools "\path\to\EZTools"` again so AppCompatCacheParser, SBECmd, SrumECmd, and MFTECmd are found too.

### Timeline

`foton timeline` puts the package's recorded times in one list, sorted by UTC, so you can read what happened around a moment. Run it after `compose` to include the EZ Tools, Hayabusa, and Chainsaw outputs; without compose it still reads Foton's own CSVs.

```powershell
.\foton.exe timeline "\path\to\Foton_case.zip"
.\foton.exe timeline "\path\to\case-folder" -From 2026-11-01 -To "2026-11-09 18:00:00"
```

Each row of `analysis\timeline.csv` has the time (UTC), the source, what that time means, a summary, the artifact and row it came from, and `DuringCollection` when it falls inside the collection window (the collector's own activity, such as its file writes in the USN journal, shows up there). A time means only what its source recorded: a Prefetch run time is a run, a Shimcache time is the file's modified time (not a run), an Amcache entry shows a file was present, and times a shortcut or jump list holds about its target are labelled as recorded in it.

| Source | Times |
|--------|-------|
| PECmd, EvtxECmd, Hayabusa, Chainsaw | Prefetch run times; events; rule hits (the engine named) |
| LECmd, JLECmd, SBECmd | Shortcut and jump-list times, and target times they record; shellbag folder interactions |
| AppCompatCacheParser, AmcacheParser | Shimcache file modified times; Amcache file, driver, and shortcut entries written |
| RECmd, SrumECmd, MFTECmd | Registry keys last written; SRUM network connections and network use per hour; USN journal changes |
| Foton's own CSVs | Process starts, scheduled-task last runs, Defender detections, BAM last runs, Recycle Bin deletions, recently modified system files; exported event logs only when there is no EvtxECmd output (the same events) |

SRUM's hourly counter tables (resource use, app timeline, energy, push notifications) are left out unless you add `-All`. Scheduled-task and Defender status times come only from Foton 2 packages; earlier packages wrote them in local time. `analysis\timeline_sources.csv` lists every artifact read: rows read, times used, cells without a usable time, times outside `-From`/`-To`, and why an artifact was left out. The timeline stops at 2,000,000 rows and says so; narrow it with `-From` and `-To`. It is a reading aid: it raises no findings.

### Examiner notes

`foton notes` records an examiner's review: a status (Not reviewed, Reviewed, Relevant, Not relevant, Follow up) and a note for each finding, and for any row of a CSV in the package. They are kept in `analysis\examiner_notes.json`, apart from `findings.csv` and the report, and are labelled as examiner input wherever they are shown.

```powershell
.\foton.exe notes "\path\to\case-folder"
.\foton.exe notes "\path\to\case-folder" -Key 3F2A9C1B -Status Relevant -Text "Matches the ticket's timeframe"
.\foton.exe notes "\path\to\case-folder" -Artifact 05_Persistence\scheduled_tasks.csv -Row 12 -Status "Follow up"
```

The listing shows every finding, most severe first, with its status and key (the first 12 characters; any unique 8 or more work with `-Key`). A finding's key comes from its category, title, artifact, and observation, so its note follows it when `analyze` runs again and produces the same finding. When a later analyze no longer produces it (new data, or a rule that words it differently), the note is kept and listed under notes on findings the latest analyze does not produce. A row note records the row's SHA-256, and the listing says when the row reads differently. A status of Not reviewed with no text removes the note. The examiner defaults to the one in the case's chain of custody. A notes file Foton cannot read is refused, never overwritten.

### Search

`foton search` looks for one value across the whole package: a user name, a file name, an IP address, a hash.

```powershell
.\foton.exe search "\path\to\case-folder" "invoice.exe"
.\foton.exe search "\path\to\Foton_case.zip" "10\.0\.0\.\d+" -Regex
```

It reads every CSV, JSON, text, log, XML, and HTML file in the package, the collected files and the outputs of parse, compose, analyze, and timeline alike, so run it after compose to include the EZ Tools, Hayabusa, and Chainsaw results. Matching ignores case. A CSV hit names the row (1 is the first row after the header) and column; a hit in another file names the line. Binary artifacts such as `.evtx`, hives, and Prefetch are not searched (compose turns them into CSVs that are), and neither are links, files over 2 GB, or files that cannot be read; the summary lists each one. A regular expression gets one second per line; a line where it runs out of time is skipped and counted. Lines longer than 65,536 characters are searched in pieces of that size, so a match split across two pieces is missed. The first 10,000 hits are written to `analysis\search_<UTC>.csv`; every match is counted, and `analysis\search_<UTC>.txt` records the search, the counts, and what was not searched. Earlier search results are not searched.

### Handoff

`foton handoff` puts the review of one package in a folder another examiner can read and check:

```powershell
.\foton.exe handoff "\path\to\case-folder"
.\foton.exe handoff "\path\to\Foton_case.zip" -OutputPath "D:\Cases\Handoffs"
```

`Foton_Handoff_<case>_<UTC>` holds `findings.csv`, `examiner_notes.json` and `examiner_notes.csv` (every finding with its status, then the other notes), `Foton_Handoff.html` (findings and the examiner's review side by side, labelled apart, with offline search), `package\chain_of_custody.txt` and `package\hashes.csv`, `HANDOFF.txt`, and `SHA256SUMS.txt` listing every other file. The package is not copied: `HANDOFF.txt` names it by the SHA-256 of its `hashes.csv` (and of the ZIP, when opened from one) and says whether it verified when the handoff was written; a package that does not verify still gets a handoff that says so, and the exit code is 2. A notes file Foton cannot read stops the handoff. `foton handoff` does not copy `Foton_Report.html`, because it cannot tell where that file was written; the console's **Export handoff** adds the report it built with **Analyze**, when unchanged.

### Analysis notes

- Suspicious-command patterns are matched only on events that carry command text (4688, Sysmon 1, 4104, 4697, 7045, 4698, 4702). On 4673/4674 the `ExecutableInfo` is the calling image (often `lsass.exe`), not a command.
- Rows inside the collection window (from `collection.log`) are excluded from the path and pattern counts and reported as an Info methodology finding. Attribution is by time only.
- Service installs (7045 and EvtxECmd 4697/7045) exclude per-user service instances of known Microsoft templates (`OneSyncSvc_1701f8` and similar) whose image is System32 `svchost.exe`; any other `Name_<hex>` service is still counted. Install events do not record `ServiceDll`, so analyze looks the instance up in `services.csv`. Instances already removed at logoff cannot be checked this way; read `Services\<name>\Parameters\ServiceDll` in the collected SYSTEM hive.
- A user-writable `ServiceDll` joins the High user-writable service finding; a `NotSigned` or `HashMismatch` one raises a Medium finding. Third-party and in-house svchost services are the usual benign source.
- Profile scans skip earlier Foton package folders on the host. Each skipped folder is listed in `collection_coverage.json` (`ExcludedEarlierPackages`) and in an Info finding, because the name and marker files that identify a package can be forged.
- Accounts created (4720) and deleted (4726) with the same SID within 60 seconds are reported separately (Low), which is typical of provisioning or local-admin rotation scripts. Persistent accounts and additions to privileged groups stay Medium.

**Collector footprint.** The collection is logged like any other activity: process creation for `foton-collect.exe` and the System32 tools it starts (`reg`, `wevtutil`, `auditpol`, `secedit`, and others), or script blocks for the 1.38.x PowerShell collector. Hunt rules for registry export and credential or policy access fire on it. `analyze` attributes such rows to the collection (by time inside the collection window, and by rows naming the collector outside it), excludes them from the Hayabusa severity bands, and reports the count as an Info methodology finding. That exclusion is inference, not process identity: genuine host activity during the collection window is excluded too, so filter the Hayabusa CSV to that window yourself if something could have coincided.

---

## 3. Workstation window: `foton-console.exe`

A window for the same workstation work, for when you would rather click than type. It runs the same code as `foton.exe`, writes the same files, and never reads the live host.

1. Start `foton-console.exe`; it opens on the **Cases** tab, where **Start here** builds a collector or baseline collector to run on an endpoint (the **Collectors** tab) or opens a case folder or ZIP. Or pass a package on its command line to open it straight away: `.\foton-console.exe "\path\to\Foton_case.zip"`. Once a case is open, the **Package** tab lists its next steps (verify, parse, compose, analyze, timeline, review, hand off) with what each has done; **Do this next** runs the first one not done.
2. On **Cases**, select a case and press **Open** (or double-click it). On the **Package** tab, **Open folder...** or **Open ZIP...** loads a case folder or package ZIP (a ZIP is extracted beside it, as with `foton.exe`). Findings already in the package are listed.
3. **Verify** checks every file against `hashes.csv`, as `foton package` does. **Parse**, **Compose**, and **Analyze** run those verbs; **Parse, compose, analyze** runs all three in order.
4. Select a finding to read why it matters, the source artifact, and the next step. **Show artifact** (or double-clicking the finding) opens that artifact in the **Viewer** tab. **Show case folder** opens the folder in Explorer. Filter the findings by **Severity**, **Status**, and **Find**; under the details, set the finding's [examiner](#examiner-notes) status and note and press **Save note**.
5. **Open report** opens `Foton_Report.html` in your browser only when this window built it with **Analyze** and the file has not changed since. The report already in a package was written on the endpoint, and a browser runs whatever an HTML file contains, so for that one the console asks to run **Analyze** first and opens the rebuilt report.
6. **Match IOCs...** runs `foton ioc` with an indicator list you choose (text, CSV, or JSON, as above). Matches are listed in the log and written to `analysis\ioc_matches.csv`, which opens in the **Viewer**.

The log pane under the tabs shows the same lines `foton.exe` prints. One action runs at a time; the buttons come back when it finishes.

The menu bar has **File** (open a case folder or ZIP, **Recent cases**, exit), **View** (find on this tab, refresh this tab, **Theme**, **Text size**, go to a tab), **Tools** (**Settings...**, and the Tools and Profile tabs), and **Help** (keyboard shortcuts, and **About**, which shows the version, schemas, release date, and the SHA-256 of `foton-console.exe` to compare with `SHA256SUMS.txt`). Shortcuts: Ctrl+O open a case folder, Ctrl+Shift+O open a ZIP, Ctrl+F find on this tab, F5 refresh this tab, Ctrl+1 to Ctrl+0 go to a tab, Ctrl+comma settings.

**Settings** holds the console's own preferences, in `%LOCALAPPDATA%\Foton\console-settings.json` (never in a package). **General**: the examiner name filled in for notes, whether the window opens on the **Cases** tab or the last case opened, and how many recent cases **File** lists. **Appearance**: **Light**, **Dark**, or **Follow Windows** (Windows' light or dark app setting, followed when it changes), and text size from 9 to 12 pt; **View** changes both too. Dark colors the window's panels, lists, grids, tabs, menus, and log; Windows still draws the title bar, scroll bars, check boxes, message boxes, and the file and folder dialogs in its own colors. With Windows High Contrast on, the console uses Windows' colors whatever theme is chosen. **Folders**: where you keep cases and baselines (the **Cases** tab lists them), where the **Collectors** tab builds bundles, and where **Export handoff** writes handoffs (empty uses `C:\Foton\Cases`, `C:\Foton\Baselines`, `C:\Foton\Bundles`, `C:\Foton\Handoffs`), and other folders for the **Cases** tab to list. Folders must be full paths. A setting the console cannot read falls back to its default without affecting the others.

The **Tools** tab lists the tools compose can find: the catalog-pinned releases (installed or not) and installs registered from a folder, with where each one is. **Install Hayabusa...** and **Install Chainsaw...** show the pinned version, license, and SHA-256, then download the release or take an archive you already downloaded (for a workstation without internet). Either way it is installed only when its SHA-256 matches the pin, as with `foton tools`. **Register existing** records an install you already have (choose `EZTools` for the Eric Zimmerman tools folder, or one tool) without downloading anything. **Compose runs** picks the tools **Compose** runs; a tool left unchecked is listed as `NotSelected` in the inventory, and its earlier output is kept as `Retained`. PATH is never changed.

The **Profile** tab builds a [collection profile](#collection-profiles). Check the categories and tasks to collect (a category is collected while any of its tasks is checked; its unchecked tasks become `ExcludeTasks`) and set each option to **On**, **Off**, or **Default** (the profile leaves it to the collector, where every one of them is off unless its switch is given). The status line lists every option the profile sets, so a profile meant to be deep shows `Deep=On`. The JSON below is checked after every change by the same rules `foton-collect -Profile` applies, and **Save profile...** and **Build bundle...** work only while it is valid. **Load profile...** opens an existing profile; one that `foton-collect` would refuse is refused here too.

**Build bundle...** goes to the **Collectors** tab with this profile chosen.

The **Cases** tab lists the case and baseline packages in `C:\Foton\Cases`, `C:\Foton\Baselines`, and any folders you add with **Add folder...** (remembered in `%LOCALAPPDATA%\Foton\console-settings.json`; **Remove folder** forgets one, the two defaults always stay). It is the same listing as `foton cases`, read from each package's own files without hashing: host and time, case number and examiner, admin or standard account, profile, finding counts (from the workstation analyze when it has run, otherwise the collector's), which of parse, compose, and analyze have run, and whether there is a ZIP. A package it cannot read is listed with the reason; links and junctions are not followed. **Verify selected** checks the selected cases against their `hashes.csv`, as **Verify** does; the result is shown until the console closes. A ZIP that has not been extracted is not verified here (that would extract it): open it first. For baselines, **Use as reference** and **Use as difference** fill in **Compare**, and **Compare these two** compares two selected baselines, the earlier capture as the reference. Nothing on this tab deletes, moves, or renames a package.

The **Collectors** tab builds the folder you carry to an endpoint, as `foton bundle` does. The console carries the `foton-collect.exe` and `foton-baseline.exe` released with it, so nothing else needs to be downloaded. **Build collection bundle** creates `Foton_Bundle_<profile>_<UTC>` with `foton-collect.exe`, the **Profile** tab's profile as `profile.json` when **Use the profile on the Profile tab** is checked (otherwise every category with the collector's defaults), `SHA256SUMS.txt`, and `RUN.txt` with the command to run. **Build baseline bundle** creates `Foton_BaselineBundle_<UTC>` with `foton-baseline.exe` (and `-LoadUserHives` in `RUN.txt` when **Include users who are not signed in** is checked). Both go under `C:\Foton\Bundles` unless you choose another folder (or set one in **Settings**). Copy the folder to the endpoint or push it with your RMM tool, run the command in `RUN.txt` (an elevated prompt collects the most; a standard user is supported), and bring the package back to open on the **Cases** tab. The console never runs a collector or asks for elevation; to collect the PC it runs on, build a bundle and run it there the same way.

The **Compare** tab runs `foton compare`: choose the reference `baseline.json` (the earlier one, or the golden image) and the difference `baseline.json` (the later one, or the host), or type or paste a baseline folder, then **Compare**. As with the verb, `baseline_diff.csv` and `Foton_BaselineCompare.html` are written beside the difference baseline. The findings are listed with their explanation, and the table below them shows every field-level change (the first 50,000; all of them are in `baseline_diff.csv`). **Open compare report** opens only the report this window built, unchanged since.

The **Viewer** tab lists the package's files. A CSV opens as a table, 1,000 rows a page, with **Find** filtering every loaded row (up to 500,000; a larger file says so); JSON opens as a tree; text and logs open as text (up to 5 MB). HTML (the package's own `Foton_Report.html`, `gpresult.html`) is shown as plain text, never rendered, because HTML written on an endpoint can contain anything; reports this console builds open in your browser from **Open report**. XML (`gpresult.xml`, task XML) opens as a tree; documents that declare a DTD are not read. **Show source** shows either file's markup. Binary artifacts such as `.evtx`, hives, and Prefetch show their size and hash only, because parse and compose read those. Every file shows its SHA-256 and whether it matches `00_Collection\hashes.csv`, changed since hashing, or is not listed (written later, such as `analysis\` outputs). Links and junctions inside a package are listed but never followed. On a CSV the timeline reads, **Show in timeline** opens the **Timeline** tab around the selected row's time.

The **Timeline** tab shows the package's [timeline](#timeline). **Build timeline** runs `foton timeline` on the open package (**Include SRUM hourly counters** is `-All`) and shows `analysis\timeline.csv`; a timeline already in the package is shown when you open the tab, with the time it was written, so build again after a new parse or compose. Filter it by **From** and **To** (UTC, as `yyyy-MM-dd` or `yyyy-MM-dd HH:mm:ss`; a bare **To** date includes that day), **Source**, and **Find** (text in the time, source, meaning, summary, or artifact), then **Apply** or press Enter. The first 10,000 matching rows are shown, with how many match in all. **Around selected row** shows every source within the chosen number of minutes of the selected row, and **Show source row** (or double-clicking a row) opens the artifact in the **Viewer** at the row it came from. Grey rows fall inside the collection window. **Note on source row...** notes the artifact row a timeline row came from.

**Note on row...** in the **Viewer** (on a CSV) records a status and note for the selected row. The **Notes** tab lists every examiner note: on findings, on findings the latest analyze no longer produces, and on rows (with whether the row still reads as it did). **Go to** (or double-clicking) opens the finding on the **Package** tab or the row in the **Viewer**; **Edit note...** changes it. The notes are the same file `foton notes` lists and sets. **Export handoff** writes a [handoff](#handoff) under `C:\Foton\Handoffs` (**Export handoff to...** asks for the folder), including `Foton_Report.html` when this window built it with **Analyze** and it has not changed.

The **Search** tab runs [`foton search`](#search) on the open package (**Regular expression** for `-Regex`; **Stop** ends it early and keeps what was found). Double-click a hit, or **Open in Viewer**, to open its file in the **Viewer** at that row; for a text file the line is shown in the status bar.

---

## Formats and compatibility

- **Collect schema 1.16.0.** 1.14.0 has the same files, tasks, and columns as 1.38.x (1.13.0), with timestamps in UTC, explicit statuses where 1.38.x wrote empty or misleading values (for example `AccessDenied` instead of `NotPresent` for an unreadable event log), and rows 1.38.x missed. 1.15.0 adds collection profiles (the `NotSelected` status, `00_Collection\collection_profile.json`, profile fields in `collection_coverage.json`). 1.16.0 adds `gpresult.xml` to a `-Deep` collection. `foton analyze` reads all of them.
- **Baseline schema 1.18.0.** `foton compare` accepts 1.14.0 (1.38.x), 1.15.0 (v2.0.0-alpha.1), 1.16.0 (v2.0.0), 1.17.0 (v2.1.0), and 1.18.0 (v2.4.0) against each other and prints which one-time format and coverage differences to expect. Older baselines are refused; recapture day 0 and goldens.
- **Notes schema 1.0.0.** `analysis\examiner_notes.json` ([Examiner notes](#examiner-notes)); a file with another major version is refused rather than rewritten.
- **`pwsh.exe` (1.18.0).** The SystemBinary record for PowerShell 7 is read from `Program Files\PowerShell\7`, where it installs; earlier schemas never found it, so it shows as Added against an older baseline. Preview builds, the Microsoft Store package, and custom install folders are not looked for.
- **Service `ServiceDll` (1.17.0).** A svchost-hosted service's `PathName` is the shared `svchost.exe`; the code it runs is its `ServiceDll`, so 1.17.0 records and compares that too, and a change is High attention. Against a baseline older than 1.17.0 the field is not compared (that side never captured it); recapture day 0 to compare it.
- **Long file names.** Windows tools fail on paths of 260 characters or more, and a package is extracted under other folders later. When a copied file's path inside the case folder would exceed 160 characters (Game Bar and phone-notification shortcuts in `Recent` reach 190-character names), Collect shortens the name to a prefix plus `~` and eight hex digits, keeps the extension, and says so in the copy row's note; `SourcePath` keeps the original name. `foton package` on a ZIP that still holds longer paths (Foton 2.2.0 and earlier) lists them as not extracted instead of failing. To check them, move the ZIP to a folder with a shorter path, delete its `-extracted` folder, and run `foton package` again.
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

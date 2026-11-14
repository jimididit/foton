# Changelog

Notable changes to Foton, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

Each release (tags `v2.*` and later) takes its "What's new" notes from the section whose heading matches the tag. A change that alters behavior or output adds a line to the section for the current `FotonVersion` in `Directory.Build.props`. If that version has already been released, bump it first. A test fails when that section is missing or its date differs from `FotonReleaseDate`.

## [3.3.0] - 2026-11-14

- New `foton update` checks GitHub for a newer stable release signed with the Foton release key. With `-Install`, it downloads the release ZIP, checks it against the signed statement, and installs the files in a new `Foton-<version>` folder beside your copy (or under `-OutputPath`). The checks cover the ZIP's SHA-256, that it holds only the expected files, and each executable's SHA-256 and version. Your copy is never replaced, so a case can be re-run with the version that produced it.
  - A release is offered only when it is newer than yours and its signature verifies against the keys pinned in Foton; prereleases and older versions are never offered.
  - A release published but not signed yet is reported, and nothing is installed. A bad signature, a statement for another version, or a future release date stops the check with the reason.
  - Every step is logged with UTC times, hashes, and the signing key's fingerprint in `%LOCALAPPDATA%\Foton\updates\update.log`.
  - A Foton installed with Scoop is pointed to `scoop update foton`.
  - See [USAGE](docs/USAGE.md#updates) and [SECURITY](SECURITY.md#release-signature-updates).
- Each release now carries `foton-release.json`: the version, release date, and SHA-256 of the ZIP and of each executable. The maintainer signs it offline after publishing (`foton-release.json.sig`); the release notes say so.

## [3.2.2] - 2026-11-14

- Each executable has its own icon, so the four are told apart in Explorer, the taskbar, and Alt+Tab: `foton-console.exe` keeps the photon wave packet (beam cyan), `foton.exe` a prompt with a quantum (violet), `foton-collect.exe` an aperture (amber), and `foton-baseline.exe` a reference beam with a break (mint), all on the reports' near-black tile. Each has a simpler cut for 16 to 24 px. The icons are in `assets/brand/icons`, named for each executable; a build test checks that every executable carries its own icon and no other.

## [3.2.1] - 2026-11-14

- Each release now has one download for most people: `Foton-<version>-windows.zip`, with all four executables, their `SHA256SUMS.txt`, `LICENSE.txt`, and a `README.txt` (which file does what, how to check them). The ZIP is listed in the release's `SHA256SUMS.txt`, carries its own build provenance attestation, and its SHA-256 is printed in the release notes. The executables stay attached on their own for RMM tools and scripts. The README quick start and Getting started now start from the ZIP.

## [3.2.0] - 2026-11-13

- Console wizards: **Build a collector** (collection or baseline, scope, folder, then the command to run), **Work a case** (choose, verify, parse/compose/analyze, review, hand off), and **Compare baselines** (reference, difference, result). Each shows its steps and runs the same action as the tab it stands for. **Start here** on the Cases tab opens them, as does **Tools > Wizards**.
- In the dark and Solarized themes, radio buttons show the selected option with an accent ring and dot instead of a grey disc that hardly showed which was chosen.

- Foton has an icon: the photon wave packet from the reports, in beam cyan on their near-black, with a simpler cut for 16 to 24 px. All four executables carry it (Explorer, the taskbar, Alt+Tab), and the console window shows it in its title bar. The masters (SVG, one-colour and reversed versions) and `foton.ico` are in `assets/brand`; a build test checks that every executable carries the icon.

## [3.1.0] - 2026-11-13

- Console themes: **Light** (Windows' own colors), **Dark**, **Campbell** (the Windows Terminal default), **Solarized Dark**, **Solarized Light**, and **Follow Windows**, from **View > Theme** or **Settings > Appearance**. Each theme gives panels, inputs, lists, buttons, and headers their own shade, and every text color in every theme meets WCAG contrast (4.5:1 for text, 3:1 for borders and the accent; a test checks it). Solarized's reds, greens, and borders are adjusted where the originals fall short.
- Dark themes now also darken the parts Windows draws: the title bar (on Windows 11 in the theme's own colors), scroll bars, tree expand glyphs, and drop-down buttons. Check boxes and radio buttons follow the theme too. These use two documented Windows calls in a new appearance-only library, `Foton.Win.Ui`, which architecture tests keep from touching the registry, files, processes, WMI, or the network; the console still never references `Foton.Win`.
- Console tabs are flat, with the selected tab marked by an accent underline, hover feedback, and a visible keyboard focus. The log and raw-text panes use Cascadia Mono or Consolas.
- About no longer says the console runs the collectors (it has not since 3.0.0), and the Settings shortcut shows as Ctrl+, instead of Ctrl+Oemcomma.
- Console layout: the log pane takes less height by default and **View > Show log** (Ctrl+L) hides it; its height and visibility are remembered (`ShowLog`, `LogPercent` in `console-settings.json`). The status bar shows the message of the tab on screen instead of the last one from any tab.
- Package tab: the next steps fit on one line (a check mark for each step done, the next one in bold, what a step does on hover), **Do this next** is the highlighted main action, and the buttons are grouped (run steps, match IOCs, open). Findings show severity by color as well as by its word (High also bold), the Severity, Status, and Tier columns are shown whole, and the finding's details get more of the height.
- Empty grids (cases, baselines, findings, timeline, notes, search, compare) say what to do next instead of staying blank.
- Selected rows use a soft tint of the theme's accent with the normal text color (Light: Windows 11's pale list blue; trees use Explorer's style), instead of a saturated blue fill. With Windows High Contrast on, Windows' own highlight stays.

## [3.0.0] - 2026-11-13

- `foton.exe` and `foton-console.exe` carry `foton-collect.exe` and `foton-baseline.exe` inside them: the same files the release publishes (a build test checks the bytes), only ever written to disk in a bundle, never run by the program that carries them. Building a bundle no longer needs the collector downloaded beside it.
- `foton bundle collect [-Profile <profile.json>] [-OutputPath <folder>]` and `foton bundle baseline [-LoadUserHives] [-OutputPath <folder>]`: a folder to carry to an endpoint (under `C:\Foton\Bundles` by default) with the collector, the profile if any, `RUN.txt` with the command, and `SHA256SUMS.txt`. A collection bundle without a profile collects every category; a baseline bundle can include signed-out users. The bundle checks that the collector it writes is the right one and the same Foton version.
- Console **Collectors** tab: **Build collection bundle** (with the Profile tab's profile, or every category) and **Build baseline bundle** (optionally with signed-out users), the same folders as `foton bundle`, using the collectors the console carries. The Profile tab's **Build bundle...** opens it with the profile chosen, and **Start here** offers **Build a collector...** and **Build a baseline collector...**. **Settings > Folders** has a **Bundles** folder (default `C:\Foton\Bundles`).
- Console **Acquire** tab removed: the console no longer runs a collector on the PC it runs on or asks for elevation. To collect or baseline that PC, build a bundle and run it there like on any endpoint; the package opens on the **Cases** tab as before.

## [2.15.0] - 2026-11-13

- Console menu bar: **File** (open a case folder or ZIP, recent cases, exit), **View** (find on this tab, refresh this tab, go to a tab), **Tools** (settings, the Tools and Profile tabs), **Help** (keyboard shortcuts; About with the version, schemas, release date, and this executable's SHA-256). Shortcuts: Ctrl+O, Ctrl+Shift+O, Ctrl+F, F5, Ctrl+1 to Ctrl+0, Ctrl+comma.
- Console **Settings** (Tools > Settings): **General** (examiner name for Acquire and notes, open on start on the Cases tab or the last case, how many recent cases to list) and **Folders** (where new cases, baselines, and handoffs go, and the other case folders the Cases tab lists). Saved in `%LOCALAPPDATA%\Foton\console-settings.json`; a setting that cannot be read falls back to its default on its own.
- Console themes and text size: **Light**, **Dark**, or **Follow Windows** (follows Windows' light or dark app setting, also when it changes), and text from 9 to 12 pt, from **View** or **Settings > Appearance**. Dark colors the panels, lists, grids, tabs, menus, and log; Windows still draws the title bar, scroll bars, check boxes, message boxes, and the file and folder dialogs in its own colors.
- Console layout: every tab has the same inner margin, button bars start flush with the panes below them, the findings and their details start at the same height, every scrolling pane has the same thin border, empty grids and read-only reading panes are white instead of gray, and the log lines up with the tab content. The Tab key moves through each tab top to bottom and left to right; Dark buttons show hover and pressed states and the selected tab shows keyboard focus; with Windows High Contrast on, the console keeps Windows' colors whatever theme is chosen.

## [2.14.0] - 2026-11-12

- `foton search <package> <text> [-Regex]`: finds a text (case-insensitive), or a regular expression, in every CSV, JSON, text, log, XML, and HTML file of a package, collected files and workstation outputs (parse, compose, analyze, timeline) alike. Each hit names the file and the CSV row and column, or the line, with the text around it. Binary artifacts (EVTX, hives, Prefetch) are listed as not searched, as are links, files over 2 GB, and unreadable files. Results go to `analysis\search_<UTC>.csv`, with what was searched in the `.txt` beside it; 10,000 hits are listed and every match is counted.
- Console **Search** tab: the same search, with **Stop**, and each hit opens in the Viewer at its row.
- Console guided start: **Start here** on the Cases tab (collect or baseline this PC, open a case folder or ZIP), and on the Package tab the steps for the open case (verify, parse, compose, analyze, timeline, review, hand off) with what each has done and **Do this next**, which runs the first step not done.

## [2.13.0] - 2026-11-12

- Examiner notes: a review status (Not reviewed, Reviewed, Relevant, Not relevant, Follow up) and a note for each finding and for any row of a package CSV, kept in `analysis\examiner_notes.json` (notes schema 1.0.0) apart from the findings and the automated report, and labelled as examiner input. A finding's note follows it across re-analyzes while its content is the same; a note whose finding is no longer produced is kept and listed as such; a row note records the row's SHA-256 and says when the row reads differently. A notes file that cannot be read is refused, never overwritten.
- `foton notes <package> [-Json]` lists every finding with its status and key, the notes on findings no longer produced, and the row notes; `foton notes <package> -Key <key> | -Artifact <file> -Row <n> [-Status] [-Text] [-Examiner]` sets one.
- Console: the Package tab's findings show their status, filter by severity, status, and text, and have a note editor; **Note on row...** in the Viewer and **Note on source row...** in the Timeline note an artifact row; the **Notes** tab lists every note with **Go to** and **Edit note...**.
- `foton handoff <package> [-OutputPath <folder>]` and the console's **Export handoff**: a `Foton_Handoff_<case>_<UTC>` folder (under `C:\Foton\Handoffs` by default) with the findings, the examiner notes (JSON and CSV), `Foton_Handoff.html` (findings and examiner review side by side, labelled apart), copies of the package's chain of custody and `hashes.csv`, `HANDOFF.txt` (case, review counts, the package's hashes, and whether it verified at export), and `SHA256SUMS.txt` over every file. The package is referenced by hash, not copied. The console adds `Foton_Report.html` only when it built the report and it is unchanged.

## [2.12.0] - 2026-11-12

- `foton timeline <package> [-From <utc>] [-To <utc>] [-All]`: one list of the package's recorded times, sorted by UTC, from the compose outputs (PECmd, EvtxECmd, Hayabusa, Chainsaw, LECmd, JLECmd, SBECmd, AppCompatCacheParser, AmcacheParser, RECmd, SrumECmd, MFTECmd) and Foton's own CSVs. Each row says what its time means (a Prefetch run is a run; a Shimcache time is a file modified time, not a run), where it came from, and whether it falls in the collection window. Writes `analysis\timeline.csv` and `analysis\timeline_sources.csv`, which records what was read and why anything was left out.
- Console **Timeline** tab: **Build timeline** runs the same builder, then the timeline can be filtered by UTC window, source, and text (the first 10,000 matching rows are shown, with the full match count). **Around selected row** shows every source within the chosen minutes of a row, and **Show source row** opens the row it came from in the Viewer. Rows in the collection window are greyed.
- Console Viewer: **Show in timeline** on a row of a CSV the timeline reads opens the Timeline tab around that row's time.

## [2.11.0] - 2026-11-12

- Console **Cases** tab, first when the console opens: the case and baseline packages in `C:\Foton\Cases`, `C:\Foton\Baselines`, and folders you add, with host, time, case number, examiner, account, profile, finding counts, and which of parse, compose, and analyze have run. Open a case, verify selected cases (results kept for the session), show the folder, or send baselines to Compare. Read-only: it never deletes, moves, or renames a package.
- `foton cases [-Path <folder>]... [-Json]` prints the same listing.

## [2.10.0] - 2026-11-12

- Console Acquire tab: collect or baseline this PC without a command prompt. The console runs the `foton-collect.exe` / `foton-baseline.exe` beside it as its own process, only after checking it against `SHA256SUMS.txt` (a mismatch is refused; with no list it asks first), through the Windows administrator prompt when asked, and shows the collector's own log as it runs. The console itself never runs elevated. A finished collection opens in the Package tab and is verified; a finished baseline is set up in Compare against this host's previous baseline.
- Console Viewer: HTML files (the package's own report, `gpresult.html`) are shown as plain text with scripts and styles removed, never rendered; XML files open as a tree (a document with a DTD is not read, so nothing external is fetched). **Show source** shows the markup of either.
- Collect `-Deep` also writes `gpresult /x` as `06_Security_Posture\gpresult.xml` next to `gpresult.html` (the same Resultant Set of Policy, as XML, which the console shows as a tree). Collect schema 1.16.0; packages without `-Deep` are unchanged.

## [2.9.1] - 2026-11-11

Fixes from the first field run of the 2.9.0 console.

- Console Profile tab: each switch option is now a Default / On / Off list instead of a three-state check box, whose "not set" state Windows 11 draws as a filled box that reads as on. The status line lists every option the profile sets (for example `Deep=On`), or says it sets none.
- Compose records the tool version for every output: a tool found on PATH (or given by explicit path) gets the version from its file, and Chainsaw, which has none, is asked for it only when it is about to run. Before, those rows had no version.
- Compose's `NoInput` note no longer tells an elevated collection to "re-collect elevated". It points to `collection_manifest.csv` for why an input was not copied; for MFTECmd it names `-IncludeUsnJournal` / `-Deep`.
- Analyze: a profile that left no task out gets "A collection profile was used" (and a reminder to check its options), not "A collection profile limited what was collected". The chain of custody says the profile chose what the collection ran, with not-selected tasks "if any".

## [2.9.0] - 2026-11-11

### Added
- `foton-console.exe`, a workstation window for the `foton` verbs. Open a case folder or package ZIP, then verify it, run parse, compose, and analyze (one at a time or in sequence), read the findings in a sortable list with each finding's explanation beside it, and open the report or the case folder. It runs the same code as `foton.exe`, so its outputs and log lines are the same, and like `foton.exe` it works only on collected packages; it never reads the live host. One file, like the other executables.
- The console's Viewer tab shows any file in a package: CSVs as a searchable, paged table, JSON as a tree, text as text, and binary artifacts as size and hash. Each file shows its SHA-256 and whether it matches `hashes.csv`. **Show artifact**, or double-clicking a finding, opens the artifact the finding cites. The console opens only a report it built itself with Analyze, because a package's own report was written on the endpoint.
- The console's Tools tab lists the tools compose can find, installs the pinned Hayabusa and Chainsaw releases (downloaded, or from an archive already on disk; refused unless the SHA-256 matches the pin), registers an existing install such as the EZ Tools folder, and picks which tools Compose runs.
- The console's Package tab has **Match IOCs...**: it runs `foton ioc` on the open package with an indicator list you choose and opens `analysis\ioc_matches.csv` in the Viewer.
- The console's Profile tab builds a collection profile from checkboxes, validated after every change by the same rules as `foton-collect -Profile`, and saves it or builds a bundle for an endpoint: `foton-collect.exe` (checked against the release `SHA256SUMS.txt` beside it, refused when it differs or predates profiles), `profile.json`, their hashes, and `RUN.txt` with the command to run.
- The console's Compare tab runs `foton compare` on two baselines and shows the findings and every field-level change; it writes the same `baseline_diff.csv` and compare report as the verb.
- Releases now include `foton-console.exe`, listed in `SHA256SUMS.txt` and covered by the build provenance attestation like the other executables.
- Compose can run a subset of its tools. A tool left out gets a `NotSelected` row in `external_parse_inventory.csv`, and its earlier output is kept and listed as `Retained`. `foton compose` still runs every tool.

## [2.8.0] - 2026-11-10

### Added
- Collection profiles. `foton-collect -Profile "\path\to\profile.json"` collects only the categories the profile lists, leaves out the tasks in its `ExcludeTasks`, and applies its `Options` (event log window, `LoadUserHives`, `Deep`, and the other switches) as defaults that command-line switches override. `-Category System,Persistence` selects categories without a file, or replaces the profile's list when both are given. A profile with an unknown key, an unknown category or task name, a wrong value type, or no categories is refused before anything runs. Keys are not case-sensitive.
- A task the profile leaves out is never run. It is recorded with the new status `NotSelected` (a sentinel artifact and a manifest row), the profile file is copied into the package as `00_Collection\collection_profile.json` (so it is hashed), and the chain of custody records the profile name, SHA-256, categories, and excluded tasks. `collection_coverage.json` lists the tasks not selected, and an excluded task these options do not run (such as a `-Deep`-only task) is listed there too. Collect schema 1.15.0; a collection without a profile has the 1.14.0 layout.
- `analyze` adds an Info finding naming the profile and the tasks it left out. No finding is drawn from their absence.

### Fixed
- "No process creation events (4688) were collected" fired when the Security log was never read (a standard-user collection skips it), claiming the log returned no events. It now fires only when the task ran.

## [2.7.1] - 2026-11-10

### Fixed
- `foton-collect -LoadUserHives` lost the hives it loaded: `registry_hives_user` tried to file-copy `NTUSER.DAT` and its logs for each mounted user, which the mount locks, and fell back to `reg save` only for users who were signed in. Those users' `NTUSER.DAT` was missing from the package (task Partial, `CopyError` rows), so RECmd and SBECmd in `compose` never saw it. A hive mounted by `-LoadUserHives` is now exported with `reg save` from its `HKU\Foton_<SID>` mount, like a signed-in user's, and its locked logs are marked `SupersededBySave`.
- `analyze` raised High findings that every Windows 10/11 host triggers. Found on a real elevated collection; re-running `foton analyze` on an existing package applies the fixes.
  - **Autostart entries:** Collect lists `Explorer\Shell Folders` for its Startup value, but Analyze treated every value there (Common Desktop, Documents, Start Menu) as an autostart command in a user-writable folder. Only `Common Startup` and `Startup` count now, and only when they no longer point to the default Startup folder.
  - **Services from user-writable paths:** Microsoft Defender's own services run from `ProgramData\Microsoft\Windows Defender\Platform`, which the user-writable list matches but only SYSTEM, Administrators, and TrustedInstaller can write. Binaries there are exempt when they are validly signed by Microsoft Corporation; an unsigned file there, or a Microsoft-signed one elsewhere, still flags.
  - **Defender configuration changed:** every event 5007 counted, and Defender logs dozens itself (Diagnostics, CoreService, Features) on platform and intelligence updates. High now needs 5001/5010/5012 or a 5007 that changes exclusions, real-time protection, tamper protection, cloud protection, or a `Disable*` setting, whether set locally, by Group Policy, or by Intune/MDM (`Policy Manager`); the rest are one Info finding with a count.
  - **The collector itself:** an unsigned `foton-collect.exe` run from Downloads was listed among unsigned processes and executables in user-writable paths. The row whose SHA-256 matches the collector recorded in `chain_of_custody.txt` is left out, and the finding says so.

## [2.7.0] - 2026-11-10

### Changed
- `foton` verbs on a package ZIP no longer extract it to a temporary folder under `%TEMP%` each time. The first verb extracts the ZIP once, beside it, into a folder named like the ZIP with `-extracted` at the end; later verbs reuse it, and all outputs are written there, as for a case folder: `analysis\parsed_records.csv`, `analysis\findings.csv`, `analysis\ioc_matches.csv`, and `Foton_Report.html` in the case folder, where its artifact links now work. The `<name>_findings.csv`, `<name>_Report.html`, `<name>_parse.csv`, `<name>_Parse.html`, and `<name>_ioc_matches.csv` files that 2.6.1 and earlier wrote beside the ZIP are no longer written. Case data is no longer left in `%TEMP%`, and the ZIP is extracted once instead of on every verb.
- `foton compose` now accepts a package ZIP and works in its `-extracted` folder; before, it refused a ZIP.
- The folder holds `foton_extraction.json` with the ZIP's SHA-256. Every verb re-hashes the ZIP before reusing the folder. If the ZIP was replaced, or the folder was not left by a finished Foton extraction, the verb stops and names the folder instead of mixing two packages; Foton never deletes that folder. Extraction is written under a temporary name and renamed when complete, so an interrupted run never leaves a folder that looks finished.
- `foton package` on a ZIP verifies the files inside the ZIP against its `hashes.csv`, so the result describes the package as collected, not what later verbs wrote into the folder. Files whose paths were too long to extract (packages from 2.2.0 and earlier) are now verified too. It then checks the extraction, which parse, compose, and analyze read, and exits with 2 when a collected file changed there (`Foton_Report.html` excepted, because analyze rewrites it).

## [2.6.1] - 2026-11-09

### Changed
- `foton-collect` is faster with the same output. An elevated collect on a busy workstation fell from about 270 to 141 seconds. `executables_in_user_writable_paths` checks signatures and hashes up to four files at a time (fewer on machines with fewer cores), keeping the same row order (43 to 14 seconds on 1,600 files). `running_processes` checks the signature and hash of each executable once instead of once per process (105 to 17 seconds on 440 processes, where browsers and Electron apps run dozens of processes from one large executable). `loaded_modules_nonstandard` hashes each module path once. The signature check no longer makes a second query for file types Windows has no signature format for, such as shortcuts; the result is unchanged, because such a file can carry no signature. Results on 2,571 test files matched the previous version exactly.

## [2.6.0] - 2026-11-09

### Added
- `foton-baseline -LoadUserHives` captures the per-user rows (UserAutorun, StartupApproved, ProxyConfig, CmdAutoRun) of users who are not signed in, the way `foton-collect -LoadUserHives` already did. It requires elevation: it mounts each such user's `NTUSER.DAT` under `HKEY_USERS` with `reg.exe` and always unmounts it when the capture ends. Without elevation the switch is ignored with a warning. The baseline header and `coverage.json` record whether hives were mounted and how many. Before, a baseline saw only the users signed in at that moment, so per-user rows came and went as people signed in and out. Compare warns when only one of the two baselines used the switch, because those rows then show as Added or Removed without anything changing on the host. Baseline schema stays 1.18.0: the records do not change, and older Foton versions ignore the new header fields.

## [2.5.0] - 2026-11-09

### Added
- `compose` runs Eric Zimmerman's **AppCompatCacheParser** on the copied SYSTEM hive (Shimcache) and **SBECmd** on the copied user hives (shellbags). `analyze` reads both. Shimcache becomes an overview (entries per control set, how many are marked Executed) and a Medium finding for executables or scripts in user-writable paths; the caveat says an entry shows a file was evaluated, not that it ran. Shellbags become an overview of folders browsed per user, including phone and camera (MTP) entries, network paths, archive contents, and drive letters other than the system drive.
- `compose` runs **SrumECmd** on the SRUM copy (with the SOFTWARE hive to name apps and users) and **MFTECmd** on the change journal exported with `-IncludeUsnJournal`. `analyze` reads both. SRUM becomes an overview (rows per table, apps, dates covered) and a Medium finding for executables in user-writable paths that used the network, with bytes sent and received. The journal becomes an overview (creates, deletes, renames in the period covered) and an Info list of executables or scripts created, by name only, because folder paths need `$MFT`. Journal rows from the collection itself are counted apart.
- `foton tools EZTools` registers AppCompatCacheParser, SBECmd, SrumECmd, and MFTECmd too. A folder registered with an earlier version needs registering again to pick them up.

## [2.4.0] - 2026-11-09

### Fixed
- Baselines never recorded `pwsh.exe`: the SystemBinary provider looked for it in System32, but PowerShell 7 installs under `Program Files\PowerShell\7`. It is now read from there. Baseline schema 1.18.0; Compare still accepts 1.14.0 and later baselines and explains that `pwsh.exe` shows as Added against an older one. Preview builds, the Microsoft Store package, and custom install folders are not looked for. This was the last open item from the 1.38.x defects found during the port.
- Collect never copied SRUM. It looked for `SRUDB.dat` under `ProgramData\Microsoft\Windows\SRUM`, a folder that does not exist (the path came from 1.38.x), recorded it as Missing, and marked the task Success. It now copies the whole `System32\sru` folder: the database plus its ESE logs and checkpoint, which do not share its name and which a parser needs to read a database copied while in use. The cap rises from 100 MiB to 1 GiB, because a busy host's database passes 100 MiB.
- `-IncludeUsnJournal` never exported the change journal. It opened `C:\$Extend\$UsnJrnl:$J` as a file, which Windows does not allow, so the copy was always Missing (1.38.x had the same code). Collect now reads the journal records through `FSCTL_READ_USN_JOURNAL` (the interface `fsutil` uses) and writes them in their on-disk layout to `UsnJrnl_J.bin`, which MFTECmd parses as `$J`. Capped at 1 GiB, keeping the newest records. The chain of custody discloses that the volume was opened read-only.

## [2.3.0] - 2026-11-09

### Changed
- `foton-collect` and `foton-baseline` now write to `C:\Foton\Cases` and `C:\Foton\Baselines` on the Windows drive when `-OutputPath` is not given, instead of the current user's Desktop. On many machines the Desktop is backed up to OneDrive, which uploaded case data to the cloud. Under RMM running as SYSTEM, or in an admin prompt opened with another account, the Desktop was also not where the operator looked. When Foton creates these folders, it limits them to SYSTEM, Administrators, and the account running the collection, because a folder under the drive root otherwise lets every signed-in user read it. Before writing, it checks `C:\Foton` and the output folder and refuses to use them if either is a junction or link, is owned by another account, grants access to anyone else, or has permissions it cannot read. Any local user can create a folder at the drive root, so without this check a standard user could prepare `C:\Foton` in advance and read what a later elevated collection writes there. When the check fails, the run stops before collecting and asks for `-OutputPath` or removal of the folder it names. An explicit `-OutputPath` is used as given, with its permissions unchanged.

### Fixed
- The triage report (`Foton_Report.html`) showed Case and Examiner as "(not supplied)" even when `-CaseNumber` and `-Examiner` were given. The report now reads both from the package's `chain_of_custody.txt` (Foton 1.38.x packages included). Values are HTML-encoded like every other package value, and "(not supplied)" remains only when the package did not record them.

## [2.2.1] - 2026-11-08

### Fixed
- Collect skipped shortcut files whose names push the copy past the Windows 260-character path limit (Game Bar and phone-notification shortcuts in `Recent` reach about 190 characters) and marked the task Partial. A copied file whose path inside the case folder would exceed 160 characters is now saved under a shortened name (prefix, `~`, eight hex digits of the original name's hash, original extension). The copy row's note says so, and `SourcePath` keeps the original name.
- `foton package` on a ZIP failed outright when an entry's path was too long to extract under `%TEMP%`. Such entries are now listed as not extracted (integrity not checked, package not reported intact) and the rest is verified. The temporary extraction folder name is shorter (`FotonPkg-` plus eight hex digits).

## [2.2.0] - 2026-11-08

### Added
- `foton tools Chainsaw` installs the pinned Chainsaw 2.17.1 rules release and checks its SHA-256. The Chainsaw rules, Sigma rules, and mappings go beside the binary, so `compose` runs Chainsaw hunts on a fresh workstation.
- `analyze` reads LECmd and JLECmd output. Each tool gets an overview finding (targets on removable media and network paths included) and findings for executable or script targets in user-writable paths and for shortcut arguments that match suspicious-command patterns.
- `analyze` reads AmcacheParser output: an overview, executables or scripts inventoried under user-writable paths (Windows components left out), and unsigned drivers that did not ship with Windows.

### Changed
- When `foton tools` reinstalls a tool, it moves any existing `config`, `rules`, `sigma`, or `mappings` folder beside the tool to `<name>.replaced-<UTC stamp>Z` instead of overwriting it, so local edits stay recoverable.
- `foton` usage text points to the operator guide instead of to 1.38.x.

EZ Tools are not pinned because upstream download URLs are unversioned. Install them with `Get-ZimmermanTools.ps1` and register the folder with `foton tools EZTools <folder>`. Schemas are unchanged: Collect 1.14.0, Baseline 1.17.0, Findings 1.0.0.

## [2.1.0] - 2026-11-08

### Added
- Baseline `Service` records carry `ServiceDll`, the DLL a svchost-hosted service runs, as a compared field. A change is High, like `PathName`. Baseline schema 1.17.0. Against an older baseline the field is not compared, because the older side never captured it; recapture day 0 to compare it.
- `analyze` reads RECmd batch output: an overview by hive type and category, Autoruns, Services, and Threat Hunting values that name user-writable paths, and keys or values RECmd recovered as deleted.
- `analyze` reads Chainsaw hunt output as one Info overview, with rows the collection itself caused counted apart.

### Removed
- `legacy/powershell/` is gone from `main`. Foton 1.38.2 is the final PowerShell release and stays available from the `v1.*` tags.

## [2.0.0] - 2026-11-08

First stable v2 release.

### Added
- Baseline `WinsockLsp` also reads the 64-bit Winsock namespace catalog (Kind `Namespace64`). Baseline schema 1.16.0; Compare accepts 1.14.0, 1.15.0, and 1.16.0 baselines and explains the differences.

### Changed
- README, USAGE, CONTRIBUTING, CARVE, and SECURITY describe v2 first.

### Fixed
- Collect no longer reads cloud-only placeholders (OneDrive Files On-Demand and other cloud-file providers). Reading one downloads it. Hashing, signature checks, copies, and stream reads now record `SkippedCloudPlaceholder` or `CloudPlaceholderNotChecked` instead. 1.38.x had the same problem.
- The finding for Hayabusa hits caused by the collection names the v2 collector (`foton-collect.exe` and the System32 tools it starts), not only 1.38.x PowerShell script blocks.

## [2.0.0-alpha.1] - 2026-11-08

First v2 prerelease: Foton ported from PowerShell to C#.

### Added
- Three single-file executables on in-box .NET Framework 4.6.2 and later (Windows 10 / Server 2016 and newer): `foton-collect.exe`, `foton-baseline.exe`, and `foton.exe` (`compare`, `parse`, `analyze`, `ioc`, `compose`, `tools`, `carve`, `package`).
- Collect writes the same files and columns as 1.38.x (Collect schema 1.14.0) with UTC timestamps and explicit statuses.
- Baseline schema 1.15.0. It records Defender properties the platform does not report as "(not reported)", an unset BITS notify command as "(not set)", and the WinHTTP proxy blob as hex. It adds active WDAC policies and the `SystemBinary` row for `explorer.exe`. A 1.14.0 standard-user capture skipped loaded user hives, so per-user rows can show as Added against it.

## 1.x (PowerShell)

Foton 1.38.2 and earlier are documented in the `ReleaseNotes` of [`legacy/powershell/Foton.psd1` at v1.38.2](https://github.com/jimididit/foton/blob/v1.38.2/legacy/powershell/Foton.psd1).

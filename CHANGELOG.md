# Changelog

Notable changes to Foton, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

Each `v2.*` release takes its "What's new" notes from the section whose heading matches the tag. A change that alters behavior or output adds a line to the section for the current `FotonVersion` in `Directory.Build.props`. If that version has already been released, bump it first. A test fails when that section is missing or its date differs from `FotonReleaseDate`.

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

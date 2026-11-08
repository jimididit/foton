# Changelog

Notable changes to Foton, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

Each `v2.*` release takes its "What's new" notes from the section whose heading matches the tag. A change that alters behavior or output adds a line to the section for the current `FotonVersion` in `Directory.Build.props`. If that version has already been released, bump it first. A test fails when that section is missing or its date differs from `FotonReleaseDate`.

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

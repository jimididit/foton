# Foton

<img src="assets/brand/foton-tile.svg" alt="Foton mark: a photon wave packet" width="72" height="72">

[![CI](https://github.com/jimididit/foton/actions/workflows/ci.yml/badge.svg)](https://github.com/jimididit/foton/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/foton?include_prereleases&sort=semver)](https://github.com/jimididit/foton/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Windows DFIR, baseline, and security-audit toolkit for incident responders, forensic examiners, and IT security teams. Capture a host into a hashed **package** with one executable, then parse, compare, and analyze it **offline**. Findings are observations, not a compromise verdict.

## Quick start

Windows 10 / Server 2016 or newer; nothing to install.

1. Download `Foton-<version>-windows.zip` from the [latest release](https://github.com/jimididit/foton/releases/latest). It holds all four executables, their `SHA256SUMS.txt`, and a `README.txt`.
2. Open PowerShell as Administrator (Start menu, type `PowerShell`, right-click **Windows PowerShell**, **Run as administrator**). Go to the folder where you saved the ZIP, replacing the path with yours:

   ```powershell
   cd "\path\to\folder"
   ```

3. Check the download. The `Hash` value it prints must match the SHA-256 shown in the release notes. If it does not, delete the ZIP and download it again. Then unblock and extract it:

   ```powershell
   Get-FileHash .\Foton-*-windows.zip
   Unblock-File .\Foton-*-windows.zip
   Expand-Archive .\Foton-*-windows.zip -DestinationPath .\Foton
   ```

4. Run the collector:

   ```powershell
   cd .\Foton
   .\foton-collect.exe -CaseNumber CASE-0001
   ```

5. Open `Foton_Report.html` in the new folder under `C:\Foton\Cases`.

With [Scoop](https://scoop.sh), `scoop bucket add foton https://github.com/jimididit/foton` and then `scoop install foton/foton` install the same ZIP, checked against its SHA-256.

[Getting started](docs/GETTING-STARTED.md) covers analyzing the package on another computer, baselines, and the stronger provenance check for casework.

## What you can do

- **Triage a host.** `foton-collect.exe` gathers processes, persistence, accounts, event logs, registry hives, Prefetch, and more into a hashed case package with a first-pass HTML report.
- **See what changed.** `foton-baseline.exe` records stable configuration (services, tasks, autoruns, accounts, drivers, certificates, firewall rules); `foton compare` lists every field that changed between two baselines of one host, or between a host and a golden image of its role.
- **Work from your own computer.** Build the collector folder for an endpoint, send it or push it with your RMM tool, then verify, parse, run Hayabusa / Chainsaw / Eric Zimmerman's tools, analyze, search, build a timeline, take notes, and hand off, all offline. Use `foton.exe` in a terminal or `foton-console.exe` in a window.

## Four executables

| Executable | Runs on | Does |
|------------|---------|------|
| `foton-collect.exe` | Endpoint | Live triage into a hashed case package: custody, coverage, manifest, findings, `Foton_Report.html`, ZIP |
| `foton-baseline.exe` | Endpoint | Snapshot of stable configuration (37 record types) for later temporal or fleet comparison |
| `foton.exe` | Workstation | `parse`, `compose`, `analyze`, `ioc`, `compare`, `timeline`, `search`, `notes`, `handoff`, `cases`, `carve`, `tools`, `package` (verify hashes), and `bundle` (build a collector folder for an endpoint) |
| `foton-console.exe` | Workstation | The same workstation work in a window, plus collection profiles and the **Collectors** tab for building collector folders |

Each is one file. Only a collector goes to an endpoint; everything else runs on your workstation. `foton.exe` and `foton-console.exe` carry the collectors released with them, so you can download just the workstation program and build the endpoint folder from it. The collectors are also published on their own, byte for byte the same.

## Requirements

- Windows 10 / Server 2016 or newer. The executables run on the .NET Framework that ships with Windows (4.6.2+); nothing to install. The commands in these docs are for PowerShell, which is built in.
- Output goes to `C:\Foton\Cases` and `C:\Foton\Baselines` unless you pass `-OutputPath`.
- **Administrator recommended**, not required. A standard-user run skips the Security log, Prefetch/Amcache/SRUM copies, registry hive exports, and other users' files, and records each as a visibility gap, not a clean result.
- The executables are not code-signed yet, so Windows SmartScreen may warn when one is started from File Explorer. For casework, check each file's SHA-256 against the release's `SHA256SUMS.txt` and its GitHub build provenance attestation, which proves it was built by this repository's release workflow ([how](docs/GETTING-STARTED.md#2-check-the-download)).
- Older hosts (Windows 7, 8.1, Server 2012 R2): use the PowerShell line, [Foton 1.38.2](https://github.com/jimididit/foton/releases/tag/v1.38.2) with its [1.38.x usage guide](https://github.com/jimididit/foton/blob/v1.38.2/legacy/powershell/release-docs/docs/USAGE.md). 1.38.2 is the final PowerShell release and is no longer maintained.

## What Foton is (and is not)

| Is | Is not |
|----|--------|
| Live triage package and known-good baseline diff | Memory imager, EDR, or CIS scorer |
| Offline parse, compose, and analyze on the package | Autoruns, KAPE, or Hayabusa reimplemented |
| Observations with tiers and artifact paths | "Infected" banners or attribution |

Live collect **changes the host**. Capture memory or disk first when the case plan requires it. Empty findings do not mean a clean host.

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | First run, step by step: download, collect, move the package, analyze, baselines, troubleshooting |
| [docs/USAGE.md](docs/USAGE.md) | Operators: every executable, switch, verb, console tab, and output |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contributors: building, layout, and how to add a collector, provider, parser, or rule |
| [docs/CARVE.md](docs/CARVE.md) | Carve limits (signature scan, not NTFS carving) |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

## Contributing

PRs welcome; see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Build and test with the .NET SDK pinned in `global.json`:

```powershell
dotnet build Foton.sln -c Release -warnaserror
dotnet test Foton.sln -c Release --no-build
```

## License

[MIT](LICENSE) © jimididit

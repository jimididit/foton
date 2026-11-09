# Foton

[![CI](https://github.com/jimididit/foton/actions/workflows/ci.yml/badge.svg)](https://github.com/jimididit/foton/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/foton?include_prereleases&sort=semver)](https://github.com/jimididit/foton/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Windows DFIR, baseline, and security-audit toolkit. Capture a host into a hashed **package** with one executable, then parse, compare, and analyze it **offline**. Findings are observations, not a compromise verdict.

## Quick start

Windows 10 / Server 2016 or newer; nothing to install.

1. Download [foton-collect.exe](https://github.com/jimididit/foton/releases/latest/download/foton-collect.exe) from the latest release. If the browser says it "isn't commonly downloaded", choose **Keep**.
2. Open PowerShell as Administrator (Start menu, type `PowerShell`, right-click **Windows PowerShell**, **Run as administrator**) and run:

```powershell
cd "$env:USERPROFILE\Downloads"
.\foton-collect.exe -CaseNumber CASE-0001
explorer C:\Foton\Cases
```

3. Open the new `Foton_...` folder and double-click `Foton_Report.html`.

For casework, [verify the download](docs/GETTING-STARTED.md#2-verify-your-download) before running it. To analyze the package on another computer with `foton.exe`, or to take baselines, follow [Getting started](docs/GETTING-STARTED.md).

## Three executables

| Executable | Runs on | Does |
|------------|---------|------|
| `foton-collect.exe` | Endpoint | Live triage into a hashed case package: custody, coverage, manifest, findings, `Foton_Report.html`, ZIP |
| `foton-baseline.exe` | Endpoint | Snapshot of stable configuration (37 record types) for later temporal or fleet comparison |
| `foton.exe` | Workstation | `parse`, `compose` (EZ Tools / Hayabusa / Chainsaw), `analyze`, `ioc`, `compare` baselines, `carve`, `tools`, `package` (verify hashes) |

Each is one file. Copy only the endpoint executable to a target; parse, compose, and analyze run on the analyst workstation.

## Requirements

- Windows 10 / Server 2016 or newer. The executables run on the .NET Framework that ships with Windows (4.6.2+); nothing to install. The commands in these docs are for PowerShell, which is built in.
- Output goes to `C:\Foton\Cases` and `C:\Foton\Baselines` unless you pass `-OutputPath`.
- **Administrator recommended**, not required. A standard-user run skips the Security log, Prefetch/Amcache/SRUM copies, registry hive exports, and other users' files, and records each as a visibility gap, not a clean result.
- The executables are not code-signed yet, so Windows SmartScreen may warn when one is started from File Explorer. For casework, check each file's SHA-256 against the release's `SHA256SUMS.txt` and its GitHub build provenance attestation, which proves it was built by this repository's release workflow ([how](docs/GETTING-STARTED.md#2-verify-your-download)).
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
| [docs/USAGE.md](docs/USAGE.md) | Operators: every executable, switch, and recipe |
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

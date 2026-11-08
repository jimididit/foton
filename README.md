# Foton

[![CI](https://github.com/jimididit/foton/actions/workflows/ci.yml/badge.svg)](https://github.com/jimididit/foton/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/foton?include_prereleases&sort=semver)](https://github.com/jimididit/foton/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Windows DFIR, baseline, and security-audit toolkit. Capture a host into a hashed **package** with one executable, then parse, compare, and analyze it **offline**. Findings are observations, not a compromise verdict.

## Quick start

Download `foton-collect.exe`, `foton-baseline.exe`, `foton.exe`, and `SHA256SUMS.txt` from [Releases](https://github.com/jimididit/foton/releases), then verify before use (the executables are not Authenticode-signed yet):

```powershell
Get-FileHash .\foton-collect.exe -Algorithm SHA256        # compare with SHA256SUMS.txt
gh attestation verify .\foton-collect.exe --repo jimididit/foton
Unblock-File .\foton-collect.exe
```

**Endpoint** (elevated prompt preferred; nothing to install):

```powershell
.\foton-collect.exe -CaseNumber CASE-0001 -OutputPath D:\Cases
```

Open `Foton_Report.html` inside the new case folder. Ship the ZIP and `*_PACKAGE_HASH.txt` (or the whole folder), not the HTML alone.

**Workstation** (against the copied package, never the live host):

```powershell
.\foton.exe parse   D:\Cases\Foton_HOSTNAME_20260101-120000Z
.\foton.exe compose D:\Cases\Foton_HOSTNAME_20260101-120000Z
.\foton.exe analyze D:\Cases\Foton_HOSTNAME_20260101-120000Z   # last: reads parse and compose output
```

## Three executables

| Executable | Runs on | Does |
|------------|---------|------|
| `foton-collect.exe` | Endpoint | Live triage into a hashed case package: custody, coverage, manifest, findings, `Foton_Report.html`, ZIP |
| `foton-baseline.exe` | Endpoint | Snapshot of stable configuration (37 record types) for later temporal or fleet comparison |
| `foton.exe` | Workstation | `parse`, `compose` (EZ Tools / Hayabusa / Chainsaw), `analyze`, `ioc`, `compare` baselines, `carve`, `tools`, `package` (verify hashes) |

Each is one file. Copy only the endpoint executable to a target; parse, compose, and analyze run on the analyst workstation.

## Requirements

- Windows 10 / Server 2016 or newer. The executables run on the .NET Framework that ships with Windows (4.6.2+); nothing to install.
- **Administrator recommended**, not required. A standard-user run skips the Security log, Prefetch/Amcache/SRUM copies, registry hive exports, and other users' files, and records each as a visibility gap, not a clean result.
- Windows SmartScreen may warn on first run until the executables are signed. Trust comes from the hash and the build provenance attestation.
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
| [docs/USAGE.md](docs/USAGE.md) | Operators: every executable, switch, and recipe |
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

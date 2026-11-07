# Foton

[![CI](https://github.com/jimididit/foton/actions/workflows/ci.yml/badge.svg)](https://github.com/jimididit/foton/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Module](https://img.shields.io/badge/module-1.38.1-informational)](legacy/powershell/Foton.psd1)

Windows DFIR, baseline, and security-audit toolkit. Capture host state into a hashed **package**, then parse, compare, and analyze **offline**. Findings are observations-not a compromise verdict.

> **Status:** 1.38.x is the final PowerShell release line and receives security fixes only ([SECURITY.md](SECURITY.md)). Foton v2 (single-file executables built in C# on the .NET Framework that ships with Windows 10 / Server 2016+) is in development on `main`. The PowerShell source lives in [`legacy/powershell/`](legacy/powershell/). Releases and the Gallery module are unchanged.

## Quick start

**Get it:** download the Collect script and workstation zip from [Releases](https://github.com/jimididit/foton/releases) (verify against `SHA256SUMS.txt`), or `Install-Module Foton` for the workstation module. Details: [docs/USAGE.md](docs/USAGE.md#0-getting-foton).

**Endpoint (one file, no module install)** - build or download a Collect flatten, then:

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect.ps1 -CaseNumber "CASE-0001" -OutputPath D:\Cases
```

Open `Foton_Report.html` **inside** the new case folder. Ship the ZIP + `*_PACKAGE_HASH.txt` (or the whole folder)-not HTML alone.

**Workstation (release zip or Gallery module; from a clone, run these in `legacy\powershell`)** - full catalog in [docs/USAGE.md](docs/USAGE.md):

```powershell
Import-Module .\Foton.psd1 -Force
Get-FotonVersion
# or: .\Foton.cmd help
```

```text
Foton.cmd parse   D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd compose D:\Cases\Foton_HOSTNAME_...Z
Foton.cmd analyze D:\Cases\Foton_HOSTNAME_...Z   # last - consumes parse/compose
```

## Two machines

| Role | You run | You get |
|------|---------|---------|
| **Endpoint** | One Collect or Baseline `.ps1` | Hashed case / baseline folder (+ ZIP) |
| **Workstation** | `Foton.cmd` / `Import-Module` | Parse, compose, analyze, baseline compare |

Do **not** copy the module tree to a target. Do **not** `Import-Module` on an engagement host.

Build flattens from a clone (run in `legacy\powershell`; `dist\` is generated, not committed):

```powershell
.\build\Build-Standalone.ps1
.\build\Build-BaselineStandalone.ps1
```

Prefer the versioned leaf (`Foton-Collect_v1.38.1_schema1.13.0.ps1`) so module and schema stay in the filename. Release assets (when published) are the same bytes.

## Requirements

- Windows · PowerShell **5.1+** (PowerShell 7 on Windows also fine)
- No extra modules on the endpoint
- **Administrator recommended** (not required). Unelevated runs skip Security log, Prefetch/Amcache/SRUM copies, registry hive exports, VSS, and other users’ files-recorded as visibility gaps, not a clean host
- Scripts are **unsigned** today; use `-ExecutionPolicy Bypass` or a signed release when available

## What Foton is (and is not)

| Is | Is not |
|----|--------|
| Live triage package + known-good baseline diff | Memory imager, EDR, or CIS scorer |
| Offline parse / compose / analyze on the package | Autoruns, KAPE, or Hayabusa reimplemented in PowerShell |
| Observations with tiers and artifact paths | “Infected” banners or attribution |

Live collect **changes the host**. Capture memory/disk first when the case plan requires it. Empty findings ≠ clean host.

## Documentation

| Doc | Audience |
|-----|----------|
| [docs/USAGE.md](docs/USAGE.md) | Operators - every command, switch, and recipe |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contributors - how to extend Collect / Baseline / Analyze |
| [docs/CARVE.md](docs/CARVE.md) | Carve limits (signature scan ≠ NTFS) |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |
| [LICENSE](LICENSE) | MIT |

## Contributing

PRs welcome. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). The PowerShell line is frozen (security fixes only); run `.\legacy\powershell\tests\Invoke-FotonTests.ps1` (Pester 5+) before opening a PR that touches it.

## License

[MIT](LICENSE) © jimididit

# Foton

[![CI](https://github.com/jimididit/foton/actions/workflows/ci.yml/badge.svg)](https://github.com/jimididit/foton/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/foton?include_prereleases&sort=semver)](https://github.com/jimididit/foton/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Windows DFIR, baseline, and security-audit toolkit. Capture a host into a hashed **package** with one executable, then parse, compare, and analyze it **offline**. Findings are observations, not a compromise verdict.

## Quick start

New to Foton? [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) walks through every step, including the workstation side. The short version, for Windows 10 / Server 2016 or newer:

1. Open PowerShell as Administrator: open the Start menu, type `PowerShell`, right-click **Windows PowerShell**, and choose **Run as administrator**.
2. Paste this block. It downloads the latest release into a `Foton` folder in your user profile and checks every file against the published hashes. You should see three `OK` lines:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
$foton = Join-Path $env:USERPROFILE 'Foton'
New-Item -ItemType Directory -Path $foton -Force | Out-Null
Set-Location $foton
$exes = 'foton-collect.exe', 'foton-baseline.exe', 'foton.exe'
foreach ($f in $exes + 'SHA256SUMS.txt') {
    Invoke-WebRequest "https://github.com/jimididit/foton/releases/latest/download/$f" -OutFile $f -UseBasicParsing
}
$sums = @{}
Get-Content .\SHA256SUMS.txt | ForEach-Object { $hash, $name = $_ -split '\s+', 2; $sums[$name] = $hash }
foreach ($f in $exes) {
    if ($sums[$f] -and (Get-FileHash $f -Algorithm SHA256).Hash -eq $sums[$f]) { Unblock-File $f; "OK    $f" }
    else { Remove-Item $f; "FAIL  $f  (deleted: it does not match SHA256SUMS.txt; run this block again)" }
}
```

3. Collect, then open the report:

```powershell
.\foton-collect.exe -CaseNumber CASE-0001
$case = Get-ChildItem C:\Foton\Cases -Directory -Filter 'Foton_*' | Sort-Object LastWriteTime | Select-Object -Last 1
Invoke-Item (Join-Path $case.FullName 'Foton_Report.html')
```

The case folder and its ZIP are in `C:\Foton\Cases`, readable only by SYSTEM, Administrators, and your account. To analyze on another computer, copy the ZIP and its `_PACKAGE_HASH.txt` there and follow [step 4 of the guide](docs/GETTING-STARTED.md#4-move-the-package-to-the-workstation).

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
- The executables are not code-signed yet, so Windows SmartScreen may warn when one is started from File Explorer. Trust comes from the published SHA-256 hashes (checked by the quick start) and the GitHub build provenance attestation (optional check with the [GitHub CLI](https://cli.github.com/): see the guide).
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

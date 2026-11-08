<#
.SYNOPSIS
    Packs the Collect parity harness for a lab VM that has no .NET SDK.

.DESCRIPTION
    Builds Release, then copies into one folder, in the repository-relative layout Invoke-CollectParity.ps1 expects:
    the harness, the built tests\Foton.CollectProbe output, and the frozen 1.38.x module (legacy\powershell manifest,
    root module, and src). Adds Run-Parity.ps1, which runs every category once and writes the comparison to
    parity-elevated.txt or parity-standard-user.txt. Zips the folder and prints its SHA-256.

    The comparison prints counts, statuses, columns, and finding titles, not artifact values. It does print case
    folder paths and the coverage file's earlier-package list, so review it before sharing beyond the lab.

.EXAMPLE
    .\tests\parity\New-ParityBundle.ps1
    Copy foton-parity-bundle.zip to the VM, extract it, then in Windows PowerShell 5.1 (once elevated, once not):
    powershell -ExecutionPolicy Bypass -File .\foton-parity\Run-Parity.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:TEMP 'foton-parity-bundle'),
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $NoBuild) {
    & dotnet build (Join-Path $root 'Foton.sln') -c Release --nologo -v q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
}
$probeBin = Join-Path $root 'tests\Foton.CollectProbe\bin\Release\net472'
if (-not (Test-Path -LiteralPath (Join-Path $probeBin 'Foton.CollectProbe.exe'))) { throw "Probe not built: $probeBin" }

if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
$stage = Join-Path $OutputPath 'foton-parity'
$copies = @(
    @{ From = (Join-Path $root 'tests\parity\Invoke-CollectParity.ps1'); To = 'tests\parity\Invoke-CollectParity.ps1' },
    @{ From = $probeBin; To = 'tests\Foton.CollectProbe\bin\Release\net472' },
    @{ From = (Join-Path $root 'legacy\powershell\Foton.psd1'); To = 'legacy\powershell\Foton.psd1' },
    @{ From = (Join-Path $root 'legacy\powershell\Foton.psm1'); To = 'legacy\powershell\Foton.psm1' },
    @{ From = (Join-Path $root 'legacy\powershell\src'); To = 'legacy\powershell\src' }
)
foreach ($c in $copies) {
    $dest = Join-Path $stage $c.To
    New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
    Copy-Item -LiteralPath $c.From -Destination $dest -Recurse -Force
}

@'
# Runs every Collect category with 1.38.x and v2 on this host and writes the comparison next to this script.
# Run once elevated and once as a standard user (Windows PowerShell 5.1; no .NET SDK needed).
$ErrorActionPreference = 'Stop'
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$label = if ($elevated) { 'elevated' } else { 'standard-user' }
$out = Join-Path $PSScriptRoot "parity-$label.txt"
$cases = Join-Path $env:TEMP "foton-collect-parity-$label"
& (Join-Path $PSScriptRoot 'tests\parity\Invoke-CollectParity.ps1') -NoBuild -OutputPath $cases `
    -Category Processes, Network, Users, System, Persistence, Security, Software, EventLogs, Filesystem *> $out
Write-Host "Comparison written to $out"
Write-Host "Case folders (host data; delete after review): $cases"
'@ | Set-Content -LiteralPath (Join-Path $stage 'Run-Parity.ps1') -Encoding UTF8

$zip = Join-Path $OutputPath 'foton-parity-bundle.zip'
Compress-Archive -Path $stage -DestinationPath $zip -Force
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
Write-Host "Bundle: $zip"
Write-Host "SHA-256: $hash"

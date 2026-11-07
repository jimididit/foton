<#
.SYNOPSIS
    Same-host parity check: frozen 1.38.x New-FotonBaseline against foton-baseline.exe, diffed with foton.exe.

.DESCRIPTION
    Captures one snapshot with the legacy PowerShell module and one with the v2 executable, back to back,
    then compares them (1.38.x as reference). Run it once as a standard user and once elevated.
    Expected differences are the documented 1.14.0 -> 1.15.0 changes (BitsJob NotifyCmdLine, Defender
    "(not reported)", WinHttpSettings hex, standard-user hive rows, tied InstalledSoftware duplicates)
    plus real drift between the two captures (a BITS job finishing, a service StartMode flip).

.EXAMPLE
    .\tests\parity\Invoke-BaselineParity.ps1
    Builds Release, captures both snapshots under %TEMP%\foton-parity, and prints changes grouped by type.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:TEMP 'foton-parity'),
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $NoBuild) {
    & dotnet build (Join-Path $root 'Foton.sln') -c Release --nologo -v q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
}
$baselineExe = Join-Path $root 'cli\Foton.Baseline.Cli\bin\Release\net462\foton-baseline.exe'
$fotonExe = Join-Path $root 'cli\Foton.Cli\bin\Release\net462\foton.exe'
$legacy = Join-Path $root 'legacy\powershell\Foton.psd1'

if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
New-Item -ItemType Directory -Path $OutputPath | Out-Null
$ps = Join-Path $OutputPath 'ps.json'
$cs = Join-Path $OutputPath 'cs.json'

& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '$legacy' -Force; New-FotonBaseline -Path '$ps' -NoHtml | Out-Null"
& $baselineExe -Path $cs | Out-Null
& $fotonExe compare $ps $cs | Out-Null

$diff = Join-Path $OutputPath 'baseline_diff.csv'
$rows = @(Import-Csv -LiteralPath $diff)
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Elevated: $elevated  Changes: $($rows.Count)  Output: $OutputPath"
$rows | Group-Object RecordType, ChangeType, Field | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize

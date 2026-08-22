# Foton standalone collector build
#
# Develop as a module; ship Collect as one file. Target endpoints often cannot
# install modules and may only accept a single script via RMM.
#
# Intended concatenation (not implemented in this scaffold):
#   Private/Core + Public/Collect + Public/Report + generated entry point
#   → dist/Foton-Collect.ps1
# No Import-Module, no extra files on disk.
#
# Until Collect is extracted from WinFoton.ps1, this script refuses to emit a
# collector so we never ship an empty or partial "Foton" that looks like v1.

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\dist\Foton-Collect.ps1')
)

$ErrorActionPreference = 'Stop'

Write-Host 'Foton Build-Standalone: Collect sources are not extracted yet.' -ForegroundColor Yellow
Write-Host 'Live triage remains the frozen reference: WinFoton.ps1 (v1.0.0).' -ForegroundColor Yellow
Write-Host 'This builder will write dist/Foton-Collect.ps1 after src/Public/Collect is populated.' -ForegroundColor DarkGray
Write-Host "Planned output: $OutputPath"

exit 2

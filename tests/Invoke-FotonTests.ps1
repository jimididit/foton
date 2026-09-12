# Invoke-FotonTests.ps1
# Runs Pester against ./tests. Requires Pester 5 (Install-Module Pester -Scope CurrentUser).

[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version]'5.0.0' })) {
    throw 'Pester 5+ is required. Install-Module Pester -Scope CurrentUser'
}

Import-Module Pester -MinimumVersion 5.0.0
$config = New-PesterConfiguration
$config.Run.Path = $Path
$config.Output.Verbosity = 'Detailed'
# Fail the process (and CI) when any test fails; Detailed still prints the table.
$config.Run.Exit = $true
Invoke-Pester -Configuration $config

# Foton.psm1
#
# Loads the module by convention, not by an ever-growing list of dotsource lines.
# Contributor rule: put a .ps1 in src/Private (helpers, data, schema) or src/Public
# (one exported command per file). This file only needs a change if you add a new
# top-level directory under src/.
#
# Load order matters: Private first so Public commands can call helpers.
# Files are sorted by full path so load order is deterministic across machines.
#
# Dot-source at *this* script scope. Dot-sourcing inside a helper function (or
# ForEach-Object) defines commands in a nested scope; they vanish on return.

Set-StrictMode -Version 1
$ErrorActionPreference = 'Continue'

$script:FotonModuleRoot = $PSScriptRoot
$script:FotonSrcRoot    = Join-Path $PSScriptRoot 'src'
$script:FotonSession    = $null

foreach ($dirName in @('Private', 'Public')) {
    $directory = Join-Path $script:FotonSrcRoot $dirName
    if (-not (Test-Path -LiteralPath $directory)) {
        continue
    }
    $files = @(
        Get-ChildItem -LiteralPath $directory -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName
    )
    foreach ($file in $files) {
        . $file.FullName
    }
}

Initialize-FotonSession

$manifestPath = Join-Path $script:FotonModuleRoot 'Foton.psd1'
if (Test-Path -LiteralPath $manifestPath) {
    $man = Import-PowerShellDataFile -LiteralPath $manifestPath
    $script:FotonSession.Version = [string]$man.ModuleVersion
}

# Public exports are declared in Foton.psd1 (FunctionsToExport).

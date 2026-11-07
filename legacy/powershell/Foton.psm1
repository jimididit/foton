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

# Foton.cmd uses Windows PowerShell 5.1 -NoProfile. Module-scope calls do not
# always auto-load Microsoft.PowerShell.Utility, so Get-FileHash is missing.
# Prefetch Utility here; Get-FotonSha256Hex also falls back to .NET.
Import-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue | Out-Null

$script:FotonModuleRoot = $PSScriptRoot
$script:FotonSrcRoot    = Join-Path $PSScriptRoot 'src'
$script:FotonSession    = $null
$script:FotonEmbeddedPatterns = $null
$script:FotonEmbeddedBaselineSchema = $null
$script:FotonBaselineProviders = New-Object System.Collections.ArrayList

# Load Private/Core first (helpers). Then remaining Private (providers register at
# load). Then Public. Sorted within each group for deterministic order.

$loaded = New-Object 'System.Collections.Generic.HashSet[string]'
$groups = @(
    (Join-Path $script:FotonSrcRoot 'Private\Core'),
    (Join-Path $script:FotonSrcRoot 'Private'),
    (Join-Path $script:FotonSrcRoot 'Public')
)
foreach ($directory in $groups) {
    if (-not (Test-Path -LiteralPath $directory)) { continue }
    $files = @(
        Get-ChildItem -LiteralPath $directory -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
            Sort-Object FullName
    )
    foreach ($file in $files) {
        if ($loaded.Contains($file.FullName)) { continue }
        $null = $loaded.Add($file.FullName)
        . $file.FullName
    }
}

Initialize-FotonSession

$manifestPath = Join-Path $script:FotonModuleRoot 'Foton.psd1'
if (Test-Path -LiteralPath $manifestPath) {
    # Import-PowerShellDataFile is a Utility cmdlet and is not always resolvable
    # from module scope during import. A missing version stamp must never fail
    # the import, so fall back to reading ModuleVersion out of the manifest text.
    $ver = ''
    $released = ''
    try {
        $man = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop
        $ver = [string]$man.ModuleVersion
        $released = [string]$man.PrivateData.Foton.ReleaseDate
    }
    catch {
        try {
            $raw = [IO.File]::ReadAllText($manifestPath)
            $m = [regex]::Match($raw, "(?m)^\s*ModuleVersion\s*=\s*'([^']+)'")
            if ($m.Success) { $ver = $m.Groups[1].Value }
            $m = [regex]::Match($raw, "(?m)^\s*ReleaseDate\s*=\s*'([^']+)'")
            if ($m.Success) { $released = $m.Groups[1].Value }
        }
        catch { }
    }
    if ($ver) { $script:FotonSession.Version = $ver }
    if ($released) { $script:FotonSession.ReleaseDate = $released }
}

# Public exports are declared in Foton.psd1 (FunctionsToExport).

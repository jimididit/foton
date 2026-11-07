# Foton release build
#
# Produces every release asset in one folder (default dist\release):
#   Foton-Collect_v{module}_schema{collect}.ps1    endpoint collector (flatten)
#   Foton-Baseline_v{module}_schema{baseline}.ps1  endpoint baseline (flatten)
#   Foton-Workstation_v{module}.zip                analyst workstation, no git clone needed
#   SHA256SUMS.txt                                 hashes of the three files above
# and a PowerShell Gallery staging folder (gallery\Foton) for Publish-Module.
#
# The workstation zip and the Gallery module carry the same allow-listed files: the
# module, Foton.cmd and its wrapper, the two flattens (so `Foton.cmd collect` works),
# and the operator docs. Tests, build scripts, and contributor docs are not shipped.

[CmdletBinding()]
param(
    # Module root (legacy\powershell). Operator docs and LICENSE come from -DocsRoot.
    [string]$RepoRoot,
    [string]$OutputPath,
    # Repository root holding LICENSE, README.md, SECURITY.md, and docs\.
    [string]$DocsRoot,
    # Skip rebuilding the flattens (tests that only exercise packaging).
    [switch]$SkipFlattenBuild
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Join-Path $PSScriptRoot '..' }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
# Operator docs shipped from DocsRoot. Validate instead of assuming a layout, so a module
# copied elsewhere fails here with a clear message rather than shipping someone else's docs.
$docFiles = @('LICENSE', 'README.md', 'SECURITY.md', 'docs\USAGE.md', 'docs\CARVE.md')
function Test-FotonDocsRoot([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    foreach ($f in $docFiles) { if (-not (Test-Path -LiteralPath (Join-Path $Path $f) -PathType Leaf)) { return $false } }
    return $true
}
if ($DocsRoot) {
    if (-not (Test-FotonDocsRoot $DocsRoot)) {
        throw "-DocsRoot '$DocsRoot' must contain: $($docFiles -join ', ')."
    }
}
else {
    # Repository layout (module in legacy\powershell) first, then the pre-move layout (docs beside the module).
    $DocsRoot = @((Join-Path $RepoRoot '..\..'), $RepoRoot) | Where-Object { Test-FotonDocsRoot $_ } | Select-Object -First 1
    if (-not $DocsRoot) {
        throw "Operator docs not found two levels above or inside -RepoRoot '$RepoRoot'. Pass -DocsRoot <folder containing $($docFiles -join ', ')>."
    }
}
$DocsRoot = (Resolve-Path -LiteralPath $DocsRoot).Path
if (-not $OutputPath) { $OutputPath = Join-Path $RepoRoot 'dist\release' }

$psd1 = Import-PowerShellDataFile -LiteralPath (Join-Path $RepoRoot 'Foton.psd1')
$version = [string]$psd1.ModuleVersion
$collectSchema = [string]$psd1.PrivateData.Foton.CollectSchemaVersion
$baselineSchema = [string]$psd1.PrivateData.Foton.BaselineSchemaVersion

if (-not $SkipFlattenBuild) {
    # Both builds run the AMSI load check and throw if it fails.
    & (Join-Path $RepoRoot 'build\Build-Standalone.ps1') -RepoRoot $RepoRoot | Out-Host
    & (Join-Path $RepoRoot 'build\Build-BaselineStandalone.ps1') -RepoRoot $RepoRoot | Out-Host
}
$collectLeaf = "Foton-Collect_v${version}_schema${collectSchema}.ps1"
$baselineLeaf = "Foton-Baseline_v${version}_schema${baselineSchema}.ps1"
foreach ($leaf in @($collectLeaf, $baselineLeaf, 'Foton-Collect.ps1', 'Foton-Baseline.ps1')) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot "dist\$leaf"))) {
        throw "dist\$leaf is missing. Run the flatten builds first (or omit -SkipFlattenBuild)."
    }
}

if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Allow-list. Module files are relative to -RepoRoot, operator docs to -DocsRoot.
# Directories are copied whole. The shipped layout is the same as before the legacy move.
$shipped = @(
    @{ Root = $RepoRoot; Rel = 'Foton.psd1' }
    @{ Root = $RepoRoot; Rel = 'Foton.psm1' }
    @{ Root = $RepoRoot; Rel = 'Foton.cmd' }
    @{ Root = $RepoRoot; Rel = 'src' }
    @{ Root = $RepoRoot; Rel = 'tools\Invoke-FotonEasy.ps1' }
    @{ Root = $RepoRoot; Rel = 'dist\Foton-Collect.ps1' }
    @{ Root = $RepoRoot; Rel = 'dist\Foton-Baseline.ps1' }
    @{ Root = $DocsRoot; Rel = 'LICENSE' }
    @{ Root = $DocsRoot; Rel = 'README.md' }
    @{ Root = $DocsRoot; Rel = 'SECURITY.md' }
    @{ Root = $DocsRoot; Rel = 'docs\USAGE.md' }
    @{ Root = $DocsRoot; Rel = 'docs\CARVE.md' }
)

function Copy-FotonShippedTree {
    param([string]$Destination)
    foreach ($item in $shipped) {
        $rel = $item.Rel
        $src = Join-Path $item.Root $rel
        if (-not (Test-Path -LiteralPath $src)) { throw "Shipped path missing: $rel" }
        $dst = Join-Path $Destination $rel
        New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
        if ((Get-Item -LiteralPath $src).PSIsContainer) {
            Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
        }
        else {
            Copy-Item -LiteralPath $src -Destination $dst -Force
        }
    }
}

# Workstation zip: one top-level folder so extracting never sprays files.
$stage = Join-Path $OutputPath 'stage'
$zipRoot = Join-Path $stage "Foton-$version"
Copy-FotonShippedTree -Destination $zipRoot
$zipLeaf = "Foton-Workstation_v${version}.zip"
$zipPath = Join-Path $OutputPath $zipLeaf
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($zipRoot, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $true)
Remove-Item -LiteralPath $stage -Recurse -Force

# Gallery staging: Publish-Module needs a folder named after the module.
$galleryModule = Join-Path $OutputPath 'gallery\Foton'
Copy-FotonShippedTree -Destination $galleryModule

Copy-Item -LiteralPath (Join-Path $RepoRoot "dist\$collectLeaf") -Destination $OutputPath -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "dist\$baselineLeaf") -Destination $OutputPath -Force

# sha256sum format (hash, two spaces, name) so `sha256sum -c` and Get-FileHash both work.
$assets = @($collectLeaf, $baselineLeaf, $zipLeaf)
$sums = foreach ($leaf in $assets) {
    '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $OutputPath $leaf) -Algorithm SHA256).Hash.ToLowerInvariant(), $leaf
}
[IO.File]::WriteAllLines((Join-Path $OutputPath 'SHA256SUMS.txt'), [string[]]$sums, (New-Object Text.UTF8Encoding $false))

Write-Host "Release assets for Foton $version in $OutputPath" -ForegroundColor Green
foreach ($leaf in @($assets + 'SHA256SUMS.txt')) { Write-Host "  $leaf" }
Write-Host "  gallery\Foton (Publish-Module -Path)" -ForegroundColor DarkGray

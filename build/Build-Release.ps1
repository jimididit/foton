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
    [string]$RepoRoot,
    [string]$OutputPath,
    # Skip rebuilding the flattens (tests that only exercise packaging).
    [switch]$SkipFlattenBuild
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Join-Path $PSScriptRoot '..' }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
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

# Allow-list, relative to the repo root. Directories are copied whole.
$shipped = @(
    'Foton.psd1', 'Foton.psm1', 'Foton.cmd', 'LICENSE', 'README.md', 'SECURITY.md',
    'src',
    'tools\Invoke-FotonEasy.ps1',
    'docs\USAGE.md', 'docs\CARVE.md',
    'dist\Foton-Collect.ps1', 'dist\Foton-Baseline.ps1'
)

function Copy-FotonShippedTree {
    param([string]$Destination)
    foreach ($rel in $shipped) {
        $src = Join-Path $RepoRoot $rel
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

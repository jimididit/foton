# Invoke-FotonEasy.ps1
# Menu/wrapper so collection and analysis do not require memorizing cmdlets.
# Collect still uses dist\Foton-Collect.ps1 (one file on the endpoint).

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Target,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$collect = Join-Path $repoRoot 'dist\Foton-Collect.ps1'
$psd1 = Join-Path $repoRoot 'Foton.psd1'
$banner = Join-Path $repoRoot 'src\Private\Core\Write-FotonBanner.ps1'

function Show-FotonEasyHelp {
    Write-Host '  Simple commands' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Collect on a Windows PC (copy ONE file, no module install):'
    Write-Host '    1. On a lab box:  .\build\Build-Standalone.ps1'
    Write-Host '    2. Copy dist\Foton-Collect.ps1 to the target'
    Write-Host '    3. Double-click it or:  powershell -File Foton-Collect.ps1'
    Write-Host ''
    Write-Host '  On this repo (workstation):'
    Write-Host '    Foton.cmd analyze  C:\FotonCases\Foton_HOST_...Z'
    Write-Host '    Foton.cmd baseline C:\Baselines\this-pc.json'
    Write-Host '    Foton.cmd compare  C:\Baselines\day0.json C:\Baselines\day1.json'
    Write-Host '    Foton.cmd parse    C:\path\file.lnk'
    Write-Host '    Foton.cmd ioc      C:\FotonCases\Foton_HOST_...Z C:\intel\iocs.txt'
    Write-Host '    Foton.cmd carve    C:\blob.bin'
    Write-Host '    Foton.cmd collect  C:\FotonCases     (runs dist\Foton-Collect.ps1 if built)'
    Write-Host ''
    Write-Host '  Open Foton_Report.html from INSIDE the case folder after analyze.'
    Write-Host '  Findings are observations, not conclusions.'
    Write-Host ''
}

$cmd = $Command.ToLower()
if ($cmd -notin @('collect', 'baseline', 'compare') -and (Test-Path -LiteralPath $banner)) {
    . $banner
    Write-FotonBanner -Kind 'Easy'
}

if ($cmd -in @('help', '-h', '/h', '/?', '')) {
    Show-FotonEasyHelp
    return
}

if ($cmd -eq 'collect') {
    if (-not (Test-Path -LiteralPath $collect)) {
        Write-Host '  dist\Foton-Collect.ps1 is missing. Run .\build\Build-Standalone.ps1 first.' -ForegroundColor Yellow
        exit 2
    }
    $out = $Target
    if (-not $out) { $out = Join-Path $env:USERPROFILE 'Desktop' }
    & $collect -OutputPath $out -NoZip @Rest
    return
}

Import-Module $psd1 -Force

switch ($cmd) {
    'analyze' {
        if (-not $Target) { throw 'Usage: Foton.cmd analyze <case-folder-or-zip>' }
        Get-FotonPackage -Path $Target | Out-Null
        Invoke-FotonAnalysis
        New-FotonReport
        Write-Host "  Report: $(Join-Path $Target 'Foton_Report.html')" -ForegroundColor Green
    }
    'baseline' {
        if (-not $Target) { throw 'Usage: Foton.cmd baseline <output.json>' }
        New-FotonBaseline -Path $Target
    }
    'compare' {
        $b = $Rest | Select-Object -First 1
        if (-not $Target -or -not $b) { throw 'Usage: Foton.cmd compare <day0.json> <day1.json>' }
        Compare-FotonBaseline -ReferencePath $Target -DifferencePath $b | Format-Table -AutoSize
    }
    'parse' {
        if (-not $Target) { throw 'Usage: Foton.cmd parse <file.pf|file.lnk>' }
        Invoke-FotonParse -Path $Target | Format-List
    }
    'ioc' {
        $iocFile = $Rest | Select-Object -First 1
        if (-not $Target -or -not $iocFile) { throw 'Usage: Foton.cmd ioc <case-folder> <ioc-file>' }
        Invoke-FotonIocMatch -Path $Target -IocPath $iocFile | Format-Table -AutoSize
    }
    'carve' {
        if (-not $Target) { throw 'Usage: Foton.cmd carve <blob>' }
        Invoke-FotonCarve -Path $Target | Format-Table -AutoSize
    }
    default {
        Show-FotonEasyHelp
        throw "Unknown command: $Command"
    }
}

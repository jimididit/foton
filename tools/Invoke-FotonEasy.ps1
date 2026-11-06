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
    Write-Host '    2. Copy dist\Foton-Collect_v*_schema*.ps1 (or Foton-Collect.ps1) to the target'
    Write-Host '    3. Double-click it or:  powershell -File Foton-Collect.ps1'
    Write-Host ''
    Write-Host '  Baseline (known-state snapshot, different file):'
    Write-Host '    .\build\Build-BaselineStandalone.ps1'
    Write-Host '    Copy dist\Foton-Baseline_v*_schema*.ps1 (or Foton-Baseline.ps1) to the target, then run it.'
    Write-Host '    Open Foton_Baseline.html inside FotonBaseline_HOSTNAME_...Z'
    Write-Host ''
    Write-Host '  On this repo (workstation). Extract a ZIP first, then parse, compose, analyze (last):'
    Write-Host '    Foton.cmd parse    D:\Cases\Foton_HOSTNAME_...Z'
    Write-Host '    Foton.cmd compose  D:\Cases\Foton_HOSTNAME_...Z'
    Write-Host '    Foton.cmd analyze  D:\Cases\Foton_HOSTNAME_...Z'
    Write-Host '    Foton.cmd ioc      D:\Cases\Foton_HOSTNAME_...Z D:\intel\iocs.txt'
    Write-Host '    Foton.cmd baseline D:\Baselines'
    Write-Host '    Foton.cmd baseline D:\Baselines\this-pc.json'
    Write-Host '    Foton.cmd compare  D:\Baselines\day0.json D:\Baselines\day1.json'
    Write-Host '    Foton.cmd tools    Hayabusa          (one-time workstation setup; does not change PATH)'
    Write-Host '    Foton.cmd tools    EZTools C:\Tools\EZTools   (register an existing install; also Chainsaw <dir>)'
    Write-Host '    Foton.cmd tools                      (list pinned tools)'
    Write-Host '    Foton.cmd carve    D:\blob.bin'
    Write-Host '    Foton.cmd collect  D:\Cases          (runs dist\Foton-Collect.ps1 if built)'
    Write-Host ''
    Write-Host '  Open Foton_Report.html after analyze. Open analysis\Foton_Parse.html after parse.'
    Write-Host '  Findings are observations, not conclusions. Full command list: docs\USAGE.md'
    Write-Host ''
}

$cmd = $Command.ToLower()
if ($cmd -notin @('collect', 'baseline', 'compare') -and (Test-Path -LiteralPath $banner)) {
    # The banner reads the version from Foton.psd1 under FotonModuleRoot; without it,
    # dot-sourcing outside the module fell back to a stale hard-coded version.
    $script:FotonModuleRoot = $repoRoot
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
        $reportPath = New-FotonReport
        Write-Host "  Report: $reportPath" -ForegroundColor Green
    }
    'baseline' {
        if (-not $Target) { throw 'Usage: Foton.cmd baseline <output-folder-or.json>' }
        if ($Target -like '*.json') {
            New-FotonBaseline -Path $Target
        }
        else {
            New-FotonBaseline -OutputPath $Target
        }
    }
    'compare' {
        $b = $Rest | Select-Object -First 1
        if (-not $Target -or -not $b) { throw 'Usage: Foton.cmd compare <day0.json-or-folder> <day1.json-or-folder>' }
        Compare-FotonBaseline -ReferencePath $Target -DifferencePath $b | Format-Table -AutoSize
        Write-Host '  Open Foton_BaselineCompare.html next to the second baseline JSON.' -ForegroundColor Green
    }
    'parse' {
        if (-not $Target) { throw 'Usage: Foton.cmd parse <case-folder-or-zip | file.pf | file.lnk | jumplist | Amcache.hve>' }
        $rows = @(Invoke-FotonParse -Path $Target)
        if ($rows.Count -eq 0) {
            Write-Host '  Nothing to show. Parse needs copied .pf/.lnk inside the package (08_Filesystem\prefetch), not a listing CSV.' -ForegroundColor Yellow
            return
        }
        $rows | Select-Object SourcePath, Format, Supported, ExecutableName, LocalBasePath, Note |
            Format-Table -AutoSize -Wrap
        Write-Host '  HTML: analysis\Foton_Parse.html (folder) or <zip>_Parse.html (ZIP). Not findings.csv.' -ForegroundColor Green
        Write-Host '  CSV:  analysis\parsed_records.csv. Win10+ Prefetch is often MAM-compressed (file seen, name not decoded). Amcache LinkDate is a stored string, not converted to UTC.' -ForegroundColor DarkGray
    }
    'compose' {
        if (-not $Target) { throw 'Usage: Foton.cmd compose <case-folder-or-zip>' }
        # Invoke-FotonExternalParse opens the package itself; loading it here too
        # just prints the "Loaded package" line twice.
        $rows = @(Invoke-FotonExternalParse -PackagePath $Target)
        $rows | Select-Object Tool, Version, Status, DestRelative, Note |
            Format-Table -AutoSize -Wrap
        Write-Host '  Inventory: analysis\external\external_parse_inventory.csv. Native Invoke-FotonParse if tools are missing.' -ForegroundColor Green
        Write-Host '  Missing Hayabusa: Foton.cmd tools Hayabusa. Existing EZ Tools / Chainsaw folder: Foton.cmd tools EZTools <dir>' -ForegroundColor DarkGray
    }
    'tools' {
        # One-time workstation setup. Never runs inside compose (offline invariant).
        if (-not $Target -or $Target -in @('list', '-list', '/list')) {
            Install-FotonTool -List | Format-Table -AutoSize -Wrap | Out-Host
            return
        }
        $archive = $null
        $existing = $null
        if ($Rest -and $Rest.Count -ge 2 -and $Rest[0] -eq '-ArchivePath') {
            $archive = $Rest[1]
        }
        elseif ($Rest -and $Rest.Count -ge 1 -and (Test-Path -LiteralPath $Rest[0])) {
            # A .zip is a release archive to install; a folder or .exe is an existing install to register.
            if ([IO.Path]::GetExtension($Rest[0]) -eq '.zip') { $archive = $Rest[0] } else { $existing = $Rest[0] }
        }
        if ($existing) {
            Install-FotonTool -Name $Target -Path $existing -Force | Out-Null
        }
        elseif ($archive) {
            Install-FotonTool -Name $Target -ArchivePath $archive -Force
        }
        else {
            Install-FotonTool -Name $Target
        }
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

<#
.SYNOPSIS
    Same-host parity check for Collect: the frozen 1.38.x module against the v2 collect orchestrator, one slice at a time.

.DESCRIPTION
    Runs the chosen categories with the legacy module (inside its module scope, in Invoke-FotonTriage's order of steps)
    and with tests\Foton.CollectProbe, back to back and without ZIPs, then compares the two case folders:

    - the 00_Collection file set, chain_of_custody.txt line by line (run-specific values masked), and coverage JSON;
    - manifest rows per task (File, Status, Records);
    - each task artifact's shape: CSV columns and row count, JSON record count and keys, TXT line count;
    - finding titles.

    Live state moves between the two runs (processes, connections, recent events), so a count delta on a volatile
    task is drift, not a defect. Run it once as a standard user and once elevated. The case folders stay under
    -OutputPath for a closer look; they hold this host's data, so never commit them.

.EXAMPLE
    .\tests\parity\Invoke-CollectParity.ps1 -Category System,Users,Software
#>
[CmdletBinding()]
param(
    [ValidateSet('Processes', 'Network', 'Users', 'System', 'Persistence', 'Security', 'Software', 'EventLogs', 'Filesystem')]
    [string[]]$Category = @(),
    [string]$OutputPath = (Join-Path $env:TEMP 'foton-collect-parity'),
    [switch]$NoBuild,
    # Re-compare the case folders already under -OutputPath without collecting again.
    [switch]$CompareOnly
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $NoBuild -and -not $CompareOnly) {
    & dotnet build (Join-Path $root 'Foton.sln') -c Release --nologo -v q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed.' }
}
$probe = Join-Path $root 'tests\Foton.CollectProbe\bin\Release\net472\Foton.CollectProbe.exe'
$legacy = Join-Path $root 'legacy\powershell\Foton.psd1'
$psOut = Join-Path $OutputPath 'ps'
$csOut = Join-Path $OutputPath 'cs'
if (-not $CompareOnly) {
    if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Recurse -Force }
    New-Item -ItemType Directory -Path $psOut, $csOut | Out-Null
}

$functions = @{
    Processes = 'Invoke-FotonProcessCollection'; Network = 'Invoke-FotonNetworkCollection'; Users = 'Invoke-FotonUserCollection'
    System = 'Invoke-FotonSystemCollection'; Persistence = 'Invoke-FotonPersistenceCollection'; Security = 'Invoke-FotonSecurityCollection'
    Software = 'Invoke-FotonSoftwareCollection'; EventLogs = 'Invoke-FotonEventLogCollection'; Filesystem = 'Invoke-FotonFilesystemCollection'
}
$order = 'Processes', 'Network', 'Users', 'System', 'Persistence', 'Security', 'Software', 'EventLogs', 'Filesystem'
$calls = ($order | Where-Object { $Category -contains $_ } | ForEach-Object { $functions[$_] }) -join '; '

# Invoke-FotonTriage's steps with only the chosen categories (no hive mount, no ZIP).
$legacyRun = @"
`$m = Import-Module '$legacy' -Force -PassThru
& `$m {
    Initialize-FotonSession
    # The Collect flatten ships without the suspicious-command list; the module loads it.
    `$script:FotonSession.SuspiciousCommandPatterns = @()
    `$script:FotonSession.Version = [string](Import-PowerShellDataFile -LiteralPath '$legacy').ModuleVersion
    `$script:FotonSession.StartTimeUtc = (Get-Date).ToUniversalTime()
    `$script:FotonSession.IsElevated = Test-FotonElevated
    `$script:FotonSession.Package = @{ CaseNumber = ''; Examiner = `$env:USERNAME; RequireAdministrator = `$false; LoadUserHives = `$false; OutputPath = '$psOut' }
    `$null = Initialize-FotonCase -OutputPath '$psOut'
    Write-FotonChainOfCustody -OutputPath '$psOut' -CaseNumber '' -Examiner `$env:USERNAME -NoZip
    $calls
    Write-FotonCollectionCoverage
    Invoke-FotonAnalysis
    Write-FotonManifestFiles
    `$null = New-FotonReport -Path (Join-Path `$script:FotonSession.CaseRoot 'Foton_Report.html')
    `$null = Write-FotonArtifactHashes
}
"@
if (-not $CompareOnly) {
    Write-Host "1.38.x: $($Category -join ', ')" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $legacyRun *> (Join-Path $OutputPath 'ps.log')
    Write-Host "v2:     $($Category -join ', ')" -ForegroundColor Cyan
    & $probe -OutputPath $csOut -Category ($Category -join ',') *> (Join-Path $OutputPath 'cs.log')
}

$psCase = (Get-ChildItem -LiteralPath $psOut -Directory | Select-Object -First 1).FullName
$csCase = (Get-ChildItem -LiteralPath $csOut -Directory | Select-Object -First 1).FullName
if (-not $psCase -or -not $csCase) { throw "A run produced no case folder (ps: $psCase, cs: $csCase)." }

function Show([string]$Title, $Rows, [switch]$List) {
    Write-Host ''
    Write-Host "== $Title" -ForegroundColor Yellow
    $Rows = @($Rows | Where-Object { $null -ne $_ })
    if ($Rows.Count -eq 0) { Write-Host '   (no differences)' -ForegroundColor Green }
    elseif ($List) { $Rows | Format-List | Out-String -Width 220 | Write-Host }
    else { $Rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host }
}

# 00_Collection file set (hashes and the report are compared by presence only).
$psFiles = Get-ChildItem -LiteralPath (Join-Path $psCase '00_Collection') -File | ForEach-Object Name
$csFiles = Get-ChildItem -LiteralPath (Join-Path $csCase '00_Collection') -File | ForEach-Object Name
Show '00_Collection files' (Compare-Object @($psFiles) @($csFiles) | Select-Object @{ n = 'File'; e = { $_.InputObject } }, @{ n = 'Only in'; e = { if ($_.SideIndicator -eq '<=') { '1.38.x' } else { 'v2' } } })

# Custody: values that differ per run are masked. The runtime lines differ by design (1.38.x: PowerShell Version and
# Script Path; v2: Runtime, Executable, and its SHA-256) and are left out of the comparison.
$mask = '^(Collection Tool|Collection Start UTC|Local Time At Start|  OutputPath)\s*[:=]'
$runtime = '^(PowerShell Version|Script Path|Runtime|Executable|Executable SHA-256)\s*:'
function Custody([string]$Case) {
    Get-Content -LiteralPath (Join-Path $Case '00_Collection\chain_of_custody.txt') | Where-Object { $_ -notmatch $runtime } |
        ForEach-Object { if ($_ -match $mask) { $Matches[0] + ' <masked>' } else { $_ } }
}
$psCustody = @(Custody $psCase)
$csCustody = @(Custody $csCase)
$custodyDiff = for ($i = 0; $i -lt [Math]::Max($psCustody.Count, $csCustody.Count); $i++) {
    if ($psCustody[$i] -cne $csCustody[$i]) { [PSCustomObject]@{ Line = $i + 1; '1.38.x' = $psCustody[$i]; v2 = $csCustody[$i] } }
}
Show 'chain_of_custody.txt' @($custodyDiff)

$psCov = Get-Content -LiteralPath (Join-Path $psCase '00_Collection\collection_coverage.json') -Raw | ConvertFrom-Json
$csCov = Get-Content -LiteralPath (Join-Path $csCase '00_Collection\collection_coverage.json') -Raw | ConvertFrom-Json
$covDiff = foreach ($p in $psCov.PSObject.Properties.Name) {
    $a = ConvertTo-Json -Compress -Depth 4 @($psCov.$p); $b = ConvertTo-Json -Compress -Depth 4 @($csCov.$p)
    if ($a -ne $b) { [PSCustomObject]@{ Field = $p; '1.38.x' = $a; v2 = $b } }
}
Show 'collection_coverage.json' @($covDiff)

# Manifest and artifact shape per task.
function Shape([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'missing' }
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $head = Get-Content -LiteralPath $Path -TotalCount 1
    if ($head -like 'Foton: *') { return 'placeholder: ' + $head }
    switch ($ext) {
        '.csv' { $rows = @(Import-Csv -LiteralPath $Path); $cols = if ($rows.Count) { $rows[0].PSObject.Properties.Name -join ',' } else { '' }; return "rows=$($rows.Count) cols=$cols" }
        '.json' {
            $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            $items = @($j); $keys = if ($items.Count -and $items[0] -is [psobject]) { ($items[0].PSObject.Properties.Name | Sort-Object) -join ',' } else { '' }
            return "items=$($items.Count) keys=$keys"
        }
        # Text artifacts differ in table layout (PowerShell formatter vs v2), so compare their section headers.
        default { return 'sections=' + ((Get-Content -LiteralPath $Path | Where-Object { $_ -match '^--- .* ---$' }) -join ' ') }
    }
}

$script:KeySets = @(@('RecordId'), @('File', 'Stream'), @('SourcePath', 'DestRelative'), @('FullName'), @('Path'))

# Per-column count of differing values between two CSV/JSON artifacts, without printing any value (host data).
function ValueDiff([string]$A, [string]$B) {
    $ext = [IO.Path]::GetExtension($A).ToLowerInvariant()
    if ($ext -notin '.csv', '.json' -or -not (Test-Path -LiteralPath $A) -or -not (Test-Path -LiteralPath $B)) { return '' }
    try {
        if ($ext -eq '.csv') { $ra = @(Import-Csv -LiteralPath $A); $rb = @(Import-Csv -LiteralPath $B) }
        else { $ra = @(Get-Content -LiteralPath $A -Raw | ConvertFrom-Json); $rb = @(Get-Content -LiteralPath $B -Raw | ConvertFrom-Json) }
    }
    catch { return '' }
    if ($ra.Count -eq 0 -or $rb.Count -eq 0 -or -not ($ra[0] -is [psobject])) { return '' }
    $cols = $ra[0].PSObject.Properties.Name
    # Rows move between the two runs (new events, files, ties in a sort), so match on an identity column when one
    # is unique on both sides; position is the fallback. Hashtable keys are case-insensitive, like Windows paths.
    foreach ($keySet in $script:KeySets) {
        if (@($keySet | Where-Object { $cols -notcontains $_ }).Count) { continue }
        $ia = @{}; $ib = @{}; $unique = $true
        foreach ($r in $ra) { $k = ($keySet | ForEach-Object { [string]$r.$_ }) -join '|'; if ($ia.ContainsKey($k)) { $unique = $false; break }; $ia[$k] = $r }
        foreach ($r in $rb) { $k = ($keySet | ForEach-Object { [string]$r.$_ }) -join '|'; if ($ib.ContainsKey($k)) { $unique = $false; break }; $ib[$k] = $r }
        if (-not $unique) { continue }
        $onlyA = @($ia.Keys | Where-Object { -not $ib.ContainsKey($_) }).Count
        $onlyB = @($ib.Keys | Where-Object { -not $ia.ContainsKey($_) }).Count
        $diff = foreach ($c in $cols) {
            $n = 0
            foreach ($k in $ia.Keys) { if ($ib.ContainsKey($k) -and (ConvertTo-Json -Compress -Depth 4 $ia[$k].$c) -cne (ConvertTo-Json -Compress -Depth 4 $ib[$k].$c)) { $n++ } }
            if ($n) { "$c($n)" }
        }
        if (-not $onlyA -and -not $onlyB -and -not $diff) { return '' }
        return ("keyed on {0}: only 1.38.x {1}, only v2 {2}; {3}" -f ($keySet -join '+'), $onlyA, $onlyB, ($diff -join ' '))
    }
    if ($ra.Count -ne $rb.Count) { return '' }
    $out = foreach ($c in $cols) {
        $n = 0
        for ($i = 0; $i -lt $ra.Count; $i++) {
            if ((ConvertTo-Json -Compress -Depth 4 $ra[$i].$c) -cne (ConvertTo-Json -Compress -Depth 4 $rb[$i].$c)) { $n++ }
        }
        if ($n) { "$c($n)" }
    }
    return ($out -join ' ')
}
$psMan = @(Import-Csv -LiteralPath (Join-Path $psCase '00_Collection\collection_manifest.csv'))
$csMan = @(Import-Csv -LiteralPath (Join-Path $csCase '00_Collection\collection_manifest.csv'))
$tasks = @($psMan.Task) + @($csMan.Task) | Where-Object { $_ } | Select-Object -Unique
$taskDiff = foreach ($t in $tasks) {
    $a = $psMan | Where-Object Task -eq $t | Select-Object -First 1
    $b = $csMan | Where-Object Task -eq $t | Select-Object -First 1
    $sa = if ($a) { Shape (Join-Path $psCase $a.File) } else { 'not run' }
    $sb = if ($b) { Shape (Join-Path $csCase $b.File) } else { 'not run' }
    $vd = if ($a -and $b) { ValueDiff (Join-Path $psCase $a.File) (Join-Path $csCase $b.File) } else { '' }
    if (-not $a -or -not $b -or $a.File -ne $b.File -or $a.Status -ne $b.Status -or $sa -ne $sb -or $vd) {
        [PSCustomObject]@{ Task = $t; '1.38.x' = "$($a.Status) $($a.Records) | $sa"; v2 = "$($b.Status) $($b.Records) | $sb"; 'Differing values' = $vd }
    }
}
Show "Tasks ($($tasks.Count) run; rows below differ in file, status, shape, or values)" @($taskDiff) -List

$psFind = @(Import-Csv -LiteralPath (Join-Path $psCase '00_Collection\findings.csv') -ErrorAction SilentlyContinue | ForEach-Object Title)
$csFind = @(Import-Csv -LiteralPath (Join-Path $csCase '00_Collection\findings.csv') -ErrorAction SilentlyContinue | ForEach-Object Title)
Show 'Finding titles' (Compare-Object $psFind $csFind | Select-Object @{ n = 'Title'; e = { $_.InputObject } }, @{ n = 'Only in'; e = { if ($_.SideIndicator -eq '<=') { '1.38.x' } else { 'v2' } } })

# Where each side spent its time (manifest DurationMs), so a slow task is visible instead of looking like a hang.
$slow = foreach ($side in @(@{ Name = '1.38.x'; Rows = $psMan }, @{ Name = 'v2'; Rows = $csMan })) {
    $total = ($side.Rows | Measure-Object { [int]$_.DurationMs } -Sum).Sum
    $top = ($side.Rows | Sort-Object { [int]$_.DurationMs } -Descending | Select-Object -First 3 | ForEach-Object { '{0} {1:N1}s' -f $_.Task, ([int]$_.DurationMs / 1000) }) -join ', '
    [PSCustomObject]@{ Side = $side.Name; 'Task time' = '{0:N1}s' -f ($total / 1000); Slowest = $top }
}
Show 'Duration' @($slow)

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ''
Write-Host "Elevated: $elevated  1.38.x: $psCase  v2: $csCase"

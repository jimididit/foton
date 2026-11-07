#requires -Version 5.1
<#
    Regenerates testdata\golden from the frozen PowerShell 1.38.x module (legacy\powershell).
    The C# tests compare against these files, so they never need PowerShell at runtime and
    keep working after legacy\powershell is deleted. Run only when a golden file must change,
    and say why in the PR:

        powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\golden\Update-Golden.ps1
#>
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Run under Windows PowerShell 5.1 (powershell.exe).' }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here '..\..')).Path
$out = Join-Path $repo 'testdata\golden'
New-Item -ItemType Directory -Force -Path $out | Out-Null

Import-Module (Join-Path $repo 'legacy\powershell\Foton.psd1') -Force
$m = Get-Module Foton

function Save-Raw([string]$Name, [string]$Text) {
    # Exact characters, UTF-8 without BOM, no trailing newline added.
    [IO.File]::WriteAllText((Join-Path $out $Name), $Text, (New-Object Text.UTF8Encoding $false))
}

# Report chrome, byte-for-byte.
Save-Raw 'nav.css' (& $m { Get-FotonReportNavCss })
Save-Raw 'navbar.html' (& $m { Get-FotonReportNavBarHtml })
Save-Raw 'nav.js' (& $m { Get-FotonReportNavScript })
Save-Raw 'mark.svg' (& $m { Get-FotonReportMarkSvg })

# HTML escaping and section ids: one input per line, tab, output.
$inputs = @('plain', 'a&b<c>d"e''f', 'C:\Path\<x>', 'ünï & çödé', '', 'Défense: 100% "ok"')
Save-Raw 'safehtml.tsv' ((& $m { param($i) foreach ($s in $i) { $s + "`t" + (ConvertTo-FotonSafeHtml -Text $s) } } $inputs) -join "`n")
$names = @('Findings', 'Persistence & Autoruns', '  leading/trailing  ', '***', 'Network (TCP/UDP) Listeners')
Save-Raw 'sectionid.tsv' ((& $m { param($i) foreach ($s in $i) { $s + "`t" + (Get-FotonReportSectionId -Name $s) } } $names) -join "`n")

# Export-Csv bytes for tricky values (what every collect CSV and the manifest look like).
$rows = @(
    [PSCustomObject]@{ Name = 'plain'; Quote = 'say "hi"'; Comma = 'a,b'; Newline = "line1`r`nline2"; Empty = ''; Null = $null; Flag = $true; Count = 42; Unicode = 'ünï ✓' }
    [PSCustomObject]@{ Name = 'second'; Quote = ''''; Comma = ','; Newline = "`n"; Empty = ''; Null = $null; Flag = $false; Count = -1; Unicode = '' }
)
$csv = Join-Path $out 'export.csv'
$rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

# Out-File -Encoding UTF8 bytes (collection.log header, skip texts, custody, hashes.txt).
@('first line', 'second line') | Out-File -FilePath (Join-Path $out 'outfile-lines.txt') -Encoding UTF8
"single string" | Out-File -FilePath (Join-Path $out 'outfile-single.txt') -Encoding UTF8
"appended" | Out-File -FilePath (Join-Path $out 'outfile-single.txt') -Encoding UTF8 -Append

# Copy-task status decisions.
$cases = [ordered]@{
    'none'    = @()
    'data'    = @([PSCustomObject]@{ Status = 'Error'; Name = 'pnp device' })
    'ok'      = @([PSCustomObject]@{ SourcePath = 'a'; Status = 'Copied'; Note = '' }, [PSCustomObject]@{ SourcePath = 'b'; Status = 'Missing'; Note = '' })
    'partial' = @([PSCustomObject]@{ SourcePath = 'a'; Status = 'Copied'; Note = '' }, [PSCustomObject]@{ SourcePath = 'C:\x'; Status = 'CopyError'; Note = 'in use' })
    'failed'  = @([PSCustomObject]@{ SourcePath = 'C:\h'; Status = 'SaveError'; Note = 'denied' }, [PSCustomObject]@{ SourcePath = 'b'; Status = 'CappedSkip'; Note = '' })
}
$lines = foreach ($k in $cases.Keys) {
    $r = & $m { param($rows) Get-FotonCopyTaskStatus -Rows $rows } $cases[$k]
    "$k`t$($r.Status)`t$($r.Message)"
}
Save-Raw 'copystatus.tsv' ($lines -join "`n")

# ---- Baseline -----------------------------------------------------------------------------
# Compare inputs: the 1.38.x fixtures with each provider's FalsePositives text filled in from the
# module (a captured baseline carries it; the fixtures predate that), plus a fleet variant.
$fixtures = Join-Path $repo 'legacy\powershell\tests\Fixtures\Baseline'
$fpOf = & $m { $h = @{}; foreach ($p in $script:FotonBaselineProviders) { $h[$p.RecordType] = $p.FalsePositives }; $h }
function Save-BaselineInput([string]$Source, [string]$Name, [string]$Hostname) {
    $doc = Get-Content -LiteralPath (Join-Path $fixtures $Source) -Raw | ConvertFrom-Json
    foreach ($p in $doc.Providers) { $p | Add-Member -NotePropertyName FalsePositives -NotePropertyValue ([string]$fpOf[$p.RecordType]) -Force }
    if ($Hostname) { $doc.Header.Hostname = $Hostname }
    ($doc | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $out $Name) -Encoding UTF8
}
Save-BaselineInput 'ref.json' 'baseline-ref.json' ''
Save-BaselineInput 'dif.json' 'baseline-dif.json' ''
Save-BaselineInput 'dif.json' 'baseline-dif-fleet.json' 'PC2'

foreach ($case in @(@{ Dif = 'baseline-dif.json'; Tag = 'temporal' }, @{ Dif = 'baseline-dif-fleet.json'; Tag = 'fleet' })) {
    $work = Join-Path $env:TEMP ('foton-golden-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    Copy-Item (Join-Path $out 'baseline-ref.json') (Join-Path $work 'ref.json')
    Copy-Item (Join-Path $out $case.Dif) (Join-Path $work 'dif.json')
    $null = Compare-FotonBaseline -ReferencePath (Join-Path $work 'ref.json') -DifferencePath (Join-Path $work 'dif.json') -NoHtml
    Copy-Item (Join-Path $work 'baseline_diff.csv') (Join-Path $out ("compare-{0}-diff.csv" -f $case.Tag))
    & $m { param($p) $script:FotonSession.Findings | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8 } (Join-Path $out ("compare-{0}-findings.csv" -f $case.Tag))
    Remove-Item -LiteralPath $work -Recurse -Force
}

# PayloadSha256 exactly as New-FotonBaseline computes it, over values that stress JSON escaping.
$records = [ordered]@{
    Service = @(
        [PSCustomObject]@{ Name = 'a"quote'; DisplayName = 'back\slash <tag> & ''apos'''; StartMode = "tab`there"; StartName = 'ünïcödé ✓'; PathName = "ctl" + [char]1 + "end" }
        [PSCustomObject]@{ Name = 'b'; DisplayName = ''; StartMode = $null; StartName = 'line1' + "`r`n" + 'line2'; PathName = [char]0x2028 + 'sep' }
    )
    LocalAccount = @(
        [PSCustomObject]@{ SID = 'S-1-5-21-1-2-3-500'; Name = 'Administrator'; Enabled = $false; PasswordRequired = $true; PasswordExpires = '' }
    )
    Empty = @()
}
$compact = $records | ConvertTo-Json -Depth 8 -Compress
$sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($compact))).Replace('-', '')
($records | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath (Join-Path $out 'payload-records.json') -Encoding UTF8
Save-Raw 'payload-compact.txt' $compact
Save-Raw 'payload-sha256.txt' $sha

Get-ChildItem $out | ForEach-Object { '{0,-30} {1,6}' -f $_.Name, $_.Length }

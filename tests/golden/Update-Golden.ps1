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

# Baseline HTML: snapshot of the difference fixture (full and capped) and both compare modes.
$work = Join-Path $env:TEMP ('foton-golden-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
Copy-Item (Join-Path $out 'baseline-ref.json') (Join-Path $work 'ref.json')
Copy-Item (Join-Path $out 'baseline-dif.json') (Join-Path $work 'dif.json')
Copy-Item (Join-Path $out 'baseline-dif-fleet.json') (Join-Path $work 'fleet.json')
$null = & $m { param($p, $o) New-FotonBaselineReport -Path $p -OutputPath $o } (Join-Path $work 'dif.json') (Join-Path $out 'baseline-snapshot.html')
$null = & $m { param($p, $o) New-FotonBaselineReport -Path $p -OutputPath $o -MaxRows 1 } (Join-Path $work 'dif.json') (Join-Path $out 'baseline-snapshot-cap1.html')
$null = New-FotonBaselineCompareReport -ReferencePath (Join-Path $work 'ref.json') -DifferencePath (Join-Path $work 'dif.json') -OutputPath (Join-Path $out 'compare-temporal.html')
$null = New-FotonBaselineCompareReport -ReferencePath (Join-Path $work 'ref.json') -DifferencePath (Join-Path $work 'fleet.json') -OutputPath (Join-Path $out 'compare-fleet.html')
$null = New-FotonBaselineCompareReport -ReferencePath (Join-Path $work 'ref.json') -DifferencePath (Join-Path $work 'dif.json') -OutputPath (Join-Path $out 'compare-temporal-cap2.html') -MaxRows 2
Remove-Item -LiteralPath $work -Recurse -Force

# ---- Parse ------------------------------------------------------------------------------------
# Synthetic inputs only (no host or client data), rebuilt byte-for-byte on every run, then the 1.38.x
# Invoke-FotonParse output over a copy of them.
$parseIn = Join-Path $repo 'testdata\parse'
if (Test-Path -LiteralPath $parseIn) { Remove-Item -LiteralPath $parseIn -Recurse -Force }
$legacyFx = Join-Path $repo 'legacy\powershell\tests\Fixtures\Parse'
function U32([uint32]$v) { ,[BitConverter]::GetBytes($v) }
function I32([int32]$v) { ,[BitConverter]::GetBytes($v) }
function U16([uint16]$v) { ,[BitConverter]::GetBytes($v) }
# Windows PowerShell reads 0xFFFFFFFE as int -2, so the CFB sentinels are spelled in decimal.
$cfbEnd = [uint32]4294967294; $cfbFree = [uint32]4294967295; $cfbFatSect = [uint32]4294967293
function Save-Bytes([string]$Rel, [byte[]]$Bytes) {
    $p = Join-Path $script:caseDir $Rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
    [IO.File]::WriteAllBytes($p, $Bytes)
}
$lnkClsid = [byte[]](0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
function New-SyntheticLnk([string]$Target, [uint32]$Flags) {
    # Shell Link header, optional 2-byte empty IDList, LinkInfo with an ANSI (Latin-1) LocalBasePath.
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange((U32 0x4C)); $b.AddRange($lnkClsid); $b.AddRange((U32 $Flags)); $b.AddRange((New-Object byte[] 52))
    if ($Flags -band 1) { $b.AddRange((U16 2)); $b.AddRange([byte[]](0, 0)) }
    if ($Flags -band 2) {
        $path = [Text.Encoding]::GetEncoding(28591).GetBytes($Target)
        $size = 0x1C + $path.Length + 2
        $b.AddRange((U32 $size)); $b.AddRange((U32 0x1C)); $b.AddRange((U32 1)); $b.AddRange((U32 0))
        $b.AddRange((U32 0x1C)); $b.AddRange((U32 0)); $b.AddRange((U32 (0x1C + $path.Length + 1)))
        $b.AddRange($path); $b.AddRange([byte[]](0, 0))
    }
    $b.AddRange((U32 0))
    return ,$b.ToArray()
}
function New-SyntheticCfb([object[]]$Streams) {
    # Minimal CFB v3 (512-byte sectors): sector 0 FAT, 1 directory, 2 miniFAT, 3.. mini stream container.
    $mini = New-Object System.Collections.Generic.List[byte]
    $miniFat = New-Object System.Collections.Generic.List[uint32]
    $dir = New-Object System.Collections.Generic.List[byte]
    $entry = {
        param([string]$Name, [byte]$Type, [int]$Child, [int]$Right, [int]$Start, [uint32]$Size)
        $e = New-Object byte[] 128
        $nb = [Text.Encoding]::Unicode.GetBytes($Name + [char]0)
        [Array]::Copy($nb, $e, $nb.Length)
        [BitConverter]::GetBytes([uint16]$nb.Length).CopyTo($e, 0x40)
        $e[0x42] = $Type; $e[0x43] = 1
        [BitConverter]::GetBytes([int32]-1).CopyTo($e, 0x44)
        [BitConverter]::GetBytes([int32]$Right).CopyTo($e, 0x48)
        [BitConverter]::GetBytes([int32]$Child).CopyTo($e, 0x4C)
        [BitConverter]::GetBytes([int32]$Start).CopyTo($e, 0x74)
        [BitConverter]::GetBytes([uint32]$Size).CopyTo($e, 0x78)
        return ,$e
    }
    $entries = @()
    for ($i = 0; $i -lt $Streams.Count; $i++) {
        $data = [byte[]]$Streams[$i].Data
        $start = -2
        if ($data.Length -gt 0) {
            $start = [int]($mini.Count / 64)
            $n = [int][Math]::Ceiling($data.Length / 64)
            for ($k = 0; $k -lt $n; $k++) { if ($k -eq $n - 1) { $miniFat.Add($cfbEnd) } else { $miniFat.Add([uint32]($start + $k + 1)) } }
            $mini.AddRange($data); $mini.AddRange((New-Object byte[] ($n * 64 - $data.Length)))
        }
        $right = -1; if ($i -lt $Streams.Count - 1) { $right = $i + 2 }
        $entries += ,(& $entry $Streams[$i].Name 2 -1 $right $start $data.Length)
    }
    $dir.AddRange((& $entry 'Root Entry' 5 1 -1 3 $mini.Count))
    foreach ($e in $entries) { $dir.AddRange($e) }
    $dir.AddRange((New-Object byte[] (512 - $dir.Count)))
    $containerSectors = [int][Math]::Ceiling($mini.Count / 512)
    $mini.AddRange((New-Object byte[] ($containerSectors * 512 - $mini.Count)))
    $fat = New-Object System.Collections.Generic.List[byte]
    $fat.AddRange((U32 $cfbFatSect)); $fat.AddRange((U32 $cfbEnd)); $fat.AddRange((U32 $cfbEnd))
    for ($k = 0; $k -lt $containerSectors; $k++) { if ($k -eq $containerSectors - 1) { $fat.AddRange((U32 $cfbEnd)) } else { $fat.AddRange((U32 (4 + $k))) } }
    while ($fat.Count -lt 512) { $fat.AddRange((U32 $cfbFree)) }
    $mf = New-Object System.Collections.Generic.List[byte]
    foreach ($v in $miniFat) { $mf.AddRange((U32 $v)) }
    while ($mf.Count -lt 512) { $mf.AddRange((U32 $cfbFree)) }
    $h = New-Object byte[] 512
    [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1) | ForEach-Object -Begin { $j = 0 } -Process { $h[$j++] = $_ }
    (U16 0x3E).CopyTo($h, 0x18); (U16 3).CopyTo($h, 0x1A); (U16 65534).CopyTo($h, 0x1C); (U16 9).CopyTo($h, 0x1E); (U16 6).CopyTo($h, 0x20)
    (U32 1).CopyTo($h, 0x2C); (I32 1).CopyTo($h, 0x30); (U32 4096).CopyTo($h, 0x38); (I32 2).CopyTo($h, 0x3C); (U32 1).CopyTo($h, 0x40)
    (I32 -2).CopyTo($h, 0x44); (U32 0).CopyTo($h, 0x48); (I32 0).CopyTo($h, 0x4C)
    for ($k = 1; $k -lt 109; $k++) { (I32 -1).CopyTo($h, 0x4C + 4 * $k) }
    $all = New-Object System.Collections.Generic.List[byte]
    $all.AddRange($h); $all.AddRange($fat.ToArray()); $all.AddRange($dir.ToArray()); $all.AddRange($mf.ToArray()); $all.AddRange($mini.ToArray())
    return ,$all.ToArray()
}
function New-SyntheticRegf([string]$Kind) {
    # Same cells as the Pester builder in legacy tests\Unit\Parse.Tests.ps1: ROOT\InventoryApplicationFile\aabbcc
    # with LowerCaseLongPath, or the legacy ROOT\File\volume\1234 layout.
    $buf = New-Object byte[] 0x3000
    [Text.Encoding]::ASCII.GetBytes('regf').CopyTo($buf, 0)
    [Text.Encoding]::ASCII.GetBytes('hbin').CopyTo($buf, 0x1000)
    [BitConverter]::GetBytes([int]0x2000).CopyTo($buf, 0x1008)
    $script:hiveNext = 0x20
    $add = {
        param([byte[]]$Payload)
        $len = 4 + $Payload.Length
        $total = $len + ((8 - ($len % 8)) % 8)
        $off = $script:hiveNext
        [BitConverter]::GetBytes(-$total).CopyTo($buf, 0x1000 + $off)
        [Array]::Copy($Payload, 0, $buf, (0x1000 + $off + 4), $Payload.Length)
        $script:hiveNext += $total
        return $off
    }
    $ft = [datetime]::SpecifyKind([datetime]'2020-01-15 12:00:00', 'Utc').ToFileTimeUtc()
    $mkNk = {
        param($Name, $SubCount, $SubList, $ValCount, $ValList)
        $nb = New-Object System.Collections.Generic.List[byte]
        $nb.AddRange([byte[]](0x6E, 0x6B)); $nb.AddRange((U16 0x20)); $nb.AddRange([BitConverter]::GetBytes([int64]$ft))
        $nb.AddRange((I32 0)); $nb.AddRange((I32 0)); $nb.AddRange((I32 $SubCount)); $nb.AddRange((I32 0)); $nb.AddRange((I32 $SubList))
        $nb.AddRange((I32 0)); $nb.AddRange((I32 $ValCount)); $nb.AddRange((I32 $ValList)); $nb.AddRange((I32 -1)); $nb.AddRange((I32 -1))
        1..5 | ForEach-Object { $nb.AddRange((I32 0)) }
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($Name)
        $nb.AddRange((U16 $nameBytes.Length)); $nb.AddRange((U16 0)); $nb.AddRange($nameBytes)
        return ,$nb.ToArray()
    }
    $mkLf = {
        param([int]$ChildOff)
        $lb = New-Object System.Collections.Generic.List[byte]
        $lb.AddRange([byte[]](0x6C, 0x66)); $lb.AddRange((U16 1)); $lb.AddRange((I32 $ChildOff)); $lb.AddRange((I32 0))
        return ,$lb.ToArray()
    }
    if ($Kind -eq 'AmcacheFile') {
        $pathData = [Text.Encoding]::Unicode.GetBytes("c:\windows\notepad.exe`0")
        $dataOff = & $add $pathData
        $vname = [Text.Encoding]::ASCII.GetBytes('LowerCaseLongPath')
        $vk = New-Object System.Collections.Generic.List[byte]
        $vk.AddRange([byte[]](0x76, 0x6B)); $vk.AddRange((U16 $vname.Length)); $vk.AddRange((U32 $pathData.Length)); $vk.AddRange((I32 $dataOff))
        $vk.AddRange((I32 1)); $vk.AddRange((U16 1)); $vk.AddRange((U16 0)); $vk.AddRange($vname)
        $vkOff = & $add $vk.ToArray()
        $vlistOff = & $add (I32 $vkOff)
        $fileOff = & $add (& $mkNk 'aabbcc' 0 -1 1 $vlistOff)
        $invLfOff = & $add (& $mkLf $fileOff)
        $invOff = & $add (& $mkNk 'InventoryApplicationFile' 1 $invLfOff 0 -1)
        $rootLfOff = & $add (& $mkLf $invOff)
        $rootOff = & $add (& $mkNk 'ROOT' 1 $rootLfOff 0 -1)
    }
    else {
        $leafOff = & $add (& $mkNk '1234' 0 -1 0 -1)
        $volLfOff = & $add (& $mkLf $leafOff)
        $volOff = & $add (& $mkNk 'volume' 1 $volLfOff 0 -1)
        $fileLfOff = & $add (& $mkLf $volOff)
        $fileOff = & $add (& $mkNk 'File' 1 $fileLfOff 0 -1)
        $rootLfOff = & $add (& $mkLf $fileOff)
        $rootOff = & $add (& $mkNk 'ROOT' 1 $rootLfOff 0 -1)
    }
    [BitConverter]::GetBytes([int32]$rootOff).CopyTo($buf, 0x24)
    return ,$buf
}

$script:caseDir = Join-Path $parseIn 'Foton_PARSEHOST_20260115-120000Z'
Save-Bytes '00_Collection\collection_manifest.csv' ([Text.Encoding]::UTF8.GetBytes("`"Task`",`"Status`"`r`n`"prefetch_files`",`"Success`"`r`n"))
Save-Bytes '01_System\os_info.json' ([Text.Encoding]::UTF8.GetBytes('{"Hostname":"PARSEHOST"}'))
Save-Bytes '07_Event_Logs\evtx\Junk.evtx' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'prefetch-not.bin')))
Save-Bytes '08_Filesystem\prefetch\NOTEPAD.EXE-11111111.pf' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'prefetch-scca-v23.bin')))
Save-Bytes '08_Filesystem\prefetch\MAM.EXE-22222222.pf' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'prefetch-mam.bin')))
Save-Bytes '08_Filesystem\prefetch\NOT.EXE-33333333.pf' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'prefetch-not.bin')))
$cafe = New-SyntheticLnk ('C:\Tools\caf' + [char]0xE9 + '.exe') 3
Save-Bytes '08_Filesystem\z-top.lnk' (New-SyntheticLnk 'C:\Windows\System32\cmd.exe' 2)
Save-Bytes '08_Filesystem\lnk\cafe.lnk' $cafe
Save-Bytes '08_Filesystem\lnk\nolinkinfo.lnk' (New-SyntheticLnk '' 0)
Save-Bytes '08_Filesystem\lnk\junk.lnk' (New-Object byte[] 100)
$custom = New-Object System.Collections.Generic.List[byte]
$custom.AddRange((U32 2)); $custom.AddRange((U32 1)); $custom.AddRange((U32 0)); $custom.AddRange($lnkClsid); $custom.AddRange($cafe); $custom.AddRange([byte[]](0xAB, 0xFB, 0xBF, 0xBA))
Save-Bytes '08_Filesystem\jumplists\4d5e6f.customDestinations-ms' $custom.ToArray()
Save-Bytes '08_Filesystem\jumplists\junk.customDestinations-ms' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'jumplist-not.bin')))
$destList = [IO.File]::ReadAllBytes((Join-Path $legacyFx 'jumplist-destlist-v1.bin'))
Save-Bytes '08_Filesystem\jumplists\1a2b3c.automaticDestinations-ms' (New-SyntheticCfb @(
        @{ Name = 'DestList'; Data = $destList }
        @{ Name = '1'; Data = (New-SyntheticLnk 'C:\Windows\notepad.exe' 3) }
        @{ Name = 'Empty'; Data = [byte[]]@() }
    ))
Save-Bytes '08_Filesystem\amcache\Amcache.hve' (New-SyntheticRegf 'AmcacheFile')
Save-Bytes '08_Filesystem\amcache\Legacy.hve' (New-SyntheticRegf 'LegacyFile')
Save-Bytes 'analysis\ignored.pf' ([IO.File]::ReadAllBytes((Join-Path $legacyFx 'prefetch-scca-v23.bin')))
$script:caseDir = Join-Path $parseIn 'Foton_EMPTYHOST_20260115-120000Z'
Save-Bytes '00_Collection\collection_manifest.csv' ([Text.Encoding]::UTF8.GetBytes("`"Task`",`"Status`"`r`n`"prefetch_files`",`"SkippedNotElevated`"`r`n"))

# 1.38.x defect, corrected for these goldens only: the OLE chain readers compare a uint32 with 0xFFFFFFFE,
# which Windows PowerShell reads as int -2, so every chain end overflows [int] and no automatic-destinations
# jumplist ever parsed. Everything else below is the frozen code.
& $m {
    foreach ($fn in 'Get-FotonOleFatChainBytes', 'Get-FotonOleMiniChainBytes') {
        $def = (Get-Command $fn).Definition.Replace('0xFFFFFFFC', '4294967292').Replace('0xFFFFFFFD', '4294967293').Replace('0xFFFFFFFE', '4294967294').Replace('0xFFFFFFFF', '4294967295')
        Set-Item -Path "function:script:$fn" -Value $def
    }
}
foreach ($case in @(@{ Name = 'Foton_PARSEHOST_20260115-120000Z'; Tag = 'parse' }, @{ Name = 'Foton_EMPTYHOST_20260115-120000Z'; Tag = 'parse-empty' })) {
    $work = Join-Path $env:TEMP ('foton-golden-' + [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath (Join-Path $parseIn $case.Name) -Destination $work -Recurse
    $null = Invoke-FotonParse -Path $work
    Copy-Item (Join-Path $work 'analysis\parsed_records.csv') (Join-Path $out ("{0}-records.csv" -f $case.Tag))
    Copy-Item (Join-Path $work 'analysis\Foton_Parse.html') (Join-Path $out ("{0}-report.html" -f $case.Tag))
    Remove-Item -LiteralPath $work -Recurse -Force
}

# ---- Analyze ----------------------------------------------------------------------------------
# A synthetic package that fires every Invoke-FotonAnalysis rule (and the quiet side of several), plus the
# 1.38.x fixture package. Top-N lists use distinct counts: ties were left in hashtable order in 1.38.x.
$anIn = Join-Path $repo 'testdata\analyze'
if (Test-Path -LiteralPath $anIn) { Remove-Item -LiteralPath $anIn -Recurse -Force }
$script:caseDir = Join-Path $anIn 'Foton_KITCHEN_20260115-120000Z'
function Save-Rows([string]$Rel, [object[]]$Rows) {
    $p = Join-Path $script:caseDir $Rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
    $Rows | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
}
function Save-Obj([string]$Rel, $Obj) {
    $p = Join-Path $script:caseDir $Rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
    ($Obj | ConvertTo-Json -Depth 6) | Out-File -FilePath $p -Encoding utf8
}
function Save-Lines([string]$Rel, [string[]]$Lines) {
    $p = Join-Path $script:caseDir $Rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null
    $Lines | Out-File -FilePath $p -Encoding utf8
}
function R { param([hashtable]$H) [PSCustomObject]$H }

Save-Lines '00_Collection\collection.log' @('Foton test collection log', '2026-01-15 12:00:00 UTC [Step] start', '2026-01-15 12:05:00 UTC [Good] done')
Save-Rows '00_Collection\collection_manifest.csv' @(
    [PSCustomObject]@{ Task = 'os_info'; Status = 'Success' }
    [PSCustomObject]@{ Task = 'prefetch_files'; Status = 'Partial' }
    [PSCustomObject]@{ Task = 'registry_hives'; Status = 'Failed' })
Save-Obj '00_Collection\collection_coverage.json' ([ordered]@{ Elevated = $false; CoverageProfile = 'StandardUser'; CollectionAccount = 'HOST\analyst'; SkippedTaskCount = 7; ExcludedEarlierPackages = @('C:\Users\analyst\Desktop\Foton_HOST_20260101-000000Z') })
Save-Obj '01_System\os_info.json' ([ordered]@{ Hostname = 'KITCHEN'; Caption = 'Microsoft Windows 11 Pro'; BuildNumber = '26100'; UptimeDays = 3.5; TimeZone = 'Eastern Standard Time'; UtcOffset = '-05:00'; SystemDirectory = 'D:\Win\System32' })
Save-Obj '06_Security_Posture\defender_status.json' ([ordered]@{ RealTimeProtectionEnabled = $false; AntivirusEnabled = $true; AMServiceEnabled = $false; IsTamperProtected = $false; AntivirusSignatureAgeDays = 12; AntivirusSignatureVersion = '1.401.0.0' })
Save-Obj '06_Security_Posture\defender_preferences_and_exclusions.json' ([ordered]@{ ExclusionPath = @('C:\Users\Public\stage', 'D:\Data'); ExclusionProcess = @('tool.exe'); DisableScriptScanning = $true; DisableBehaviorMonitoring = $false; DisableIOAVProtection = $false })
Save-Rows '06_Security_Posture\defender_detections.csv' @(
    [PSCustomObject]@{ ThreatName = 'HackTool:Win32/Mimikatz'; Resources = 'file:_C:\Users\Public\m.exe' }
    [PSCustomObject]@{ ThreatName = 'Trojan:Win32/Test'; Resources = 'file:_C:\Temp\t.exe' })
Save-Rows '06_Security_Posture\hardening_registry_settings.csv' @(
    foreach ($kv in @(@('UseLogonCredential', '1'), @('EnableLUA', '0'), @('AlwaysInstallElevated', '1'), @('AutoAdminLogon', '1'), @('DefaultUserName', 'kiosk'),
            @('LocalAccountTokenFilterPolicy', '1'), @('SMB1', '1'), @('EnableScriptBlockLogging', '0'))) { [PSCustomObject]@{ Setting = $kv[0]; Value = $kv[1] } })
Save-Rows '04_Network\firewall_profiles.csv' @([PSCustomObject]@{ Name = 'Domain'; Enabled = $true }, [PSCustomObject]@{ Name = 'Public'; Enabled = $false }, [PSCustomObject]@{ Name = 'Private'; Enabled = 'No' })
Save-Obj '02_Users_and_Access\rdp_configuration.json' ([ordered]@{ RdpEnabled = $true; UserAuthentication = 0; PortNumber = 3389; RemoteDesktopUsers = @('HOST\a', 'HOST\b') })
Save-Rows '02_Users_and_Access\local_users.csv' @(
    [PSCustomObject]@{ Name = 'Guest'; Enabled = $true; PasswordRequired = $false; SID = 'S-1-5-21-1-2-3-501' }
    [PSCustomObject]@{ Name = 'kiosk'; Enabled = $true; PasswordRequired = $false; SID = 'S-1-5-21-1-2-3-1003' }
    [PSCustomObject]@{ Name = 'old'; Enabled = $false; PasswordRequired = $false; SID = 'S-1-5-21-1-2-3-1004' })
Save-Rows '02_Users_and_Access\local_group_membership.csv' @(foreach ($m in 'HOST\Administrator', 'HOST\a', 'HOST\b', 'HOST\c', 'HOST\d', 'DOMAIN\Domain Admins') { [PSCustomObject]@{ Group = 'Administrators'; Member = $m } }; [PSCustomObject]@{ Group = 'Users'; Member = 'HOST\e' })
Save-Rows '03_Processes_and_Volatile\running_processes.csv' @(
    [PSCustomObject]@{ Name = 'evil.exe'; PID = 4100; ParentName = 'explorer.exe'; Path = 'C:\Users\Public\evil.exe'; CommandLine = 'evil.exe'; SignatureStatus = 'NotSigned'; UserWritablePath = $true; SuspiciousCmdHits = '' }
    [PSCustomObject]@{ Name = 'powershell.exe'; PID = 4200; ParentName = 'WINWORD.EXE'; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = 'powershell -encodedcommand ZQBjAGgAbwA='; SignatureStatus = 'Valid'; UserWritablePath = $false; SuspiciousCmdHits = '' }
    [PSCustomObject]@{ Name = 'svchost.exe'; PID = 900; ParentName = 'services.exe'; Path = 'C:\Windows\System32\svchost.exe'; CommandLine = 'svchost.exe -k netsvcs'; SignatureStatus = 'Valid'; UserWritablePath = $false; SuspiciousCmdHits = '' })
Save-Rows '03_Processes_and_Volatile\powershell_console_history.csv' @(
    [PSCustomObject]@{ User = 'analyst'; Command = 'Get-ChildItem'; SuspiciousHits = '' }
    [PSCustomObject]@{ User = 'analyst'; Command = 'certutil -urlcache -f http://x/a.exe a.exe'; SuspiciousHits = '' })
Save-Rows '05_Persistence\autorun_registry_keys.csv' @(
    [PSCustomObject]@{ ValueName = 'Updater'; Command = 'C:\Users\Public\up.exe'; UserWritableTarget = $true; SuspiciousHits = '' }
    [PSCustomObject]@{ ValueName = 'SecurityHealth'; Command = 'C:\Windows\System32\SecurityHealthSystray.exe'; UserWritableTarget = $false; SuspiciousHits = '' })
Save-Rows '05_Persistence\scheduled_tasks.csv' @(
    [PSCustomObject]@{ TaskPath = '\'; TaskName = 'Sync'; RunAsUser = 'SYSTEM'; Actions = 'powershell -File C:\Temp\s.ps1'; UserWritableTarget = $false; SuspiciousHits = '' }
    [PSCustomObject]@{ TaskPath = '\Microsoft\Windows\'; TaskName = 'Defrag'; RunAsUser = 'SYSTEM'; Actions = 'defrag.exe -c'; UserWritableTarget = $false; SuspiciousHits = '' })
Save-Rows '05_Persistence\services.csv' @(
    [PSCustomObject]@{ Name = 'EvilSvc'; State = 'Running'; StartMode = 'Auto'; PathName = 'C:\Users\Public\svc.exe'; ResolvedExe = 'C:\Users\Public\svc.exe'; SignatureStatus = 'NotSigned'; UserWritablePath = $true; UnquotedPath = $false; ServiceDll = ''; ServiceDllSource = ''; ServiceDllUserWritablePath = $false; ServiceDllSignatureStatus = '' }
    [PSCustomObject]@{ Name = 'HijackSvc'; State = 'Running'; StartMode = 'Manual'; PathName = 'C:\Windows\System32\svchost.exe -k netsvcs'; ResolvedExe = 'C:\Windows\System32\svchost.exe'; SignatureStatus = 'Valid'; UserWritablePath = $false; UnquotedPath = $false; ServiceDll = 'C:\ProgramData\h.dll'; ServiceDllSource = 'Parameters'; ServiceDllUserWritablePath = $true; ServiceDllSignatureStatus = 'NotSigned' }
    [PSCustomObject]@{ Name = 'Vendor Agent'; State = 'Stopped'; StartMode = 'Auto'; PathName = 'C:\Program Files\Vendor Agent\agent.exe'; ResolvedExe = 'C:\Program Files\Vendor Agent\agent.exe'; SignatureStatus = 'Valid'; UserWritablePath = $false; UnquotedPath = $true; ServiceDll = ''; ServiceDllSource = ''; ServiceDllUserWritablePath = $false; ServiceDllSignatureStatus = '' }
    [PSCustomObject]@{ Name = 'Sysmon64'; State = 'Stopped'; StartMode = 'Auto'; PathName = 'C:\Windows\Sysmon64.exe'; ResolvedExe = 'C:\Windows\Sysmon64.exe'; SignatureStatus = 'Valid'; UserWritablePath = $false; UnquotedPath = $false; ServiceDll = ''; ServiceDllSource = ''; ServiceDllUserWritablePath = $false; ServiceDllSignatureStatus = '' }
    [PSCustomObject]@{ Name = 'OneSyncSvc_1701f8'; State = 'Running'; StartMode = 'Auto'; PathName = 'C:\Windows\system32\svchost.exe -k UnistackSvcGroup'; ResolvedExe = 'C:\Windows\system32\svchost.exe'; SignatureStatus = 'Valid'; UserWritablePath = $false; UnquotedPath = $false; ServiceDll = 'D:\Win\System32\APHostService.dll'; ServiceDllSource = 'Template:OneSyncSvc'; ServiceDllUserWritablePath = $false; ServiceDllSignatureStatus = 'Valid' })
Save-Rows '05_Persistence\winlogon_lsa_and_dll_hijacks.csv' @(
    [PSCustomObject]@{ Mechanism = 'IFEO'; Location = 'HKLM\...\sethc.exe'; Name = 'Debugger'; Value = 'cmd.exe' }
    [PSCustomObject]@{ Mechanism = 'AppInit'; Location = 'HKLM\...\Windows'; Name = 'AppInit_DLLs'; Value = 'C:\Temp\inj.dll' }
    [PSCustomObject]@{ Mechanism = 'Winlogon'; Location = 'HKLM\...\Winlogon'; Name = 'Shell'; Value = 'explorer.exe' }
    [PSCustomObject]@{ Mechanism = 'Winlogon'; Location = 'HKLM\...\Winlogon'; Name = 'Userinit'; Value = 'C:\Windows\system32\userinit.exe, C:\Temp\u.exe' })
Save-Rows '05_Persistence\accessibility_binary_integrity.csv' @(
    [PSCustomObject]@{ Binary = 'sethc.exe'; SignatureStatus = 'Valid'; IFEODebugger = 'cmd.exe' }
    [PSCustomObject]@{ Binary = 'utilman.exe'; SignatureStatus = 'Valid'; IFEODebugger = '' })
Save-Rows '05_Persistence\com_hijack_candidates.csv' @([PSCustomObject]@{ User = 'analyst'; CLSID = '{11111111-2222-3333-4444-555555555555}'; Target = 'C:\Users\analyst\AppData\Roaming\x.dll'; UserWritableTarget = $true })
Save-Rows '05_Persistence\startup_folder_items.csv' @([PSCustomObject]@{ FullName = 'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.lnk'; SignatureStatus = 'NotSigned' })
Save-Lines '05_Persistence\wmi_event_subscriptions.txt' @('=== __EventFilter ===', 'Name: Evil', 'Query: SELECT * FROM __InstanceModificationEvent', '=== CommandLineEventConsumer ===', 'Name: Evil')
Save-Rows '04_Network\active_connections.csv' @(
    [PSCustomObject]@{ ProcessName = 'evil.exe'; RemoteAddress = '203.0.113.5'; RemotePort = 443; State = 'Established'; RemoteIsExternal = $true; UserWritablePath = $true }
    [PSCustomObject]@{ ProcessName = 'chrome.exe'; RemoteAddress = '198.51.100.7'; RemotePort = 443; State = 'Established'; RemoteIsExternal = $true; UserWritablePath = $false }
    [PSCustomObject]@{ ProcessName = 'svchost.exe'; RemoteAddress = '10.0.0.2'; RemotePort = 135; State = 'Established'; RemoteIsExternal = $false; UserWritablePath = $false })
Save-Lines '04_Network\hosts_file.txt' @('# hosts', '127.0.0.1 localhost', '', '10.0.0.9 update.vendor.example')
Save-Rows '07_Event_Logs\security_policy_and_log_changes.csv' @([PSCustomObject]@{ EventId = 1102; TimeCreatedUtc = '2026-01-14 03:00:00'; Message = 'The audit log was cleared.' })
Save-Rows '07_Event_Logs\system_log_and_boot.csv' @([PSCustomObject]@{ EventId = 104; TimeCreatedUtc = '2026-01-14 03:00:05'; Message = 'The System log file was cleared.' }, [PSCustomObject]@{ EventId = 6005; TimeCreatedUtc = '2026-01-13 08:00:00'; Message = 'started' })
Save-Rows '07_Event_Logs\system_service_and_driver.csv' @(
    [PSCustomObject]@{ EventId = 7045; TimeCreatedUtc = '2026-01-14 03:01:00'; Message = 'A service was installed in the system.  Service Name:  EvilSvc  Service File Name:  C:\Users\Public\svc.exe  Service Type:  user mode service' }
    [PSCustomObject]@{ EventId = 7045; TimeCreatedUtc = '2026-01-14 02:00:00'; Message = 'A service was installed in the system.  Service Name:  OneSyncSvc_1701f8  Service File Name:  %SystemRoot%\system32\svchost.exe -k UnistackSvcGroup  Service Type:  user mode service' }
    [PSCustomObject]@{ EventId = 7036; TimeCreatedUtc = '2026-01-14 01:00:00'; Message = 'state change' })
Save-Rows '07_Event_Logs\security_account_management.csv' @(
    [PSCustomObject]@{ EventId = 4720; TimeCreatedUtc = '2026-01-14 04:00:00'; Message = 'A user account was created.  New Account:  Security ID:  S-1-5-21-1-2-3-1010  Account Name:  temp user  Account Domain:  HOST' }
    [PSCustomObject]@{ EventId = 4726; TimeCreatedUtc = '2026-01-14 04:00:30'; Message = 'A user account was deleted.  Target Account:  Security ID:  S-1-5-21-1-2-3-1010  Account Name:  temp user  Account Domain:  HOST' }
    [PSCustomObject]@{ EventId = 4720; TimeCreatedUtc = '2026-01-14 05:00:00'; Message = 'A user account was created.  New Account:  Security ID:  S-1-5-21-1-2-3-1011  Account Name:  backdoor  Account Domain:  HOST' }
    [PSCustomObject]@{ EventId = 4732; TimeCreatedUtc = '2026-01-14 05:00:05'; Message = 'A member was added.  Member:  Security ID:  S-1-5-21-1-2-3-1011  Account Name:  -  Group:  Security ID:  S-1-5-32-544  Group Name:  Administrators  Group Domain:  Builtin' }
    [PSCustomObject]@{ EventId = 4732; TimeCreatedUtc = '2026-01-14 05:00:06'; Message = 'A member was added.  Member:  Security ID:  S-1-5-21-1-2-3-1011  Account Name:  -  Group:  Security ID:  S-1-5-21-1-2-3-513  Group Name:  None  Group Domain:  HOST' })
Save-Rows '07_Event_Logs\security_logon_events.csv' @(@(1..26 | ForEach-Object { [PSCustomObject]@{ EventId = 4625; TimeCreatedUtc = '2026-01-14 06:00:00'; Message = 'failed' } }) + @([PSCustomObject]@{ EventId = 4648; TimeCreatedUtc = '2026-01-14 06:30:00'; Message = 'explicit' }))
Save-Rows '07_Event_Logs\powershell_operational.csv' @(
    [PSCustomObject]@{ EventId = 4104; TimeCreatedUtc = '2026-01-15 12:02:00'; Message = 'Creating Scriptblock text: iex (New-Object Net.WebClient).DownloadString($u)' }
    [PSCustomObject]@{ EventId = 4104; TimeCreatedUtc = '2026-01-10 09:00:00'; Message = 'Creating Scriptblock text: Get-FotonRegValue -Path HKLM:\x; iex $x' }
    [PSCustomObject]@{ EventId = 4104; TimeCreatedUtc = '2026-01-09 08:00:00'; Message = 'Creating Scriptblock text: powershell -enc QQBCAEMA' }
    [PSCustomObject]@{ EventId = 4104; TimeCreatedUtc = '2026-01-08 08:00:00'; Message = 'Creating Scriptblock text: Get-Date' })
Save-Rows '07_Event_Logs\defender_operational.csv' @(
    [PSCustomObject]@{ EventId = 5007; TimeCreatedUtc = '2026-01-14 03:05:00'; Message = 'config changed' }
    [PSCustomObject]@{ EventId = 1116; TimeCreatedUtc = '2026-01-14 03:06:00'; Message = 'detected' }
    [PSCustomObject]@{ EventId = 1000; TimeCreatedUtc = '2026-01-14 03:07:00'; Message = 'scan' })
Save-Rows '07_Event_Logs\terminal_services_remote.csv' @([PSCustomObject]@{ EventId = 1149; TimeCreatedUtc = '2026-01-14 07:00:00'; Message = 'Source Network Address: 203.0.113.9' })
Save-Rows '07_Event_Logs\wmi_activity.csv' @([PSCustomObject]@{ EventId = 5861; TimeCreatedUtc = '2026-01-14 08:00:00'; Message = 'binding' })
Save-Rows '07_Event_Logs\event_log_configuration.csv' @([PSCustomObject]@{ LogName = 'Security'; IsEnabled = $true }, [PSCustomObject]@{ LogName = 'Microsoft-Windows-Sysmon/Operational'; IsEnabled = 'NotPresent' })
Save-Rows '09_Software_and_Drivers\remote_access_tool_indicators.csv' @([PSCustomObject]@{ Source = 'InstalledSoftware'; Detail = 'AnyDesk 8.0' }, [PSCustomObject]@{ Source = 'Process'; Detail = 'rclone.exe' })
Save-Rows '09_Software_and_Drivers\drivers.csv' @([PSCustomObject]@{ Name = 'evildrv'; State = 'Running'; SignatureStatus = 'NotSigned' }, [PSCustomObject]@{ Name = 'disk'; State = 'Running'; SignatureStatus = 'Valid' })
Save-Rows '08_Filesystem\executables_in_user_writable_paths.csv' @(
    [PSCustomObject]@{ Path = 'C:\Users\Public\evil.exe'; Extension = '.exe'; SignatureStatus = 'NotSigned'; ModifiedUtc = '2026-01-14 02:59:00' }
    [PSCustomObject]@{ Path = 'C:\Users\Public\notes.txt'; Extension = '.txt'; SignatureStatus = 'NotSigned'; ModifiedUtc = '2026-01-14 02:58:00' })
Save-Rows '08_Filesystem\alternate_data_streams.csv' @([PSCustomObject]@{ File = 'C:\Users\Public\a.txt'; Stream = 'Zone.Identifier' }, [PSCustomObject]@{ File = 'C:\Users\Public\b.txt'; Stream = 'payload' })
Save-Rows '08_Filesystem\usb_device_history.csv' @([PSCustomObject]@{ Source = 'USBSTOR'; FriendlyName = 'SanDisk Cruzer' }, [PSCustomObject]@{ Source = 'USB'; FriendlyName = 'Mouse' })
Save-Rows 'analysis\parsed_records.csv' @(
    [PSCustomObject]@{ SourcePath = '08_Filesystem\lnk\a.lnk'; Format = 'LNK'; Supported = $true; Identity = 'C:\Users\Public\evil.exe'; SizeBytes = 100; SHA256 = 'A'; Note = '' }
    [PSCustomObject]@{ SourcePath = '08_Filesystem\lnk\b.lnk'; Format = 'LNK'; Supported = $true; Identity = 'C:\Windows\notepad.exe'; SizeBytes = 100; SHA256 = 'B'; Note = '' }
    [PSCustomObject]@{ SourcePath = '08_Filesystem\lnk\c.lnk'; Format = 'LNK'; Supported = $true; Identity = 'C:\Temp\drop.exe'; SizeBytes = 100; SHA256 = 'C'; Note = '' })
Save-Rows 'analysis\baseline_diff.csv' @(
    [PSCustomObject]@{ RecordType = 'Service'; Identity = 'EvilSvc'; ChangeType = 'Modified'; Field = 'PathName'; OldValue = 'C:\Windows\a.exe'; NewValue = 'C:\Users\Public\svc.exe' }
    [PSCustomObject]@{ RecordType = 'Service'; Identity = 'NewSvc'; ChangeType = 'Added'; Field = ''; OldValue = ''; NewValue = '' }
    [PSCustomObject]@{ RecordType = 'LocalGroupMember'; Identity = 'Administrators|S-1-5-21-1-2-3-1011'; ChangeType = 'Added'; Field = ''; OldValue = ''; NewValue = '' }
    [PSCustomObject]@{ RecordType = 'Certificate'; Identity = 'Cert:\LocalMachine\Root|ABCDEF'; ChangeType = 'Added'; Field = ''; OldValue = ''; NewValue = '' }
    [PSCustomObject]@{ RecordType = 'Winlogon'; Identity = 'Userinit'; ChangeType = 'Modified'; Field = 'Value'; OldValue = 'userinit.exe,'; NewValue = 'userinit.exe, u.exe' }
    [PSCustomObject]@{ RecordType = 'DefenderPreference'; Identity = 'Switch|DisableRealtimeMonitoring'; ChangeType = 'Modified'; Field = 'Value'; OldValue = 'False'; NewValue = 'True' }
    [PSCustomObject]@{ RecordType = 'ProxyConfig'; Identity = 'WinHttp|WinHttpSettings'; ChangeType = 'Modified'; Field = 'Value'; OldValue = ''; NewValue = '1800' }
    [PSCustomObject]@{ RecordType = 'InstalledSoftware'; Identity = 'App|Vendor'; ChangeType = 'Modified'; Field = 'DisplayVersion'; OldValue = '1'; NewValue = '2' })
$hayLines = @(
    '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"'
    '"2026-01-14 03:00:00 +00:00","Mimikatz Use","high","K","Sec",4688,1,"m","x","r1"'
    '"2026-01-14 03:00:01 +00:00","Mimikatz Use","high","K","Sec",4688,2,"m","x","r1"'
    '"2026-01-14 03:00:02 +00:00","Suspicious Service","high","K","Sys",7045,3,"s","x","r2"'
    '"2026-01-14 03:00:03 +00:00","WMI Persistence","med","K","Wmi",5861,4,"w","x","r3"'
    '"2026-01-14 03:00:04 +00:00","WMI Persistence","med","K","Wmi",5861,5,"w","x","r3"'
    '"2026-01-14 03:00:05 +00:00","Odd PwSh","medium","K","PS",4104,6,"p","x","r4"'
    '"2026-01-14 03:00:06 +00:00","Log Cleared","crit","K","Sec",1102,7,"c","x","r5"'
    '"2026-01-14 03:00:07 +00:00","Proc Exec","low","K","Sys",1,8,"l","x","r6"'
    '"2026-01-14 03:00:08 +00:00","Proc Exec","low","K","Sys",1,9,"l","x","r6"'
    '"2026-01-14 03:00:09 +00:00","Dns","info","K","Sys",22,10,"i","x","r7"'
    '"2026-01-15 12:01:00 +00:00","Potentially Malicious PwSh","med","K","PS",4104,11,"collector run","x","r8"'
    '"2026-01-10 01:00:00 +00:00","Registry Hive Access","high","K","PS",4104,12,"Save-FotonRegistryHive -Name SAM","x","r9"')
Save-Lines 'analysis\external\hayabusa\hayabusa.csv' $hayLines
Save-Rows 'analysis\external\PECmd\pecmd.csv' @(
    foreach ($e in @('CMD.EXE', 'CMD.EXE', 'CMD.EXE', 'EVIL.EXE', 'EVIL.EXE', 'NOTEPAD.EXE')) {
        [PSCustomObject]@{ ExecutableName = $e; FilesLoaded = '\VOLUME{01}\WINDOWS\SYSTEM32\NTDLL.DLL, \VOLUME{01}\USERS\PUBLIC\EVIL.EXE'; Directories = '\VOLUME{01}\WINDOWS'; SourceFilename = 'C:\Cases\K\08_Filesystem\prefetch\X.pf' } })
Save-Rows 'analysis\external\EvtxECmd\evtxecmd.csv' @(
    @(1..4 | ForEach-Object { [PSCustomObject]@{ EventId = '4688'; TimeCreated = '2026-01-14 03:10:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Users\Public\evil.exe -enc AAAA' } }) +
    @(1..2 | ForEach-Object { [PSCustomObject]@{ EventId = '7045'; TimeCreated = '2026-01-14 03:11:00.0000000'; PayloadData1 = 'Name: EvilSvc'; PayloadData2 = ''; ExecutableInfo = 'C:\Windows\System32\evilsvc.exe' } }) +
    @([PSCustomObject]@{ EventId = '7045'; TimeCreated = '2026-01-14 02:00:00.0000000'; PayloadData1 = 'Name: OneSyncSvc_1701f8'; PayloadData2 = ''; ExecutableInfo = '%SystemRoot%\system32\svchost.exe -k UnistackSvcGroup' }) +
    @([PSCustomObject]@{ EventId = '4104'; TimeCreated = '2026-01-15 12:03:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Users\Public\collector.ps1' }) +
    @([PSCustomObject]@{ EventId = '4104'; TimeCreated = '2026-01-13 01:00:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Windows\x.ps1' }) +
    @([PSCustomObject]@{ EventId = '1102'; TimeCreated = '2026-01-14 03:00:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = '' }))

foreach ($case in @(@{ Src = (Join-Path $anIn 'Foton_KITCHEN_20260115-120000Z'); Tag = 'kitchen' }, @{ Src = (Join-Path $repo 'testdata\packages\WinFoton_FIXTURE_20260115-120000Z'); Tag = 'fixture' })) {
    $work = Join-Path $env:TEMP ('foton-golden-' + [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $case.Src -Destination $work -Recurse
    Get-FotonPackage -Path $work | Out-Null
    Invoke-FotonAnalysis
    Copy-Item (Join-Path $work 'analysis\findings.csv') (Join-Path $out ("analyze-{0}-findings.csv" -f $case.Tag))
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

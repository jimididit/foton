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

# Offline REGF (hive) walk. Bytes only. Used by ConvertFrom-FotonAmcache.
# Offsets in cells are relative to the first hbin (file offset 0x1000).
# Fail closed: return $null rather than a guessed name or time.

function Get-FotonRegfCellPayload {
    param(
        [byte[]]$Bytes,
        [int]$CellOffset
    )
    if ($null -eq $Bytes) { return $null }
    if ($CellOffset -lt 0) { return $null }
    $pos = 0x1000 + $CellOffset
    if ($pos -lt 0x1000 -or ($pos + 4) -gt $Bytes.Length) { return $null }
    $rawSize = [BitConverter]::ToInt32($Bytes, $pos)
    if ($rawSize -eq 0) { return $null }
    $len = [Math]::Abs($rawSize)
    if ($len -lt 8) { return $null }
    if (($pos + $len) -gt $Bytes.Length) { return $null }
    $payloadLen = $len - 4
    $payload = New-Object byte[] $payloadLen
    [Array]::Copy($Bytes, ($pos + 4), $payload, 0, $payloadLen)
    return $payload
}

function Get-FotonRegfNk {
    param(
        [byte[]]$Bytes,
        [int]$CellOffset
    )
    $p = Get-FotonRegfCellPayload -Bytes $Bytes -CellOffset $CellOffset
    if ($null -eq $p -or $p.Length -lt 0x4C) { return $null }
    if (-not ($p[0] -eq 0x6E -and $p[1] -eq 0x6B)) { return $null }
    $flags = [BitConverter]::ToUInt16($p, 2)
    $nameLen = [BitConverter]::ToUInt16($p, 0x48)
    if ((0x4C + $nameLen) -gt $p.Length) { return $null }
    $name = ''
    if ($nameLen -gt 0) {
        if (($flags -band 0x0020) -ne 0) {
            $name = [Text.Encoding]::ASCII.GetString($p, 0x4C, $nameLen).Trim([char]0)
        }
        else {
            $name = [Text.Encoding]::Unicode.GetString($p, 0x4C, $nameLen).Trim([char]0)
        }
    }
    $lw = ConvertFrom-FotonFileTimeUtc -Bytes $p -Offset 4
    [PSCustomObject]@{
        CellOffset       = $CellOffset
        Name             = $name
        KeyLastWriteUtc  = $lw
        SubkeyCount      = [BitConverter]::ToInt32($p, 0x14)
        SubkeyListOffset = [BitConverter]::ToInt32($p, 0x1C)
        ValueCount       = [BitConverter]::ToInt32($p, 0x24)
        ValueListOffset  = [BitConverter]::ToInt32($p, 0x28)
    }
}

function Get-FotonRegfSubkeyOffsetsFromList {
    param(
        [byte[]]$Bytes,
        [int]$ListOffset,
        [int]$ExpectedCount
    )
    $out = New-Object System.Collections.Generic.List[int]
    if ($ListOffset -lt 0 -or $ExpectedCount -le 0) { return @() }
    $p = Get-FotonRegfCellPayload -Bytes $Bytes -CellOffset $ListOffset
    if ($null -eq $p -or $p.Length -lt 4) { return @() }
    $sig = [Text.Encoding]::ASCII.GetString($p, 0, 2)
    $count = [BitConverter]::ToUInt16($p, 2)
    if ($sig -eq 'ri') {
        $i = 0
        while ($i -lt $count) {
            $offPos = 4 + ($i * 4)
            if (($offPos + 4) -gt $p.Length) { break }
            $inner = [BitConverter]::ToInt32($p, $offPos)
            $nested = @(Get-FotonRegfSubkeyOffsetsFromList -Bytes $Bytes -ListOffset $inner -ExpectedCount $ExpectedCount)
            foreach ($n in $nested) { $out.Add([int]$n) }
            $i++
        }
        return @($out.ToArray())
    }
    $entrySize = 4
    if ($sig -eq 'lf' -or $sig -eq 'lh') { $entrySize = 8 }
    elseif ($sig -eq 'li') { $entrySize = 4 }
    else { return @() }
    $i = 0
    while ($i -lt $count) {
        $offPos = 4 + ($i * $entrySize)
        if (($offPos + 4) -gt $p.Length) { break }
        $out.Add([BitConverter]::ToInt32($p, $offPos))
        $i++
    }
    return @($out.ToArray())
}

function Get-FotonRegfSubkeys {
    param(
        [byte[]]$Bytes,
        $Nk
    )
    $list = @()
    if ($null -eq $Nk) { return @() }
    $n = [int]$Nk.SubkeyCount
    if ($n -le 0) { return @() }
    if ($n -gt 20000) { $n = 20000 }
    $offs = @(Get-FotonRegfSubkeyOffsetsFromList -Bytes $Bytes -ListOffset ([int]$Nk.SubkeyListOffset) -ExpectedCount $n)
    $i = 0
    foreach ($off in $offs) {
        if ($i -ge $n) { break }
        $cellOff = 0
        try { $cellOff = [int]$off } catch { $i++; continue }
        $child = Get-FotonRegfNk -Bytes $Bytes -CellOffset $cellOff
        if ($null -ne $child) { $list += $child }
        $i++
    }
    return @($list)
}

function Get-FotonRegfVkDecoded {
    param(
        [byte[]]$Bytes,
        [int]$VkOffset
    )
    $p = Get-FotonRegfCellPayload -Bytes $Bytes -CellOffset $VkOffset
    if ($null -eq $p -or $p.Length -lt 0x14) { return $null }
    if (-not ($p[0] -eq 0x76 -and $p[1] -eq 0x6B)) { return $null }
    $nameLen = [BitConverter]::ToUInt16($p, 2)
    $dataSizeField = [BitConverter]::ToUInt32($p, 4)
    $dataOff = [BitConverter]::ToInt32($p, 8)
    $vtype = [BitConverter]::ToInt32($p, 0x0C)
    $vflags = [BitConverter]::ToUInt16($p, 0x10)
    if ((0x14 + $nameLen) -gt $p.Length) { return $null }
    $vname = '(default)'
    if ($nameLen -gt 0) {
        if (($vflags -band 0x0001) -ne 0) {
            $vname = [Text.Encoding]::ASCII.GetString($p, 0x14, $nameLen).Trim([char]0)
        }
        else {
            $vname = [Text.Encoding]::Unicode.GetString($p, 0x14, $nameLen).Trim([char]0)
        }
    }
    $inline = (($dataSizeField -band 0x80000000) -ne 0)
    $dlen = [int]($dataSizeField -band 0x7FFFFFFF)
    $data = $null
    if ($dlen -lt 0) { return $null }
    if ($inline) {
        $data = [BitConverter]::GetBytes($dataOff)
        if ($dlen -lt $data.Length) {
            $trim = New-Object byte[] $dlen
            [Array]::Copy($data, 0, $trim, 0, $dlen)
            $data = $trim
        }
    }
    else {
        if ($dlen -eq 0) { $data = [byte[]]@() }
        else {
            $dp = Get-FotonRegfCellPayload -Bytes $Bytes -CellOffset $dataOff
            if ($null -eq $dp) { return $null }
            if ($dp.Length -lt $dlen) { $dlen = $dp.Length }
            $data = New-Object byte[] $dlen
            [Array]::Copy($dp, 0, $data, 0, $dlen)
        }
    }
    $text = ''
    if ($vtype -eq 1 -or $vtype -eq 2) {
        if ($data.Length -ge 2) {
            $text = [Text.Encoding]::Unicode.GetString($data).Trim([char]0)
        }
        elseif ($data.Length -gt 0) {
            $text = [Text.Encoding]::ASCII.GetString($data).Trim([char]0)
        }
    }
    elseif ($vtype -eq 4 -and $data.Length -ge 4) {
        $text = [BitConverter]::ToUInt32($data, 0).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    [PSCustomObject]@{
        Name = $vname
        Type = $vtype
        Text = $text
    }
}

function Get-FotonRegfValues {
    param(
        [byte[]]$Bytes,
        $Nk
    )
    $map = @{}
    if ($null -eq $Nk) { return ,$map }
    $n = [int]$Nk.ValueCount
    if ($n -le 0) { return ,$map }
    if ($n -gt 500) { $n = 500 }
    $lp = Get-FotonRegfCellPayload -Bytes $Bytes -CellOffset ([int]$Nk.ValueListOffset)
    if ($null -eq $lp) { return ,$map }
    $i = 0
    while ($i -lt $n) {
        $pos = $i * 4
        if (($pos + 4) -gt $lp.Length) { break }
        $vkOff = [BitConverter]::ToInt32($lp, $pos)
        $vk = Get-FotonRegfVkDecoded -Bytes $Bytes -VkOffset $vkOff
        if ($null -ne $vk -and $vk.Name -and $vk.Text) {
            $map[$vk.Name] = $vk.Text
        }
        $i++
    }
    return ,$map
}

function Get-FotonRegfRootNk {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 0x1020) { return $null }
    $magic = [Text.Encoding]::ASCII.GetString($Bytes, 0, 4)
    if ($magic -ne 'regf') { return $null }
    $rootOff = [BitConverter]::ToInt32($Bytes, 0x24)
    return (Get-FotonRegfNk -Bytes $Bytes -CellOffset $rootOff)
}

function Get-FotonRegfFindSubkey {
    param(
        [byte[]]$Bytes,
        $StartNk,
        [string]$Name,
        [int]$MaxDepth = 4
    )
    if ($null -eq $StartNk -or -not $Name) { return $null }
    $want = $Name.ToLowerInvariant()
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue(@($StartNk, 0))
    $seen = 0
    while ($queue.Count -gt 0 -and $seen -lt 8000) {
        $item = $queue.Dequeue()
        $nk = $item[0]
        $depth = [int]$item[1]
        $seen++
        if ([string]$nk.Name -and ([string]$nk.Name).ToLowerInvariant() -eq $want) {
            return $nk
        }
        if ($depth -ge $MaxDepth) { continue }
        foreach ($ch in @(Get-FotonRegfSubkeys -Bytes $Bytes -Nk $nk)) {
            $queue.Enqueue(@($ch, ($depth + 1)))
        }
    }
    return $null
}

function Get-FotonOleCompoundStreams {
    <#
        Extract named streams from an OLE compound file (CFB). Used for
        .automaticDestinations-ms. Caps streams and size. Returns @() on failure.
    #>
    param(
        [byte[]]$Bytes,
        [int]$MaxStreams = 64,
        [int]$MaxStreamBytes = 2097152
    )
    $out = @()
    if ($null -eq $Bytes -or $Bytes.Length -lt 512) { return $out }
    if ($Bytes[0] -ne 0xD0 -or $Bytes[1] -ne 0xCF -or $Bytes[2] -ne 0x11 -or $Bytes[3] -ne 0xE0) { return $out }
    try {
        $shift = [BitConverter]::ToUInt16($Bytes, 0x1E)
        if ($shift -lt 9 -or $shift -gt 12) { return $out }
        $sectorSize = 1 -shl $shift
        $miniShift = [BitConverter]::ToUInt16($Bytes, 0x20)
        $miniSize = 64
        if ($miniShift -ge 4 -and $miniShift -le 8) { $miniSize = 1 -shl $miniShift }
        $dirStart = [BitConverter]::ToInt32($Bytes, 0x30)
        $miniCutoff = [BitConverter]::ToUInt32($Bytes, 0x38)
        $miniFatStart = [BitConverter]::ToInt32($Bytes, 0x3C)
        $difatStart = [BitConverter]::ToInt32($Bytes, 0x44)
        $difatCount = [BitConverter]::ToInt32($Bytes, 0x48)
        $fatSectors = New-Object 'System.Collections.Generic.List[int]'
        for ($i = 0; $i -lt 109; $i++) {
            $id = [BitConverter]::ToInt32($Bytes, 0x4C + (4 * $i))
            if ($id -ge 0) { $null = $fatSectors.Add($id) }
        }
        $dif = $difatStart
        $guard = 0
        $perDif = ($sectorSize / 4) - 1
        while ($dif -ge 0 -and $guard -lt $difatCount -and $guard -lt 32) {
            $sec = Get-FotonOleSectorSlice -Bytes $Bytes -SectorSize $sectorSize -Index $dif
            if ($null -eq $sec) { break }
            $n = [int]$perDif
            for ($j = 0; $j -lt $n; $j++) {
                $id = [BitConverter]::ToInt32($sec, 4 * $j)
                if ($id -ge 0) { $null = $fatSectors.Add($id) }
            }
            $dif = [BitConverter]::ToInt32($sec, $sectorSize - 4)
            $guard++
        }
        $fat = New-Object 'System.Collections.Generic.List[uint32]'
        foreach ($fs in $fatSectors) {
            $sec = Get-FotonOleSectorSlice -Bytes $Bytes -SectorSize $sectorSize -Index $fs
            if ($null -eq $sec) { continue }
            $ents = $sectorSize / 4
            for ($k = 0; $k -lt $ents; $k++) {
                $null = $fat.Add([BitConverter]::ToUInt32($sec, 4 * $k))
            }
        }
        if ($fat.Count -lt 1) { return $out }
        $dirBytes = Get-FotonOleFatChainBytes -Bytes $Bytes -SectorSize $sectorSize -Fat $fat -Start $dirStart -MaxBytes (1MB)
        if ($null -eq $dirBytes -or $dirBytes.Length -lt 128) { return $out }
        $entries = @()
        $off = 0
        while (($off + 128) -le $dirBytes.Length) {
            $type = $dirBytes[$off + 0x42]
            $nameLen = [BitConverter]::ToUInt16($dirBytes, $off + 0x40)
            $name = ''
            if ($nameLen -ge 2) {
                $nb = [int]$nameLen - 2
                if ($nb -gt 64) { $nb = 64 }
                if ($nb -gt 0) { $name = [Text.Encoding]::Unicode.GetString($dirBytes, $off, $nb).Trim([char]0) }
            }
            $start = [BitConverter]::ToInt32($dirBytes, $off + 0x74)
            $size = [BitConverter]::ToUInt32($dirBytes, $off + 0x78)
            $entries += [PSCustomObject]@{ Type = $type; Name = $name; Start = $start; Size = $size }
            $off += 128
        }
        $root = $entries | Where-Object { $_.Type -eq 5 } | Select-Object -First 1
        $miniData = $null
        $miniFat = $null
        if ($null -ne $root -and $root.Size -gt 0 -and $root.Start -ge 0) {
            $miniData = Get-FotonOleFatChainBytes -Bytes $Bytes -SectorSize $sectorSize -Fat $fat -Start $root.Start -MaxBytes ([int]$root.Size)
            if ($miniFatStart -ge 0) {
                $mf = Get-FotonOleFatChainBytes -Bytes $Bytes -SectorSize $sectorSize -Fat $fat -Start $miniFatStart -MaxBytes 256KB
                if ($mf) {
                    $miniFat = New-Object 'System.Collections.Generic.List[uint32]'
                    for ($m = 0; $m -lt ($mf.Length / 4); $m++) {
                        $null = $miniFat.Add([BitConverter]::ToUInt32($mf, 4 * $m))
                    }
                }
            }
        }
        $taken = 0
        foreach ($e in $entries) {
            if ($e.Type -ne 2) { continue }
            if (-not $e.Name) { continue }
            if ($taken -ge $MaxStreams) { break }
            $want = [int]$e.Size
            if ($want -gt $MaxStreamBytes) { $want = $MaxStreamBytes }
            $data = $null
            if ($e.Size -lt $miniCutoff -and $null -ne $miniData -and $null -ne $miniFat) {
                $data = Get-FotonOleMiniChainBytes -MiniData $miniData -MiniFat $miniFat -MiniSize $miniSize -Start $e.Start -Size $want
            }
            else {
                $data = Get-FotonOleFatChainBytes -Bytes $Bytes -SectorSize $sectorSize -Fat $fat -Start $e.Start -MaxBytes $want
            }
            if ($null -eq $data) { continue }
            if ($data.Length -gt $want) {
                $trim = New-Object byte[] $want
                [Array]::Copy($data, 0, $trim, 0, $want)
                $data = $trim
            }
            $out += [PSCustomObject]@{ Name = $e.Name; Data = $data }
            $taken++
        }
    }
    catch { }
    return $out
}

function Get-FotonOleSectorSlice {
    param([byte[]]$Bytes, [int]$SectorSize, [int]$Index)
    if ($Index -lt 0) { return $null }
    $off = 512 + ($Index * $SectorSize)
    if (($off + $SectorSize) -gt $Bytes.Length) { return $null }
    $buf = New-Object byte[] $SectorSize
    [Array]::Copy($Bytes, $off, $buf, 0, $SectorSize)
    return $buf
}

function Get-FotonOleFatChainBytes {
    param(
        [byte[]]$Bytes,
        [int]$SectorSize,
        $Fat,
        [int]$Start,
        [int]$MaxBytes
    )
    if ($Start -lt 0) { return $null }
    $chunks = New-Object System.Collections.Generic.List[byte]
    $s = [uint32]$Start
    $guard = 0
    while ($guard -lt 4096 -and $chunks.Count -lt $MaxBytes) {
        if ($s -eq 0xFFFFFFFE -or $s -eq 0xFFFFFFFF -or $s -eq 0xFFFFFFFD -or $s -eq 0xFFFFFFFC) { break }
        $idx = [int]$s
        $sec = Get-FotonOleSectorSlice -Bytes $Bytes -SectorSize $SectorSize -Index $idx
        if ($null -eq $sec) { break }
        $take = $sec.Length
        $remain = $MaxBytes - $chunks.Count
        if ($take -gt $remain) { $take = $remain }
        for ($i = 0; $i -lt $take; $i++) { $null = $chunks.Add($sec[$i]) }
        if ($idx -ge $Fat.Count) { break }
        $s = [uint32]$Fat[$idx]
        $guard++
    }
    if ($chunks.Count -eq 0) { return $null }
    return [byte[]]$chunks.ToArray()
}

function Get-FotonOleMiniChainBytes {
    param(
        [byte[]]$MiniData,
        $MiniFat,
        [int]$MiniSize,
        [int]$Start,
        [int]$Size
    )
    $chunks = New-Object System.Collections.Generic.List[byte]
    $s = [uint32]$Start
    $guard = 0
    while ($guard -lt 4096 -and $chunks.Count -lt $Size) {
        if ($s -eq 0xFFFFFFFE -or $s -eq 0xFFFFFFFF) { break }
        $off = [int]$s * $MiniSize
        if (($off + $MiniSize) -gt $MiniData.Length) { break }
        $take = $MiniSize
        $remain = $Size - $chunks.Count
        if ($take -gt $remain) { $take = $remain }
        for ($i = 0; $i -lt $take; $i++) { $null = $chunks.Add($MiniData[$off + $i]) }
        $idx = [int]$s
        if ($idx -ge $MiniFat.Count) { break }
        $s = [uint32]$MiniFat[$idx]
        $guard++
    }
    if ($chunks.Count -eq 0) { return $null }
    return [byte[]]$chunks.ToArray()
}

function ConvertFrom-FotonJumplist {
    <#
    .SYNOPSIS
        Parse a Windows jumplist already copied off the host.

    .DESCRIPTION
        Offline bytes only. Automatic destinations (.automaticDestinations-ms) are
        OLE compound files: DestList paths/FILETIME (versions 1 and 2/3/4) plus
        embedded LNK LocalBasePath. Custom destinations (.customDestinations-ms)
        are scanned for the Shell Link CLSID and parsed with the LNK helper.

        Unknown DestList versions and failed OLE reads emit unsupported rows
        instead of guessed times. Does not execute targets.

    .PARAMETER Path
        Path to a .automaticDestinations-ms or .customDestinations-ms file.

    .EXAMPLE
        ConvertFrom-FotonJumplist -Path D:\Cases\...\9b9cdc69de0e5dea.automaticDestinations-ms

    .OUTPUTS
        One or more parse rows (DestList entries and/or embedded LNK paths).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Jumplist file not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $sha = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    $base = {
        param($Kind, $Supported, $Identity, $Note, $StreamName, $LastAccessUtc, $PinStatus, $Hostname, $LocalBasePath)
        [PSCustomObject]@{
            SourcePath     = $item.FullName
            SizeBytes      = $bytes.Length
            SHA256         = $sha
            Format         = $Kind
            Supported      = $Supported
            Identity       = $Identity
            StreamName     = $StreamName
            Hostname       = $Hostname
            LastAccessUtc  = $LastAccessUtc
            PinStatus      = $PinStatus
            LocalBasePath  = $LocalBasePath
            Note           = $Note
        }
    }

    if ($bytes.Length -lt 8) {
        return @(
            & $base 'Unsupported-TooSmall' $false '' 'Shorter than a jumplist header. Paths were not guessed.' '' '' '' '' ''
        )
    }

    $isOle = ($bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0)
    $rows = @()
    if ($isOle) {
        $streams = @(Get-FotonOleCompoundStreams -Bytes $bytes)
        if ($streams.Count -eq 0) {
            return @(
                & $base 'AutomaticDestinations' $false '' 'OLE compound header present but streams were not extracted. Use an OLE/jumplist tool; DestList times were not guessed.' '' '' '' '' ''
            )
        }
        foreach ($st in $streams) {
            if ($st.Name -eq 'DestList') {
                foreach ($d in @(ConvertFrom-FotonDestListBytes -Bytes $st.Data)) {
                    $rows += & $base 'DestList' $d.Supported $d.Identity $d.Note 'DestList' $d.LastAccessUtc $d.PinStatus $d.Hostname ''
                }
            }
            elseif ($st.Name -match '^[0-9a-fA-F]+$') {
                $lnk = Get-FotonLnkParseFromBytes -Bytes $st.Data
                $ok = [bool]$lnk.Supported
                $note = $lnk.Note
                if ($note) { $note = 'Embedded LNK stream ' + $st.Name + '. ' + $note }
                $rows += & $base 'JumplistLnk' $ok $lnk.LocalBasePath $note $st.Name '' '' '' $lnk.LocalBasePath
            }
        }
        if ($rows.Count -eq 0) {
            $rows += & $base 'AutomaticDestinations' $false '' 'OLE streams were present but none were DestList or hex-named LNK streams.' '' '' '' '' ''
        }
        return $rows
    }

    $clsid = [byte[]](0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
    $found = 0
    $i = 0
    while ($i -le ($bytes.Length - 20) -and $found -lt 40) {
        $hit = $true
        for ($c = 0; $c -lt 16; $c++) {
            if ($bytes[$i + $c] -ne $clsid[$c]) { $hit = $false; break }
        }
        if (-not $hit) { $i++; continue }
        $lnkStart = -1
        if (($i + 20) -le $bytes.Length -and [BitConverter]::ToUInt32($bytes, $i + 16) -eq 0x4C) {
            $lnkStart = $i + 16
        }
        elseif ($i -ge 4 -and [BitConverter]::ToUInt32($bytes, $i - 4) -eq 0x4C) {
            $lnkStart = $i - 4
        }
        if ($lnkStart -lt 0) {
            $i++
            continue
        }
        $end = $bytes.Length
        for ($j = $lnkStart + 4; $j -le ($bytes.Length - 4); $j++) {
            if ($bytes[$j] -eq 0xAB -and $bytes[$j + 1] -eq 0xFB -and $bytes[$j + 2] -eq 0xBF -and $bytes[$j + 3] -eq 0xBA) {
                $end = $j
                break
            }
        }
        $len = $end - $lnkStart
        if ($len -lt 0x4C) { $i++; continue }
        $slice = New-Object byte[] $len
        [Array]::Copy($bytes, $lnkStart, $slice, 0, $len)
        $lnk = Get-FotonLnkParseFromBytes -Bytes $slice
        $found++
        $verNote = 'Custom destinations embedded LNK (Shell Link CLSID). '
        if ($bytes.Length -ge 4) {
            $hv = [BitConverter]::ToUInt32($bytes, 0)
            if ($hv -ne 2) { $verNote = $verNote + ("File header version is {0} (libyal documents 2); LNK still parsed when CLSID+HeaderSize matched. " -f $hv) }
        }
        $rows += & $base 'CustomDestinations' ([bool]$lnk.Supported) $lnk.LocalBasePath ($verNote + $lnk.Note) '' '' '' '' $lnk.LocalBasePath
        $i = $end
        if ($i -lt $lnkStart + 1) { $i = $lnkStart + 1 }
    }
    if ($rows.Count -eq 0) {
        return @(
            & $base 'Unsupported-NotJumplist' $false '' 'Not an OLE automatic destinations file and no Shell Link CLSID+LNK header was found. Paths were not guessed.' '' '' '' '' ''
        )
    }
    return $rows
}

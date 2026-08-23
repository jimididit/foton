function ConvertFrom-FotonDestListBytes {
    <#
        DestList stream from an automatic destinations jumplist (libyal dtformats).
        Versions 1 (Win7) and 2/3/4 (Win10+ extended). Unknown versions: one unsupported row.
        FILETIME is emitted only at the documented offset 100.
    #>
    param(
        [byte[]]$Bytes,
        [int]$MaxEntries = 200
    )
    $rows = @()
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        $rows += [PSCustomObject]@{
            Kind          = 'DestList'
            Supported     = $false
            Identity      = ''
            Hostname      = ''
            LastAccessUtc = ''
            PinStatus     = ''
            EntryNumber   = ''
            Note          = 'DestList stream is empty. Not proof the jumplist never had entries.'
        }
        return $rows
    }
    if ($Bytes.Length -lt 32) {
        $rows += [PSCustomObject]@{
            Kind          = 'DestList'
            Supported     = $false
            Identity      = ''
            Hostname      = ''
            LastAccessUtc = ''
            PinStatus     = ''
            EntryNumber   = ''
            Note          = 'DestList shorter than the 32-byte header. Entries were not guessed.'
        }
        return $rows
    }
    $ver = [BitConverter]::ToUInt32($Bytes, 0)
    $count = [BitConverter]::ToUInt32($Bytes, 4)
    if ($ver -ne 1 -and $ver -ne 2 -and $ver -ne 3 -and $ver -ne 4) {
        $rows += [PSCustomObject]@{
            Kind          = 'DestList'
            Supported     = $false
            Identity      = ''
            Hostname      = ''
            LastAccessUtc = ''
            PinStatus     = ''
            EntryNumber   = ''
            Note          = ("DestList format version {0} is not 1, 2, 3, or 4. Paths and times were not guessed. Use a DestList-aware jumplist tool." -f $ver)
        }
        return $rows
    }
    $pos = 32
    $n = [int]$count
    if ($n -gt $MaxEntries) { $n = $MaxEntries }
    $parsed = 0
    for ($i = 0; $i -lt $n; $i++) {
        $need = 114
        if ($ver -ne 1) { $need = 130 }
        if (($pos + $need) -gt $Bytes.Length) {
            $rows += [PSCustomObject]@{
                Kind          = 'DestList'
                Supported     = $false
                Identity      = ''
                Hostname      = ''
                LastAccessUtc = ''
                PinStatus     = ''
                EntryNumber   = ''
                Note          = ("DestList truncated after {0} of {1} header entries (version {2}). Remaining paths were not guessed." -f $parsed, $count, $ver)
            }
            break
        }
        $hostBytes = New-Object byte[] 16
        [Array]::Copy($Bytes, $pos + 72, $hostBytes, 0, 16)
        $hostname = ([Text.Encoding]::ASCII.GetString($hostBytes)).Trim([char]0)
        $entryNum = [BitConverter]::ToUInt32($Bytes, $pos + 88)
        $lastUtc = ConvertFrom-FotonFileTimeUtc -Bytes $Bytes -Offset ($pos + 100)
        $pinRaw = [BitConverter]::ToInt32($Bytes, $pos + 108)
        $pin = 'Pinned'
        if ($pinRaw -eq -1) { $pin = 'Unpinned' }
        $pathOff = 114
        if ($ver -ne 1) { $pathOff = 130 }
        $pathChars = [BitConverter]::ToUInt16($Bytes, $pos + $pathOff - 2)
        $pathBytes = [int]$pathChars * 2
        if (($pos + $pathOff + $pathBytes) -gt $Bytes.Length) {
            $rows += [PSCustomObject]@{
                Kind          = 'DestList'
                Supported     = $false
                Identity      = ''
                Hostname      = $hostname
                LastAccessUtc = $lastUtc
                PinStatus     = $pin
                EntryNumber   = [string]$entryNum
                Note          = 'DestList path overruns the stream. This entry path was not guessed.'
            }
            break
        }
        $path = ''
        if ($pathBytes -gt 0) {
            $path = [Text.Encoding]::Unicode.GetString($Bytes, $pos + $pathOff, $pathBytes)
        }
        $pad = 0
        if ($ver -ne 1) { $pad = 4 }
        $rows += [PSCustomObject]@{
            Kind          = 'DestList'
            Supported     = [bool]$path
            Identity      = $path
            Hostname      = $hostname
            LastAccessUtc = $lastUtc
            PinStatus     = $pin
            EntryNumber   = [string]$entryNum
            Note          = ("DestList v{0} path. LastAccessUtc is the DestList FILETIME at offset 100, not the LNK timestamps." -f $ver)
        }
        $pos = $pos + $pathOff + $pathBytes + $pad
        $parsed++
    }
    return $rows
}

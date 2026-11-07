function Get-FotonLnkParseFromBytes {
    <# LinkInfo ANSI LocalBasePath from a Shell Link buffer. No file I/O. #>
    param([byte[]]$Bytes)
    $r = [PSCustomObject]@{
        Format        = 'Unknown'
        Supported     = $false
        LocalBasePath = ''
        Note          = ''
    }
    if ($null -eq $Bytes -or $Bytes.Length -lt 0x4C) {
        $r.Format = 'Unsupported-TooSmall'
        $r.Note = 'Shorter than a Shell Link header. Path not guessed.'
        return $r
    }
    $headerSize = [BitConverter]::ToUInt32($Bytes, 0)
    if ($headerSize -ne 0x4C) {
        $r.Format = 'Unsupported-NotLnk'
        $r.Note = 'HeaderSize is not 0x4C. Wrong fields would be worse than this record.'
        return $r
    }
    $r.Format = 'LNK'
    $flags = [BitConverter]::ToUInt32($Bytes, 20)
    $pos = 0x4C
    try {
        if (($flags -band 0x01) -ne 0) {
            if (($pos + 2) -gt $Bytes.Length) { throw 'truncated IDList' }
            $idSize = [BitConverter]::ToUInt16($Bytes, $pos)
            $pos = $pos + 2 + $idSize
        }
        if (($flags -band 0x02) -ne 0) {
            if (($pos + 20) -gt $Bytes.Length) { throw 'truncated LinkInfo' }
            $localOff = [BitConverter]::ToUInt32($Bytes, $pos + 16)
            $pathAt = $pos + [int]$localOff
            if ($pathAt -ge $Bytes.Length -or $localOff -eq 0) {
                $r.Note = 'LinkInfo present but LocalBasePath offset is empty or past EOF.'
                return $r
            }
            $chars = @()
            for ($i = $pathAt; $i -lt $Bytes.Length; $i++) {
                if ($Bytes[$i] -eq 0) { break }
                $chars += [char]$Bytes[$i]
            }
            $r.LocalBasePath = -join $chars
            if ($r.LocalBasePath) {
                $r.Supported = $true
                $r.Note = 'LocalBasePath from LinkInfo (ANSI). Arguments and timestamps are not parsed in this version.'
            }
            else {
                $r.Note = 'LinkInfo contained no ANSI local path.'
            }
            return $r
        }
        $r.Note = 'No LinkInfo block (flags). Network or IDList-only shortcuts are not expanded here.'
    }
    catch {
        $r.Note = "Parse stopped: $($_.Exception.Message). Partial fields are not invented."
    }
    return $r
}

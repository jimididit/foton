function ConvertFrom-FotonLnk {
    <#
    .SYNOPSIS
        Parse a Windows shortcut (.lnk) already copied off the host.

    .DESCRIPTION
        Pure function over bytes. Reads the local base path from LinkInfo when present.
        Does not execute the shortcut. Unknown extra blocks are ignored. If the header
        is not a Shell Link, returns Format Unsupported-NotLnk instead of guessed fields.

    .PARAMETER Path
        Path to a .lnk file or fixture.

    .EXAMPLE
        ConvertFrom-FotonLnk -Path D:\Cases\...\foo.lnk

    .OUTPUTS
        Shortcut summary. Supported is false when the path could not be read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "LNK file not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $sha = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    $out = [PSCustomObject]@{
        SourcePath     = $item.FullName
        SizeBytes      = $bytes.Length
        SHA256         = $sha
        Format         = 'Unknown'
        Supported      = $false
        LocalBasePath  = ''
        Note           = ''
    }
    if ($bytes.Length -lt 0x4C) {
        $out.Format = 'Unsupported-TooSmall'
        $out.Note = 'Shorter than a Shell Link header. Path not guessed.'
        return $out
    }
    $headerSize = [BitConverter]::ToUInt32($bytes, 0)
    if ($headerSize -ne 0x4C) {
        $out.Format = 'Unsupported-NotLnk'
        $out.Note = 'HeaderSize is not 0x4C. Wrong fields would be worse than this record.'
        return $out
    }
    $out.Format = 'LNK'
    $flags = [BitConverter]::ToUInt32($bytes, 20)
    $pos = 0x4C
    try {
        if (($flags -band 0x01) -ne 0) {
            if (($pos + 2) -gt $bytes.Length) { throw 'truncated IDList' }
            $idSize = [BitConverter]::ToUInt16($bytes, $pos)
            $pos = $pos + 2 + $idSize
        }
        if (($flags -band 0x02) -ne 0) {
            if (($pos + 20) -gt $bytes.Length) { throw 'truncated LinkInfo' }
            $localOff = [BitConverter]::ToUInt32($bytes, $pos + 16)
            $pathAt = $pos + [int]$localOff
            if ($pathAt -ge $bytes.Length -or $localOff -eq 0) {
                $out.Note = 'LinkInfo present but LocalBasePath offset is empty or past EOF.'
                return $out
            }
            $chars = @()
            for ($i = $pathAt; $i -lt $bytes.Length; $i++) {
                if ($bytes[$i] -eq 0) { break }
                $chars += [char]$bytes[$i]
            }
            $out.LocalBasePath = -join $chars
            if ($out.LocalBasePath) {
                $out.Supported = $true
                $out.Note = 'LocalBasePath from LinkInfo (ANSI). Arguments and timestamps are not parsed in this version.'
            }
            else {
                $out.Note = 'LinkInfo contained no ANSI local path.'
            }
            return $out
        }
        $out.Note = 'No LinkInfo block (flags). Network or IDList-only shortcuts are not expanded here.'
    }
    catch {
        $out.Note = "Parse stopped: $($_.Exception.Message). Partial fields are not invented."
    }
    return $out
}

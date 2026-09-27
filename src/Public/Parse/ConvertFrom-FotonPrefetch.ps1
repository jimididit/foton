function ConvertFrom-FotonPrefetch {
    <#
    .SYNOPSIS
        Parse a Prefetch file already copied off the host (bytes on disk).

    .DESCRIPTION
        Pure function over a file path. Does not read %SystemRoot%\Prefetch live.
        Windows 10+ MAM-compressed prefetch is recorded as unsupported rather than
        guessed. Uncompressed SCCA v17/v23: executable name from the header.

    .PARAMETER Path
        Prefetch .pf file (or a fixture).

    .EXAMPLE
        ConvertFrom-FotonPrefetch -Path D:\Cases\...\NOTEPAD.EXE-*.pf

    .OUTPUTS
        Prefetch summary object. Format Unsupported* when the layout is not parsed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Prefetch file not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    $bytes = [IO.File]::ReadAllBytes($item.FullName)
    $sha = Get-FotonSha256Hex -LiteralPath $item.FullName
    $base = [PSCustomObject]@{
        SourcePath     = $item.FullName
        SizeBytes      = $bytes.Length
        SHA256         = $sha
        Format         = 'Unknown'
        Supported      = $false
        Version        = $null
        ExecutableName = ''
        Note           = ''
    }
    if ($bytes.Length -lt 8) {
        $base.Format = 'Unsupported-TooSmall'
        $base.Note = 'File is shorter than a Prefetch header. Do not invent timestamps.'
        return $base
    }
    $magic = [Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    if ($magic -eq 'MAM' -or ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x41 -and $bytes[2] -eq 0x4D)) {
        $base.Format = 'MAM-compressed'
        $base.Note = 'Win10+ Prefetch is compressed. This parser does not inflate MAM; use an offline decompressor then re-run. Absence of a parsed name is a format limit, not evidence the file is empty.'
        return $base
    }
    if ($magic -ne 'SCCA') {
        $base.Format = 'Unsupported-NotPrefetch'
        $base.Note = 'Header is not SCCA or MAM. Wrong fields would be worse than this record.'
        return $base
    }
    $version = [BitConverter]::ToInt32($bytes, 4)
    $base.Version = $version
    $base.Format = 'SCCA'
    $name = ''
    if ($bytes.Length -ge 0x4C -and $version -in @(17, 23, 26, 30)) {
        $name = [Text.Encoding]::Unicode.GetString($bytes, 0x10, 60).Trim([char]0)
    }
    if ($name) {
        $base.Supported = $true
        $base.ExecutableName = $name
        $base.Note = 'Name from uncompressed SCCA header. Run count and timestamps are not parsed in this version.'
    }
    else {
        $base.Note = ("SCCA version {0} name layout is not implemented. Recorded as unsupported rather than guessed." -f $version)
    }
    return $base
}

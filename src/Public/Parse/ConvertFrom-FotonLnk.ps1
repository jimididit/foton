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
    $sha = Get-FotonSha256Hex -LiteralPath $item.FullName
    $parsed = Get-FotonLnkParseFromBytes -Bytes $bytes
    [PSCustomObject]@{
        SourcePath     = $item.FullName
        SizeBytes      = $bytes.Length
        SHA256         = $sha
        Format         = $parsed.Format
        Supported      = $parsed.Supported
        LocalBasePath  = $parsed.LocalBasePath
        Note           = $parsed.Note
    }
}

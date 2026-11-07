function Get-FotonSha256Hex {
    <#
        SHA-256 hex of a readable file via .NET.

        Foton.cmd launches Windows PowerShell 5.1 -NoProfile. Calls from inside
        this module's scope often do not auto-load Microsoft.PowerShell.Utility,
        so bare Get-FileHash becomes CommandNotFound (seen on Install-FotonTool
        and ConvertFrom-FotonPrefetch). Flatten scripts must not load modules
        either. .NET hashing avoids both problems.
    #>
    param([Parameter(Mandatory)][string]$LiteralPath)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = $null
    try {
        $fs = [IO.File]::OpenRead($LiteralPath)
        return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '')
    }
    finally {
        if ($fs) { $fs.Dispose() }
        if ($sha) { $sha.Dispose() }
    }
}

function Get-FotonSafeHash {
    <#
        SHA-256 of a file, or a sentinel string when hashing is skipped, the path is missing,
        the file is over 200MB, or the read failed. Sentinels are facts about the attempt,
        not hashes - do not treat them as IOC values.
    #>
    param([string]$Path)
    if ($script:FotonSession.SkipHashing) { return 'NotHashed' }
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'FileNotFound' }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.Length -gt 200MB) { return 'SkippedTooLarge' }
        return (Get-FotonSha256Hex -LiteralPath $item.FullName)
    }
    catch { return 'HashError' }
}

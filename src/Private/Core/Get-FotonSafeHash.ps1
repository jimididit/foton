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
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch { return 'HashError' }
}

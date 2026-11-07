function Test-FotonPathAccessible {
    <#
        Test-Path that treats access-denied as false. SYSTEM and ServiceProfiles
        paths throw UnauthorizedAccessException for a standard user; that is not a
        collection error.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop)
    }
    catch {
        return $false
    }
}

function Test-FotonUserWritablePath {
    <#
        Heuristic only: path matches substrings where a well-behaved system binary rarely lives.
        ProgramData is often *not* user-writable - hits are leads, not proof of a dropper.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($pattern in $script:FotonSession.UserWritablePatterns) {
        if ($Path -match $pattern) { return $true }
    }
    return $false
}

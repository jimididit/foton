function Test-FotonSuspiciousCommand {
    <#
        Match living-off-the-land / staging patterns. Returns joined hit names or $null.

        Short flags (-enc) and short alphanumeric tokens use word-boundary regex so
        "-enc" does not hit "Transfer-Encode" (jOVAL/compliance agents). Longer
        substrings keep Contains matching. Admin tooling still matches.

        Do not hardcode credential-theft token names in this file: Core is embedded
        in the Collect flatten and AMSI / Build tests reject those strings.
    #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lower = $Text.ToLowerInvariant()
    $hits = @()
    foreach ($pattern in $script:FotonSession.SuspiciousCommandPatterns) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        $p = $pattern.ToLowerInvariant()
        $token = $p.Trim()
        $matched = $false
        # Flag form (-enc) or short bare token (loaded from Patterns/*.txt, not inlined here)
        $useBoundary = ($token -match '^-[a-z0-9]+$') -or (
            $token.Length -le 8 -and $token -match '^[a-z0-9]+$'
        )
        if ($useBoundary) {
            $escaped = [regex]::Escape($token)
            if ($token.StartsWith('-')) {
                $re = '(?<![\w-])' + $escaped + '\b'
            }
            else {
                $re = '(?<![\w])' + $escaped + '(?![\w])'
            }
            if ([regex]::IsMatch($lower, $re)) { $matched = $true }
        }
        elseif ($lower.Contains($p)) {
            $matched = $true
        }
        if ($matched) { $hits += $pattern }
    }
    if ($hits.Count -gt 0) { return ($hits -join ', ') }
    return $null
}

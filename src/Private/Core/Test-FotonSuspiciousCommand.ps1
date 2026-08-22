function Test-FotonSuspiciousCommand {
    <#
        Substring match against living-off-the-land / staging patterns.
        Returns joined hit names or $null. Admin tooling (PsExec, AnyDesk, rclone) matches too.
    #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lower = $Text.ToLower()
    $hits = @()
    foreach ($pattern in $script:FotonSession.SuspiciousCommandPatterns) {
        if ($lower.Contains($pattern)) { $hits += $pattern }
    }
    if ($hits.Count -gt 0) { return ($hits -join ', ') }
    return $null
}

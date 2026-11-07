function Get-FotonTaskActionScriptPath {
    <#
        Resolve script-like paths from a scheduled-task Action Execute + Arguments.
        Used by Deep Collect task_action_scripts. Returns unique full paths only.
        Does not interpret malice - path facts for later copy.
    #>
    param(
        [string]$Execute,
        [string]$Arguments
    )

    $exts = @('.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta')
    $found = New-Object System.Collections.ArrayList
    $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

    $candidates = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($Execute)) {
        $null = $candidates.Add($Execute)
    }
    if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
        foreach ($m in [regex]::Matches($Arguments, '"([^"]+\.(?:ps1|bat|cmd|vbs|js|wsf|hta))"', $opt)) {
            $null = $candidates.Add($m.Groups[1].Value)
        }
        foreach ($m in [regex]::Matches(
                $Arguments,
                '(?:^|[\s=])((?:[A-Za-z]:\\|\\\\)[^\s"]+\.(?:ps1|bat|cmd|vbs|js|wsf|hta))\b',
                $opt)) {
            $null = $candidates.Add($m.Groups[1].Value)
        }
    }

    foreach ($raw in $candidates) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $p = ([string]$raw).Trim().Trim('"').Trim("'")
        if (-not $p) { continue }
        try {
            $p = [Environment]::ExpandEnvironmentVariables($p)
        }
        catch { }
        $leafExt = [IO.Path]::GetExtension($p)
        if (-not $leafExt) { continue }
        $ok = $false
        foreach ($e in $exts) {
            if ($leafExt.Equals($e, [StringComparison]::OrdinalIgnoreCase)) { $ok = $true; break }
        }
        if (-not $ok) { continue }
        if (-not [IO.Path]::IsPathRooted($p)) { continue }
        # Keep UNC in the result list so callers can emit SkippedUnc without opening them.
        # Do not GetFullPath UNC here (would touch the network).
        if ($p.StartsWith('\\') -or $p.StartsWith('//')) {
            $null = $found.Add($p)
            continue
        }
        try {
            $p = [IO.Path]::GetFullPath($p)
        }
        catch { continue }
        if ($p -notmatch '^[A-Za-z]:\\') { continue }
        $null = $found.Add($p)
    }

    @($found | Select-Object -Unique)
}

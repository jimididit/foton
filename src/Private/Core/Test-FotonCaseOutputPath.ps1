function Test-FotonCaseOutputPath {
    <#
        True when a path sits inside an earlier Foton case or baseline package.

        Operators often leave an earlier package on the Desktop or in Downloads.
        A later collection that walks those folders would sweep the earlier package's
        copied LNKs, task scripts, and hives back in as if they were host artifacts.

        A folder name alone is not enough: anything on the host can be named
        Foton_X_20260101-000000Z to hide from these scans. The folder must also hold
        the files Foton writes into every package (00_Collection\collection.log, or
        baseline.json for a baseline package). Every folder skipped this way is
        logged once, so the exclusion is visible in collection.log.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $m = [regex]::Match($Path, '(?i)^(?<root>.*?[\\/](?:Win)?Foton(?:Baseline)?_[^\\/]+_\d{8}-\d{6}Z)(?:[\\/]|$)')
    if (-not $m.Success) { return $false }
    $root = $m.Groups['root'].Value

    # Per-session cache: one Test-Path pair and one log line per package folder.
    $cache = @{}
    if ($script:FotonSession) {
        if (-not $script:FotonSession.ContainsKey('CaseOutputCache')) { $script:FotonSession['CaseOutputCache'] = @{} }
        $cache = $script:FotonSession['CaseOutputCache']
    }
    if ($cache.ContainsKey($root)) { return $cache[$root] }

    $isPackage = $false
    $label = 'earlier Foton package'
    if ($script:FotonSession -and $script:FotonSession.CaseRoot -and
        [string]::Equals(([string]$script:FotonSession.CaseRoot).TrimEnd('\', '/'), $root, [StringComparison]::OrdinalIgnoreCase)) {
        $isPackage = $true
        $label = 'this collection''s own case folder'
    }
    elseif ((Test-Path -LiteralPath (Join-Path $root '00_Collection\collection.log') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $root 'baseline.json') -PathType Leaf)) {
        $isPackage = $true
    }
    $cache[$root] = $isPackage
    if ($isPackage -and (Get-Command Write-FotonStatus -ErrorAction SilentlyContinue)) {
        Write-FotonStatus ("Skipping {0} in profile scan: {1}" -f $label, $root) 'Info'
    }
    return $isPackage
}

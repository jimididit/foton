function Test-FotonCaseOutputPath {
    <#
        True when a path sits inside a Foton case or baseline folder
        (Foton_HOST_yyyyMMdd-HHmmssZ, WinFoton_..., FotonBaseline_...).

        Operators often leave an earlier package on the Desktop or in Downloads.
        A later collection that walks those folders would sweep the earlier package's
        copied LNKs, task scripts, and hives back in as if they were host artifacts.
        Recursive profile scans skip these folders; the current run's output is
        skipped the same way.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '(?i)[\\/](?:Win)?Foton(?:Baseline)?_[^\\/]+_\d{8}-\d{6}Z(?:[\\/]|$)')
}

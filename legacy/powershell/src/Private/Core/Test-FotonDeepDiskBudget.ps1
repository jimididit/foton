function Test-FotonDeepDiskBudget {
    <#
        Deep copy gate: CaseRoot volume must have at least 2 GiB free.
        Returns $true when copies may proceed. Fail-open on probe errors so
        Deep still attempts copy on odd volume APIs; callers still have byte caps.
    #>
    param(
        [long]$MinFreeBytes = 2147483648
    )

    $root = $null
    if ($script:FotonSession -and $script:FotonSession.CaseRoot) {
        $root = [string]$script:FotonSession.CaseRoot
    }
    if (-not $root) { return $true }

    try {
        $driveLetter = [IO.Path]::GetPathRoot($root)
        if (-not $driveLetter) { return $true }
        $di = New-Object System.IO.DriveInfo($driveLetter)
        if (-not $di.IsReady) { return $true }
        return ($di.AvailableFreeSpace -ge $MinFreeBytes)
    }
    catch {
        return $true
    }
}

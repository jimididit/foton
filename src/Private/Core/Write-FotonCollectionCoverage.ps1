function Write-FotonCollectionCoverage {
    <#
        Records how this run was privileged so an analyst does not read a thin package
        as a quiet host. Written after collection so skipped-task counts are accurate.
    #>
    $skipped = @($script:FotonSession.Manifest | Where-Object { $_.Status -eq 'SkippedNotElevated' })
    $incomplete = @($script:FotonSession.Manifest | Where-Object { $_.Status -in @('Partial', 'Failed') })
    $profileName = 'Elevated'
    if (-not $script:FotonSession.IsElevated) { $profileName = 'StandardUser' }
    $pkg = $script:FotonSession.Package
    $obj = [PSCustomObject]@{
        CoverageProfile        = $profileName
        Elevated               = $script:FotonSession.IsElevated
        CollectionAccount      = "$env:USERDOMAIN\$env:USERNAME"
        RequireAdministrator   = [bool]($pkg.RequireAdministrator)
        LoadUserHivesRequested = [bool]($pkg.LoadUserHives)
        LoadUserHivesActive    = [bool]$script:FotonSession.LoadUserHivesActive
        SkippedTaskCount       = $skipped.Count
        SkippedTasks           = @($skipped | ForEach-Object { $_.Task })
        IncompleteTaskCount    = $incomplete.Count
        IncompleteTasks        = @($incomplete | ForEach-Object { '{0} ({1})' -f $_.Task, $_.Status })
        WorthCollectingWithoutAdmin = @(
            'Current-user processes (image hash/signature only if the file is readable)',
            'TCP connections and listeners the token can enumerate',
            'HKCU autoruns, user Startup folder, PSReadLine history for accessible profiles',
            'Readable HKLM software/uninstall, OS identity, environment, hosts file',
            'Application / PowerShell / Defender operational logs when ACLs allow',
            'Browser extensions and executables under the current profile'
        )
        NotCollectedWithoutAdmin = @(
            'Security event log (parsed and EVTX export)',
            'Prefetch listing and copied .pf files',
            'Amcache hive copy',
            'SRUM database copy',
            'Volume shadow copy listing (vssadmin)',
            'auditpol / secedit exports',
            'Offline NTUSER.DAT for other users',
            'Other users'' AppData, recycle bins, and files the token cannot read'
        )
    }
    $path = Join-Path $script:FotonSession.Dirs['Collection'] 'collection_coverage.json'
    $obj | ConvertTo-Json -Depth 5 | Out-File -FilePath $path -Encoding UTF8
    $script:FotonSession.Data['collection_coverage'] = $obj
}

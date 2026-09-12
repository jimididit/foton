function Invoke-FotonTriage {
    <#
    .SYNOPSIS
        Live collect → analyze → HTML report → hashed package (v1 WinFoton behavior).

    .DESCRIPTION
        Runs on a Windows endpoint. Administrator is preferred; standard-user coverage
        is supported. Writes a Foton_<host>_<stamp>Z case folder. Does not remediate.

        This is the Collect orchestrator. On an engagement, prefer dist/Foton-Collect.ps1
        (single file on the endpoint). Loading the Foton module and calling this command
        is for lab/dev on a workstation.

    .EXAMPLE
        Invoke-FotonTriage -OutputPath C:\FotonCases -CaseNumber 'LAB-1' -NoZip

        Collect with the current token into C:\FotonCases.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = "$env:USERPROFILE\Desktop",
        [string]$CaseNumber = '',
        [string]$Examiner = "$env:USERNAME",
        [int]$EventLogDays = 14,
        [int]$MaxEventsPerLog = 3000,
        [switch]$SkipEvtxExport,
        [switch]$SkipHashing,
        [switch]$LoadUserHives,
        [switch]$IncludeFileTimeline,
        [switch]$IncludeUsnJournal,
        [switch]$NoZip,
        [switch]$RequireAdministrator
    )

    if ($env:OS -ne 'Windows_NT') {
        Write-Host '  [x] Foton Collect runs on Windows only.' -ForegroundColor Red
        return
    }

    Initialize-FotonSession -SkipHashing:$SkipHashing -EventLogDays $EventLogDays `
        -MaxEventsPerLog $MaxEventsPerLog -SkipEvtxExport:$SkipEvtxExport `
        -IncludeFileTimeline:$IncludeFileTimeline -IncludeUsnJournal:$IncludeUsnJournal

    if (-not $script:FotonSession.Version) {
        $script:FotonSession.Version = '1.5.0'
    }
    $script:FotonSession.StartTimeUtc = (Get-Date).ToUniversalTime()
    $script:FotonSession.IsElevated = Test-FotonElevated
    $script:FotonSession.Package = @{
        CaseNumber            = $CaseNumber
        Examiner              = $Examiner
        RequireAdministrator  = [bool]$RequireAdministrator
        LoadUserHives         = [bool]$LoadUserHives
        OutputPath            = $OutputPath
    }

    Write-FotonBanner -Kind 'Collect'

    if ($RequireAdministrator -and -not $script:FotonSession.IsElevated) {
        Write-Host '  [x] -RequireAdministrator was set, but this process is not elevated.' -ForegroundColor Red
        Write-Host '      Re-run from an elevated PowerShell, or omit -RequireAdministrator' -ForegroundColor Red
        Write-Host '      to collect with standard-user coverage.' -ForegroundColor Red
        return
    }

    if (-not $script:FotonSession.IsElevated) {
        Write-Host '  [!] Standard-user coverage (not Administrator).' -ForegroundColor Yellow
        Write-Host '      Still collected: this user''s processes, readable network state,' -ForegroundColor Yellow
        Write-Host '      HKCU persistence, profile files, and any logs the token can read.' -ForegroundColor Yellow
        Write-Host '      Skipped: Security log, Prefetch copies, Amcache, SRUM, VSS, auditpol/secedit, other users.' -ForegroundColor Yellow
        Write-Host ''
    }

    $caseRoot = Initialize-FotonCase -OutputPath $OutputPath
    Write-FotonStatus "Case folder: $caseRoot" 'Good'
    $covLabel = 'StandardUser'
    if ($script:FotonSession.IsElevated) { $covLabel = 'Elevated' }
    Write-FotonStatus "Examiner: $Examiner | Case: $(if ($CaseNumber) { $CaseNumber } else { 'not supplied' }) | Coverage: $covLabel" 'Info'
    Write-FotonChainOfCustody -OutputPath $OutputPath -CaseNumber $CaseNumber -Examiner $Examiner `
        -LoadUserHives:$LoadUserHives -NoZip:$NoZip -RequireAdministrator:$RequireAdministrator

    if ($LoadUserHives) {
        if (-not $script:FotonSession.IsElevated) {
            Write-FotonStatus 'LoadUserHives ignored: mounting NTUSER.DAT requires elevation' 'Warn'
        }
        else {
            Write-FotonStatus 'Mounting offline user registry hives' 'Step'
            $mounted = Mount-FotonOfflineUserHive
            $script:FotonSession.LoadUserHivesActive = $true
            Write-FotonStatus ("Mounted {0} offline hive(s)" -f @($mounted).Count) 'Info'
        }
    }

    try {
        Invoke-FotonProcessCollection
        Invoke-FotonNetworkCollection
        Invoke-FotonUserCollection
        Invoke-FotonSystemCollection
        Invoke-FotonPersistenceCollection
        Invoke-FotonSecurityCollection
        Invoke-FotonSoftwareCollection
        Invoke-FotonEventLogCollection
        Invoke-FotonFilesystemCollection

        Write-FotonCollectionCoverage
        Invoke-FotonAnalysis
    }
    finally {
        if ($script:FotonSession.LoadUserHivesActive) {
            Write-FotonStatus 'Unmounting offline user registry hives' 'Step'
            Dismount-FotonOfflineUserHive
        }
    }

    Write-FotonManifestFiles
    $reportPath = Join-Path $script:FotonSession.CaseRoot 'Foton_Report.html'
    New-FotonReport -Path $reportPath | Out-Null
    $artifactCount = Write-FotonArtifactHashes

    $zipPath = $null
    if (-not $NoZip) {
        $zipPath = Compress-FotonCasePackage
    }

    $zipHash = ''
    $zipSizeMb = 0
    if ($zipPath -and (Test-Path -LiteralPath $zipPath)) {
        try { $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash } catch { $zipHash = 'HASH_ERROR' }
        $zipSizeMb = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 2)
        $stamp = @()
        $stamp += 'Foton package integrity record'
        $stamp += ''
        $stamp += "Package      : $(Split-Path $zipPath -Leaf)"
        $stamp += "SHA-256      : $zipHash"
        $stamp += "Size (MB)    : $zipSizeMb"
        $stamp += "Created UTC  : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))"
        $stamp += "Host         : $env:COMPUTERNAME"
        $stamp += "Examiner     : $Examiner"
        $stamp += "Case         : $CaseNumber"
        $stamp += ''
        $stamp += 'Record this hash on receipt and verify it at every custody transfer:'
        $stamp += '  Get-FileHash -Algorithm SHA256 <package.zip>'
        $stamp | Out-File -FilePath ("$($script:FotonSession.CaseRoot)" + '_PACKAGE_HASH.txt') -Encoding UTF8
    }

    $sevCounts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $script:FotonSession.Findings) { $sevCounts[$f.Severity] = $sevCounts[$f.Severity] + 1 }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host '   COLLECTION COMPLETE' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor Cyan
    Write-Host ("   Artifacts collected : {0} files across {1} categories" -f $artifactCount, $script:FotonSession.Categories.Count)
    Write-Host ("   Collection errors   : {0}" -f $script:FotonSession.Errors.Count)
    Write-Host ("   Observations        : {0} high, {1} medium, {2} low, {3} info" -f `
            $sevCounts['High'], $sevCounts['Medium'], $sevCounts['Low'], $sevCounts['Info'])
    Write-Host ("   Duration            : {0} min" -f [math]::Round(((Get-Date).ToUniversalTime() - $script:FotonSession.StartTimeUtc).TotalMinutes, 1))
    Write-Host ''
    Write-Host "   Case folder : $($script:FotonSession.CaseRoot)" -ForegroundColor White
    Write-Host "   Report      : $reportPath" -ForegroundColor White
    if ($zipPath) {
        Write-Host "   Package     : $zipPath ($zipSizeMb MB)" -ForegroundColor White
        Write-Host "   SHA-256     : $zipHash" -ForegroundColor Green
    }
    Write-Host ''
    Write-Host '   Open Foton_Report.html from inside the extracted folder so' -ForegroundColor DarkGray
    Write-Host '   the artifact links resolve. Findings are automated observations,' -ForegroundColor DarkGray
    Write-Host '   not conclusions - verify each one against its source artifact.' -ForegroundColor DarkGray
    Write-Host ''
}

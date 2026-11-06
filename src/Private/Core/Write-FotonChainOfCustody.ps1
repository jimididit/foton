function Write-FotonChainOfCustody {
    param(
        [string]$OutputPath,
        [string]$CaseNumber,
        [string]$Examiner,
        [switch]$LoadUserHives,
        [switch]$NoZip,
        [switch]$RequireAdministrator
    )
    $elevated = $script:FotonSession.IsElevated
    $tz = [System.TimeZoneInfo]::Local
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $cs = $null
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }

    $lines = @()
    $lines += '================================================================'
    $lines += ' Foton - Collection Record / Chain of Custody Header'
    $lines += '================================================================'
    $lines += ''
    $lines += "Case Number          : $(if ($CaseNumber) { $CaseNumber } else { '(not supplied)' })"
    $lines += "Examiner             : $Examiner"
    $lines += "Collection Tool      : Foton v$($script:FotonSession.Version)"
    $lines += "Collection Type      : Live (running system) logical collection"
    $lines += "Collection Start UTC : $($script:FotonSession.StartTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Local Time At Start  : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "System Time Zone     : $($tz.Id) (UTC offset $($tz.GetUtcOffset((Get-Date))))"
    $lines += ''
    $lines += "Hostname             : $env:COMPUTERNAME"
    $lines += "Domain / Workgroup   : $(if ($cs) { $cs.Domain } else { 'unknown' })"
    $lines += "Manufacturer / Model : $(if ($cs) { "$($cs.Manufacturer) $($cs.Model)" } else { 'unknown' })"
    $lines += "Operating System     : $(if ($os) { "$($os.Caption) $($os.Version) (build $($os.BuildNumber))" } else { 'unknown' })"
    $lines += "Last Boot UTC        : $(if ($os) { $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown' })"
    $lines += ''
    $lines += "Collection Account   : $env:USERDOMAIN\$env:USERNAME"
    $lines += "Elevated (Admin)     : $elevated"
    $lines += "Coverage Profile     : $(if ($elevated) { 'Elevated' } else { 'StandardUser' })"
    $lines += "PowerShell Version   : $($PSVersionTable.PSVersion.ToString())"
    $lines += "Script Path          : $($MyInvocation.ScriptName)"
    $lines += ''
    $lines += 'Parameters Used:'
    $lines += "  OutputPath          = $OutputPath"
    $lines += "  EventLogDays        = $($script:FotonSession.EventLogDays)"
    $lines += "  MaxEventsPerLog     = $($script:FotonSession.MaxEventsPerLog)"
    $lines += "  SkipEvtxExport      = $($script:FotonSession.SkipEvtxExport)"
    $lines += "  SkipHashing         = $($script:FotonSession.SkipHashing)"
    $lines += "  LoadUserHives       = $LoadUserHives"
    $lines += "  IncludeFileTimeline = $($script:FotonSession.IncludeFileTimeline)"
    $lines += "  IncludeUsnJournal   = $($script:FotonSession.IncludeUsnJournal)"
    $lines += "  Deep                = $($script:FotonSession.Deep)"
    $lines += "  NoZip               = $NoZip"
    $lines += "  RequireAdministrator = $RequireAdministrator"
    $lines += ''
    $lines += '----------------------------------------------------------------'
    $lines += ' METHODOLOGY DISCLOSURE'
    $lines += '----------------------------------------------------------------'
    $lines += 'This was a LIVE collection. Executing this tool altered the target'
    $lines += 'system state: it created a process, wrote files to the output path,'
    $lines += 'generated event log entries, updated prefetch/AmCache, and read'
    $lines += 'registry keys (updating last-access metadata on some artifacts).'
    $lines += 'Volatile data (RAM, live network state) was captured only to the'
    $lines += 'extent listed in the manifest. No memory image and no disk image'
    $lines += 'were produced. If either is required, capture them before or'
    $lines += 'independently of this collection.'
    $lines += ''
    if ($elevated) {
        # Written before collection runs, so this states the method, not the outcome.
        $lines += 'Loaded registry hives (SYSTEM, SOFTWARE, DEFAULT, and signed-in users'
        $lines += 'NTUSER.DAT/UsrClass.dat) are exported with reg save. The export files'
        $lines += 'in the output path are the only writes; no key is modified. Whether each'
        $lines += 'export succeeded is recorded per file in registry_hives_machine.csv and'
        $lines += 'registry_hives_user.csv (Status Saved / SaveError) and in the manifest.'
        $lines += 'SAM and SECURITY are not collected by design (credential material).'
        $lines += ''
    }
    if ($LoadUserHives -and $elevated) {
        $lines += 'The -LoadUserHives option was used: NTUSER.DAT hives for users not'
        $lines += 'logged on were mounted into HKEY_USERS and unloaded at the end'
        $lines += 'of collection. This is a registry write operation on the target.'
        $lines += ''
    }
    elseif ($LoadUserHives -and -not $elevated) {
        $lines += 'The -LoadUserHives option was requested but ignored: mounting NTUSER.DAT'
        $lines += 'requires an elevated token. Per-user keys are limited to hives already loaded.'
        $lines += ''
    }
    if (-not $elevated) {
        $lines += 'Coverage profile STANDARD USER. This process was not elevated. The package'
        $lines += 'contains what the current token could read (typically the interactive user''s'
        $lines += 'processes, HKCU persistence, readable HKLM values, network snapshot, and that'
        $lines += 'user''s profile artifacts). The Security event log, Prefetch/Amcache/SRUM copies,'
        $lines += 'VSS listing, auditpol, secedit export, and other users'' files were not collected (see'
        $lines += 'collection_coverage.json and manifest Status=SkippedNotElevated). Absence of'
        $lines += 'those artifacts is a visibility gap, not evidence they were empty on the host.'
        $lines += ''
    }
    $lines += 'SHA-256 hashes for every collected artifact are recorded in'
    $lines += 'hashes.csv, produced after collection completed. Verify these hashes'
    $lines += 'on receipt and at each transfer. Record custody transfers below.'
    $lines += ''
    $lines += 'Transfer Log:'
    $lines += '  [Date/Time UTC] --- from ______________ to ______________ purpose ______________'
    $lines += '  [Date/Time UTC] --- from ______________ to ______________ purpose ______________'
    $lines += ''

    $file = Join-Path $script:FotonSession.Dirs['Collection'] 'chain_of_custody.txt'
    $lines | Out-File -FilePath $file -Encoding UTF8
}

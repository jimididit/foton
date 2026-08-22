# Invoke-FotonEventLogCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint runs still use WinFoton.ps1 until the standalone flatten build.

function Invoke-FotonEventLogCollection {
    $eventLogDays = $script:FotonSession.EventLogDays
    $maxEventsPerLog = $script:FotonSession.MaxEventsPerLog
    Write-FotonStatus "Collecting event logs (last $eventLogDays days, max $maxEventsPerLog per query)" 'Step'
    $start = (Get-Date).AddDays(-1 * $eventLogDays)

    $queries = @(
        @{ Name = 'security_logon_events'; Log = 'Security'; Ids = @(4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779); Desc = 'Logon success/failure, explicit credential use, privilege assignment' },
        @{ Name = 'security_account_management'; Log = 'Security'; Ids = @(4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4757, 4767, 4781); Desc = 'Account creation, modification, group membership changes' },
        @{ Name = 'security_process_creation'; Log = 'Security'; Ids = @(4688, 4689); Desc = 'Process creation/termination (requires audit policy enabled)' },
        @{ Name = 'security_policy_and_log_changes'; Log = 'Security'; Ids = @(1102, 4719, 4739, 4907, 4912); Desc = 'Audit log cleared and audit policy changes' },
        @{ Name = 'security_object_and_share_access'; Log = 'Security'; Ids = @(5140, 5142, 5143, 5144, 5145, 4663, 4656); Desc = 'Share and object access events' },
        @{ Name = 'security_scheduled_task_and_service'; Log = 'Security'; Ids = @(4697, 4698, 4699, 4700, 4701, 4702); Desc = 'Service installation and scheduled task changes' },
        @{ Name = 'security_kerberos_ntlm'; Log = 'Security'; Ids = @(4768, 4769, 4771, 4776); Desc = 'Kerberos/NTLM authentication events' },
        @{ Name = 'system_service_and_driver'; Log = 'System'; Ids = @(7045, 7040, 7034, 7031, 7036, 219, 41, 1001); Desc = 'Service install/state change, driver load, unexpected shutdown' },
        @{ Name = 'system_log_and_boot'; Log = 'System'; Ids = @(104, 6005, 6006, 6008, 6013, 1074); Desc = 'Log clearing, boot, shutdown events' },
        @{ Name = 'powershell_operational'; Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4103, 4104, 53504); Desc = 'PowerShell script block and module logging' },
        @{ Name = 'powershell_classic'; Log = 'Windows PowerShell'; Ids = @(400, 403, 600, 800); Desc = 'Classic PowerShell engine lifecycle and provider events' },
        @{ Name = 'defender_operational'; Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012); Desc = 'Defender detections, actions, and configuration changes' },
        @{ Name = 'task_scheduler_operational'; Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(106, 129, 140, 141, 200, 201); Desc = 'Task registration, deletion, and execution' },
        @{ Name = 'terminal_services_local'; Log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Ids = @(21, 22, 23, 24, 25, 39, 40); Desc = 'RDP session connect/disconnect/reconnect' },
        @{ Name = 'terminal_services_remote'; Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149, 1148); Desc = 'RDP authentication attempts with source IP' },
        @{ Name = 'wmi_activity'; Log = 'Microsoft-Windows-WMI-Activity/Operational'; Ids = @(5857, 5858, 5859, 5860, 5861); Desc = 'WMI provider and permanent subscription activity' },
        @{ Name = 'windows_firewall'; Log = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Ids = @(2003, 2004, 2005, 2006, 2033); Desc = 'Firewall rule and profile changes' },
        @{ Name = 'bits_client'; Log = 'Microsoft-Windows-Bits-Client/Operational'; Ids = @(3, 4, 59, 60); Desc = 'BITS transfer jobs (download activity)' },
        @{ Name = 'app_crashes'; Log = 'Application'; Ids = @(1000, 1001, 1002); Desc = 'Application crash and hang reports' },
        @{ Name = 'sysmon_operational'; Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1, 3, 6, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25); Desc = 'Sysmon telemetry if Sysmon is deployed' }
    )

    # GetNewClosure() copies *variables* into a private scope so each query keeps its own
    # $q, but it does not copy script functions. Capture the helpers here or the task
    # fails with "Get-FotonWinEvent is not recognized" (seen on Windows 11 / PS7).
    $fnGetEvents = ${function:Get-FotonWinEvent}
    $fnToRow = ${function:ConvertTo-FotonEventRow}

    foreach ($q in $queries) {
        $needAdmin = $false
        if ($q.Log -eq 'Security') { $needAdmin = $true }
        $query = $q
        $windowStart = $start
        $maxEv = $maxEventsPerLog
        Invoke-FotonCollection -Category 'EventLogs' -Name $q.Name -Format 'Csv' -Description $q.Desc -RequiresElevation:$needAdmin -Script {
            $events = & $fnGetEvents -LogName $query.Log -EventIds $query.Ids -StartTime $windowStart -MaxEvents $maxEv
            if (-not $events) { return @() }
            $rows = @()
            foreach ($e in $events) { $rows += (& $fnToRow -EventRecord $e -LogLabel $query.Log) }
            $rows | Sort-Object TimeCreatedUtc -Descending
        }.GetNewClosure() | Out-Null
    }

    Invoke-FotonCollection -Category 'EventLogs' -Name 'event_log_configuration' -Format 'Csv' -Description 'Log size, retention, and enablement (gap analysis)' -Script {
        $rows = @()
        $logs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Sysmon/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-WMI-Activity/Operational')
        foreach ($l in $logs) {
            try {
                $cfg = Get-WinEvent -ListLog $l -ErrorAction Stop
                $rows += [PSCustomObject]@{
                    LogName        = $cfg.LogName
                    IsEnabled      = $cfg.IsEnabled
                    LogMode        = [string]$cfg.LogMode
                    MaximumSizeMB  = [math]::Round($cfg.MaximumSizeInBytes / 1MB, 2)
                    CurrentSizeMB  = [math]::Round($cfg.FileSize / 1MB, 2)
                    RecordCount    = $cfg.RecordCount
                    OldestRecordUtc = ''
                    LogFilePath    = $cfg.LogFilePath
                }
            }
            catch {
                $rows += [PSCustomObject]@{ LogName = $l; IsEnabled = 'NotPresent'; LogMode = ''; MaximumSizeMB = 0; CurrentSizeMB = 0; RecordCount = 0; OldestRecordUtc = ''; LogFilePath = '' }
            }
        }
        $rows
    } | Out-Null

    if (-not $script:FotonSession.SkipEvtxExport) {
        Write-FotonStatus 'Exporting raw EVTX files (time-filtered)' 'Step'
        $evtxDir = Join-Path $script:FotonSession.Dirs['EventLogs'] 'evtx'
        New-Item -Path $evtxDir -ItemType Directory -Force | Out-Null
        $ms = [int64]$eventLogDays * 86400000
        $exportLogs = @('Security', 'System', 'Application',
            'Microsoft-Windows-PowerShell/Operational',
            'Microsoft-Windows-TaskScheduler/Operational',
            'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
            'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
            'Microsoft-Windows-WMI-Activity/Operational',
            'Microsoft-Windows-Sysmon/Operational')
        foreach ($log in $exportLogs) {
            if ((-not $script:FotonSession.IsElevated) -and ($log -eq 'Security')) {
                Write-FotonStatus "EVTX export skipped for Security (not elevated)" 'Info'
                continue
            }
            $safeName = ($log -replace '[\\/ ]', '_') + '.evtx'
            $dest = Join-Path $evtxDir $safeName
            try {
                $query = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
                $null = & wevtutil.exe epl "$log" "$dest" "/q:$query" /ow:true 2>&1
                if (Test-Path -LiteralPath $dest) {
                    Write-FotonStatus "Exported $log" 'Good'
                }
                else {
                    Write-FotonStatus "No EVTX export produced for $log" 'Info'
                }
            }
            catch { Write-FotonStatus "EVTX export failed for $log : $($_.Exception.Message)" 'Warn' }
        }
    }
    else {
        Write-FotonStatus 'EVTX export skipped by parameter' 'Info'
    }
}

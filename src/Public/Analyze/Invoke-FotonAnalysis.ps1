# Invoke-FotonAnalysis
# Heuristics only. Never acquire live host state. Identical package in, identical findings out.
function Invoke-FotonAnalysis {
    <#
    .SYNOPSIS
        Apply v1 triage heuristics to artifacts already loaded in the session.

    .DESCRIPTION
        Reads $script:FotonSession.Data (typically filled by Get-FotonPackage).
        Clears prior findings, then emits Add-FotonFinding rows. Does not touch
        the live registry, WMI, or network.

        Writes analysis/findings.csv under the case folder when CaseRoot is set.
        Does not rewrite 00_Collection/hashes.csv.

    .EXAMPLE
        Get-FotonPackage -Path C:\Cases\WinFoton_PC1_20260101-120000Z
        Invoke-FotonAnalysis
        New-FotonReport

    .OUTPUTS
        None. Findings are in $script:FotonSession.Findings (module scope).
    #>
    [CmdletBinding()]
    param()

    if ($null -eq $script:FotonSession -or $null -eq $script:FotonSession.Data) {
        throw 'No package data loaded. Call Get-FotonPackage first.'
    }
    $script:FotonSession.Findings = New-Object System.Collections.ArrayList
    Write-FotonStatus 'Evaluating collected artifacts against triage heuristics' 'Step'

    # ---------- Baseline context (always present, Tier 1) ----------
    $osInfo = $script:FotonSession.Data['os_info']
    if ($osInfo) {
        Add-FotonFinding -Severity 'Info' -Category 'System' -Tier 1 -Title 'Host and collection baseline' `
            -Observation ("{0} running {1} (build {2}), uptime {3} days, time zone {4} (offset {5})." -f `
                $osInfo.Hostname, $osInfo.Caption, $osInfo.BuildNumber, $osInfo.UptimeDays, $osInfo.TimeZone, $osInfo.UtcOffset) `
            -WhyItMatters 'All timestamps in this package are recorded in UTC. Confirm the host clock was accurate before building any timeline (see time_sync.txt).' `
            -Artifact (Get-FotonArtifactPath 'System' 'os_info' 'json')
    }

    $cov = $script:FotonSession.Data['collection_coverage']
    if ($cov -and $cov.Elevated -eq $false) {
        Add-FotonFinding -Severity 'Info' -Category 'Collection' -Tier 1 -Title 'Collection ran without Administrator rights' `
            -Observation ("Coverage profile {0} as {1}. {2} task(s) were skipped because they require an elevated token (see collection_coverage.json)." -f `
                $cov.CoverageProfile, $cov.CollectionAccount, $cov.SkippedTaskCount) `
            -WhyItMatters 'Standard-user collection still captures the current user''s process list, readable network state, HKCU persistence, and profile artifacts. It does not capture the Security log, Prefetch copies, Amcache, SRUM, VSS, audit policy export, or other users'' files. Missing those artifacts is a visibility gap, not evidence they were empty. Re-run elevated when the host owner can grant it.' `
            -Artifact (Get-FotonArtifactPath 'Collection' 'collection_coverage' 'json') `
            -NextStep 'If this is an incident, obtain an elevated collection or a disk/memory image. If this is a self-audit on a locked-down work PC, treat skipped tasks as out of scope and verify remaining artifacts against that user''s activity only.'
    }

    # ---------- Defender / AV ----------
    $def = $script:FotonSession.Data['defender_status']
    if ($def) {
        if ($def.RealTimeProtectionEnabled -eq $false) {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender real-time protection is disabled' `
                -Observation 'Get-MpComputerStatus reports RealTimeProtectionEnabled = False.' `
                -WhyItMatters 'Real-time protection off is both a common attacker action after gaining privilege and a common administrator misconfiguration. Correlate with Defender event IDs 5001/5007 to establish when and by what it was changed.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_status' 'json') `
                -NextStep 'Check defender_operational.csv for configuration-change events around the disable time, and confirm whether a third-party AV legitimately took over.'
        }
        if ($def.AntivirusEnabled -eq $false -or $def.AMServiceEnabled -eq $false) {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender antimalware service is not running' `
                -Observation ("AMServiceEnabled = {0}, AntivirusEnabled = {1}." -f $def.AMServiceEnabled, $def.AntivirusEnabled) `
                -WhyItMatters 'A stopped antimalware service leaves the endpoint without on-access detection. This may be legitimate if a third-party product is installed; confirm against installed_av_products.csv.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_status' 'json')
        }
        if ($def.IsTamperProtected -eq $false) {
            Add-FotonFinding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'Defender tamper protection is off' `
                -Observation 'IsTamperProtected = False.' `
                -WhyItMatters 'Without tamper protection, Defender settings can be modified by any process running with local administrator rights.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_status' 'json')
        }
        if ($null -ne $def.AntivirusSignatureAgeDays -and $def.AntivirusSignatureAgeDays -gt 7) {
            Add-FotonFinding -Severity 'Medium' -Category 'Security' -Tier 1 -Title 'Antivirus signatures are stale' `
                -Observation ("Signature age is {0} days (version {1})." -f $def.AntivirusSignatureAgeDays, $def.AntivirusSignatureVersion) `
                -WhyItMatters 'Stale signatures reduce detection coverage and can indicate the host has been offline, or that update channels are blocked.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_status' 'json')
        }
    }

    $pref = $script:FotonSession.Data['defender_preferences_and_exclusions']
    if ($pref) {
        $exPaths = @($pref.ExclusionPath) | Where-Object { $_ }
        $exProcs = @($pref.ExclusionProcess) | Where-Object { $_ }
        if ($exPaths.Count -gt 0 -or $exProcs.Count -gt 0) {
            $risky = @()
            foreach ($p in $exPaths) {
                if ((Test-FotonUserWritablePath -Path $p) -or $p -match '^[A-Za-z]:\\?$' -or $p -match '^[A-Za-z]:\\Users\\?$' -or $p -match '^[A-Za-z]:\\Windows\\?$') { $risky += $p }
            }
            $sev = 'Medium'
            if ($risky.Count -gt 0) { $sev = 'High' }
            Add-FotonFinding -Severity $sev -Category 'Security' -Tier 2 -Title 'Defender exclusions are configured' `
                -Observation ("{0} path exclusion(s) and {1} process exclusion(s) are set. Paths: {2}. Processes: {3}." -f `
                    $exPaths.Count, $exProcs.Count, (ConvertTo-FotonSample $exPaths), (ConvertTo-FotonSample $exProcs)) `
                -WhyItMatters 'Exclusions are frequently added by attackers to create a safe staging directory, and are also routinely added by administrators for line-of-business software. Broad exclusions (drive roots, user-writable directories) are the ones worth scrutiny.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_preferences_and_exclusions' 'json') `
                -NextStep 'Determine who added each exclusion and when. Inspect the contents of every excluded path directly, since on-access scanning did not cover it.'
        }
        if ($pref.DisableScriptScanning -eq $true -or $pref.DisableBehaviorMonitoring -eq $true -or $pref.DisableIOAVProtection -eq $true) {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Defender protection components are disabled by preference' `
                -Observation ("DisableScriptScanning={0}, DisableBehaviorMonitoring={1}, DisableIOAVProtection={2}." -f `
                    $pref.DisableScriptScanning, $pref.DisableBehaviorMonitoring, $pref.DisableIOAVProtection) `
                -WhyItMatters 'Selective component disabling is a targeted weakening of endpoint defenses rather than a broad on/off toggle.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'defender_preferences_and_exclusions' 'json')
        }
    }

    $detections = $script:FotonSession.Data['defender_detections']
    if ($detections -and @($detections).Count -gt 0) {
        Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Antivirus detection history is present' `
            -Observation ("{0} detection record(s) recorded. Sample: {1}." -f @($detections).Count, (ConvertTo-FotonSample (@($detections) | ForEach-Object { $_.Resources }) 3)) `
            -WhyItMatters 'Prior detections show what reached the endpoint. A detection that was only partially remediated, or that recurred, is a strong lead.' `
            -Artifact (Get-FotonArtifactPath 'Security' 'defender_detections' 'csv') `
            -NextStep 'For each detection, confirm the remediation action succeeded and check whether the same resource path appears in the filesystem or persistence artifacts.'
    }

    # ---------- Hardening settings ----------
    $hard = $script:FotonSession.Data['hardening_registry_settings']
    if ($hard) {
        $map = @{}
        foreach ($h in $hard) { $map[$h.Setting] = $h.Value }

        if ($map['UseLogonCredential'] -eq '1') {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'WDigest cleartext credential storage is enabled' `
                -Observation 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 1.' `
                -WhyItMatters 'This forces plaintext credentials into LSASS memory. It is not a default setting and is a well-documented pre-credential-theft modification.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv') `
                -NextStep 'Establish when this value was set and by which account. Treat credentials used on this host as potentially exposed.'
        }
        if ($map['EnableLUA'] -eq '0') {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'User Account Control is disabled' `
                -Observation 'EnableLUA = 0.' `
                -WhyItMatters 'With UAC off, any process launched by an administrator account runs fully elevated without prompting.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['AlwaysInstallElevated'] -eq '1') {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'AlwaysInstallElevated is enabled' `
                -Observation 'HKLM Installer policy AlwaysInstallElevated = 1.' `
                -WhyItMatters 'Any user can install an MSI package with SYSTEM privileges. This is a direct local privilege escalation path.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['AutoAdminLogon'] -eq '1') {
            Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 2 -Title 'Automatic logon is configured' `
                -Observation ("AutoAdminLogon = 1 for account '{0}'." -f $map['DefaultUserName']) `
                -WhyItMatters 'Autologon commonly accompanies a DefaultPassword value stored in cleartext in the registry, and it grants console access without authentication.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv') `
                -NextStep 'Check for a DefaultPassword value in the Winlogon key and rotate that credential.'
        }
        if ($map['LocalAccountTokenFilterPolicy'] -eq '1') {
            Add-FotonFinding -Severity 'Medium' -Category 'Security' -Tier 2 -Title 'LocalAccountTokenFilterPolicy is enabled' `
                -Observation 'LocalAccountTokenFilterPolicy = 1.' `
                -WhyItMatters 'Local administrator accounts can authenticate remotely with full token privileges, which enables pass-the-hash style lateral movement using local accounts.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['SMB1'] -eq '1') {
            Add-FotonFinding -Severity 'Medium' -Category 'Security' -Tier 1 -Title 'SMBv1 server is enabled' `
                -Observation 'LanmanServer SMB1 = 1.' `
                -WhyItMatters 'SMBv1 is deprecated and carries known remote code execution exposure. It also lacks modern signing and encryption.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
        if ($map['EnableScriptBlockLogging'] -ne '1') {
            Add-FotonFinding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'PowerShell script block logging is not enabled' `
                -Observation 'EnableScriptBlockLogging is not set to 1.' `
                -WhyItMatters 'This is a visibility gap rather than a compromise indicator: PowerShell activity prior to collection may not be recoverable from logs. Absence of PowerShell events in this package cannot be read as absence of PowerShell activity.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'powershell_environment' 'json')
        }
        if ($map['RunAsPPL'] -ne '1') {
            Add-FotonFinding -Severity 'Low' -Category 'Security' -Tier 1 -Title 'LSASS is not running as a protected process' `
                -Observation 'RunAsPPL is not set to 1.' `
                -WhyItMatters 'Without PPL, LSASS memory can be read by any process with debug privilege, which is the standard credential-dumping path.' `
                -Artifact (Get-FotonArtifactPath 'Security' 'hardening_registry_settings' 'csv')
        }
    }

    # ---------- Firewall / RDP ----------
    $fw = $script:FotonSession.Data['firewall_profiles']
    if ($fw) {
        $off = @($fw | Where-Object { $_.Enabled -eq $false -or $_.Enabled -eq 'False' })
        if ($off.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Network' -Tier 1 -Title 'One or more firewall profiles are disabled' `
                -Observation ("Disabled profile(s): {0}." -f (ConvertTo-FotonSample ($off | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'A disabled profile removes inbound filtering on networks using that profile and is a common post-compromise change to enable remote access.' `
                -Artifact (Get-FotonArtifactPath 'Network' 'firewall_profiles' 'csv')
        }
    }
    $rdp = $script:FotonSession.Data['rdp_configuration']
    if ($rdp -and $rdp.RdpEnabled -eq $true) {
        $sev = 'Low'
        $note = 'RDP is enabled.'
        if ($rdp.UserAuthentication -eq 0) {
            $sev = 'Medium'
            $note = 'RDP is enabled and Network Level Authentication is disabled.'
        }
        Add-FotonFinding -Severity $sev -Category 'Users' -Tier 1 -Title 'Remote Desktop is enabled' `
            -Observation ("{0} Listening port: {1}. Members of Remote Desktop Users: {2}." -f $note, $rdp.PortNumber, $rdp.RemoteDesktopUsers) `
            -WhyItMatters 'RDP is one of the most common initial access and lateral movement vectors. Whether this is expected depends on the endpoint role; confirm with the system owner.' `
            -Artifact (Get-FotonArtifactPath 'Users' 'rdp_configuration' 'json') `
            -NextStep 'Review terminal_services_remote.csv (event 1149) for the source IPs of successful RDP authentications.'
    }

    # ---------- Accounts ----------
    $users = $script:FotonSession.Data['local_users']
    if ($users) {
        $guest = @($users | Where-Object { $_.Name -eq 'Guest' -and ($_.Enabled -eq $true -or $_.Enabled -eq 'True') })
        if ($guest.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Users' -Tier 1 -Title 'Guest account is enabled' `
                -Observation 'The built-in Guest account is enabled.' `
                -WhyItMatters 'The Guest account is disabled by default. Enabling it creates an unauthenticated access path and is occasionally used to maintain low-visibility access.' `
                -Artifact (Get-FotonArtifactPath 'Users' 'local_users' 'csv')
        }
        $noPw = @($users | Where-Object { $_.PasswordRequired -eq $false -and ($_.Enabled -eq $true -or $_.Enabled -eq 'True') })
        if ($noPw.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Users' -Tier 1 -Title 'Enabled accounts do not require a password' `
                -Observation ("Account(s): {0}." -f (ConvertTo-FotonSample ($noPw | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'Accounts without a password requirement can be used for local logon and, depending on policy, remote authentication.' `
                -Artifact (Get-FotonArtifactPath 'Users' 'local_users' 'csv')
        }
    }

    $groups = $script:FotonSession.Data['local_group_membership']
    if ($groups) {
        $admins = @($groups | Where-Object { $_.Group -eq 'Administrators' -and $_.Member -ne '(none)' })
        if ($admins.Count -gt 0) {
            $sev = 'Info'
            if ($admins.Count -gt 5) { $sev = 'Low' }
            Add-FotonFinding -Severity $sev -Category 'Users' -Tier 1 -Title 'Local Administrators group membership' `
                -Observation ("{0} member(s): {1}." -f $admins.Count, (ConvertTo-FotonSample ($admins | ForEach-Object { $_.Member }) 8)) `
                -WhyItMatters 'Membership should be compared against the organization''s expected baseline. Unexpected members, especially local (non-domain) accounts, warrant follow-up.' `
                -Artifact (Get-FotonArtifactPath 'Users' 'local_group_membership' 'csv') `
                -NextStep 'Cross-reference with security_account_management.csv (event 4732) to see whether any member was added inside the collection window.'
        }
    }

    # ---------- Processes ----------
    $procs = $script:FotonSession.Data['running_processes']
    if ($procs) {
        $unsignedUserPath = @($procs | Where-Object {
                $_.UserWritablePath -eq $true -and $_.SignatureStatus -ne 'Valid' -and $_.Path
            })
        if ($unsignedUserPath.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Unsigned processes running from user-writable paths' `
                -Observation ("{0} process(es): {1}." -f $unsignedUserPath.Count, (ConvertTo-FotonSample ($unsignedUserPath | ForEach-Object { "$($_.Name) [PID $($_.PID)] $($_.Path)" }))) `
                -WhyItMatters 'Legitimate software is normally installed under Program Files and signed. Unsigned executables running from AppData, Temp, or ProgramData match common malware staging behavior, but also match some legitimate updaters and developer tooling.' `
                -Artifact (Get-FotonArtifactPath 'Processes' 'running_processes' 'csv') `
                -NextStep 'Submit the SHA-256 values in the artifact to threat intelligence, and check parent process and creation time for each.'
        }
        $suspCmd = @($procs | ForEach-Object {
                $hits = Resolve-FotonSuspiciousHits -Row $_ -StoredProperty 'SuspiciousCmdHits' -TextProperty 'CommandLine'
                if ($hits) { [PSCustomObject]@{ Name = $_.Name; Hits = $hits } }
            })
        if ($suspCmd.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Running process command lines contain high-risk patterns' `
                -Observation ("{0} process(es) matched: {1}." -f $suspCmd.Count, (ConvertTo-FotonSample ($suspCmd | ForEach-Object { "$($_.Name) [$($_.Hits)]" }))) `
                -WhyItMatters 'Patterns such as encoded commands, in-memory download-and-execute, and shadow copy deletion are heavily used in intrusions. They also appear in legitimate management tooling, so each match needs to be read in context.' `
                -Artifact (Get-FotonArtifactPath 'Processes' 'running_processes' 'csv') `
                -NextStep 'Decode any base64 command lines and review the full CommandLine column in the artifact before drawing conclusions.'
        }
        $officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'onenote.exe', 'visio.exe')
        $childShells = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe')
        $odd = @($procs | Where-Object {
                $_.ParentName -and $_.Name -and
                ($officeParents -contains $_.ParentName.ToLower()) -and
                ($childShells -contains $_.Name.ToLower())
            })
        if ($odd.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'Office application spawned a scripting or shell process' `
                -Observation ("Observed: {0}." -f (ConvertTo-FotonSample ($odd | ForEach-Object { "$($_.ParentName) -> $($_.Name) [PID $($_.PID)]" }))) `
                -WhyItMatters 'Office applications spawning shells or script hosts is a classic macro or exploit execution chain. Some add-ins do this legitimately, so confirm the command line and the originating document.' `
                -Artifact (Get-FotonArtifactPath 'Processes' 'process_tree' 'txt')
        }
    }

    $psHist = $script:FotonSession.Data['powershell_console_history']
    if ($psHist) {
        $flagged = @($psHist | Where-Object {
                Resolve-FotonSuspiciousHits -Row $_ -StoredProperty 'SuspiciousHits' -TextProperty 'Command'
            })
        if ($flagged.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Processes' -Tier 2 -Title 'PowerShell console history contains high-risk commands' `
                -Observation ("{0} matching line(s) across profiles. Sample: {1}." -f $flagged.Count, (ConvertTo-FotonSample ($flagged | ForEach-Object { "$($_.User): $($_.Command)" }) 4)) `
                -WhyItMatters 'PSReadLine history persists across reboots and is not covered by event log retention, so it often preserves activity that logging missed. Note that history files are user-editable and carry no timestamps.' `
                -Artifact (Get-FotonArtifactPath 'Processes' 'powershell_console_history' 'csv') `
                -NextStep 'Correlate each command with PowerShell operational events (4104) and process creation events (4688) to establish execution and timing.'
        }
    }

    # ---------- Persistence ----------
    $autoruns = $script:FotonSession.Data['autorun_registry_keys']
    if ($autoruns) {
        $badRuns = @($autoruns | Where-Object {
                $_.UserWritableTarget -eq $true -or
                (Resolve-FotonSuspiciousHits -Row $_ -StoredProperty 'SuspiciousHits' -TextProperty 'Command')
            })
        if ($badRuns.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Autostart entries point to user-writable locations or contain risky patterns' `
                -Observation ("{0} of {1} autostart entries flagged. Sample: {2}." -f $badRuns.Count, @($autoruns).Count, (ConvertTo-FotonSample ($badRuns | ForEach-Object { "$($_.ValueName) = $($_.Command)" }) 4)) `
                -WhyItMatters 'Run keys are the most common persistence mechanism. Entries executing from AppData or Temp, or invoking script interpreters, deserve individual verification.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'autorun_registry_keys' 'csv') `
                -NextStep 'For each flagged entry, hash the target binary, check its signature, and determine the registry key write time from a registry hive if available.'
        }
    }

    $tasks = $script:FotonSession.Data['scheduled_tasks']
    if ($tasks) {
        $badTasks = @($tasks | Where-Object {
                $_.UserWritableTarget -eq $true -or
                (Resolve-FotonSuspiciousHits -Row $_ -StoredProperty 'SuspiciousHits' -TextProperty 'Actions')
            })
        if ($badTasks.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Scheduled tasks reference user-writable paths or risky commands' `
                -Observation ("{0} task(s) flagged. Sample: {1}." -f $badTasks.Count, (ConvertTo-FotonSample ($badTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName): $($_.Actions)" }) 4)) `
                -WhyItMatters 'Scheduled tasks provide reliable, privileged persistence and are frequently created with innocuous names in the root task folder.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'scheduled_tasks' 'csv') `
                -NextStep 'Compare against scheduled_task_files.csv creation timestamps to identify tasks created inside the incident window.'
        }
        $sysTasks = @($tasks | Where-Object { $_.RunAsUser -match 'SYSTEM' -and $_.TaskPath -eq '\' })
        if ($sysTasks.Count -gt 0) {
            Add-FotonFinding -Severity 'Low' -Category 'Persistence' -Tier 1 -Title 'SYSTEM-level tasks exist in the root task folder' `
                -Observation ("{0} task(s): {1}." -f $sysTasks.Count, (ConvertTo-FotonSample ($sysTasks | ForEach-Object { $_.TaskName }))) `
                -WhyItMatters 'Microsoft tasks are normally nested under \Microsoft\Windows\. Root-folder SYSTEM tasks are more often third-party software, but this is also where attacker-created tasks tend to land.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'scheduled_tasks' 'csv')
        }
    }

    $svcs = $script:FotonSession.Data['services']
    if ($svcs) {
        $svcUserPath = @($svcs | Where-Object { $_.UserWritablePath -eq $true -and $_.ResolvedExe })
        if ($svcUserPath.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Services execute binaries from user-writable paths' `
                -Observation ("{0} service(s): {1}." -f $svcUserPath.Count, (ConvertTo-FotonSample ($svcUserPath | ForEach-Object { "$($_.Name) -> $($_.PathName)" }) 4)) `
                -WhyItMatters 'A service binary in a user-writable directory can be replaced by a non-administrative user, and is also a common location for attacker-installed services.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'services' 'csv')
        }
        $svcUnquoted = @($svcs | Where-Object { $_.UnquotedPath -eq $true })
        if ($svcUnquoted.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Persistence' -Tier 1 -Title 'Services configured with unquoted paths containing spaces' `
                -Observation ("{0} service(s): {1}." -f $svcUnquoted.Count, (ConvertTo-FotonSample ($svcUnquoted | ForEach-Object { $_.Name }))) `
                -WhyItMatters 'Unquoted service paths are a privilege escalation vector if any parent directory is writable by a non-administrative user. This is a misconfiguration, not evidence of compromise.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'services' 'csv')
        }
        $svcUnsigned = @($svcs | Where-Object { $_.ResolvedExe -and $_.SignatureStatus -notin @('Valid', 'FileNotFound', 'NotHashed') -and $_.State -eq 'Running' })
        if ($svcUnsigned.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Running services with unsigned or invalid-signature binaries' `
                -Observation ("{0} service(s): {1}." -f $svcUnsigned.Count, (ConvertTo-FotonSample ($svcUnsigned | ForEach-Object { "$($_.Name) [$($_.SignatureStatus)]" }))) `
                -WhyItMatters 'Unsigned service binaries are common in older or in-house software, so this is a prioritization signal rather than a detection.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'services' 'csv')
        }
    }

    $winlogon = $script:FotonSession.Data['winlogon_lsa_and_dll_hijacks']
    if ($winlogon) {
        $ifeo = @($winlogon | Where-Object { $_.Mechanism -eq 'IFEO' -and $_.Name -eq 'Debugger' })
        if ($ifeo.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Image File Execution Options debugger entries present' `
                -Observation ("{0} entry/entries: {1}." -f $ifeo.Count, (ConvertTo-FotonSample ($ifeo | ForEach-Object { "$($_.Location) -> $($_.Value)" }) 4)) `
                -WhyItMatters 'An IFEO Debugger value causes the named program to be replaced at launch by the specified binary. Legitimate uses exist (debuggers, some AV), but this is the mechanism behind sticky-keys style backdoors.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
        $appInit = @($winlogon | Where-Object { $_.Name -eq 'AppInit_DLLs' -and $_.Value })
        if ($appInit.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'AppInit_DLLs is populated' `
                -Observation ("Value(s): {0}." -f (ConvertTo-FotonSample ($appInit | ForEach-Object { $_.Value }))) `
                -WhyItMatters 'DLLs listed here load into most user-mode processes that link user32.dll, giving broad code injection with a single registry write.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
        $shell = @($winlogon | Where-Object { $_.Mechanism -eq 'Winlogon' -and $_.Name -eq 'Shell' -and $_.Value -ne 'explorer.exe' })
        $userinit = @($winlogon | Where-Object { $_.Mechanism -eq 'Winlogon' -and $_.Name -eq 'Userinit' -and $_.Value -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$' })
        if ($shell.Count -gt 0 -or $userinit.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Winlogon Shell or Userinit value is non-default' `
                -Observation ("Shell: {0}. Userinit: {1}." -f (ConvertTo-FotonSample ($shell | ForEach-Object { $_.Value })), (ConvertTo-FotonSample ($userinit | ForEach-Object { $_.Value }))) `
                -WhyItMatters 'These values control what launches at interactive logon. Appended commands here execute for every logon with the user''s privileges.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'winlogon_lsa_and_dll_hijacks' 'csv')
        }
    }

    $access = $script:FotonSession.Data['accessibility_binary_integrity']
    if ($access) {
        $tampered = @($access | Where-Object { $_.IFEODebugger -or ($_.SignatureStatus -ne 'Valid' -and $_.SignatureStatus -ne 'NotHashed') })
        if ($tampered.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 2 -Title 'Accessibility binaries show signs of replacement or hijack' `
                -Observation ("Affected: {0}." -f (ConvertTo-FotonSample ($tampered | ForEach-Object { "$($_.Binary) sig=$($_.SignatureStatus) debugger=$($_.IFEODebugger)" }))) `
                -WhyItMatters 'Replacing sethc.exe or utilman.exe, or attaching a debugger to them, yields a SYSTEM shell from the pre-authentication logon screen.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'accessibility_binary_integrity' 'csv') `
                -NextStep 'Compare file hash and modification time against a known-good build of the same Windows version.'
        }
    }

    $com = $script:FotonSession.Data['com_hijack_candidates']
    if ($com) {
        $comBad = @($com | Where-Object { $_.UserWritableTarget -eq $true })
        if ($comBad.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Per-user COM registrations target user-writable files' `
                -Observation ("{0} CLSID override(s): {1}." -f $comBad.Count, (ConvertTo-FotonSample ($comBad | ForEach-Object { "$($_.User) $($_.CLSID) -> $($_.Target)" }) 4)) `
                -WhyItMatters 'HKCU COM registrations take precedence over HKLM, so a per-user CLSID override pointing at a user-writable DLL can hijack legitimate component loads.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'com_hijack_candidates' 'csv')
        }
    }

    $startupItems = $script:FotonSession.Data['startup_folder_items']
    if ($startupItems) {
        $unsignedStartup = @($startupItems | Where-Object { $_.SignatureStatus -notin @('Valid', 'NotHashed') })
        if ($unsignedStartup.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'Startup folder contains unsigned items' `
                -Observation ("{0} item(s): {1}." -f $unsignedStartup.Count, (ConvertTo-FotonSample ($unsignedStartup | ForEach-Object { $_.FullName }) 4)) `
                -WhyItMatters 'Startup folder placement requires no registry access and survives reboot. Shortcut (.lnk) items should be examined for their target and arguments.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'startup_folder_items' 'csv')
        }
    }

    # ---------- Network ----------
    $conns = $script:FotonSession.Data['active_connections']
    if ($conns) {
        $extSuspect = @($conns | Where-Object { $_.RemoteIsExternal -eq $true -and $_.UserWritablePath -eq $true })
        if ($extSuspect.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'Network' -Tier 2 -Title 'External connections from binaries in user-writable paths' `
                -Observation ("{0} connection(s): {1}." -f $extSuspect.Count, (ConvertTo-FotonSample ($extSuspect | ForEach-Object { "$($_.ProcessName) -> $($_.RemoteAddress):$($_.RemotePort)" }) 5)) `
                -WhyItMatters 'This pairing - a binary outside standard install locations holding an outbound session - is a common command-and-control pattern, and also a common pattern for legitimate portable applications.' `
                -Artifact (Get-FotonArtifactPath 'Network' 'active_connections' 'csv') `
                -NextStep 'Resolve and enrich the remote addresses, and confirm the process hash against threat intelligence before treating this as C2.'
        }
        $extAll = @($conns | Where-Object { $_.RemoteIsExternal -eq $true -and $_.State -eq 'Established' })
        if ($extAll.Count -gt 0) {
            Add-FotonFinding -Severity 'Info' -Category 'Network' -Tier 1 -Title 'Established external connections at collection time' `
                -Observation ("{0} established external session(s). Sample: {1}." -f $extAll.Count, (ConvertTo-FotonSample ($extAll | ForEach-Object { "$($_.ProcessName) -> $($_.RemoteAddress):$($_.RemotePort)" }) 6)) `
                -WhyItMatters 'This is a point-in-time snapshot. Sessions that opened and closed before collection are not represented here.' `
                -Artifact (Get-FotonArtifactPath 'Network' 'active_connections' 'csv')
        }
    }

    $hosts = $script:FotonSession.Data['hosts_file']
    if ($hosts) {
        $entries = @($hosts | Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') })
        if ($entries.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Network' -Tier 1 -Title 'hosts file contains active entries' `
                -Observation ("{0} non-comment line(s): {1}." -f $entries.Count, (ConvertTo-FotonSample $entries 5)) `
                -WhyItMatters 'hosts entries override DNS. They are used both to block security vendor domains and to redirect traffic, and are also common in development environments.' `
                -Artifact (Get-FotonArtifactPath 'Network' 'hosts_file' 'txt')
        }
    }

    # ---------- Event log derived ----------
    $polChanges = $script:FotonSession.Data['security_policy_and_log_changes']
    if ($polChanges) {
        $cleared = @($polChanges | Where-Object { $_.EventId -eq 1102 })
        if ($cleared.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Security event log was cleared' `
                -Observation ("Event ID 1102 recorded {0} time(s). Most recent: {1} UTC." -f $cleared.Count, (@($cleared)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Clearing the Security log destroys authentication and audit history. It is occasionally done during maintenance, but it is also a standard anti-forensic step.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'security_policy_and_log_changes' 'csv') `
                -NextStep 'Identify the account in the 1102 record and determine whether the clearing was authorized. Any event history before that timestamp is unavailable from this host.'
        }
    }
    $sysLog = $script:FotonSession.Data['system_log_and_boot']
    if ($sysLog) {
        $logCleared = @($sysLog | Where-Object { $_.EventId -eq 104 })
        if ($logCleared.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'An event log was cleared (System log, event 104)' `
                -Observation ("Event ID 104 recorded {0} time(s). Most recent: {1} UTC." -f $logCleared.Count, (@($logCleared)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 104 records which log was cleared and by whom. Coverage gaps created by clearing must be stated explicitly in any timeline built from this data.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'system_log_and_boot' 'csv')
        }
    }
    $svcEvents = $script:FotonSession.Data['system_service_and_driver']
    if ($svcEvents) {
        $installs = @($svcEvents | Where-Object { $_.EventId -eq 7045 })
        if ($installs.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Services were installed during the collection window' `
                -Observation ("{0} service install event(s) (ID 7045). Most recent: {1} UTC." -f $installs.Count, (@($installs)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Remote execution tooling (PsExec and similar) and many malware families install a service. Compare each install against expected software deployment activity.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'system_service_and_driver' 'csv')
        }
    }
    $acctEvents = $script:FotonSession.Data['security_account_management']
    if ($acctEvents) {
        $created = @($acctEvents | Where-Object { $_.EventId -eq 4720 })
        $adminAdd = @($acctEvents | Where-Object { $_.EventId -in @(4732, 4728, 4756) })
        if ($created.Count -gt 0 -or $adminAdd.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Account creation or privileged group changes occurred in the window' `
                -Observation ("{0} account creation event(s) (4720) and {1} group addition event(s) (4728/4732/4756)." -f $created.Count, $adminAdd.Count) `
                -WhyItMatters 'New accounts and group additions are both routine IT activity and a standard persistence/privilege step. The distinguishing factor is whether they map to an approved change.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'security_account_management' 'csv') `
                -NextStep 'Match each event to a change ticket or known onboarding. Note the account that performed the change, not just the account affected.'
        }
    }
    $logons = $script:FotonSession.Data['security_logon_events']
    if ($logons) {
        $failed = @($logons | Where-Object { $_.EventId -eq 4625 })
        if ($failed.Count -gt 25) {
            Add-FotonFinding -Severity 'Medium' -Category 'EventLogs' -Tier 2 -Title 'Elevated volume of failed logon attempts' `
                -Observation ("{0} failed logon event(s) (4625) in the last {1} days." -f $failed.Count, $script:FotonSession.EventLogDays) `
                -WhyItMatters 'High 4625 volume is consistent with password spraying or brute force, and equally consistent with a stale service account or a mapped drive using an expired credential.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'security_logon_events' 'csv') `
                -NextStep 'Group the failures by target account, source workstation, and logon type before characterizing the activity.'
        }
        $explicit = @($logons | Where-Object { $_.EventId -eq 4648 })
        if ($explicit.Count -gt 0) {
            Add-FotonFinding -Severity 'Low' -Category 'EventLogs' -Tier 1 -Title 'Explicit credential use recorded' `
                -Observation ("{0} event(s) with ID 4648 (logon using explicitly supplied credentials)." -f $explicit.Count) `
                -WhyItMatters '4648 records runas-style credential use and often marks the pivot point in lateral movement, though it is also generated by ordinary administrative tooling.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'security_logon_events' 'csv')
        }
    }
    $psEvents = $script:FotonSession.Data['powershell_operational']
    if ($psEvents) {
        $flagged = @($psEvents | Where-Object { Test-FotonSuspiciousCommand -Text $_.Message })
        if ($flagged.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'EventLogs' -Tier 2 -Title 'PowerShell script block logs contain high-risk content' `
                -Observation ("{0} event(s) matched risk patterns. Most recent: {1} UTC." -f $flagged.Count, (@($flagged)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Script block logging captures deobfuscated script content at execution time, which makes it some of the highest-value evidence available on a Windows endpoint.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'powershell_operational' 'csv') `
                -NextStep 'Read the full Message column for each matched event and reconstruct the script from multi-part 4104 records.'
        }
    }
    $defEvents = $script:FotonSession.Data['defender_operational']
    if ($defEvents) {
        $cfg = @($defEvents | Where-Object { $_.EventId -in @(5001, 5007, 5010, 5012) })
        if ($cfg.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Defender configuration or protection state was changed' `
                -Observation ("{0} configuration-change event(s) (5001/5007/5010/5012). Most recent: {1} UTC." -f $cfg.Count, (@($cfg)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 5007 records the old and new value of a Defender setting, which is how exclusion additions and protection disables are attributed and timed.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'defender_operational' 'csv')
        }
        $detEvents = @($defEvents | Where-Object { $_.EventId -in @(1116, 1117) })
        if ($detEvents.Count -gt 0) {
            Add-FotonFinding -Severity 'High' -Category 'EventLogs' -Tier 1 -Title 'Defender logged malware detections in the window' `
                -Observation ("{0} detection event(s) (1116/1117). Most recent: {1} UTC." -f $detEvents.Count, (@($detEvents)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Detection events name the threat, the file path, and the process that introduced it, which anchors the earliest known point of the intrusion.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'defender_operational' 'csv')
        }
    }
    $rdpEvents = $script:FotonSession.Data['terminal_services_remote']
    if ($rdpEvents) {
        $auth = @($rdpEvents | Where-Object { $_.EventId -eq 1149 })
        if ($auth.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'EventLogs' -Tier 1 -Title 'Successful RDP authentications recorded' `
                -Observation ("{0} event(s) with ID 1149 in the last {1} days. Most recent: {2} UTC." -f $auth.Count, $script:FotonSession.EventLogDays, (@($auth)[0].TimeCreatedUtc)) `
                -WhyItMatters 'Event 1149 carries the source IP address of the connecting client, which is the fastest way to separate expected administrative access from unexpected remote access.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'terminal_services_remote' 'csv')
        }
    }
    $wmiEvents = $script:FotonSession.Data['wmi_activity']
    if ($wmiEvents) {
        $perm = @($wmiEvents | Where-Object { $_.EventId -in @(5860, 5861) })
        if ($perm.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'EventLogs' -Tier 2 -Title 'WMI permanent subscription activity recorded' `
                -Observation ("{0} event(s) with ID 5860/5861." -f $perm.Count) `
                -WhyItMatters 'Event 5861 records permanent event consumer registration, the core artifact of fileless WMI persistence. Legitimate management software also registers consumers.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'wmi_activity' 'csv') `
                -NextStep 'Compare against wmi_event_subscriptions.txt to see which subscriptions currently exist on the host.'
        }
    }

    # ---------- Software / drivers ----------
    $rat = $script:FotonSession.Data['remote_access_tool_indicators']
    if ($rat -and @($rat).Count -gt 0) {
        Add-FotonFinding -Severity 'Medium' -Category 'Software' -Tier 2 -Title 'Remote access or data transfer tooling present' `
            -Observation ("{0} indicator(s): {1}." -f @($rat).Count, (ConvertTo-FotonSample (@($rat) | ForEach-Object { "$($_.Source): $($_.Detail)" }) 6)) `
            -WhyItMatters 'Tools such as remote support agents, tunneling utilities, and bulk transfer clients are used legitimately by IT and are also the tools of choice for hands-on-keyboard access and exfiltration. Presence alone is not an indicator of compromise.' `
            -Artifact (Get-FotonArtifactPath 'Software' 'remote_access_tool_indicators' 'csv') `
            -NextStep 'Confirm each item against the approved software inventory and check install dates against the incident timeline.'
    }
    $drivers = $script:FotonSession.Data['drivers']
    if ($drivers) {
        $unsignedDrv = @($drivers | Where-Object { $_.State -eq 'Running' -and $_.SignatureStatus -notin @('Valid', 'FileNotFound', 'NotHashed') })
        if ($unsignedDrv.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Software' -Tier 2 -Title 'Running drivers without a valid signature' `
                -Observation ("{0} driver(s): {1}." -f $unsignedDrv.Count, (ConvertTo-FotonSample ($unsignedDrv | ForEach-Object { "$($_.Name) [$($_.SignatureStatus)]" }))) `
                -WhyItMatters 'Kernel drivers run with the highest privilege available. Unsigned or invalidly signed drivers are worth verifying, though signature checks on system drivers can fail for benign reasons including catalog-signed files.' `
                -Artifact (Get-FotonArtifactPath 'Software' 'drivers' 'csv')
        }
    }

    # ---------- Filesystem ----------
    $exes = $script:FotonSession.Data['executables_in_user_writable_paths']
    if ($exes) {
        $recentUnsigned = @($exes | Where-Object {
                $_.SignatureStatus -notin @('Valid', 'NotHashed') -and
                $_.Extension -match '\.(exe|dll|scr|com|pif|sys)$'
            })
        if ($recentUnsigned.Count -gt 0) {
            $sev = 'Medium'
            if ($recentUnsigned.Count -gt 25) { $sev = 'Low' }
            Add-FotonFinding -Severity $sev -Category 'Filesystem' -Tier 2 -Title 'Unsigned executables present in user-writable directories' `
                -Observation ("{0} file(s). Most recently modified: {1}." -f $recentUnsigned.Count, (ConvertTo-FotonSample ($recentUnsigned | ForEach-Object { "$($_.Path) ($($_.ModifiedUtc))" }) 5)) `
                -WhyItMatters 'Temp and AppData accumulate unsigned files from ordinary use (installers, updaters, browser downloads), so volume alone means little. The value here is having hashes and timestamps to filter against the incident window.' `
                -Artifact (Get-FotonArtifactPath 'Filesystem' 'executables_in_user_writable_paths' 'csv') `
                -NextStep 'Filter the artifact by ModifiedUtc within the suspected incident window and hash-check the survivors.'
        }
    }
    $ads = $script:FotonSession.Data['alternate_data_streams']
    if ($ads) {
        $oddAds = @($ads | Where-Object { $_.Stream -ne 'Zone.Identifier' })
        if ($oddAds.Count -gt 0) {
            Add-FotonFinding -Severity 'Medium' -Category 'Filesystem' -Tier 2 -Title 'Non-standard alternate data streams found' `
                -Observation ("{0} stream(s): {1}." -f $oddAds.Count, (ConvertTo-FotonSample ($oddAds | ForEach-Object { "$($_.File):$($_.Stream)" }) 4)) `
                -WhyItMatters 'ADS can hide executable content inside an otherwise innocuous file. Zone.Identifier streams are normal and are excluded from this count.' `
                -Artifact (Get-FotonArtifactPath 'Filesystem' 'alternate_data_streams' 'csv')
        }
    }
    $usb = $script:FotonSession.Data['usb_device_history']
    if ($usb) {
        $usbstor = @($usb | Where-Object { $_.Source -eq 'USBSTOR' })
        if ($usbstor.Count -gt 0) {
            Add-FotonFinding -Severity 'Info' -Category 'Filesystem' -Tier 1 -Title 'USB storage device history' `
                -Observation ("{0} USB storage device record(s). Sample: {1}." -f $usbstor.Count, (ConvertTo-FotonSample ($usbstor | ForEach-Object { $_.FriendlyName }) 5)) `
                -WhyItMatters 'USBSTOR records which removable devices have been attached. Registry presence establishes connection, not that files were copied.' `
                -Artifact (Get-FotonArtifactPath 'Filesystem' 'usb_device_history' 'csv')
        }
    }

    # ---------- WMI persistence ----------
    $wmiSubs = $script:FotonSession.Data['wmi_event_subscriptions']
    if ($wmiSubs) {
        $text = ($wmiSubs -join "`n")
        if ($text -match '__EventFilter' -and $text -notmatch '(?s)=== __EventFilter ===\s*\(none\)') {
            Add-FotonFinding -Severity 'Medium' -Category 'Persistence' -Tier 2 -Title 'WMI event subscriptions exist on this host' `
                -Observation 'One or more objects were returned from root\subscription (__EventFilter, __EventConsumer, or __FilterToConsumerBinding).' `
                -WhyItMatters 'WMI subscriptions provide fileless persistence that survives reboot and leaves no file on disk. Monitoring products (SCCM among them) also create subscriptions, so each one must be identified.' `
                -Artifact (Get-FotonArtifactPath 'Persistence' 'wmi_event_subscriptions' 'txt') `
                -NextStep 'Read the artifact and identify the consumer command for each binding. Anything invoking a script interpreter warrants immediate attention.'
        }
    }

    # ---------- Visibility gaps ----------
    $logCfg = $script:FotonSession.Data['event_log_configuration']
    if ($logCfg) {
        $sysmon = @($logCfg | Where-Object { $_.LogName -like '*Sysmon*' -and $_.IsEnabled -eq 'NotPresent' })
        if ($sysmon.Count -gt 0) {
            Add-FotonFinding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'Sysmon is not installed on this host' `
                -Observation 'The Microsoft-Windows-Sysmon/Operational log is not present.' `
                -WhyItMatters 'Without Sysmon, process creation with hashes, network connection attribution, and image load telemetry are largely unavailable. This limits what can be reconstructed and should be stated as a limitation in any report.' `
                -Artifact (Get-FotonArtifactPath 'EventLogs' 'event_log_configuration' 'csv')
        }
    }
    $procCreate = $script:FotonSession.Data['security_process_creation']
    if (-not $procCreate -or @($procCreate).Count -eq 0) {
        Add-FotonFinding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'No process creation events (4688) were collected' `
            -Observation 'The Security log returned no 4688 events for the collection window.' `
            -WhyItMatters 'Process creation auditing is off by default. The absence of these events is a logging gap, not evidence that no processes were created.' `
            -Artifact (Get-FotonArtifactPath 'Security' 'audit_policy' 'txt')
    }

    # ---------- Parsed records + baseline diff (offline files; Import-FotonPackageData skips analysis/) ----------
    $caseRoot = $script:FotonSession.CaseRoot
    if ($caseRoot -and (Test-Path -LiteralPath $caseRoot)) {
        $parsedPath = Join-Path $caseRoot 'analysis\parsed_records.csv'
        if (-not (Test-Path -LiteralPath $parsedPath)) {
            $parsedPath = Join-Path $caseRoot 'analysis\parsed_records.csv'
        }
        if (Test-Path -LiteralPath $parsedPath) {
            try {
                $parsed = @(Import-Csv -LiteralPath $parsedPath)
                $hits = @()
                foreach ($r in $parsed) {
                    $p = [string]$r.LocalBasePath
                    if (-not $p) { $p = [string]$r.Path }
                    if (-not $p) { $p = [string]$r.LowerCaseLongPath }
                    if (-not $p) { $p = [string]$r.Identity }
                    if (-not $p) { continue }
                    if (Test-FotonUserWritablePath -Path $p) {
                        $hits += $p
                    }
                }
                $hits = @($hits | Select-Object -Unique)
                if ($hits.Count -gt 0) {
                    $sample = ($hits | Select-Object -First 8) -join '; '
                    Add-FotonFinding -Severity 'Medium' -Category 'Execution' -Tier 2 -Title 'Parsed artifacts reference user-writable paths' `
                        -Observation ("analysis/parsed_records.csv contains {0} distinct path(s) under user-writable locations. Sample: {1}" -f $hits.Count, $sample) `
                        -WhyItMatters 'Prefetch/LNK/Amcache rows are observations about files that were referenced. A user-writable path is a review item (updater, user binary, or unexpected drop). This is not a verdict of compromise.' `
                        -Artifact 'analysis/parsed_records.csv' `
                        -NextStep 'Open the parsed row, hash the file if it is still in the package, and compare to software inventory / baseline diffs.'
                }
            }
            catch { }
        }

        $diffPath = Join-Path $caseRoot 'analysis\baseline_diff.csv'
        if (Test-Path -LiteralPath $diffPath) {
            try {
                $diffs = @(Import-Csv -LiteralPath $diffPath)
                $svc = @($diffs | Where-Object {
                        $_.RecordType -eq 'Service' -and (
                            ($_.ChangeType -eq 'Added') -or
                            ($_.ChangeType -eq 'Modified' -and $_.Field -eq 'PathName')
                        )
                    })
                if ($svc.Count -gt 0) {
                    $ids = (@($svc | ForEach-Object { $_.Identity } | Select-Object -First 8) -join '; ')
                    Add-FotonFinding -Severity 'High' -Category 'Persistence' -Tier 1 -Title 'Baseline diff: service ImagePath or new service' `
                        -Observation ("Compare-FotonBaseline records show {0} service Added or PathName Modified. Identities: {1}" -f $svc.Count, $ids) `
                        -WhyItMatters 'A new service or a changed ImagePath is a stable-config fact between two snapshots. Patching also replaces binaries. This does not establish who changed it or that the host is compromised.' `
                        -Artifact 'analysis/baseline_diff.csv' `
                        -NextStep 'Diff the PathName strings against the day0 baseline and the collected service CSV.'
                }
                $adm = @($diffs | Where-Object { $_.RecordType -eq 'LocalGroupMember' -and $_.ChangeType -eq 'Added' -and [string]$_.Identity -like 'Administrators|*' })
                if ($adm.Count -gt 0) {
                    Add-FotonFinding -Severity 'High' -Category 'Users' -Tier 1 -Title 'Baseline diff: Administrators membership added' `
                        -Observation ("{0} Added LocalGroupMember row(s) for Administrators in analysis/baseline_diff.csv." -f $adm.Count) `
                        -WhyItMatters 'Local admin membership is a high-attention trust change. Helpdesk, LAPS, and domain join also add members.' `
                        -Artifact 'analysis/baseline_diff.csv'
                }
                $def = @($diffs | Where-Object { $_.RecordType -eq 'DefenderPreference' -and [string]$_.Identity -like '*DisableRealtimeMonitoring*' })
                if ($def.Count -gt 0) {
                    Add-FotonFinding -Severity 'High' -Category 'Security' -Tier 1 -Title 'Baseline diff: Defender real-time monitoring setting changed' `
                        -Observation 'DefenderPreference DisableRealtimeMonitoring changed between baselines (see baseline_diff.csv).' `
                        -WhyItMatters 'The change is a fact. Tampering, troubleshooting, and GPO/Intune all flip this switch.' `
                        -Artifact 'analysis/baseline_diff.csv'
                }
            }
            catch { }
        }

        $hay = Join-Path $caseRoot 'analysis\external\hayabusa'
        if (Test-Path -LiteralPath $hay) {
            # A Hayabusa timeline is routinely hundreds of MB, so stream it and pull
            # only RuleTitle and Level (fields 2 and 3, ahead of the free-text
            # Details column). A single "it found hits" row is useless at this volume:
            # band the hits by the tool's own level so the operator sees which rules
            # fired, not just that something did.
            $counts = @{}
            $titles = @{}
            # Script block logging records the collector's own code, so Sigma rules
            # such as "Potentially Malicious PwSh" fire on Foton itself. Counted into
            # the bands, that footprint is reported as host activity - on a real
            # package it was the single largest medium-level "detection". Track those
            # rows separately instead of dropping them: an examiner may want the
            # collector's trace, but it is not evidence about the host.
            # Text matching alone is far too weak: on a real package only 12 of 312
            # "Potentially Malicious PwSh" rows named a Foton function, because most
            # collector script blocks are ordinary PowerShell. 274 of them fell inside
            # the collection window, so the window is the load-bearing signal and the
            # token match only catches stragglers outside it (earlier Foton runs).
            $selfCounts = @{}
            $selfTitles = @{}
            $selfTotal = 0
            $selfByWindow = 0
            $selfByName = 0
            $window = Get-FotonCollectionWindow -CaseRoot $caseRoot
            $read = 0
            $capped = $false
            $maxLines = 2000000
            foreach ($hf in @(Get-ChildItem -LiteralPath $hay -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
                $reader = $null
                try {
                    $reader = [IO.StreamReader]::new($hf.FullName)
                    $null = $reader.ReadLine()
                    while ($null -ne ($line = $reader.ReadLine())) {
                        $read++
                        if ($read -gt $maxLines) { $capped = $true; break }
                        $m = [regex]::Match($line, '^"(?<ts>[^"]*)","(?<t>[^"]*)","(?<l>[^"]*)"')
                        if (-not $m.Success) { continue }
                        $lvl = $m.Groups['l'].Value.ToLowerInvariant()
                        $ttl = $m.Groups['t'].Value

                        # Two independent attribution signals, neither of which is
                        # process identity - Hayabusa rows carry no collector PID.
                        $isSelf = $false
                        $byWindow = $false
                        if ($window) {
                            try {
                                $ts = [datetimeoffset]::Parse($m.Groups['ts'].Value,
                                    [Globalization.CultureInfo]::InvariantCulture)
                                if ($ts -ge $window.StartUtc -and $ts -le $window.EndUtc) {
                                    $isSelf = $true
                                    $byWindow = $true
                                }
                            }
                            catch { }
                        }
                        # The Details column carries the logged script block, so a row
                        # naming a Foton function is the collector even outside the
                        # window - typically an earlier run on the same host.
                        if (-not $isSelf -and $line.IndexOf('Foton', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $isSelf = $true
                        }

                        if ($isSelf) {
                            $selfTotal++
                            if ($byWindow) { $selfByWindow++ } else { $selfByName++ }
                            if (-not $selfCounts.ContainsKey($lvl)) {
                                $selfCounts[$lvl] = 0
                                $selfTitles[$lvl] = @{}
                            }
                            $selfCounts[$lvl] = $selfCounts[$lvl] + 1
                            if (-not $selfTitles[$lvl].ContainsKey($ttl)) { $selfTitles[$lvl][$ttl] = 0 }
                            $selfTitles[$lvl][$ttl] = $selfTitles[$lvl][$ttl] + 1
                            continue
                        }

                        if (-not $counts.ContainsKey($lvl)) {
                            $counts[$lvl] = 0
                            $titles[$lvl] = @{}
                        }
                        $counts[$lvl] = $counts[$lvl] + 1
                        if (-not $titles[$lvl].ContainsKey($ttl)) { $titles[$lvl][$ttl] = 0 }
                        $titles[$lvl][$ttl] = $titles[$lvl][$ttl] + 1
                    }
                }
                catch { }
                finally { if ($reader) { $reader.Dispose() } }
            }

            $describe = {
                param($Map, $Level)
                $t = $Map[$Level]
                if (-not $t) { return '' }
                $top = @($t.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 6)
                return (($top | ForEach-Object { "{0} ({1})" -f $_.Key, $_.Value }) -join '; ')
            }
            $capNote = ''
            if ($capped) { $capNote = (" Row scan capped at {0} lines; counts are a floor, not a total." -f $maxLines) }
            $selfNote = ''
            if ($selfTotal -gt 0) {
                $selfNote = (" Excludes {0} row(s) attributable to the Foton collector itself; see the collector-footprint finding." -f $selfTotal)
            }

            # Hayabusa abbreviates levels in CSV output unless -b is passed, so a
            # timeline says "med" and "crit". Accept both spellings or whole bands
            # silently vanish from the findings.
            $sevBand = @(
                @{ Levels = @('emergency', 'emer', 'critical', 'crit'); Severity = 'High'; Label = 'critical-level' }
                @{ Levels = @('high'); Severity = 'High'; Label = 'high-level' }
                @{ Levels = @('medium', 'med'); Severity = 'Medium'; Label = 'medium-level' }
            )
            foreach ($band in $sevBand) {
                $total = 0
                $samples = @()
                foreach ($l in $band.Levels) {
                    if ($counts.ContainsKey($l)) {
                        $total += $counts[$l]
                        $d = & $describe $titles $l
                        if ($d) { $samples += $d }
                    }
                }
                if ($total -le 0) { continue }
                Add-FotonFinding -Severity $band.Severity -Category 'EventLogs' -Tier 2 `
                    -Title ("Hayabusa reported {0} rule hits on copied EVTX" -f $band.Label) `
                    -Observation ("{0} {1} detection(s) in analysis/external/hayabusa. Top rules: {2}.{3}{4}" -f $total, $band.Label, ($samples -join '; '), $capNote, $selfNote) `
                    -WhyItMatters 'These are Hayabusa/Sigma rule hits, not a Foton engine and not a verdict. Sigma rules fire on legitimate administration, backup software, and management agents, and a Foton collection can itself trigger hive-access and script-execution rules. Judge each rule against what was expected on this host.' `
                    -Artifact 'analysis/external/hayabusa' `
                    -NextStep 'Filter the Hayabusa CSV to these RuleTitle values, note the RuleID and Timestamp, and corroborate against process, persistence, and account artifacts before drawing any conclusion.'
            }

            $lowVol = 0
            foreach ($l in @('low', 'info', 'informational')) {
                if ($counts.ContainsKey($l)) { $lowVol += $counts[$l] }
            }
            if ($lowVol -gt 0) {
                Add-FotonFinding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'Hayabusa low and informational event volume' `
                    -Observation ("{0} low/informational Hayabusa row(s) recorded. These are mostly normal telemetry (process execution, DNS queries, file creation) and are context for a timeline, not indicators.{1}{2}" -f $lowVol, $capNote, $selfNote) `
                    -WhyItMatters 'Volume here reflects how much Sysmon/audit telemetry the host was producing. It is useful for timeline coverage and for spotting where telemetry stops.' `
                    -Artifact 'analysis/external/hayabusa' `
                    -NextStep 'Use these rows to bound the observable window rather than as suspicion.'
            }

            # Methodology disclosure, not a host observation. Reported so the operator
            # can see what the collection itself put into the event log, and so the
            # band counts above can be trusted as being about the host.
            if ($selfTotal -gt 0) {
                $selfSamples = @()
                foreach ($l in @($selfCounts.Keys | Sort-Object)) {
                    $d = & $describe $selfTitles $l
                    if ($d) { $selfSamples += ("{0}: {1}" -f $l, $d) }
                }
                $winText = 'no collection window could be read from 00_Collection\collection.log'
                if ($window) {
                    $winText = ("collection window {0} to {1} UTC" -f
                        $window.StartUtc.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss'),
                        $window.EndUtc.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss'))
                }
                Add-FotonFinding -Severity 'Info' -Category 'Methodology' -Tier 2 -Title 'Hayabusa hits caused by the Foton collection itself' `
                    -Observation ("{0} Hayabusa row(s) are attributed to the collection and excluded from the severity bands above: {1} fell inside the {2}, and {3} named a Foton function outside it. By level - {4}." -f $selfTotal, $selfByWindow, $winText, $selfByName, ($selfSamples -join ' | ')) `
                    -WhyItMatters 'Script block logging records the collector''s own PowerShell, so Sigma rules for suspicious scripting and for registry or credential access fire on Foton. Left in the counts, that footprint is reported as host activity and can dominate a severity band. Attribution is inference, not process identity: rows are matched by time and by name, so genuine host activity that happened during the collection window is excluded here too, and an earlier Foton run on this host is included.' `
                    -Artifact 'analysis/external/hayabusa' `
                    -NextStep 'If a real event could have coincided with the collection, filter the Hayabusa CSV to that window and read the Details column directly rather than relying on this exclusion.'
            }
        }

        # PECmd / EvtxECmd compose CSV → observations that name the tool. Thin ingest
        # only: coverage + path/EventId signals Foton already knows how to talk about.
        # Do not reimplement Prefetch or EVTX parsers, and do not invent Sigma bands.
        $pecmdDir = Join-Path $caseRoot 'analysis\external\PECmd'
        if (Test-Path -LiteralPath $pecmdDir) {
            $peRows = 0
            $peNames = @{}
            $peWritable = @{}
            $peCapped = $false
            $peMax = 200000
            foreach ($pf in @(Get-ChildItem -LiteralPath $pecmdDir -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
                # Timeline CSV is one row per run; main CSV carries FilesLoaded/Directories.
                try {
                    foreach ($row in @(Import-Csv -LiteralPath $pf.FullName -ErrorAction Stop)) {
                        $peRows++
                        if ($peRows -gt $peMax) { $peCapped = $true; break }
                        $exe = [string]$row.ExecutableName
                        if ($exe) {
                            if (-not $peNames.ContainsKey($exe)) { $peNames[$exe] = 0 }
                            $peNames[$exe] = $peNames[$exe] + 1
                        }
                        $blobs = @(
                            [string]$row.FilesLoaded
                            [string]$row.Directories
                            [string]$row.SourceFilename
                        )
                        if ($exe -and $exe.IndexOf('\') -ge 0) { $blobs += $exe }
                        foreach ($blob in $blobs) {
                            if (-not $blob) { continue }
                            foreach ($piece in @($blob -split '[,;\r\n]+')) {
                                $p = $piece.Trim().Trim('"')
                                if (-not $p -or $p.IndexOf('\') -lt 0) { continue }
                                if (Test-FotonUserWritablePath -Path $p) {
                                    if (-not $peWritable.ContainsKey($p)) { $peWritable[$p] = $true }
                                }
                            }
                        }
                    }
                }
                catch { }
                if ($peCapped) { break }
            }
            if ($peRows -gt 0) {
                $top = @($peNames.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8)
                $sample = (($top | ForEach-Object { "{0} ({1})" -f $_.Key, $_.Value }) -join '; ')
                $capNote = ''
                if ($peCapped) { $capNote = (" Row scan capped at {0}; counts are a floor." -f $peMax) }
                Add-FotonFinding -Severity 'Info' -Category 'Execution' -Tier 1 -Title 'PECmd Prefetch rows present in compose output' `
                    -Observation ("PECmd wrote {0} Prefetch row(s) under analysis/external/PECmd. Top ExecutableName values: {1}.{2}" -f $peRows, $sample, $capNote) `
                    -WhyItMatters 'These are Eric Zimmerman PECmd facts about Prefetch already copied into the package, not a Foton-native Prefetch parse and not a verdict. Prefetch is often disabled on servers and is incomplete for short-lived processes.' `
                    -Artifact 'analysis/external/PECmd' `
                    -NextStep 'Open pecmd.csv for RunCount/LastRun and corroborate interesting executables against process, persistence, and software inventory.'
            }
            if ($peWritable.Count -gt 0) {
                $wSample = (@($peWritable.Keys | Select-Object -First 8) -join '; ')
                Add-FotonFinding -Severity 'Medium' -Category 'Execution' -Tier 2 -Title 'PECmd Prefetch references user-writable paths' `
                    -Observation ("PECmd FilesLoaded/Directories (and path-like ExecutableName) include {0} distinct user-writable path(s). Sample: {1}" -f $peWritable.Count, $wSample) `
                    -WhyItMatters 'A Prefetch-referenced path under a user-writable location is a review item (updater, user binary, or unexpected drop). PECmd reported the reference; this finding does not establish that the file is malicious.' `
                    -Artifact 'analysis/external/PECmd' `
                    -NextStep 'Hash the path if the bytes are still in the package and compare to software inventory / baseline diffs.'
            }
        }

        $evtxeDir = Join-Path $caseRoot 'analysis\external\EvtxECmd'
        if (Test-Path -LiteralPath $evtxeDir) {
            $evRows = 0
            $evIds = @{}
            $evWritable = @{}
            $evSusp = @{}
            $evCapped = $false
            $evMax = 2000000
            # High-attention IDs only — not a hunt engine. Counts cite EvtxECmd.
            $attention = @{
                '1102' = @{ Severity = 'High';   Label = 'Security audit log cleared' }
                '104'  = @{ Severity = 'High';   Label = 'Event log cleared' }
                '4697' = @{ Severity = 'Medium'; Label = 'Service installed (Security 4697)' }
                '7045' = @{ Severity = 'Medium'; Label = 'Service installed (System 7045)' }
                '4698' = @{ Severity = 'Medium'; Label = 'Scheduled task created' }
            }
            $attCounts = @{}
            foreach ($ef in @(Get-ChildItem -LiteralPath $evtxeDir -Filter '*.csv' -File -ErrorAction SilentlyContinue)) {
                try {
                    foreach ($row in (Import-Csv -LiteralPath $ef.FullName -ErrorAction Stop)) {
                        $evRows++
                        if ($evRows -gt $evMax) { $evCapped = $true; break }
                        $eid = [string]$row.EventId
                        if (-not $eid) { $eid = [string]$row.EventID }
                        if ($eid) {
                            if (-not $evIds.ContainsKey($eid)) { $evIds[$eid] = 0 }
                            $evIds[$eid] = $evIds[$eid] + 1
                            if ($attention.ContainsKey($eid)) {
                                if (-not $attCounts.ContainsKey($eid)) { $attCounts[$eid] = 0 }
                                $attCounts[$eid] = $attCounts[$eid] + 1
                            }
                        }
                        $execInfo = [string]$row.ExecutableInfo
                        if ($execInfo) {
                            if (Test-FotonUserWritablePath -Path $execInfo) {
                                if (-not $evWritable.ContainsKey($execInfo)) { $evWritable[$execInfo] = $true }
                            }
                            else {
                                # ExecutableInfo often embeds a path inside a longer string.
                                foreach ($m in [regex]::Matches($execInfo, '(?i)[A-Za-z]:\\[^\s\|"]+')) {
                                    $p = $m.Value
                                    if (Test-FotonUserWritablePath -Path $p) {
                                        if (-not $evWritable.ContainsKey($p)) { $evWritable[$p] = $true }
                                    }
                                }
                            }
                            $hit = Test-FotonSuspiciousCommand -Text $execInfo
                            if ($hit) {
                                if (-not $evSusp.ContainsKey($hit)) { $evSusp[$hit] = 0 }
                                $evSusp[$hit] = $evSusp[$hit] + 1
                            }
                        }
                    }
                }
                catch { }
                if ($evCapped) { break }
            }
            if ($evRows -gt 0) {
                $topIds = @($evIds.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8)
                $idSample = (($topIds | ForEach-Object { "EventId {0} ({1})" -f $_.Key, $_.Value }) -join '; ')
                $capNote = ''
                if ($evCapped) { $capNote = (" Row scan capped at {0}; counts are a floor." -f $evMax) }
                Add-FotonFinding -Severity 'Info' -Category 'EventLogs' -Tier 1 -Title 'EvtxECmd event rows present in compose output' `
                    -Observation ("EvtxECmd wrote {0} event row(s) under analysis/external/EvtxECmd. Top EventId values: {1}.{2}" -f $evRows, $idSample, $capNote) `
                    -WhyItMatters 'These are Eric Zimmerman EvtxECmd facts about EVTX already copied into the package. Volume reflects which channels were collected and how noisy they were — not a compromise score.' `
                    -Artifact 'analysis/external/EvtxECmd' `
                    -NextStep 'Filter evtxecmd.csv by EventId and Channel for the investigation window; use Hayabusa/Chainsaw compose for Sigma-style hunts.'
            }
            foreach ($eid in @($attCounts.Keys | Sort-Object)) {
                $meta = $attention[$eid]
                $n = $attCounts[$eid]
                Add-FotonFinding -Severity $meta.Severity -Category 'EventLogs' -Tier 1 `
                    -Title ("EvtxECmd: {0}" -f $meta.Label) `
                    -Observation ("EvtxECmd reported {0} EventId {1} row(s) in analysis/external/EvtxECmd." -f $n, $eid) `
                    -WhyItMatters 'This EventId is a high-attention audit fact when present. Benign administrators, installers, and management agents also clear logs, install services, and create tasks. EvtxECmd reported the row; this is not attribution.' `
                    -Artifact 'analysis/external/EvtxECmd' `
                    -NextStep ("Open the EvtxECmd CSV filtered to EventId {0}, note TimeCreated/UserName/ExecutableInfo, and corroborate against persistence and account artifacts." -f $eid)
            }
            if ($evWritable.Count -gt 0) {
                $wSample = (@($evWritable.Keys | Select-Object -First 8) -join '; ')
                Add-FotonFinding -Severity 'Medium' -Category 'Execution' -Tier 2 -Title 'EvtxECmd ExecutableInfo references user-writable paths' `
                    -Observation ("EvtxECmd ExecutableInfo fields include {0} distinct user-writable path(s). Sample: {1}" -f $evWritable.Count, $wSample) `
                    -WhyItMatters 'Mapped ExecutableInfo often carries process paths, service ImagePath, or task actions. A user-writable location is a review item, not proof of compromise.' `
                    -Artifact 'analysis/external/EvtxECmd' `
                    -NextStep 'Corroborate the path against Prefetch/PECmd, persistence CSVs, and software inventory.'
            }
            if ($evSusp.Count -gt 0) {
                $sSample = (($evSusp.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 6 |
                        ForEach-Object { "{0} ({1})" -f $_.Key, $_.Value }) -join '; ')
                Add-FotonFinding -Severity 'Medium' -Category 'Execution' -Tier 2 -Title 'EvtxECmd ExecutableInfo matched suspicious-command patterns' `
                    -Observation ("EvtxECmd ExecutableInfo matched {0} distinct suspicious-command pattern(s). Sample: {1}" -f $evSusp.Count, $sSample) `
                    -WhyItMatters 'These are the same workstation pattern matches used on collected process rows, applied to EvtxECmd-mapped command text. Admin scripts and installers often match. Not a verdict.' `
                    -Artifact 'analysis/external/EvtxECmd' `
                    -NextStep 'Read the matching EvtxECmd rows in full and corroborate against process creation and persistence artifacts.'
            }
        }
    }

    # Absence is not evidence. The endpoint flatten ships without the
    # suspicious-command pattern list (Defender AMSI blocks the flatten when it is
    # embedded - see build/Build-Standalone.ps1), so every rule that depends on it
    # is silently inert there. Say so rather than letting a pattern-free run read as
    # a clean result.
    if (@($script:FotonSession.SuspiciousCommandPatterns).Count -eq 0) {
        Add-FotonFinding -Severity 'Info' -Category 'Methodology' -Tier 1 -Title 'Suspicious-command pattern matching did not run' `
            -Observation 'No suspicious-command pattern list was loaded in this session, so process command lines, PowerShell console history, autostart values, and scheduled task actions were not matched against high-risk patterns. Any other finding in this report is unaffected.' `
            -WhyItMatters 'This is a visibility gap, not a negative result: the absence of pattern findings here says nothing about whether such commands ran. The endpoint collector intentionally ships without the pattern list because embedding it causes antivirus to block the collector at load.' `
            -Artifact 'src/Private/Patterns/SuspiciousCommandPatterns.txt' `
            -NextStep 'Re-run Invoke-FotonAnalysis against this package from the Foton module on an analyst workstation, where the pattern list loads and these rules evaluate.'
    }

    Write-FotonStatus ("Findings generated: {0}" -f $script:FotonSession.Findings.Count) 'Good'

    # Collect already ran these same rules on the endpoint before zipping, so a
    # workstation re-run over an untouched package reproduces that report rather
    # than adding detection. Say so instead of letting it look like new analysis.
    $caseRoot = $script:FotonSession.CaseRoot
    if ($caseRoot -and (Test-Path -LiteralPath $caseRoot)) {
        $endpointFindings = Join-Path $caseRoot '00_Collection\findings.csv'
        $extraInputs = @(
            (Join-Path $caseRoot 'analysis\parsed_records.csv')
            (Join-Path $caseRoot 'analysis\baseline_diff.csv')
            (Join-Path $caseRoot 'analysis\external')
        )
        $haveExtra = $false
        foreach ($p in $extraInputs) {
            if (Test-Path -LiteralPath $p) { $haveExtra = $true }
        }
        if ((Test-Path -LiteralPath $endpointFindings) -and -not $haveExtra) {
            Write-FotonStatus 'These heuristics already ran on the endpoint during Collect (00_Collection\findings.csv), so this run reproduces that report rather than adding detection. New findings come from Invoke-FotonParse, Invoke-FotonExternalParse (compose), Invoke-FotonIocMatch, or Compare-FotonBaseline - then re-run analyze.' 'Warn'
        }
    }

    if ($caseRoot -and (Test-Path -LiteralPath $caseRoot)) {
        $analysisDir = Join-Path $caseRoot 'analysis'
        New-Item -Path $analysisDir -ItemType Directory -Force | Out-Null
        $findingsPath = Join-Path $analysisDir 'findings.csv'
        if ($script:FotonSession.Findings.Count -gt 0) {
            $script:FotonSession.Findings | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
            # For a ZIP the case root is a temp extraction the operator never sees.
            # Drop a second copy beside the ZIP so the findings survive cleanup.
            $pkgMeta = $script:FotonSession.Package
            if ($pkgMeta -and $pkgMeta.Kind -eq 'Zip' -and $pkgMeta.SourcePath) {
                $stem = [IO.Path]::GetFileNameWithoutExtension($pkgMeta.SourcePath)
                $beside = Join-Path (Split-Path -Parent $pkgMeta.SourcePath) ($stem + '_findings.csv')
                $script:FotonSession.Findings | Export-Csv -Path $beside -NoTypeInformation -Encoding UTF8
            }
        }
    }
}


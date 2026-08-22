# Invoke-FotonPersistenceCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint runs still use WinFoton.ps1 until the standalone flatten build.

function Invoke-FotonPersistenceCollection {
    Write-FotonStatus 'Collecting persistence mechanisms (autoruns, tasks, services, WMI)' 'Step'

    Invoke-FotonCollection -Category 'Persistence' -Name 'autorun_registry_keys' -Format 'Csv' -Description 'Run/RunOnce and policy autostart keys, machine and per-user' -Script {
        $rows = @()
        $machineKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
            'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
        )
        foreach ($k in $machineKeys) {
            foreach ($v in (Get-FotonRegValueList -Path $k)) {
                $rows += [PSCustomObject]@{
                    Scope = 'Machine'; User = 'N/A'; Key = $v.Key; ValueName = $v.Name; Command = $v.Value
                    SuspiciousHits = (Test-FotonSuspiciousCommand -Text $v.Value)
                    UserWritableTarget = (Test-FotonUserWritablePath -Path $v.Value)
                }
            }
        }
        $userSubKeys = @(
            'Software\Microsoft\Windows\CurrentVersion\Run',
            'Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'Software\Microsoft\Windows\CurrentVersion\RunServices',
            'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            foreach ($sub in $userSubKeys) {
                $full = Join-Path $hiveRoot.Root $sub
                foreach ($v in (Get-FotonRegValueList -Path $full)) {
                    $rows += [PSCustomObject]@{
                        Scope = 'User'; User = $hiveRoot.UserName; Key = $v.Key; ValueName = $v.Name; Command = $v.Value
                        SuspiciousHits = (Test-FotonSuspiciousCommand -Text $v.Value)
                        UserWritableTarget = (Test-FotonUserWritablePath -Path $v.Value)
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'startup_folder_items' -Format 'Csv' -Description 'Files in machine and per-user Startup folders' -Script {
        $rows = @()
        $paths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
        foreach ($userProfile in (Get-FotonUserProfile)) {
            $paths += (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        }
        foreach ($p in $paths) {
            if (-not (Test-FotonPathAccessible -Path $p)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $sig = Get-FotonSignatureInfo -Path $f.FullName
                $rows += [PSCustomObject]@{
                    StartupFolder   = $p
                    Name            = $f.Name
                    FullName        = $f.FullName
                    SizeBytes       = $f.Length
                    CreatedUtc      = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    ModifiedUtc     = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    SignatureStatus = $sig.Status
                    SHA256          = (Get-FotonSafeHash -Path $f.FullName)
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'startup_approved' -Format 'Csv' -Description 'Task Manager / Settings StartupApproved enable-disable bits (not the Startup folder)' -Script {
        Get-FotonStartupApprovedRows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'scheduled_tasks' -Format 'Csv' -Description 'Scheduled tasks with actions, principals, and last run state' -Script {
        $rows = @()
        try {
            foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
                $info = $null
                try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }
                $actions = @()
                foreach ($a in $t.Actions) {
                    if ($a.Execute) { $actions += ("{0} {1}" -f $a.Execute, $a.Arguments) }
                    elseif ($a.ClassId) { $actions += ("COM:{0}" -f $a.ClassId) }
                }
                $actionText = ($actions -join ' | ')
                $exePath = ''
                if ($t.Actions -and $t.Actions[0].Execute) {
                    $exePath = [Environment]::ExpandEnvironmentVariables($t.Actions[0].Execute.Trim('"'))
                }
                $triggers = @()
                foreach ($tr in $t.Triggers) { $triggers += $tr.CimClass.CimClassName }
                $rows += [PSCustomObject]@{
                    TaskPath       = $t.TaskPath
                    TaskName       = $t.TaskName
                    State          = [string]$t.State
                    Author         = $t.Author
                    RunAsUser      = $t.Principal.UserId
                    RunLevel       = [string]$t.Principal.RunLevel
                    Triggers       = ($triggers -join ', ')
                    Actions        = $actionText
                    LastRunTime    = if ($info) { [string]$info.LastRunTime } else { '' }
                    LastResult     = if ($info) { $info.LastTaskResult } else { '' }
                    NextRunTime    = if ($info) { [string]$info.NextRunTime } else { '' }
                    Description    = $t.Description
                    SuspiciousHits = (Test-FotonSuspiciousCommand -Text $actionText)
                    UserWritableTarget = (Test-FotonUserWritablePath -Path $exePath)
                    SHA256         = (Get-FotonSafeHash -Path $exePath)
                }
            }
        }
        catch {
            $rows += [PSCustomObject]@{ TaskPath = 'ERROR'; TaskName = $_.Exception.Message; State = ''; Author = ''; RunAsUser = ''; RunLevel = ''; Triggers = ''; Actions = ''; LastRunTime = ''; LastResult = ''; NextRunTime = ''; Description = ''; SuspiciousHits = ''; UserWritableTarget = $false; SHA256 = '' }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'scheduled_task_files' -Format 'Csv' -Description 'Task XML files on disk with timestamps (creation-time pivot)' -Script {
        $base = "$env:SystemRoot\System32\Tasks"
        if (-not (Test-Path -LiteralPath $base)) { return @() }
        Get-ChildItem -LiteralPath $base -Recurse -File -Force -ErrorAction SilentlyContinue |
            Select-Object FullName,
            @{n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            @{n = 'ModifiedUtc'; e = { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            Length |
            Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'services' -Format 'Csv' -Description 'All services with binary path, signature, hash, unquoted-path flag' -Script {
        $rows = @()
        foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $pathName = $s.PathName
            $exe = ''
            if ($pathName) {
                if ($pathName.StartsWith('"')) { $exe = $pathName.Split('"')[1] }
                else {
                    $m = [regex]::Match($pathName, '^(.*?\.exe)', 'IgnoreCase')
                    if ($m.Success) { $exe = $m.Groups[1].Value } else { $exe = $pathName.Split(' ')[0] }
                }
                $exe = [Environment]::ExpandEnvironmentVariables($exe)
            }
            $unquoted = $false
            if ($pathName -and -not $pathName.StartsWith('"') -and $pathName -match ' ' -and $exe -match ' ') { $unquoted = $true }
            $sig = Get-FotonSignatureInfo -Path $exe
            $rows += [PSCustomObject]@{
                Name            = $s.Name
                DisplayName     = $s.DisplayName
                State           = $s.State
                StartMode       = $s.StartMode
                StartName       = $s.StartName
                ProcessId       = $s.ProcessId
                PathName        = $pathName
                ResolvedExe     = $exe
                ServiceType     = $s.ServiceType
                UnquotedPath    = $unquoted
                UserWritablePath = (Test-FotonUserWritablePath -Path $exe)
                SignatureStatus = $sig.Status
                Signer          = $sig.Signer
                SHA256          = (Get-FotonSafeHash -Path $exe)
                Description     = $s.Description
            }
        }
        $rows | Sort-Object Name
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'wmi_event_subscriptions' -Format 'Txt' -Description 'WMI filters, consumers, and bindings (fileless persistence)' -Script {
        $out = @()
        foreach ($class in @('__EventFilter', '__EventConsumer', '__FilterToConsumerBinding')) {
            $out += "=== $class ==="
            try {
                $items = Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction Stop
                if ($items) { $out += ($items | Format-List * | Out-String -Width 400) }
                else { $out += '(none)' }
            }
            catch { $out += "Error: $($_.Exception.Message)" }
        }
        $out
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'winlogon_lsa_and_dll_hijacks' -Format 'Csv' -Description 'Winlogon Shell/Userinit, AppInit_DLLs, LSA packages, IFEO debuggers' -Script {
        $rows = @()
        $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        foreach ($n in @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'GinaDLL', 'UserInitMprLogonScript')) {
            $val = Get-FotonRegValue -Path $winlogon -Name $n
            if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'Winlogon'; Location = $winlogon; Name = $n; Value = [string]$val } }
        }
        foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            foreach ($n in @('AppInit_DLLs', 'LoadAppInit_DLLs', 'Load', 'Run', 'IconServiceLib')) {
                $val = Get-FotonRegValue -Path $k -Name $n
                if ($null -ne $val -and "$val" -ne '') { $rows += [PSCustomObject]@{ Mechanism = 'AppInit/Windows'; Location = $k; Name = $n; Value = [string]$val } }
            }
        }
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($n in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
            $val = Get-FotonRegValue -Path $lsa -Name $n
            if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'LSA Package'; Location = $lsa; Name = $n; Value = ($val -join ', ') } }
        }
        $val = Get-FotonRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -Name 'SecurityProviders'
        if ($val) { $rows += [PSCustomObject]@{ Mechanism = 'SecurityProviders'; Location = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders'; Name = 'SecurityProviders'; Value = [string]$val } }

        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path -LiteralPath $ifeo) {
            foreach ($sub in (Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
                foreach ($n in @('Debugger', 'GlobalFlag', 'MonitorProcess')) {
                    $v = Get-FotonRegValue -Path $sub.PSPath -Name $n
                    if ($v) { $rows += [PSCustomObject]@{ Mechanism = 'IFEO'; Location = $sub.Name; Name = $n; Value = [string]$v } }
                }
            }
        }
        foreach ($n in @('AppCertDlls')) {
            foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls')) {
                $rows += [PSCustomObject]@{ Mechanism = 'AppCertDlls'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
            }
        }
        foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')) {
            if ($v.Name -in @('BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand', 'PendingFileRenameOperations')) {
                $rows += [PSCustomObject]@{ Mechanism = 'SessionManager'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
            }
        }
        foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors')) {
            $rows += [PSCustomObject]@{ Mechanism = 'PrintMonitor'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
        }
        foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SOFTWARE\Microsoft\Netsh')) {
            $rows += [PSCustomObject]@{ Mechanism = 'NetshHelper'; Location = $v.Key; Name = $v.Name; Value = $v.Value }
        }
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $env_ = Join-Path $hiveRoot.Root 'Environment'
            foreach ($n in @('UserInitMprLogonScript')) {
                $v = Get-FotonRegValue -Path $env_ -Name $n
                if ($v) { $rows += [PSCustomObject]@{ Mechanism = 'LogonScript'; Location = "$($hiveRoot.UserName): $env_"; Name = $n; Value = [string]$v } }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'accessibility_binary_integrity' -Format 'Csv' -Description 'Sticky-keys style backdoor check on accessibility binaries' -Script {
        $targets = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
        $rows = @()
        foreach ($t in $targets) {
            $p = Join-Path "$env:SystemRoot\System32" $t
            if (-not (Test-Path -LiteralPath $p)) { continue }
            $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            $sig = Get-FotonSignatureInfo -Path $p
            $ifeoDebugger = Get-FotonRegValue -Path ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$t") -Name 'Debugger'
            $rows += [PSCustomObject]@{
                Binary          = $t
                Path            = $p
                SizeBytes       = $item.Length
                ModifiedUtc     = $item.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                SignatureStatus = $sig.Status
                IsOSBinary      = $sig.IsOSBinary
                IFEODebugger    = [string]$ifeoDebugger
                SHA256          = (Get-FotonSafeHash -Path $p)
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'com_hijack_candidates' -Format 'Csv' -Description 'Per-user COM CLSID overrides pointing to user-writable DLLs' -Script {
        $rows = @()
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $clsidRoot = Join-Path $hiveRoot.Root 'Software\Classes\CLSID'
            if (-not (Test-Path -LiteralPath $clsidRoot)) { continue }
            foreach ($clsid in (Get-ChildItem -LiteralPath $clsidRoot -ErrorAction SilentlyContinue)) {
                foreach ($server in @('InprocServer32', 'LocalServer32', 'InprocHandler32')) {
                    $sp = Join-Path $clsid.PSPath $server
                    if (-not (Test-Path -LiteralPath $sp)) { continue }
                    $default = Get-FotonRegValue -Path $sp -Name '(default)'
                    if (-not $default) { continue }
                    $rows += [PSCustomObject]@{
                        User        = $hiveRoot.UserName
                        CLSID       = (Split-Path $clsid.Name -Leaf)
                        ServerType  = $server
                        Target      = [string]$default
                        UserWritableTarget = (Test-FotonUserWritablePath -Path ([string]$default))
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'bits_jobs' -Format 'Txt' -Description 'Background Intelligent Transfer jobs (download persistence)' -Script {
        $out = @()
        try {
            $jobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
            if ($jobs) { $out += ($jobs | Select-Object JobId, DisplayName, JobState, OwnerAccount, TransferType, CreationTime, FileList | Format-List | Out-String -Width 400) }
            else { $out += '(no BITS jobs)' }
        }
        catch { $out += "Get-BitsTransfer unavailable: $($_.Exception.Message)" }
        $out += '--- bitsadmin /list /allusers /verbose ---'
        $out += (& bitsadmin.exe /list /allusers /verbose 2>&1 | Out-String)
        $out
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'office_addins_and_templates' -Format 'Csv' -Description 'Office add-ins and startup template locations' -Script {
        $rows = @()
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $base = Join-Path $hiveRoot.Root 'Software\Microsoft\Office'
            if (-not (Test-Path -LiteralPath $base)) { continue }
            foreach ($addin in (Get-ChildItem -LiteralPath $base -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match 'Addins|Resiliency|Security\\Trusted Locations' })) {
                foreach ($v in (Get-FotonRegValueList -Path $addin.PSPath)) {
                    $rows += [PSCustomObject]@{ User = $hiveRoot.UserName; Key = $v.Key; Name = $v.Name; Value = $v.Value }
                }
            }
        }
        foreach ($userProfile in (Get-FotonUserProfile)) {
            $startup = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Word\STARTUP'
            if (Test-Path -LiteralPath $startup) {
                foreach ($f in (Get-ChildItem -LiteralPath $startup -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{ User = $userProfile.UserName; Key = 'Word STARTUP folder'; Name = $f.Name; Value = $f.FullName }
                }
            }
        }
        $rows
    } | Out-Null
}

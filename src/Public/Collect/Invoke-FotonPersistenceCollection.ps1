# Invoke-FotonPersistenceCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint collect. Rebuild dist/Foton-Collect.ps1 after edits.

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
                    # Analyze derives this from Command; patterns cannot ship in the flatten.
                    SuspiciousHits = ''
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
                        SuspiciousHits = ''
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
                    SuspiciousHits = ''
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

    Invoke-FotonCollection -Category 'Persistence' -Name 'cmd_autorun' -Format 'Csv' -Description 'cmd.exe Command Processor AutoRun (HKLM and loaded HKCU)' -Script {
        $rows = @()
        foreach ($rel in @('SOFTWARE\Microsoft\Command Processor', 'SOFTWARE\Wow6432Node\Microsoft\Command Processor')) {
            $path = 'HKLM:\' + $rel
            if ($rel -like '*Wow6432Node*' -and -not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Wow6432Node')) { continue }
            $val = Get-FotonRegValue -Path $path -Name 'AutoRun'
            $shown = '(not set)'
            if ($null -ne $val -and [string]$val -ne '') { $shown = [string]$val }
            $rows += [PSCustomObject]@{ Scope = 'HKLM'; Key = $rel; Command = $shown }
        }
        foreach ($h in @(Get-FotonUserHiveRoot)) {
            foreach ($rel in @('Software\Microsoft\Command Processor', 'Software\Wow6432Node\Microsoft\Command Processor')) {
                $val = Get-FotonRegValue -Path (Join-Path $h.Root $rel) -Name 'AutoRun'
                if ($null -eq $val -or [string]$val -eq '') { continue }
                $rows += [PSCustomObject]@{ Scope = $h.UserName; Key = $rel; Command = [string]$val }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'session_manager_boot' -Format 'Csv' -Description 'Session Manager BootExecute family (includes PFRO as a live fact)' -Script {
        $rows = @()
        $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        foreach ($n in @('BootExecute', 'BootExecuteNoPnpSync', 'SetupExecute', 'Execute', 'S0InitialCommand', 'PendingFileRenameOperations')) {
            $val = Get-FotonRegValue -Path $sm -Name $n
            $shown = '(not set)'
            if ($null -ne $val) {
                $parts = @()
                foreach ($x in @($val)) { if ([string]$x) { $parts += [string]$x } }
                if ($parts.Count -gt 0) { $shown = ($parts -join ' ') }
            }
            $rows += [PSCustomObject]@{ Name = $n; Value = $shown }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'known_dlls' -Format 'Csv' -Description 'Session Manager KnownDLLs search-order map' -Script {
        $rows = @()
        foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs')) {
            $rows += [PSCustomObject]@{ Name = $v.Name; MappedFile = $v.Value }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'winsock_lsp' -Format 'Csv' -Description 'Winsock protocol and namespace catalog LibraryPath' -Script {
        $rows = @()
        $protoRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9'
        foreach ($leaf in @('Catalog_Entries', 'Catalog_Entries64')) {
            $root = Join-Path $protoRoot $leaf
            if (-not (Test-Path -LiteralPath $root)) { continue }
            $kind = 'Protocol'
            if ($leaf -eq 'Catalog_Entries64') { $kind = 'Protocol64' }
            foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $packed = Get-FotonRegValue -Path $sub.PSPath -Name 'PackedCatalogItem'
                $rows += [PSCustomObject]@{
                    Kind        = $kind
                    Entry       = $sub.PSChildName
                    LibraryPath = Get-FotonWinsockPackedPath -Bytes $packed
                }
            }
        }
        $ns = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries'
        foreach ($sub in (Get-ChildItem -LiteralPath $ns -ErrorAction SilentlyContinue)) {
            $lib = Get-FotonRegValue -Path $sub.PSPath -Name 'LibraryPath'
            $shown = '(not set)'
            if ($null -ne $lib -and [string]$lib -ne '') { $shown = [string]$lib }
            $rows += [PSCustomObject]@{ Kind = 'Namespace'; Entry = $sub.PSChildName; LibraryPath = $shown }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'active_setup' -Format 'Csv' -Description 'HKLM Active Setup Installed Components StubPath' -Script {
        $rows = @()
        foreach ($root in @(
                'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components'
            )) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $stub = Get-FotonRegValue -Path $sub.PSPath -Name 'StubPath'
                $ver = Get-FotonRegValue -Path $sub.PSPath -Name 'Version'
                $rows += [PSCustomObject]@{
                    Key      = $root
                    Guid     = $sub.PSChildName
                    StubPath = $(if ($null -eq $stub -or [string]$stub -eq '') { '(not set)' } else { [string]$stub })
                    Version  = $(if ($null -eq $ver -or [string]$ver -eq '') { '(not set)' } else { [string]$ver })
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'silent_process_exit' -Format 'Csv' -Description 'SilentProcessExit MonitorProcess/ReportingMode (and IFEO GlobalFlag when present)' -Script {
        $rows = @()
        $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path -LiteralPath $root) {
            foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $name = [string]$sub.PSChildName
                $gflag = Get-FotonRegValue -Path (Join-Path $ifeo $name) -Name 'GlobalFlag'
                $gShown = '(not set)'
                if ($null -ne $gflag -and [string]$gflag -ne '') { $gShown = [string]$gflag }
                $mon = Get-FotonRegValue -Path $sub.PSPath -Name 'MonitorProcess'
                $mode = Get-FotonRegValue -Path $sub.PSPath -Name 'ReportingMode'
                $dump = Get-FotonRegValue -Path $sub.PSPath -Name 'LocalDumpFolder'
                $monS = '(not set)'; if ($null -ne $mon -and [string]$mon -ne '') { $monS = [string]$mon }
                $modeS = '(not set)'; if ($null -ne $mode -and [string]$mode -ne '') { $modeS = [string]$mode }
                $dumpS = '(not set)'; if ($null -ne $dump -and [string]$dump -ne '') { $dumpS = [string]$dump }
                $rows += [PSCustomObject]@{
                    ImageName       = $name
                    MonitorProcess  = $monS
                    ReportingMode   = $modeS
                    LocalDumpFolder = $dumpS
                    IfeoGlobalFlag  = $gShown
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'netsh_helpers' -Format 'Csv' -Description 'Netsh helper DLL registrations (HKLM NetSh)' -Script {
        $rows = @()
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\NetSh', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh')) {
            foreach ($v in (Get-FotonRegValueList -Path $root)) {
                if (-not $v.Name -or $v.Name -eq '(default)') { continue }
                $rows += [PSCustomObject]@{ Key = $root; Name = $v.Name; Dll = $v.Value }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'time_providers' -Format 'Csv' -Description 'W32Time TimeProviders DllName (not NTP peer churn)' -Script {
        $rows = @()
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
        if (Test-Path -LiteralPath $root) {
            foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $dll = Get-FotonRegValue -Path $sub.PSPath -Name 'DllName'
                $en = Get-FotonRegValue -Path $sub.PSPath -Name 'Enabled'
                $inp = Get-FotonRegValue -Path $sub.PSPath -Name 'InputProvider'
                $dllS = '(not set)'; if ($null -ne $dll -and [string]$dll -ne '') { $dllS = [string]$dll }
                $enS = '(not set)'; if ($null -ne $en -and [string]$en -ne '') { $enS = [string]$en }
                $inpS = '(not set)'; if ($null -ne $inp -and [string]$inp -ne '') { $inpS = [string]$inp }
                $rows += [PSCustomObject]@{
                    Name          = $sub.PSChildName
                    DllName       = $dllS
                    Enabled       = $enS
                    InputProvider = $inpS
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Persistence' -Name 'screensaver' -Format 'Csv' -Description 'Screensaver executable from Desktop and policy keys (loaded hives). User churn; not a baseline.' -Script {
        $rows = @()
        $names = @('SCRNSAVE.EXE', 'ScreenSaveActive', 'ScreenSaverIsSecure', 'ScreenSaveTimeOut')
        $emitKey = {
            param($Scope, $User, $Source, $Path)
            if (-not (Test-Path -LiteralPath $Path)) { return }
            $any = $false
            $got = @()
            foreach ($n in $names) {
                $val = Get-FotonRegValue -Path $Path -Name $n
                if ($null -eq $val -or [string]$val -eq '') { continue }
                $any = $true
                $got += [PSCustomObject]@{ Scope = $Scope; User = $User; Source = $Source; ValueName = $n; Value = [string]$val }
            }
            if ($any) { $got }
        }
        foreach ($r in @(& $emitKey 'Machine' 'N/A' 'Policy' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop')) {
            $rows += $r
        }
        foreach ($h in @(Get-FotonUserHiveRoot)) {
            $desktop = Join-Path $h.Root 'Control Panel\Desktop'
            $policy = Join-Path $h.Root 'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
            foreach ($r in @(& $emitKey 'User' $h.UserName 'Desktop' $desktop)) { $rows += $r }
            foreach ($r in @(& $emitKey 'User' $h.UserName 'Policy' $policy)) { $rows += $r }
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

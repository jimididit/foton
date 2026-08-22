# Invoke-FotonProcessCollection - volatile process state, modules, PS history.

function Invoke-FotonProcessCollection {
    Write-FotonStatus 'Collecting running processes, modules, and volatile state' 'Step'

    Invoke-FotonCollection -Category 'Processes' -Name 'running_processes' -Format 'Csv' -Description 'Processes with path, command line, parent, hash, signature' -Script {
        $procList = @{}
        try {
            foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procList[[int]$p.ProcessId] = $p }
        }
        catch { }

        $owners = @{}
        try {
            foreach ($p in $procList.Values) {
                try {
                    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                    if ($o -and $o.User) { $owners[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)" }
                }
                catch { }
            }
        }
        catch { }

        $rows = @()
        foreach ($p in ($procList.Values | Sort-Object ProcessId)) {
            $path = $p.ExecutablePath
            $sig = Get-FotonSignatureInfo -Path $path
            $parentName = ''
            if ($procList.ContainsKey([int]$p.ParentProcessId)) { $parentName = $procList[[int]$p.ParentProcessId].Name }
            $rows += [PSCustomObject]@{
                PID               = $p.ProcessId
                Name              = $p.Name
                ParentPID         = $p.ParentProcessId
                ParentName        = $parentName
                Owner             = if ($owners.ContainsKey([int]$p.ProcessId)) { $owners[[int]$p.ProcessId] } else { '' }
                Path              = $path
                CommandLine       = $p.CommandLine
                CreationTimeUtc   = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                SessionId         = $p.SessionId
                SignatureStatus   = $sig.Status
                Signer            = $sig.Signer
                IsOSBinary        = $sig.IsOSBinary
                SHA256            = (Get-FotonSafeHash -Path $path)
                UserWritablePath  = (Test-FotonUserWritablePath -Path $path)
                SuspiciousCmdHits = (Test-FotonSuspiciousCommand -Text $p.CommandLine)
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Processes' -Name 'process_tree' -Format 'Txt' -Description 'Parent/child process tree rendering' -Script {
        $procs = @{}
        try { foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) { $procs[[int]$p.ProcessId] = $p } } catch { return 'Unavailable' }
        $children = @{}
        foreach ($p in $procs.Values) {
            $ppid = [int]$p.ParentProcessId
            if (-not $children.ContainsKey($ppid)) { $children[$ppid] = @() }
            $children[$ppid] += $p
        }
        $lines = New-Object System.Collections.ArrayList
        function Write-FotonProcessBranch {
            param($ProcId, $Depth, $ChildMap, $ProcMap, $Sink)
            if ($Depth -gt 12) { return }
            foreach ($child in ($ChildMap[$ProcId] | Sort-Object ProcessId)) {
                $indent = '  ' * $Depth
                $null = $Sink.Add(("{0}[{1}] {2}  {3}" -f $indent, $child.ProcessId, $child.Name, $child.ExecutablePath))
                if ($ChildMap.ContainsKey([int]$child.ProcessId)) {
                    Write-FotonProcessBranch -ProcId ([int]$child.ProcessId) -Depth ($Depth + 1) -ChildMap $ChildMap -ProcMap $ProcMap -Sink $Sink
                }
            }
        }
        foreach ($rootPid in ($children.Keys | Sort-Object)) {
            if (-not $procs.ContainsKey($rootPid)) {
                $null = $lines.Add("[$rootPid] (parent no longer running)")
                Write-FotonProcessBranch -ProcId $rootPid -Depth 1 -ChildMap $children -ProcMap $procs -Sink $lines
            }
        }
        $null = $lines.Add('')
        $null = $lines.Add('--- Tree from System (PID 4) ---')
        Write-FotonProcessBranch -ProcId 4 -Depth 1 -ChildMap $children -ProcMap $procs -Sink $lines
        $lines
    } | Out-Null

    Invoke-FotonCollection -Category 'Processes' -Name 'loaded_modules_nonstandard' -Format 'Csv' -Description 'Loaded DLLs outside System32/Program Files' -Script {
        $rows = @()
        foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
            try {
                foreach ($m in $proc.Modules) {
                    $fn = $m.FileName
                    if ($fn -match '\\Windows\\System32\\' -or $fn -match '\\Windows\\SysWOW64\\' -or
                        $fn -match '\\Windows\\WinSxS\\' -or $fn -match '\\Program Files') { continue }
                    $rows += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        PID         = $proc.Id
                        Module      = $m.ModuleName
                        Path        = $fn
                        Company     = $m.FileVersionInfo.CompanyName
                        SHA256      = (Get-FotonSafeHash -Path $fn)
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Path -Unique
    } | Out-Null

    Invoke-FotonCollection -Category 'Processes' -Name 'powershell_console_history' -Format 'Csv' -Description 'PSReadLine history for every profile (analyst-critical)' -Script {
        $rows = @()
        foreach ($userProfile in (Get-FotonUserProfile)) {
            $hist = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (-not (Test-FotonPathAccessible -Path $hist)) { continue }
            $lineNo = 0
            try {
                foreach ($line in (Get-Content -LiteralPath $hist -ErrorAction Stop)) {
                    $lineNo++
                    $rows += [PSCustomObject]@{
                        User           = $userProfile.UserName
                        HistoryFile    = $hist
                        LineNumber     = $lineNo
                        Command        = $line
                        SuspiciousHits = (Test-FotonSuspiciousCommand -Text $line)
                    }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Processes' -Name 'clipboard_and_recent_docs' -Format 'Txt' -Description 'Recent document MRU keys' -Script {
        $out = @()
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $mru = "$($hiveRoot.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
            if (Test-FotonPathAccessible -Path $mru) {
                $out += "=== RecentDocs for $($hiveRoot.UserName) ==="
                $out += (Get-ChildItem -LiteralPath $mru -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Out-String)
            }
        }
        if ($out.Count -eq 0) { $out += 'No RecentDocs keys accessible.' }
        $out
    } | Out-Null
}

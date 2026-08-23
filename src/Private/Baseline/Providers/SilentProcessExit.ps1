# SilentProcessExit - HKLM SilentProcessExit\<image>. MonitorProcess is the ASEP (T1003 dump / debugging).
# Empty tree is omitted. IFEO GlobalFlag is Collect-only (ImageFileExecution stays Debugger-only).
Register-FotonBaselineProvider -RecordType 'SilentProcessExit' `
    -IdentityFields @('ImageName') `
    -ComparedFields @('MonitorProcess', 'ReportingMode', 'LocalDumpFolder') `
    -FalsePositives 'Procmon, Application Verifier, and crash-dump lab machines set MonitorProcess. ReportingMode/LocalDumpFolder changes without a new MonitorProcess are often debugging, not persistence.' `
    -Collect {
        $rows = @()
        $root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
        if (Test-Path -LiteralPath $root) {
            try {
                foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                    $name = [string]$sub.PSChildName
                    if (-not $name) { continue }
                    $mon = Get-FotonRegValue -Path $sub.PSPath -Name 'MonitorProcess'
                    $mode = Get-FotonRegValue -Path $sub.PSPath -Name 'ReportingMode'
                    $dump = Get-FotonRegValue -Path $sub.PSPath -Name 'LocalDumpFolder'
                    $monS = '(not set)'
                    if ($null -ne $mon -and [string]$mon -ne '') { $monS = [string]$mon }
                    $modeS = '(not set)'
                    if ($null -ne $mode -and [string]$mode -ne '') { $modeS = [string]$mode }
                    $dumpS = '(not set)'
                    if ($null -ne $dump -and [string]$dump -ne '') { $dumpS = [string]$dump }
                    $rows += [PSCustomObject]@{
                        ImageName       = $name
                        MonitorProcess  = $monS
                        ReportingMode   = $modeS
                        LocalDumpFolder = $dumpS
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object ImageName
    }

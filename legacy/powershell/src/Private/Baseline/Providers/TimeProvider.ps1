# TimeProvider - W32Time TimeProviders\<Name> DllName/Enabled/InputProvider. Not the NTP peer list (churn).
Register-FotonBaselineProvider -RecordType 'TimeProvider' `
    -IdentityFields @('Name') `
    -ComparedFields @('DllName', 'Enabled', 'InputProvider') `
    -FalsePositives 'NtpClient and NtpServer are the usual pair. Hyper-V VMICTimeProvider and domain NTP stacks are common. Enabled flips are often GPO; DllName changing to a user-writable path is the review item.' `
    -Collect {
        $rows = @()
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
        if (Test-Path -LiteralPath $root) {
            try {
                foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                    $name = [string]$sub.PSChildName
                    if (-not $name) { continue }
                    $dll = Get-FotonRegValue -Path $sub.PSPath -Name 'DllName'
                    $en = Get-FotonRegValue -Path $sub.PSPath -Name 'Enabled'
                    $inp = Get-FotonRegValue -Path $sub.PSPath -Name 'InputProvider'
                    $dllS = '(not set)'
                    if ($null -ne $dll -and [string]$dll -ne '') { $dllS = [string]$dll }
                    $enS = '(not set)'
                    if ($null -ne $en -and [string]$en -ne '') { $enS = [string]$en }
                    $inpS = '(not set)'
                    if ($null -ne $inp -and [string]$inp -ne '') { $inpS = [string]$inp }
                    $rows += [PSCustomObject]@{
                        Name          = $name
                        DllName       = $dllS
                        Enabled       = $enS
                        InputProvider = $inpS
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Name
    }

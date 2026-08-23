# ProxyConfig - WinHTTP blob + HKLM/policy/user Internet Settings. Not DefaultConnectionSettings (churn).
# PAC AutoConfigURL is Medium; explicit ProxyServer / WinHttpSettings is High.
Register-FotonBaselineProvider -RecordType 'ProxyConfig' `
    -IdentityFields @('Scope', 'Setting') `
    -ComparedFields @('Value') `
    -FalsePositives 'Corporate PAC (AutoConfigURL) and WPAD change often. Explicit ProxyServer or WinHttpSettings pointing at an unexpected host is the usual review item. Per-user rows exist only when a proxy/PAC is set on a loaded hive.' `
    -Collect {
        $rows = @()
        $shown = {
            param($v)
            if ($null -eq $v) { return '(not set)' }
            if ($v -is [byte[]]) {
                if ($v.Length -eq 0) { return '(not set)' }
                return ([BitConverter]::ToString($v) -replace '-', '').ToLowerInvariant()
            }
            $s = [string]$v
            if ($s -eq '') { return '(not set)' }
            return $s
        }
        $names = @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL')
        $machine = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
        foreach ($n in $names) {
            $rows += [PSCustomObject]@{
                Scope   = 'Machine'
                Setting = $n
                Value   = & $shown (Get-FotonRegValue -Path $machine -Name $n)
            }
        }
        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        foreach ($n in $names) {
            $rows += [PSCustomObject]@{
                Scope   = 'MachinePolicy'
                Setting = $n
                Value   = & $shown (Get-FotonRegValue -Path $pol -Name $n)
            }
        }
        $conn = Join-Path $machine 'Connections'
        $rows += [PSCustomObject]@{
            Scope   = 'WinHttp'
            Setting = 'WinHttpSettings'
            Value   = & $shown (Get-FotonRegValue -Path $conn -Name 'WinHttpSettings')
        }
        foreach ($h in @(Get-FotonUserHiveRoot)) {
            $ukey = Join-Path $h.Root 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $interesting = $false
            $vals = @{}
            foreach ($n in $names) {
                $vals[$n] = Get-FotonRegValue -Path $ukey -Name $n
                $sv = & $shown $vals[$n]
                if ($n -eq 'ProxyEnable' -and $sv -eq '1') { $interesting = $true }
                if ($n -ne 'ProxyEnable' -and $sv -ne '(not set)') { $interesting = $true }
            }
            if (-not $interesting) { continue }
            foreach ($n in $names) {
                $rows += [PSCustomObject]@{
                    Scope   = [string]$h.SID
                    Setting = $n
                    Value   = & $shown $vals[$n]
                }
            }
        }
        $rows | Sort-Object Scope, Setting
    }

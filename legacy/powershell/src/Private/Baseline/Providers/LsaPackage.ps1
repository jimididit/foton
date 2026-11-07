# LsaPackage - one row per token in LSA MULTI_SZ (and SecurityProviders). Identity Kind + Package.
# Added/Removed only (order of the MULTI_SZ is not compared). FP: MFA/EDR SSP installers (T1547.005).
Register-FotonBaselineProvider -RecordType 'LsaPackage' `
    -IdentityFields @('Kind', 'Package') `
    -ComparedFields @() `
    -FalsePositives 'Third-party MFA, VPN, and EDR often add a Security Package or Notification Package. Compare to the role image. A new unknown DLL name is the interesting case, not msv1_0/kerberos churn.' `
    -Collect {
        $rows = New-Object System.Collections.ArrayList
        $seen = @{}
        $add = {
            param($Kind, $Package)
            $p = ([string]$Package).Trim()
            if (-not $p) { return }
            $k = ($Kind + '|' + $p).ToLowerInvariant()
            if ($seen.ContainsKey($k)) { return }
            $seen[$k] = $true
            $null = $rows.Add([PSCustomObject]@{
                    Kind    = $Kind
                    Package = $p
                })
        }
        $split = {
            param($Val)
            $out = @()
            foreach ($part in @($Val)) {
                if ($null -eq $part) { continue }
                foreach ($tok in ([string]$part -split '[,;\s]+')) {
                    $t = $tok.Trim()
                    if ($t) { $out += $t }
                }
            }
            return $out
        }

        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($n in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
            $val = Get-FotonRegValue -Path $lsa -Name $n
            if ($null -eq $val) { continue }
            foreach ($pkg in @(& $split $val)) {
                & $add $n $pkg
            }
        }
        $osCfg = Join-Path $lsa 'OSConfig'
        $val = Get-FotonRegValue -Path $osCfg -Name 'Authentication Packages'
        if ($null -ne $val) {
            foreach ($pkg in @(& $split $val)) {
                & $add 'OSConfig Authentication Packages' $pkg
            }
        }
        $val = Get-FotonRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -Name 'SecurityProviders'
        if ($null -ne $val) {
            foreach ($pkg in @(& $split $val)) {
                & $add 'SecurityProviders' $pkg
            }
        }

        @($rows) | Sort-Object Kind, Package
    }

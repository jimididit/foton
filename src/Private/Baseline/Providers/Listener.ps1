# Listener - TCP Listen plus UDP below the IANA ephemeral range. No PID.
# Ephemeral UDP (49152-65535) is process-lifetime noise, not stable config.
Register-FotonBaselineProvider -RecordType 'Listener' `
    -IdentityFields @('Protocol', 'LocalAddress', 'LocalPort') `
    -ComparedFields @() `
    -FalsePositives 'New TCP listeners from debug servers and WinRM. UDP above 49151 is omitted on purpose. Wildcard 0.0.0.0 vs a specific bind looks like remove+add.' `
    -Collect {
        $rows = @()
        try {
            foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    Protocol     = 'TCP'
                    LocalAddress = [string]$c.LocalAddress
                    LocalPort    = [string]$c.LocalPort
                }
            }
        }
        catch { }
        try {
            foreach ($u in (Get-NetUDPEndpoint -ErrorAction Stop)) {
                $portNum = 0
                try { $portNum = [int]([string]$u.LocalPort) } catch { $portNum = 0 }
                if ($portNum -ge 49152) { continue }
                $rows += [PSCustomObject]@{
                    Protocol     = 'UDP'
                    LocalAddress = [string]$u.LocalAddress
                    LocalPort    = [string]$u.LocalPort
                }
            }
        }
        catch { }
        $rows | Sort-Object Protocol, LocalPort, LocalAddress
    }

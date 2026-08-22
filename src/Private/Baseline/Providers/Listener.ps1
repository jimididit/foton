# Listener — identity Protocol + LocalAddress + LocalPort. No PID (volatile). Added/removed only.
Register-FotonBaselineProvider -RecordType 'Listener' `
    -IdentityFields @('Protocol', 'LocalAddress', 'LocalPort') `
    -ComparedFields @() `
    -FalsePositives 'Ephemeral services and debug listeners come and go. Wildcard 0.0.0.0 vs a specific bind looks like remove+add. Fleet-compare against the role image, not a busy workstation.' `
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

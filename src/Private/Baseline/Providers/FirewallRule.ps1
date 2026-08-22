# FirewallRule — identity Name + Direction. Enabled/Action are compared; profiles can churn with GPO.
Register-FotonBaselineProvider -RecordType 'FirewallRule' `
    -IdentityFields @('Name', 'Direction') `
    -ComparedFields @('Action', 'Enabled', 'Profile') `
    -FalsePositives 'Windows and vendor installers add allow rules. A new inbound Allow is worth review; a new outbound Allow is common.' `
    -Collect {
        $rows = @()
        try {
            foreach ($r in (Get-NetFirewallRule -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    Name      = [string]$r.Name
                    Direction = [string]$r.Direction
                    Action    = [string]$r.Action
                    Enabled   = [string]$r.Enabled
                    Profile   = [string]$r.Profile
                }
            }
        }
        catch { }
        $rows | Sort-Object Name, Direction
    }

# LocalGroupMember - identity Group + SID.
Register-FotonBaselineProvider -RecordType 'LocalGroupMember' `
    -IdentityFields @('Group', 'SID') `
    -ComparedFields @('Member') `
    -FalsePositives 'Domain join adds Domain Admins. Intune/LAPS may add a local admin. Compare to the role golden image, not a random workstation.' `
    -Collect {
        $rows = @()
        try {
            foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
                try {
                    foreach ($m in (Get-LocalGroupMember -Group $g.Name -ErrorAction Stop)) {
                        $rows += [PSCustomObject]@{
                            Group  = [string]$g.Name
                            SID    = [string]$m.SID
                            Member = [string]$m.Name
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        $rows | Sort-Object Group, SID
    }

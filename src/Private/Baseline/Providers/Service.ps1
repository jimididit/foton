# Service — identity Name. Ignore State and PID (volatile).
Register-FotonBaselineProvider -RecordType 'Service' `
    -IdentityFields @('Name') `
    -ComparedFields @('DisplayName', 'StartMode', 'StartName', 'PathName') `
    -FalsePositives 'Patch Tuesday can replace PathName for the same service. Third-party updaters change StartMode. Compare against a provisioning snapshot, not a post-compromise one.' `
    -Collect {
        $rows = @()
        foreach ($s in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $rows += [PSCustomObject]@{
                Name        = [string]$s.Name
                DisplayName = [string]$s.DisplayName
                StartMode   = [string]$s.StartMode
                StartName   = [string]$s.StartName
                PathName    = [string]$s.PathName
            }
        }
        $rows | Sort-Object Name
    }

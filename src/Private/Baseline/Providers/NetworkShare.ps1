# NetworkShare - identity Name. Hidden admin shares (C$, ADMIN$) are expected; a new named share is the usual review item.
Register-FotonBaselineProvider -RecordType 'NetworkShare' `
    -IdentityFields @('Name') `
    -ComparedFields @('Path', 'Type', 'Description') `
    -FalsePositives 'Print and scan shares, OneDrive/File History, and C$/ADMIN$/IPC$ are normal. Type is the Win32_Share numeric type, not a verdict.' `
    -Collect {
        $rows = @()
        try {
            foreach ($s in (Get-CimInstance -ClassName Win32_Share -ErrorAction Stop)) {
                $rows += [PSCustomObject]@{
                    Name        = [string]$s.Name
                    Path        = [string]$s.Path
                    Type        = [string]$s.Type
                    Description = [string]$s.Description
                }
            }
        }
        catch {
            try {
                foreach ($s in (Get-WmiObject -Class Win32_Share -ErrorAction Stop)) {
                    $rows += [PSCustomObject]@{
                        Name        = [string]$s.Name
                        Path        = [string]$s.Path
                        Type        = [string]$s.Type
                        Description = [string]$s.Description
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Name
    }

# Driver — identity Name. Ignore State (started/stopped is volatile).
Register-FotonBaselineProvider -RecordType 'Driver' `
    -IdentityFields @('Name') `
    -ComparedFields @('DisplayName', 'StartMode', 'PathName') `
    -FalsePositives 'Windows Update replaces driver PathName. Catalog-signed drivers still show odd signature status in Collect; this snapshot does not include signature.' `
    -Collect {
        $rows = @()
        foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
            $path = [string]$d.PathName
            if ($path) { $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"')) }
            $rows += [PSCustomObject]@{
                Name        = [string]$d.Name
                DisplayName = [string]$d.DisplayName
                StartMode   = [string]$d.StartMode
                PathName    = $path
            }
        }
        $rows | Sort-Object Name
    }

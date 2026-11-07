# HardeningRegistry - identity Setting (value name). Same table as Collect.
Register-FotonBaselineProvider -RecordType 'HardeningRegistry' `
    -IdentityFields @('Setting') `
    -ComparedFields @('Value') `
    -FalsePositives 'Domain GPO and Windows edition change defaults. Expected values in the Collect table are a common lab baseline, not proof of compromise when they differ.' `
    -Collect {
        if ($null -eq $script:FotonSession) {
            Initialize-FotonSession
        }
        elseif (-not $script:FotonSession.HardeningRegistryChecks -or @($script:FotonSession.HardeningRegistryChecks).Count -eq 0) {
            Import-FotonPatternTables
        }
        $rows = @()
        foreach ($c in $script:FotonSession.HardeningRegistryChecks) {
            $val = Get-FotonRegValue -Path $c.Path -Name $c.Name
            $rows += [PSCustomObject]@{
                Setting = [string]$c.Name
                Key     = [string]$c.Path
                Value   = if ($null -eq $val) { '(not set)' } else { [string]$val }
            }
        }
        $rows | Sort-Object Setting
    }

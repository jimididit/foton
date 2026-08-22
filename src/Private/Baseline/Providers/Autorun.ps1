# Autorun — machine Run/RunOnce only. Per-user keys follow who is logged on (noisy for fleet).
Register-FotonBaselineProvider -RecordType 'Autorun' `
    -IdentityFields @('Key', 'ValueName') `
    -ComparedFields @('Command') `
    -FalsePositives 'Installers add Run keys. Cloud-sync and updaters live here. Compare Command, not presence of a vendor Run value.' `
    -Collect {
        $rows = @()
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        )
        foreach ($k in $keys) {
            foreach ($v in (Get-FotonRegValueList -Path $k)) {
                $rows += [PSCustomObject]@{
                    Key       = [string]$v.Key
                    ValueName = [string]$v.Name
                    Command   = [string]$v.Value
                }
            }
        }
        $rows | Sort-Object Key, ValueName
    }

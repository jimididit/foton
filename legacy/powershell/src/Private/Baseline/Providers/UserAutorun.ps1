# UserAutorun - per-user Run/RunOnce on loaded hives. Machine Run stays RecordType Autorun.
Register-FotonBaselineProvider -RecordType 'UserAutorun' `
    -IdentityFields @('SID', 'Key', 'ValueName') `
    -ComparedFields @('Command') `
    -FalsePositives 'Cloud-sync, chat, and updaters write HKCU Run. Only loaded user hives are visible. Fleet-compare is noisy; temporal on one host is the usual reading.' `
    -Collect {
        $rows = @()
        $subKeys = @(
            'Software\Microsoft\Windows\CurrentVersion\Run',
            'Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )
        foreach ($h in @(Get-FotonUserHiveRoot)) {
            foreach ($sub in $subKeys) {
                $full = Join-Path $h.Root $sub
                foreach ($v in (Get-FotonRegValueList -Path $full)) {
                    $rows += [PSCustomObject]@{
                        SID       = [string]$h.SID
                        UserName  = [string]$h.UserName
                        Key       = [string]$v.Key
                        ValueName = [string]$v.Name
                        Command   = [string]$v.Value
                    }
                }
            }
        }
        $rows | Sort-Object SID, Key, ValueName
    }

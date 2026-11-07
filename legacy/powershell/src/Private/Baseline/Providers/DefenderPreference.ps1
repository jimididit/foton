# DefenderPreference - stable MpPreference switches and exclusion entries. Not signature age or last-scan time.
Register-FotonBaselineProvider -RecordType 'DefenderPreference' `
    -IdentityFields @('Kind', 'Name') `
    -ComparedFields @('Value') `
    -FalsePositives 'Intune, GPO, and tamper-protection UI change these. An exclusion add is a new row (Kind + path), not proof of compromise.' `
    -Collect {
        $rows = @()
        $p = $null
        try { $p = Get-MpPreference -ErrorAction Stop } catch { return @() }
        if ($null -eq $p) { return @() }

        $flags = @(
            @{ Name = 'DisableRealtimeMonitoring'; Value = [string]$p.DisableRealtimeMonitoring }
            @{ Name = 'DisableBehaviorMonitoring'; Value = [string]$p.DisableBehaviorMonitoring }
            @{ Name = 'DisableScriptScanning'; Value = [string]$p.DisableScriptScanning }
            @{ Name = 'DisableArchiveScanning'; Value = [string]$p.DisableArchiveScanning }
            @{ Name = 'DisableIOAVProtection'; Value = [string]$p.DisableIOAVProtection }
            @{ Name = 'DisableIntrusionPreventionSystem'; Value = [string]$p.DisableIntrusionPreventionSystem }
            @{ Name = 'DisableBlockAtFirstSeen'; Value = [string]$p.DisableBlockAtFirstSeen }
            @{ Name = 'MAPSReporting'; Value = [string]$p.MAPSReporting }
            @{ Name = 'SubmitSamplesConsent'; Value = [string]$p.SubmitSamplesConsent }
            @{ Name = 'PUAProtection'; Value = [string]$p.PUAProtection }
            @{ Name = 'EnableControlledFolderAccess'; Value = [string]$p.EnableControlledFolderAccess }
        )
        foreach ($f in $flags) {
            $rows += [PSCustomObject]@{
                Kind  = 'Switch'
                Name  = $f.Name
                Value = $f.Value
            }
        }

        $lists = @(
            @{ Kind = 'ExclusionPath'; Items = @($p.ExclusionPath) }
            @{ Kind = 'ExclusionProcess'; Items = @($p.ExclusionProcess) }
            @{ Kind = 'ExclusionExtension'; Items = @($p.ExclusionExtension) }
            @{ Kind = 'ExclusionIpAddress'; Items = @($p.ExclusionIpAddress) }
        )
        foreach ($list in $lists) {
            $items = @()
            foreach ($i in $list.Items) {
                if ($null -eq $i) { continue }
                $s = [string]$i
                if ($s -eq '') { continue }
                $items += $s
            }
            foreach ($s in ($items | Sort-Object -Unique)) {
                $rows += [PSCustomObject]@{
                    Kind  = $list.Kind
                    Name  = $s
                    Value = 'listed'
                }
            }
        }
        $rows | Sort-Object Kind, Name
    }

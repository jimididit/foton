# Winlogon - Userinit/Shell and related HKLM Winlogon values. Identity value name. Userinit/Shell edits are High; third-party Gina/credential providers are a false-positive source.
Register-FotonBaselineProvider -RecordType 'Winlogon' `
    -IdentityFields @('Name') `
    -ComparedFields @('Value') `
    -FalsePositives 'Some EDR and MFA packages change Userinit or Shell. Compare to the role image, not a busy analyst workstation.' `
    -Collect {
        $names = @(
            'Userinit', 'Shell', 'System', 'UIHost', 'GinaDLL', 'Taskman',
            'ShellInfrastructure', 'VmApplet', 'AutoRestartShell'
        )
        $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $rows = @()
        foreach ($n in $names) {
            $val = Get-FotonRegValue -Path $key -Name $n
            $shown = '(not set)'
            if ($null -ne $val -and [string]$val -ne '') { $shown = [string]$val }
            $rows += [PSCustomObject]@{
                Name  = $n
                Value = $shown
            }
        }
        $rows | Sort-Object Name
    }

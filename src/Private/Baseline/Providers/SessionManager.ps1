# SessionManager - BootExecute and related SM MULTI_SZ, plus AppCertDlls.
# PendingFileRenameOperations is reboot-volatile and is not captured (Collect still lists it).
Register-FotonBaselineProvider -RecordType 'SessionManager' `
    -IdentityFields @('Kind', 'Name') `
    -ComparedFields @('Value') `
    -FalsePositives 'autocheck autochk * is the usual BootExecute. Disk tools and some imaging agents add tokens. AppCertDlls is empty on most hosts; AV/EDR may register a DLL. PendingFileRenameOperations is intentionally omitted.' `
    -Collect {
        $rows = @()
        $joinVal = {
            param($Val)
            if ($null -eq $Val) { return '(not set)' }
            $parts = @()
            foreach ($x in @($Val)) {
                $s = [string]$x
                if ($s) { $parts += $s }
            }
            if ($parts.Count -eq 0) { return '(not set)' }
            return ($parts -join ' ')
        }
        $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        foreach ($n in @('BootExecute', 'BootExecuteNoPnpSync', 'SetupExecute', 'Execute', 'S0InitialCommand')) {
            $val = Get-FotonRegValue -Path $sm -Name $n
            $rows += [PSCustomObject]@{
                Kind  = 'SessionValue'
                Name  = $n
                Value = & $joinVal $val
            }
        }
        $ac = Join-Path $sm 'AppCertDlls'
        foreach ($v in (Get-FotonRegValueList -Path $ac)) {
            $rows += [PSCustomObject]@{
                Kind  = 'AppCertDlls'
                Name  = [string]$v.Name
                Value = [string]$v.Value
            }
        }
        $rows | Sort-Object Kind, Name
    }

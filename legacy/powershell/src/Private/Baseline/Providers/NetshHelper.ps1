# NetshHelper - HKLM NetSh helper DLL map (T1546.007). Value name is the helper; data is the DLL.
Register-FotonBaselineProvider -RecordType 'NetshHelper' `
    -IdentityFields @('Key', 'Name') `
    -ComparedFields @('Dll') `
    -FalsePositives 'Inbox helpers (dhcpmon, fwmon, rasmontr, wshelper) are normal. VPN/EDR/third-party stacks add helpers. Wow6432Node is a separate Key.' `
    -Collect {
        $rows = @()
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\NetSh',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh'
        )
        foreach ($root in $roots) {
            foreach ($v in (Get-FotonRegValueList -Path $root)) {
                if (-not $v.Name -or $v.Name -eq '(default)') { continue }
                $dll = [string]$v.Value
                if (-not $dll) { $dll = '(not set)' }
                $rows += [PSCustomObject]@{
                    Key  = $root
                    Name = [string]$v.Name
                    Dll  = $dll
                }
            }
        }
        $rows | Sort-Object Key, Name
    }

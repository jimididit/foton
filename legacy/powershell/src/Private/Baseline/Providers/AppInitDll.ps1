# AppInitDll - AppInit_DLLs / LoadAppInit_DLLs (native and Wow64). Empty strings are still rows so an added DLL is Modified, not a missing type.
Register-FotonBaselineProvider -RecordType 'AppInitDll' `
    -IdentityFields @('Key', 'Name') `
    -ComparedFields @('Value') `
    -FalsePositives 'Legacy AV and some graphics injectors still use AppInit. LoadAppInit_DLLs=0 with an empty DLL list is the usual modern default.' `
    -Collect {
        $rows = @()
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        )
        $names = @('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs')
        foreach ($k in $keys) {
            foreach ($n in $names) {
                $val = Get-FotonRegValue -Path $k -Name $n
                $shown = '(not set)'
                if ($null -ne $val) { $shown = [string]$val }
                $rows += [PSCustomObject]@{
                    Key   = $k
                    Name  = $n
                    Value = $shown
                }
            }
        }
        $rows | Sort-Object Key, Name
    }

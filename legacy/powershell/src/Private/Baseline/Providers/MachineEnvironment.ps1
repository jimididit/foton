# MachineEnvironment - HKLM Session Manager Environment. Identity value name. PATH edits are High; installers appending Path is a common false positive.
Register-FotonBaselineProvider -RecordType 'MachineEnvironment' `
    -IdentityFields @('Name') `
    -ComparedFields @('Value') `
    -FalsePositives 'Installers and Visual Studio/Java/Python append Path. TEMP/TMP and NUMBER_OF_PROCESSORS can differ by hardware or user TEMP policy.' `
    -Collect {
        $rows = @()
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        foreach ($v in (Get-FotonRegValueList -Path $key)) {
            $val = $v.Value
            if ($val -is [System.Array]) {
                $val = (@($val | ForEach-Object { [string]$_ }) -join ';')
            }
            $rows += [PSCustomObject]@{
                Name  = [string]$v.Name
                Value = [string]$val
            }
        }
        $rows | Sort-Object Name
    }

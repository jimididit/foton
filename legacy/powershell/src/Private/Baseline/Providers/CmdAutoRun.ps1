# CmdAutoRun - cmd.exe HKLM/HKCU Command Processor AutoRun. PowerShell does not read this key.
# HKLM rows always exist (including (not set)). HKCU only when set, loaded hives only.
Register-FotonBaselineProvider -RecordType 'CmdAutoRun' `
    -IdentityFields @('Hive', 'Key') `
    -ComparedFields @('Command') `
    -FalsePositives 'IT shops set AutoRun for doskey, clink, or conda hooks. That is a Command change, not malware by itself. Empty HKCU is omitted so logon/logoff does not churn (not set) rows.' `
    -Collect {
        $rows = @()
        $relKeys = @(
            'SOFTWARE\Microsoft\Command Processor',
            'SOFTWARE\Wow6432Node\Microsoft\Command Processor'
        )
        foreach ($rel in $relKeys) {
            $path = 'HKLM:\' + $rel
            $emit = $true
            if ($rel -like '*Wow6432Node*' -and -not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Wow6432Node')) {
                $emit = $false
            }
            if ($emit) {
                $val = Get-FotonRegValue -Path $path -Name 'AutoRun'
                $shown = '(not set)'
                if ($null -ne $val -and [string]$val -ne '') { $shown = [string]$val }
                $rows += [PSCustomObject]@{
                    Hive    = 'HKLM'
                    Key     = $rel
                    Command = $shown
                }
            }
        }
        foreach ($h in @(Get-FotonUserHiveRoot)) {
            foreach ($rel in @(
                    'Software\Microsoft\Command Processor',
                    'Software\Wow6432Node\Microsoft\Command Processor'
                )) {
                $full = Join-Path $h.Root $rel
                $val = Get-FotonRegValue -Path $full -Name 'AutoRun'
                if ($null -eq $val -or [string]$val -eq '') { continue }
                $rows += [PSCustomObject]@{
                    Hive    = [string]$h.SID
                    Key     = $rel
                    Command = [string]$val
                }
            }
        }
        $rows | Sort-Object Hive, Key
    }

# SystemBinary - identity leaf name under System32. Hash change of these files is High attention; Windows Update is the usual benign source.
Register-FotonBaselineProvider -RecordType 'SystemBinary' `
    -IdentityFields @('Name') `
    -ComparedFields @('Sha256', 'Length') `
    -FalsePositives 'Patch Tuesday and servicing stack replace these binaries. Missing optional files (pwsh.exe) appear as Added when first installed, not as FileNotFound rows.' `
    -Collect {
        $names = @(
            'ntdll.dll', 'kernel32.dll', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
            'lsass.exe', 'services.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe',
            'explorer.exe', 'userinit.exe', 'svchost.exe', 'conhost.exe',
            'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
            'mmc.exe', 'netsh.exe', 'taskhostw.exe'
        )
        $root = Join-Path $env:SystemRoot 'System32'
        $rows = @()
        foreach ($n in $names) {
            $p = Join-Path $root $n
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
            $item = $null
            try { $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop } catch { }
            $len = ''
            if ($item) { $len = [string]$item.Length }
            $rows += [PSCustomObject]@{
                Name   = $n
                Path   = $p
                Length = $len
                Sha256 = Get-FotonSafeHash -Path $p
            }
        }
        $rows | Sort-Object Name
    }

# PrintMonitor - HKLM Print\Monitors subkeys. Identity monitor Name; compared Driver DLL.
# Spooler loads these as SYSTEM. FP: vendor printer installs (HP, Canon, TCP/IP port).
Register-FotonBaselineProvider -RecordType 'PrintMonitor' `
    -IdentityFields @('Name') `
    -ComparedFields @('Driver') `
    -FalsePositives 'Installing a printer or print server role adds Standard TCP/IP Port, WSD, and vendor monitors. A new Driver DLL under an unexpected Name is the review item, not Local Port.' `
    -Collect {
        $rows = @()
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
        if (-not (Test-Path -LiteralPath $root)) { return @() }
        try {
            foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                $name = [string]$sub.PSChildName
                if (-not $name) { continue }
                $drv = Get-FotonRegValue -Path $sub.PSPath -Name 'Driver'
                $shown = '(not set)'
                if ($null -ne $drv -and [string]$drv -ne '') { $shown = [string]$drv }
                $rows += [PSCustomObject]@{
                    Name   = $name
                    Driver = $shown
                }
            }
        }
        catch { }
        $rows | Sort-Object Name
    }

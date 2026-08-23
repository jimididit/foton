# ActiveSetup - HKLM Installed Components only (StubPath). Per-user "already run" keys churn on logon.
Register-FotonBaselineProvider -RecordType 'ActiveSetup' `
    -IdentityFields @('Key', 'Guid') `
    -ComparedFields @('StubPath', 'Version', 'IsInstalled') `
    -FalsePositives 'Office, browsers, and runtimes add GUIDs and bump Version. StubPath changing to a user-writable binary is the review item. HKCU once-per-user stamps are Collect-only.' `
    -Collect {
        $rows = @()
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components'
        )
        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            try {
                foreach ($sub in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
                    $guid = [string]$sub.PSChildName
                    if (-not $guid) { continue }
                    $stub = Get-FotonRegValue -Path $sub.PSPath -Name 'StubPath'
                    $ver = Get-FotonRegValue -Path $sub.PSPath -Name 'Version'
                    $inst = Get-FotonRegValue -Path $sub.PSPath -Name 'IsInstalled'
                    $stubS = '(not set)'
                    if ($null -ne $stub -and [string]$stub -ne '') { $stubS = [string]$stub }
                    $verS = '(not set)'
                    if ($null -ne $ver -and [string]$ver -ne '') { $verS = [string]$ver }
                    $instS = '(not set)'
                    if ($null -ne $inst -and [string]$inst -ne '') { $instS = [string]$inst }
                    $rows += [PSCustomObject]@{
                        Key         = $root
                        Guid        = $guid
                        StubPath    = $stubS
                        Version     = $verS
                        IsInstalled = $instS
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object Key, Guid
    }

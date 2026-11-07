# InstalledSoftware - identity DisplayName + Publisher (version is compared, not identity).
Register-FotonBaselineProvider -RecordType 'InstalledSoftware' `
    -IdentityFields @('DisplayName', 'Publisher') `
    -ComparedFields @('DisplayVersion', 'InstallLocation') `
    -FalsePositives 'Patch Tuesday and in-place upgrades change DisplayVersion. Publisher string is not stable across all MSI packages.' `
    -Collect {
        $rows = @()
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($p in $paths) {
            try {
                Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
                    if (-not $_.DisplayName) { return }
                    $rows += [PSCustomObject]@{
                        DisplayName     = [string]$_.DisplayName
                        Publisher       = [string]$_.Publisher
                        DisplayVersion  = [string]$_.DisplayVersion
                        InstallLocation = [string]$_.InstallLocation
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object DisplayName, Publisher
    }

# Invoke-FotonSoftwareCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint collect. Rebuild dist/Foton-Collect.ps1 after edits.

function Invoke-FotonSoftwareCollection {
    Write-FotonStatus 'Collecting installed software, drivers, and browser extensions' 'Step'

    Invoke-FotonCollection -Category 'Software' -Name 'installed_software' -Format 'Csv' -Description 'Installed programs from all registry views' -Script {
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
                        Scope           = 'Machine'
                        User            = ''
                        DisplayName     = $_.DisplayName
                        DisplayVersion  = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        UninstallString = $_.UninstallString
                    }
                }
            }
            catch { }
        }
        foreach ($hiveRoot in (Get-FotonUserHiveRoot)) {
            $up = Join-Path $hiveRoot.Root 'Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            try {
                Get-ItemProperty -Path $up -ErrorAction SilentlyContinue | ForEach-Object {
                    if (-not $_.DisplayName) { return }
                    $rows += [PSCustomObject]@{
                        Scope           = 'User'
                        User            = $hiveRoot.UserName
                        DisplayName     = $_.DisplayName
                        DisplayVersion  = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        UninstallString = $_.UninstallString
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object DisplayName
    } | Out-Null

    Invoke-FotonCollection -Category 'Software' -Name 'drivers' -Format 'Csv' -Description 'Kernel and file system drivers with signature state' -Script {
        $rows = @()
        foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
            $path = $d.PathName
            if ($path) { $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"')) }
            $sig = Get-FotonSignatureInfo -Path $path
            $rows += [PSCustomObject]@{
                Name            = $d.Name
                DisplayName     = $d.DisplayName
                State           = $d.State
                StartMode       = $d.StartMode
                PathName        = $path
                SignatureStatus = $sig.Status
                Signer          = $sig.Signer
                SHA256          = (Get-FotonSafeHash -Path $path)
            }
        }
        $rows | Sort-Object Name
    } | Out-Null

    Invoke-FotonCollection -Category 'Software' -Name 'browser_extensions' -Format 'Csv' -Description 'Chromium-family extension folders and Firefox profile add-ons' -Script {
        $rows = @()
        $browsers = @(
            @{ Name = 'Chrome'; Sub = 'AppData\Local\Google\Chrome\User Data' },
            @{ Name = 'Edge'; Sub = 'AppData\Local\Microsoft\Edge\User Data' },
            @{ Name = 'Brave'; Sub = 'AppData\Local\BraveSoftware\Brave-Browser\User Data' }
        )
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            foreach ($b in $browsers) {
                $base = Join-Path $userProfile.ProfilePath $b.Sub
                if (-not (Test-Path -LiteralPath $base)) { continue }
                foreach ($bp in (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
                    $extDir = Join-Path $bp.FullName 'Extensions'
                    if (-not (Test-Path -LiteralPath $extDir)) { continue }
                    foreach ($ext in (Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue)) {
                        $name = ''
                        $version = ''
                        $perms = ''
                        try {
                            $manifest = Get-ChildItem -LiteralPath $ext.FullName -Recurse -Filter 'manifest.json' -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($manifest) {
                                $json = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                                $name = [string]$json.name
                                $version = [string]$json.version
                                if ($json.permissions) { $perms = ($json.permissions -join ', ') }
                            }
                        }
                        catch { }
                        $rows += [PSCustomObject]@{
                            User          = $userProfile.UserName
                            Browser       = $b.Name
                            BrowserProfile = $bp.Name
                            ExtensionId   = $ext.Name
                            Name          = $name
                            Version       = $version
                            Permissions   = $perms
                            InstalledUtc  = $ext.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    }
                }
            }
            $ffBase = Join-Path $userProfile.ProfilePath 'AppData\Roaming\Mozilla\Firefox\Profiles'
            if (Test-Path -LiteralPath $ffBase) {
                foreach ($fp in (Get-ChildItem -LiteralPath $ffBase -Directory -ErrorAction SilentlyContinue)) {
                    $extPath = Join-Path $fp.FullName 'extensions'
                    if (-not (Test-Path -LiteralPath $extPath)) { continue }
                    foreach ($x in (Get-ChildItem -LiteralPath $extPath -ErrorAction SilentlyContinue)) {
                        $rows += [PSCustomObject]@{
                            User = $userProfile.UserName; Browser = 'Firefox'; BrowserProfile = $fp.Name
                            ExtensionId = $x.Name; Name = ''; Version = ''; Permissions = ''
                            InstalledUtc = $x.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        }
                    }
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Software' -Name 'remote_access_tool_indicators' -Format 'Csv' -Description 'Presence of common remote access / tunneling tooling' -Script {
        $known = @($script:FotonSession.RemoteAccessToolNames)
        $rows = @()
        $installed = $script:FotonSession.Data['installed_software']
        foreach ($app in $installed) {
            $n = ("{0} {1}" -f $app.DisplayName, $app.Publisher).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'InstalledSoftware'; Match = $k; Detail = $app.DisplayName
                        Publisher = $app.Publisher; Extra = $app.InstallLocation
                    }
                    break
                }
            }
        }
        $procs = $script:FotonSession.Data['running_processes']
        foreach ($p in $procs) {
            $n = ("{0} {1}" -f $p.Name, $p.Path).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'RunningProcess'; Match = $k; Detail = $p.Name
                        Publisher = $p.Signer; Extra = $p.Path
                    }
                    break
                }
            }
        }
        $svcs = $script:FotonSession.Data['services']
        foreach ($s in $svcs) {
            $n = ("{0} {1} {2}" -f $s.Name, $s.DisplayName, $s.PathName).ToLower()
            foreach ($k in $known) {
                if ($n.Contains($k)) {
                    $rows += [PSCustomObject]@{
                        Source = 'Service'; Match = $k; Detail = $s.DisplayName
                        Publisher = $s.Signer; Extra = $s.PathName
                    }
                    break
                }
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Software' -Name 'appx_packages' -Format 'Csv' -Description 'Installed Store/AppX packages' -Script {
        # -AllUsers requires elevation. Standard-user coverage is this token's packages only.
        if ($script:FotonSession.IsElevated) {
            Get-AppxPackage -AllUsers -ErrorAction Stop |
                Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, SignatureKind, Status
        }
        else {
            Get-AppxPackage -ErrorAction Stop |
                Select-Object Name, PackageFullName, Publisher, Version, InstallLocation, SignatureKind, Status
        }
    } | Out-Null
}

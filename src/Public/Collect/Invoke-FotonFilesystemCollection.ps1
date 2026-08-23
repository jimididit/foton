# Invoke-FotonFilesystemCollection
# Live facts only. Called from Invoke-FotonTriage when that exists.
# Endpoint collect. Rebuild dist/Foton-Collect.ps1 after edits.

function Invoke-FotonFilesystemCollection {
    Write-FotonStatus 'Collecting filesystem artifacts, execution evidence, and device history' 'Step'

    Invoke-FotonCollection -Category 'Filesystem' -Name 'executables_in_user_writable_paths' -Format 'Csv' -Description 'Executable content in temp/appdata/programdata/public paths' -Script {
        $roots = @("$env:SystemRoot\Temp", "$env:ProgramData", "$env:PUBLIC")
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Local\Temp')
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Roaming')
            $roots += (Join-Path $userProfile.ProfilePath 'Downloads')
            $roots += (Join-Path $userProfile.ProfilePath 'Desktop')
        }
        $depth = 3
        if ($script:FotonSession.IncludeFileTimeline) { $depth = 6 }
        $exts = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf', '.hta', '.scr', '.jar', '.lnk', '.msi', '.sys', '.com', '.pif')
        $rows = @()
        foreach ($r in ($roots | Sort-Object -Unique)) {
            if (-not (Test-FotonPathAccessible -Path $r)) { continue }
            try {
                $files = Get-ChildItem -LiteralPath $r -Recurse -File -Force -Depth $depth -ErrorAction SilentlyContinue |
                    Where-Object { $exts -contains $_.Extension.ToLower() }
                foreach ($f in $files) {
                    $sig = Get-FotonSignatureInfo -Path $f.FullName
                    $rows += [PSCustomObject]@{
                        Path            = $f.FullName
                        SizeBytes       = $f.Length
                        CreatedUtc      = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        ModifiedUtc     = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        AccessedUtc     = $f.LastAccessTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        Extension       = $f.Extension
                        SignatureStatus = $sig.Status
                        Signer          = $sig.Signer
                        SHA256          = (Get-FotonSafeHash -Path $f.FullName)
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'recently_modified_system_files' -Format 'Csv' -Description 'System32/SysWOW64 binaries modified inside the collection window' -Script {
        $cutoff = (Get-Date).AddDays(-1 * $script:FotonSession.EventLogDays)
        $rows = @()
        foreach ($dir in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            try {
                Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Extension -match '\.(exe|dll|sys|ps1|bat|cmd)$' } |
                    ForEach-Object {
                        $sig = Get-FotonSignatureInfo -Path $_.FullName
                        $rows += [PSCustomObject]@{
                            Path            = $_.FullName
                            SizeBytes       = $_.Length
                            ModifiedUtc     = $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                            CreatedUtc      = $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                            SignatureStatus = $sig.Status
                            SHA256          = (Get-FotonSafeHash -Path $_.FullName)
                        }
                    }
            }
            catch { }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'prefetch_listing' -Format 'Csv' -Description 'Prefetch entries (execution evidence, names and timestamps only)' -RequiresElevation -Script {
        $pf = "$env:SystemRoot\Prefetch"
        if (-not (Test-Path -LiteralPath $pf)) { return @() }
        Get-ChildItem -LiteralPath $pf -Filter '*.pf' -Force -ErrorAction SilentlyContinue |
            Select-Object Name, Length,
            @{n = 'CreatedUtc'; e = { $_.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } },
            @{n = 'LastRunUtc_FileWrite'; e = { $_.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') } } |
            Sort-Object LastRunUtc_FileWrite -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'prefetch_files' -Format 'Csv' -Description 'Copied Prefetch .pf files (capped; parse these, not the live directory)' -RequiresElevation -Script {
        $pf = "$env:SystemRoot\Prefetch"
        $dest = Join-Path $script:FotonSession.Dirs['Filesystem'] 'prefetch'
        $rel = Join-Path $script:FotonSession.Categories['Filesystem'] 'prefetch'
        Copy-FotonCappedHostFiles -SourceDirectory $pf -Filter '*.pf' -DestinationDirectory $dest -PackageRelativeDirectory $rel
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'amcache_hive' -Format 'Csv' -Description 'Copied Amcache.hve plus hive logs (locked-file copy)' -RequiresElevation -Script {
        $src = Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
        $dest = Join-Path $script:FotonSession.Dirs['Filesystem'] 'amcache'
        $rel = Join-Path $script:FotonSession.Categories['Filesystem'] 'amcache'
        Copy-FotonHostFileFamily -SourcePath $src -DestinationDirectory $dest -PackageRelativeDirectory $rel
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'srum_database' -Format 'Csv' -Description 'Copied SRUDB.dat plus WAL/SHM if present (capped; locked-file copy)' -RequiresElevation -Script {
        $src = Join-Path $env:ProgramData 'Microsoft\Windows\SRUM\SRUDB.dat'
        $dest = Join-Path $script:FotonSession.Dirs['Filesystem'] 'srum'
        $rel = Join-Path $script:FotonSession.Categories['Filesystem'] 'srum'
        Copy-FotonHostFileFamily -SourcePath $src -DestinationDirectory $dest -PackageRelativeDirectory $rel -MaxTotalBytes 104857600
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'alternate_data_streams' -Format 'Csv' -Description 'Non-default NTFS streams in user paths (Zone.Identifier and beyond)' -Script {
        $rows = @()
        $roots = @("$env:PUBLIC")
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $roots += (Join-Path $userProfile.ProfilePath 'Downloads')
            $roots += (Join-Path $userProfile.ProfilePath 'Desktop')
            $roots += (Join-Path $userProfile.ProfilePath 'AppData\Local\Temp')
        }
        foreach ($r in ($roots | Sort-Object -Unique)) {
            if (-not (Test-FotonPathAccessible -Path $r)) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Force -Depth 3 -ErrorAction SilentlyContinue)) {
                    try {
                        foreach ($s in (Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction Stop)) {
                            if ($s.Stream -eq ':$DATA') { continue }
                            $content = ''
                            if ($s.Length -lt 4096) {
                                try { $content = ((Get-Content -LiteralPath $f.FullName -Stream $s.Stream -ErrorAction Stop) -join ' | ') } catch { }
                            }
                            $rows += [PSCustomObject]@{
                                File       = $f.FullName
                                Stream     = $s.Stream
                                LengthBytes = $s.Length
                                Content    = $content
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'recycle_bin_contents' -Format 'Csv' -Description 'Deleted items still present in $Recycle.Bin per SID' -Script {
        $rows = @()
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            $rb = Join-Path $drive.Root '$Recycle.Bin'
            if (-not (Test-Path -LiteralPath $rb)) { continue }
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $rb -Recurse -File -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{
                        Drive       = $drive.Root
                        SidFolder   = (Split-Path (Split-Path $f.FullName -Parent) -Leaf)
                        FileName    = $f.Name
                        SizeBytes   = $f.Length
                        DeletedUtc  = $f.CreationTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        FullName    = $f.FullName
                    }
                }
            }
            catch { }
        }
        $rows | Sort-Object DeletedUtc -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'usb_device_history' -Format 'Csv' -Description 'USBSTOR entries and mounted device history (exfiltration pivot)' -Script {
        $rows = @()
        $usbstor = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-Path -LiteralPath $usbstor) {
            foreach ($dev in (Get-ChildItem -LiteralPath $usbstor -ErrorAction SilentlyContinue)) {
                foreach ($inst in (Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
                    $friendly = Get-FotonRegValue -Path $inst.PSPath -Name 'FriendlyName'
                    $rows += [PSCustomObject]@{
                        Source       = 'USBSTOR'
                        Device       = (Split-Path $dev.Name -Leaf)
                        SerialOrId   = (Split-Path $inst.Name -Leaf)
                        FriendlyName = [string]$friendly
                        Value        = ''
                    }
                }
            }
        }
        foreach ($v in (Get-FotonRegValueList -Path 'HKLM:\SYSTEM\MountedDevices')) {
            $rows += [PSCustomObject]@{ Source = 'MountedDevices'; Device = $v.Name; SerialOrId = ''; FriendlyName = ''; Value = $v.Value }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'shortcut_and_jumplist_inventory' -Format 'Csv' -Description 'Recent LNK and jump list files (file access evidence)' -Script {
        $rows = @()
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $paths = @(
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent'),
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'),
                (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations')
            )
            foreach ($p in $paths) {
                if (-not (Test-FotonPathAccessible -Path $p)) { continue }
                foreach ($f in (Get-ChildItem -LiteralPath $p -File -Force -ErrorAction SilentlyContinue)) {
                    $rows += [PSCustomObject]@{
                        User        = $userProfile.UserName
                        Folder      = (Split-Path $p -Leaf)
                        Name        = $f.Name
                        SizeBytes   = $f.Length
                        ModifiedUtc = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                        FullName    = $f.FullName
                    }
                }
            }
        }
        $rows | Sort-Object ModifiedUtc -Descending
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'hidden_or_odd_root_items' -Format 'Csv' -Description 'Hidden or unexpected items at drive roots and ProgramData' -Script {
        $rows = @()
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
            try {
                foreach ($i in (Get-ChildItem -LiteralPath $drive.Root -Force -ErrorAction SilentlyContinue)) {
                    $isHidden = ($i.Attributes -band [IO.FileAttributes]::Hidden) -ne 0
                    if (-not $isHidden) { continue }
                    $rows += [PSCustomObject]@{
                        Location    = $drive.Root
                        Name        = $i.Name
                        IsDirectory = $i.PSIsContainer
                        Attributes  = [string]$i.Attributes
                        ModifiedUtc = $i.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                }
            }
            catch { }
        }
        $rows
    } | Out-Null
}

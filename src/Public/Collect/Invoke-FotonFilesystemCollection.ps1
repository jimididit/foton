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
                    Where-Object { $exts -contains $_.Extension.ToLower() -and -not (Test-FotonCaseOutputPath -Path $_.FullName) }
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

    Invoke-FotonCollection -Category 'Filesystem' -Name 'registry_hives_machine' -Format 'Csv' -Description 'SYSTEM/SOFTWARE/DEFAULT hives exported with reg save (loaded hives cannot be file-copied; not parsed on the endpoint). SAM and SECURITY are not collected by design. For RECmd / Registry Explorer.' -RequiresElevation -Script {
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'hives\machine'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'hives\machine'
        $rows = @()
        foreach ($h in @(
                @{ Key = 'HKLM\SYSTEM'; File = 'SYSTEM' },
                @{ Key = 'HKLM\SOFTWARE'; File = 'SOFTWARE' },
                @{ Key = 'HKU\.DEFAULT'; File = 'DEFAULT' })) {
            $rows += Save-FotonRegistryHive -RegistryPath $h.Key -DestinationPath (Join-Path $destRoot $h.File) `
                -PackageRelativePath (Join-Path $relRoot $h.File)
        }
        # SAM and SECURITY hold credential material (local password hashes, LSA
        # secrets). Exporting them is the textbook credential-theft step, so EDR and
        # AMSI treat it as such; the account and policy facts Foton needs come from
        # live queries instead. Recorded as a disclosed gap, not silently omitted.
        foreach ($name in @('SAM', 'SECURITY')) {
            $rows += [PSCustomObject]@{
                SourcePath   = "HKLM\$name"
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'NotCollectedByDesign'
                Note         = 'Credential hive. Not exported: it holds password hashes / LSA secrets and exporting it matches credential-theft detections. Use a full image or KAPE if the case needs it.'
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'registry_hives_user' -Format 'Csv' -Description 'NTUSER.DAT and UsrClass.dat per profile: file copy for unloaded hives, reg save for loaded ones (capped; not parsed on the endpoint).' -RequiresElevation -Script {
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'hives\users'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'hives\users'
        $rows = @()
        $budget = [int64]209715200
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $seg = Get-FotonSafePathSegment -Name $userProfile.UserName
            $userDest = Join-Path $destRoot $seg
            $userRel = Join-Path $relRoot $seg
            $hives = @(
                @{ Src = (Join-Path $userProfile.ProfilePath 'NTUSER.DAT'); Key = ('HKU\{0}' -f $userProfile.SID); File = 'NTUSER.DAT' },
                @{ Src = (Join-Path $userProfile.ProfilePath 'AppData\Local\Microsoft\Windows\UsrClass.dat'); Key = ('HKU\{0}_Classes' -f $userProfile.SID); File = 'UsrClass.dat' }
            )
            foreach ($h in $hives) {
                if ($budget -le 0) { break }
                $fam = @(Copy-FotonHostFileFamily -SourcePath $h.Src -DestinationDirectory $userDest -PackageRelativeDirectory $userRel -MaxTotalBytes $budget)
                $primary = $fam | Where-Object { [IO.Path]::GetFileName([string]$_.SourcePath) -eq $h.File } | Select-Object -First 1
                # A signed-in user's hive is loaded and locked exactly like the machine
                # hives. Fall back to reg save of the loaded key; the copied sidecars
                # (.LOG*, .regtrans-ms) stay in the package as context.
                if ($primary -and $primary.Status -eq 'CopyError' -and $userProfile.HiveLoaded -and
                    (Test-FotonPathAccessible -Path ('Registry::HKEY_USERS\{0}' -f ($h.Key -replace '^HKU\\', '')))) {
                    $saved = Save-FotonRegistryHive -RegistryPath $h.Key -DestinationPath (Join-Path $userDest $h.File) `
                        -PackageRelativePath (Join-Path $userRel $h.File)
                    $rest = @($fam | Where-Object { $_ -ne $primary })
                    if ($saved.Status -eq 'Saved') {
                        # Locked .LOG sidecars are moot once the hive is exported whole.
                        foreach ($r in $rest) {
                            if ($r.Status -eq 'CopyError') {
                                $r.Status = 'SupersededBySave'
                                $r.Note = 'Locked transaction log of a loaded hive; the reg save export already includes its changes.'
                            }
                        }
                    }
                    $fam = $rest + @($saved)
                }
                $rows += $fam
                foreach ($r in $fam) {
                    if ($r.Status -in @('Copied', 'Saved')) { $budget = $budget - [int64]$r.SizeBytes }
                }
            }
        }
        if ($rows.Count -eq 0) {
            return @([PSCustomObject]@{
                    SourcePath = ''; DestRelative = ''; SizeBytes = 0; SHA256 = ''; Status = 'NoData'
                    Note       = 'No profile hives were copied. Standard-user collect skips other users; missing NTUSER is a visibility gap.'
                })
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'usn_journal' -Format 'Csv' -Description 'USN queryjournal metadata; optional $J copy when -IncludeUsnJournal is set. $MFT is not copied (use KAPE/ORC).' -RequiresElevation -Script {
        $destDir = Join-Path $script:FotonSession.Dirs['Filesystem'] 'usn'
        $rel = Join-Path $script:FotonSession.Categories['Filesystem'] 'usn'
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        $rows = @()
        $drive = $env:SystemDrive
        if (-not $drive) { $drive = 'C:' }
        $metaPath = Join-Path $destDir 'usn_queryjournal.txt'
        try {
            $out = & fsutil.exe usn queryjournal $drive 2>&1 | Out-String
            Set-Content -LiteralPath $metaPath -Value $out -Encoding UTF8
            $hash = Get-FotonSafeHash -Path $metaPath
            $len = (Get-Item -LiteralPath $metaPath).Length
            $rows += [PSCustomObject]@{
                SourcePath = ("fsutil usn queryjournal {0}" -f $drive)
                DestRelative = (Join-Path $rel 'usn_queryjournal.txt')
                SizeBytes  = $len
                SHA256     = $hash
                Status     = 'Copied'
                Note       = 'Journal metadata only. Not a full USN parse.'
            }
        }
        catch {
            $rows += [PSCustomObject]@{
                SourcePath = ("fsutil usn queryjournal {0}" -f $drive)
                DestRelative = ''
                SizeBytes  = 0
                SHA256     = ''
                Status     = 'CopyError'
                Note       = $_.Exception.Message
            }
        }
        if ($script:FotonSession.IncludeUsnJournal) {
            $jPath = Join-Path $drive '\$Extend\$UsnJrnl:$J'
            $jDest = Join-Path $destDir 'UsnJrnl_J.bin'
            $copy = Copy-FotonHostFile -SourcePath $jPath -DestinationPath $jDest
            $jRel = Join-Path $rel 'UsnJrnl_J.bin'
            $note = $copy.Note
            if ($copy.Status -ne 'Copied') {
                $note = 'Optional $J copy failed or is unsupported on this volume. Use KAPE/ORC for USN. ' + [string]$copy.Note
            }
            $rows += [PSCustomObject]@{
                SourcePath   = $jPath
                DestRelative = $jRel
                SizeBytes    = $copy.SizeBytes
                SHA256       = $copy.SHA256
                Status       = $copy.Status
                Note         = $note
            }
        }
        else {
            $rows += [PSCustomObject]@{
                SourcePath   = '$Extend\$UsnJrnl:$J'
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'Skipped'
                Note         = 'Full USN $J copy is off by default (size). Re-collect with -IncludeUsnJournal. $MFT is never copied by Foton.'
            }
        }
        $rows
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'bam_dam_user_settings' -Format 'Csv' -Description 'BAM/DAM UserSettings (path = value name; FILETIME in data). Admin. Not a baseline.' -RequiresElevation -Script {
        $rows = @()
        $pairs = @(
            @{ Kind = 'BAM'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' },
            @{ Kind = 'BAM'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' },
            @{ Kind = 'DAM'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings' },
            @{ Kind = 'DAM'; Root = 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\UserSettings' }
        )
        foreach ($p in $pairs) {
            $rows += @(Get-FotonBamDamRows -Kind $p.Kind -Root $p.Root)
        }
        $seen = @{}
        $out = @()
        foreach ($r in $rows) {
            $k = '{0}|{1}|{2}' -f $r.Kind, $r.SID, $r.Path
            if ($seen.ContainsKey($k)) { continue }
            $seen[$k] = $true
            $out += $r
        }
        $out | Sort-Object Kind, SID, Path
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'appcompatcache_export' -Format 'Csv' -Description 'Raw AppCompatCache (Shimcache) blob copied into the package; entries are not parsed' -RequiresElevation -Script {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
        $blob = Get-FotonRegValue -Path $key -Name 'AppCompatCache'
        $destDir = Join-Path $script:FotonSession.Dirs['Filesystem'] 'appcompat'
        $dest = Join-Path $destDir 'AppCompatCache.bin'
        $row = [PSCustomObject]@{
            SourceKey  = $key
            DestName   = 'AppCompatCache.bin'
            SizeBytes  = 0
            SHA256     = ''
            Status     = 'Missing'
            HeaderHex  = ''
            Note       = ''
        }
        if ($null -eq $blob) {
            $row.Note = 'AppCompatCache value not present or not readable. Visibility gap, not proof Shimcache was empty.'
            return @($row)
        }
        $bytes = $null
        if ($blob -is [byte[]]) { $bytes = $blob }
        else {
            try { $bytes = [byte[]]$blob } catch { }
        }
        if ($null -eq $bytes -or $bytes.Length -eq 0) {
            $row.Status = 'CopyError'
            $row.Note = 'Value was not REG_BINARY. Structured Shimcache parse was not attempted.'
            return @($row)
        }
        try {
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            [IO.File]::WriteAllBytes($dest, $bytes)
            $item = Get-Item -LiteralPath $dest -Force -ErrorAction Stop
            $n = [Math]::Min(8, $bytes.Length)
            $hdr = New-Object byte[] $n
            [Array]::Copy($bytes, $hdr, $n)
            $row.SizeBytes = $item.Length
            $row.SHA256 = Get-FotonSafeHash -Path $dest
            $row.Status = 'Copied'
            $row.HeaderHex = ([BitConverter]::ToString($hdr) -replace '-', '').ToLowerInvariant()
            $row.Note = 'Raw blob at 08_Filesystem/appcompat/AppCompatCache.bin. Entry-level Shimcache parse is not implemented; wrong execution times would be worse than this export.'
        }
        catch {
            $row.Status = 'CopyError'
            $row.Note = $_.Exception.Message
        }
        @($row)
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
                    if (Test-FotonCaseOutputPath -Path $f.FullName) { continue }
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

    Invoke-FotonCollection -Category 'Filesystem' -Name 'shortcut_and_jumplist_files' -Format 'Csv' -Description 'Copied Recent .lnk and jumplist files (capped). Parse these copies, not the live profile.' -RequiresElevation -Script {
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'lnk_jumplist'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'lnk_jumplist'
        $items = @()
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $seg = Get-FotonSafePathSegment -Name $userProfile.UserName
            $spec = @(
                @{ Dir = (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent'); Filter = '*.lnk'; Folder = 'Recent' }
                @{ Dir = (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'); Filter = '*.automaticDestinations-ms'; Folder = 'AutomaticDestinations' }
                @{ Dir = (Join-Path $userProfile.ProfilePath 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'); Filter = '*.customDestinations-ms'; Folder = 'CustomDestinations' }
            )
            foreach ($s in $spec) {
                if (-not (Test-FotonPathAccessible -Path $s.Dir)) { continue }
                foreach ($f in (Get-ChildItem -LiteralPath $s.Dir -Filter $s.Filter -File -Force -ErrorAction SilentlyContinue)) {
                    $items += [PSCustomObject]@{
                        SourcePath   = $f.FullName
                        DestRelative = (Join-Path $seg (Join-Path $s.Folder $f.Name))
                    }
                }
            }
        }
        Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $destRoot -PackageRelativeDirectory $relRoot -MaxFiles 400 -MaxTotalBytes 83886080
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'scheduled_task_xml' -Format 'Csv' -Description 'Copied %SystemRoot%\System32\Tasks XML (capped). Complements the task CSV; not parsed on the endpoint.' -RequiresElevation -Script {
        $srcRoot = Join-Path $env:SystemRoot 'System32\Tasks'
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'task_xml'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'task_xml'
        $items = @()
        if (Test-Path -LiteralPath $srcRoot) {
            foreach ($f in (Get-ChildItem -LiteralPath $srcRoot -File -Recurse -Force -ErrorAction SilentlyContinue)) {
                $rel = $f.FullName.Substring($srcRoot.Length).TrimStart('\')
                $items += [PSCustomObject]@{ SourcePath = $f.FullName; DestRelative = $rel }
            }
        }
        Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $destRoot -PackageRelativeDirectory $relRoot -MaxFiles 500 -MaxTotalBytes 52428800
    } | Out-Null

    # Deep only: copy script bodies referenced by scheduled-task Actions (Accanto-shaped gap).
    if ($script:FotonSession.Deep) {
        Invoke-FotonCollection -Category 'Filesystem' -Name 'task_action_scripts' -Format 'Csv' -Description 'Deep: copied local script files referenced by scheduled-task Execute/Arguments (raised caps; UNC skipped; under 2 GiB free skips copy).' -Script {
            $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'task_scripts'
            $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'task_scripts'
            if (-not (Test-FotonDeepDiskBudget)) {
                return @([PSCustomObject]@{
                        SourcePath   = ''
                        DestRelative = ''
                        SizeBytes    = 0
                        SHA256       = ''
                        Status       = 'SkippedLowDisk'
                        Note         = 'Deep task-script copy skipped: output volume has under 2 GiB free. Visibility gap, not proof scripts were absent.'
                    })
            }
            $items = @()
            $preRows = New-Object System.Collections.ArrayList
            $seen = @{}
            try {
                foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
                    foreach ($a in @($t.Actions)) {
                        $exe = ''
                        $args = ''
                        if ($a.Execute) { $exe = [string]$a.Execute }
                        if ($a.Arguments) { $args = [string]$a.Arguments }
                        foreach ($p in (Get-FotonTaskActionScriptPath -Execute $exe -Arguments $args)) {
                            $key = $p.ToLowerInvariant()
                            if ($seen.ContainsKey($key)) { continue }
                            $seen[$key] = $true

                            # UNC: record and do not open (NTLM / remote auth).
                            if ($p.StartsWith('\\') -or $p.StartsWith('//')) {
                                $null = $preRows.Add([PSCustomObject]@{
                                        SourcePath   = $p
                                        DestRelative = ''
                                        SizeBytes    = 0
                                        SHA256       = ''
                                        Status       = 'SkippedUnc'
                                        Note         = 'UNC task-script path refused. Deep Collect does not follow remote paths (NTLM / network footprint).'
                                    })
                                continue
                            }

                            # Resolve .. and env-expanded quirks to a local full path.
                            $full = $null
                            try { $full = [IO.Path]::GetFullPath($p) } catch { continue }
                            if (-not $full -or $full -notmatch '^[A-Za-z]:\\') { continue }

                            # Keep drive letter in DestRelative so C:\a.ps1 and D:\a.ps1 do not collide.
                            # C:\Temp\x.ps1 -> C\Temp\x.ps1 (no colon; no ..).
                            $rel = $full.Substring(0, 1) + $full.Substring(2)
                            $rel = $rel -replace ':', '_'
                            if ($rel -match '(^|[\\/])\.\.([\\/]|$)') { continue }

                            $items += [PSCustomObject]@{ SourcePath = $full; DestRelative = $rel }
                        }
                    }
                }
            }
            catch { }
            $copyRows = @(Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $destRoot -PackageRelativeDirectory $relRoot -MaxFiles 10000 -MaxTotalBytes 1073741824)
            @($preRows) + @($copyRows)
        } | Out-Null
    }

    Invoke-FotonCollection -Category 'Filesystem' -Name 'browser_databases' -Format 'Csv' -Description 'Copied browser History/Cookies/places.sqlite (capped). No cookie decryption, no Graph. Locked files are coverage gaps.' -RequiresElevation -Script {
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'browser_db'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'browser_db'
        $items = @()
        foreach ($userProfile in (Get-FotonUserProfile)) {
            if (-not $userProfile.Exists) { continue }
            $seg = Get-FotonSafePathSegment -Name $userProfile.UserName
            $local = Join-Path $userProfile.ProfilePath 'AppData\Local'
            $roam = Join-Path $userProfile.ProfilePath 'AppData\Roaming'
            $candidates = @(
                (Join-Path $local 'Google\Chrome\User Data\Default\History'),
                (Join-Path $local 'Google\Chrome\User Data\Default\Cookies'),
                (Join-Path $local 'Google\Chrome\User Data\Default\Login Data'),
                (Join-Path $local 'Microsoft\Edge\User Data\Default\History'),
                (Join-Path $local 'Microsoft\Edge\User Data\Default\Cookies'),
                (Join-Path $local 'Microsoft\Edge\User Data\Default\Login Data'),
                (Join-Path $roam 'Mozilla\Firefox\Profiles')
            )
            foreach ($c in $candidates) {
                if ($c -like '*Firefox\Profiles') {
                    if (-not (Test-Path -LiteralPath $c)) { continue }
                    foreach ($ff in (Get-ChildItem -LiteralPath $c -Directory -ErrorAction SilentlyContinue)) {
                        foreach ($leaf in @('places.sqlite', 'cookies.sqlite')) {
                            $p = Join-Path $ff.FullName $leaf
                            if (Test-Path -LiteralPath $p -PathType Leaf) {
                                $items += [PSCustomObject]@{
                                    SourcePath   = $p
                                    DestRelative = (Join-Path $seg (Join-Path ('Firefox_' + $ff.Name) $leaf))
                                }
                            }
                        }
                    }
                    continue
                }
                if (Test-Path -LiteralPath $c -PathType Leaf) {
                    $brand = 'Chrome'
                    if ($c -match 'Microsoft\\Edge') { $brand = 'Edge' }
                    $items += [PSCustomObject]@{
                        SourcePath   = $c
                        DestRelative = (Join-Path $seg (Join-Path $brand ([IO.Path]::GetFileName($c))))
                    }
                }
            }
        }
        Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $destRoot -PackageRelativeDirectory $relRoot -MaxFiles 80 -MaxTotalBytes 104857600
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'host_text_logs' -Format 'Csv' -Description 'Copied setupapi.dev.log, CBS.log (capped), and PowerShell transcripts if the policy path exists.' -RequiresElevation -Script {
        $destRoot = Join-Path $script:FotonSession.Dirs['Filesystem'] 'host_logs'
        $relRoot = Join-Path $script:FotonSession.Categories['Filesystem'] 'host_logs'
        $items = @()
        $setup = Join-Path $env:SystemRoot 'inf\setupapi.dev.log'
        if (Test-Path -LiteralPath $setup) {
            $items += [PSCustomObject]@{ SourcePath = $setup; DestRelative = 'setupapi.dev.log' }
        }
        $cbs = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
        if (Test-Path -LiteralPath $cbs) {
            $items += [PSCustomObject]@{ SourcePath = $cbs; DestRelative = 'CBS.log' }
        }
        $tx = Get-FotonRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory'
        if ($tx -and (Test-Path -LiteralPath ([string]$tx))) {
            foreach ($f in (Get-ChildItem -LiteralPath ([string]$tx) -Filter '*.txt' -File -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 40)) {
                $items += [PSCustomObject]@{ SourcePath = $f.FullName; DestRelative = (Join-Path 'powershell_transcript' $f.Name) }
            }
        }
        $ci = Join-Path $env:SystemRoot 'System32\CodeIntegrity'
        if (Test-Path -LiteralPath $ci) {
            foreach ($f in (Get-ChildItem -LiteralPath $ci -Include '*.cip', '*.p7b', 'SiPolicy.p7b' -File -Force -ErrorAction SilentlyContinue)) {
                $items += [PSCustomObject]@{ SourcePath = $f.FullName; DestRelative = (Join-Path 'codeintegrity' $f.Name) }
            }
        }
        Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $destRoot -PackageRelativeDirectory $relRoot -MaxFiles 50 -MaxTotalBytes 52428800
    } | Out-Null

    Invoke-FotonCollection -Category 'Filesystem' -Name 'onedrive_teams_local' -Format 'Csv' -Description 'OneDrive/Teams local folders and account registry (no Graph, no cookie/DB copy)' -Script {
        Get-FotonOneDriveTeamsRows
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

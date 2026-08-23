function Get-FotonOneDriveTeamsRows {
    <#
        Local OneDrive and Teams presence. Inventory only: registry account fields,
        sync-root folders (no recurse into the cloud tree), and a capped log listing.
        Does not copy databases, cookies, or tokens. Does not call Graph.
    #>
    param(
        $UserProfiles,
        $UserHiveRoots,
        [string]$MachineOneDriveRoot
    )
    if ($null -eq $UserProfiles) { $UserProfiles = @(Get-FotonUserProfile) }
    if ($null -eq $UserHiveRoots) { $UserHiveRoots = @(Get-FotonUserHiveRoot) }

    $machineRoots = @()
    if ($PSBoundParameters.ContainsKey('MachineOneDriveRoot')) {
        if ($MachineOneDriveRoot) { $machineRoots = @($MachineOneDriveRoot) }
    }
    else {
        $machineRoots = @(
            'HKLM:\SOFTWARE\Microsoft\OneDrive',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive'
        )
    }

    $rows = @()
    foreach ($mr in $machineRoots) {
        if (-not (Test-Path -LiteralPath $mr)) { continue }
        $rk = $null
        try { $rk = Get-Item -LiteralPath $mr -ErrorAction Stop } catch { continue }
        $ver = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'Version'
        $loc = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'CurrentVersionPath'
        if (-not $loc) { $loc = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'InstallLocation' }
        $rows += New-FotonCloudClientRow -Kind 'OneDriveMachine' -Scope 'Machine' -User 'N/A' -Identity $mr `
            -Path $loc -Exists:(Test-FotonPathAccessible -Path $loc) -Email '' `
            -Detail $ver -Note 'HKLM OneDrive install path/version. Not a sync inventory.'
    }

    foreach ($hive in @($UserHiveRoots)) {
        $user = [string]$hive.UserName
        if (-not $user) { $user = [string]$hive.SID }
        $acctRoot = Join-Path $hive.Root 'Software\Microsoft\OneDrive\Accounts'
        if (Test-Path -LiteralPath $acctRoot) {
            try {
                foreach ($acct in (Get-ChildItem -LiteralPath $acctRoot -ErrorAction Stop)) {
                    $rk = $null
                    try { $rk = Get-Item -LiteralPath $acct.PSPath -ErrorAction Stop } catch { continue }
                    $folder = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'UserFolder'
                    $email = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'UserEmail'
                    $cid = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'cid'
                    $endpoint = Get-FotonCloudJoinDisplayValue -Key $rk -Name 'ServiceEndpointUri'
                    $leaf = [string]$acct.PSChildName
                    $id = $cid
                    if (-not $id) { $id = $leaf }
                    $detail = $leaf
                    if ($endpoint) { $detail = $detail + '; Endpoint=' + $endpoint }
                    $rows += New-FotonCloudClientRow -Kind 'OneDriveAccount' -Scope 'User' -User $user -Identity $id `
                        -Path $folder -Exists:(Test-FotonPathAccessible -Path $folder) -Email $email `
                        -Detail $detail -Note 'OneDrive Accounts subkey. Endpoint is cached config, not a live tenant call. Token values are omitted.'
                    if ($folder) {
                        $rows += @(Get-FotonCloudClientFolderRow -Kind 'OneDriveFolder' -Scope 'User' -User $user -Identity $id `
                            -Path $folder -Email $email -Note 'Sync root only. Children at depth 0. Cloud contents are not walked or copied.')
                    }
                }
            }
            catch { }
        }
    }

    foreach ($profile in @($UserProfiles)) {
        if (-not $profile.Exists) { continue }
        $user = [string]$profile.UserName
        $root = [string]$profile.ProfilePath
        if (-not $root) { continue }

        try {
            $odDirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'OneDrive*' } |
                Select-Object -First 8)
            foreach ($d in $odDirs) {
                $already = @($rows | Where-Object { $_.Kind -eq 'OneDriveFolder' -and $_.Path -eq $d.FullName })
                if ($already.Count -gt 0) { continue }
                $rows += @(Get-FotonCloudClientFolderRow -Kind 'OneDriveFolder' -Scope 'User' -User $user -Identity $d.Name `
                    -Path $d.FullName -Email '' -Note 'Profile-root folder named OneDrive*. Not a full cloud listing.')
            }
        }
        catch { }

        $logRoot = Join-Path $root 'AppData\Local\Microsoft\OneDrive\logs'
        $rows += @(Get-FotonCloudClientLogRows -Kind 'OneDriveLog' -User $user -Directory $logRoot -Depth 2 -MaxFiles 20)

        $teamsClassic = Join-Path $root 'AppData\Roaming\Microsoft\Teams'
        $rows += @(Get-FotonCloudClientFolderRow -Kind 'TeamsClassic' -Scope 'User' -User $user -Identity 'TeamsClassic' `
            -Path $teamsClassic -Email '' -Note 'Classic Teams appdata. Cookies/IndexedDB are not copied.' -OnlyIfExists)

        $classicLog = Join-Path $teamsClassic 'logs.txt'
        if (Test-FotonPathAccessible -Path $classicLog) {
            $rows += @(Get-FotonCloudClientFileRow -Kind 'TeamsLog' -User $user -Path $classicLog -Note 'Classic Teams logs.txt name/size/mtime only. Contents not read.')
        }

        $teamsLocal = Join-Path $root 'AppData\Local\Microsoft\Teams'
        $rows += @(Get-FotonCloudClientFolderRow -Kind 'TeamsLocal' -Scope 'User' -User $user -Identity 'TeamsLocal' `
            -Path $teamsLocal -Email '' -Note 'Local Microsoft\Teams folder (new or leftover client). Not copied.' -OnlyIfExists)

        $pkgRoot = Join-Path $root 'AppData\Local\Packages'
        if (Test-FotonPathAccessible -Path $pkgRoot) {
            try {
                $pkgs = @(Get-ChildItem -LiteralPath $pkgRoot -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like 'MSTeams_*' -or $_.Name -like 'MicrosoftTeams_*' } |
                    Select-Object -First 4)
                foreach ($p in $pkgs) {
                    $rows += @(Get-FotonCloudClientFolderRow -Kind 'TeamsStore' -Scope 'User' -User $user -Identity $p.Name `
                        -Path $p.FullName -Email '' -Note 'Store/MSIX Teams package folder. Databases inside are not copied or parsed.')
                }
            }
            catch { }
        }
    }

    $rows | Sort-Object Kind, User, Identity, Path
}

function New-FotonCloudClientRow {
    param(
        [string]$Kind,
        [string]$Scope,
        [string]$User,
        [string]$Identity,
        [string]$Path,
        [bool]$Exists,
        [string]$Email,
        [string]$Detail,
        [string]$Note,
        $SizeBytes = '',
        [string]$ModifiedUtc = ''
    )
    [PSCustomObject]@{
        Kind        = $Kind
        Scope       = $Scope
        User        = $User
        Identity    = $Identity
        Path        = $Path
        Exists      = $Exists
        SizeBytes   = $SizeBytes
        ModifiedUtc = $ModifiedUtc
        Email       = $Email
        Detail      = $Detail
        Note        = $Note
    }
}

function Get-FotonCloudClientFolderRow {
    param(
        [string]$Kind,
        [string]$Scope,
        [string]$User,
        [string]$Identity,
        [string]$Path,
        [string]$Email,
        [string]$Note,
        [switch]$OnlyIfExists
    )
    $exists = Test-FotonPathAccessible -Path $Path
    if ($OnlyIfExists -and -not $exists) { return @() }
    $mtime = ''
    $detail = ''
    if ($exists) {
        try {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            $mtime = $item.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
            $n = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count
            $detail = 'RootChildCount=' + $n
        }
        catch { }
    }
    New-FotonCloudClientRow -Kind $Kind -Scope $Scope -User $User -Identity $Identity -Path $Path -Exists $exists `
        -Email $Email -Detail $detail -Note $Note -ModifiedUtc $mtime
}

function Get-FotonCloudClientFileRow {
    param(
        [string]$Kind,
        [string]$User,
        [string]$Path,
        [string]$Note
    )
    try {
        $f = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        New-FotonCloudClientRow -Kind $Kind -Scope 'User' -User $User -Identity $f.Name -Path $f.FullName -Exists $true `
            -Email '' -Detail '' -Note $Note -SizeBytes $f.Length -ModifiedUtc ($f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))
    }
    catch {
        @()
    }
}

function Get-FotonCloudClientLogRows {
    param(
        [string]$Kind,
        [string]$User,
        [string]$Directory,
        [int]$Depth,
        [int]$MaxFiles
    )
    $out = @()
    if (-not (Test-FotonPathAccessible -Path $Directory)) { return $out }
    try {
        $files = @(Get-ChildItem -LiteralPath $Directory -File -Force -Recurse -Depth $Depth -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '\.(log|txt|aodl)$' } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First $MaxFiles)
        foreach ($f in $files) {
            $out += New-FotonCloudClientRow -Kind $Kind -Scope 'User' -User $User -Identity $f.Name -Path $f.FullName -Exists $true `
                -Email '' -Detail '' -Note 'Log name/size/mtime only. Contents are not read or copied.' `
                -SizeBytes $f.Length -ModifiedUtc ($f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))
        }
    }
    catch { }
    return $out
}

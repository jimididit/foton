function Mount-FotonOfflineUserHive {
    <#
        Loads NTUSER.DAT for profiles whose hive is not loaded, so per-user persistence keys can be read.
        This WRITES to the registry. Always pair with Dismount-FotonOfflineUserHive in a finally block.
        Mount point prefix is Foton_<SID> (v1 used WinFoton_<SID>).
    #>
    $mounted = @()
    $prefix = $script:FotonSession.HiveMountPrefix
    foreach ($userProfile in (Get-FotonUserProfile)) {
        if ($userProfile.HiveLoaded -or -not $userProfile.Exists) { continue }
        if ($userProfile.SID -notlike 'S-1-5-21-*') { continue }
        $dat = Join-Path $userProfile.ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { continue }
        $mountName = "${prefix}_$($userProfile.SID)"
        try {
            $null = & reg.exe load "HKU\$mountName" "$dat" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $null = $script:FotonSession.LoadedHives.Add($mountName)
                $mounted += [PSCustomObject]@{
                    SID        = $userProfile.SID
                    UserName   = $userProfile.UserName
                    MountPoint = "HKEY_USERS\$mountName"
                }
                Write-FotonStatus "Loaded offline hive for $($userProfile.UserName)" 'Info'
            }
        }
        catch { Write-FotonStatus "Could not load hive for $($userProfile.UserName): $($_.Exception.Message)" 'Warn' }
    }
    return $mounted
}

function Dismount-FotonOfflineUserHive {
    <# Unload hives this run mounted. GC collect first so handles are released. Failures are warnings - leftover keys need manual unload. #>
    foreach ($mountName in $script:FotonSession.LoadedHives) {
        try {
            [gc]::Collect()
            $null = & reg.exe unload "HKU\$mountName" 2>&1
            Write-FotonStatus "Unloaded hive $mountName" 'Info'
        }
        catch { Write-FotonStatus "Failed to unload hive $mountName - manual cleanup required" 'Warn' }
    }
}

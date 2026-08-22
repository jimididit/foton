function Get-FotonUserProfile {
    <# Local profiles from ProfileList (SID → path). Used to iterate per-user artifacts without assuming who is logged on. #>
    $profiles = @()
    try {
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        Get-ChildItem -LiteralPath $base -ErrorAction Stop | ForEach-Object {
            $sid = Split-Path $_.Name -Leaf
            $path = Get-FotonRegValue -Path $_.PSPath -Name 'ProfileImagePath'
            if ($path) {
                $name = Split-Path $path -Leaf
                $profiles += [PSCustomObject]@{
                    SID         = $sid
                    UserName    = $name
                    ProfilePath = $path
                    Exists      = (Test-Path -LiteralPath $path)
                    HiveLoaded  = (Test-Path -LiteralPath ("Registry::HKEY_USERS\$sid"))
                }
            }
        }
    }
    catch { }
    return $profiles
}

function Get-FotonUserHiveRoot {
    <#
        HKEY_USERS roots worth examining, mapped to a username when ProfileList allows.
        Accepts live SIDs plus Foton_* and WinFoton_* mount prefixes from this tool's hive load.
    #>
    $roots = @()
    $profiles = Get-FotonUserProfile
    $prefix = $script:FotonSession.HiveMountPrefix
    try {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object {
            $leaf = Split-Path $_.Name -Leaf
            if ($leaf -like '*_Classes') { return }
            $isSid = $leaf -like 'S-1-5-21-*'
            $isFotonMount = $leaf -like "${prefix}_*"
            $isLegacyMount = $leaf -like 'WinFoton_*'
            if (-not $isSid -and -not $isFotonMount -and -not $isLegacyMount) { return }
            $sid = $leaf -replace ('^' + [regex]::Escape($prefix) + '_'), ''
            $sid = $sid -replace '^WinFoton_', ''
            $match = $profiles | Where-Object { $_.SID -eq $sid } | Select-Object -First 1
            $userName = $sid
            if ($match) { $userName = $match.UserName }
            $roots += [PSCustomObject]@{
                SID      = $sid
                UserName = $userName
                Root     = "Registry::HKEY_USERS\$leaf"
            }
        }
    }
    catch { }
    return $roots
}

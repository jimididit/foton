function Get-FotonStartupApprovedState {
    <#
        Task Manager / Settings "Startup apps" writes a REG_BINARY in StartupApproved.
        Byte 0: 2 or 6 = enabled, 3 or 7 = disabled. Other values stay as Other:N.
    #>
    param($Value)
    $bytes = $null
    if ($Value -is [byte[]]) {
        $bytes = $Value
    }
    elseif ($null -ne $Value -and $Value -is [System.Array] -and $Value.Length -gt 0) {
        try { $bytes = [byte[]]$Value } catch { $bytes = $null }
    }
    if ($null -eq $bytes -or $bytes.Length -lt 1) { return 'Unknown' }
    $b = [int]$bytes[0]
    if ($b -eq 2 -or $b -eq 6) { return 'Enabled' }
    if ($b -eq 3 -or $b -eq 7) { return 'Disabled' }
    return ('Other:{0}' -f $b)
}

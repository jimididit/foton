function Get-FotonStartupApprovedRows {
    <#
        HKLM and loaded HKU StartupApproved stores. Same rows for Collect CSV and baseline.
        State is Enabled/Disabled/Other from the REG_BINARY (Task Manager / Settings).
    #>
    $rows = @()
    $stores = @('Run', 'Run32', 'StartupFolder')
    $rel = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    $keys = @()
    foreach ($s in $stores) {
        $keys += [PSCustomObject]@{ Scope = 'HKLM'; Store = $s; Path = ('HKLM:\' + $rel + '\' + $s) }
    }
    foreach ($h in @(Get-FotonUserHiveRoot)) {
        foreach ($s in $stores) {
            $keys += [PSCustomObject]@{
                Scope = [string]$h.SID
                Store = $s
                Path  = ($h.Root + '\' + $rel + '\' + $s)
            }
        }
    }
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k.Path)) { continue }
        try {
            $item = Get-Item -LiteralPath $k.Path -ErrorAction Stop
            foreach ($n in @($item.GetValueNames())) {
                if ([string]::IsNullOrWhiteSpace($n)) { continue }
                $rows += [PSCustomObject]@{
                    Scope     = [string]$k.Scope
                    Store     = [string]$k.Store
                    ValueName = [string]$n
                    State     = Get-FotonStartupApprovedState -Value $item.GetValue($n)
                }
            }
        }
        catch { }
    }
    return @($rows | Sort-Object Scope, Store, ValueName)
}

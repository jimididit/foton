function Get-FotonBamDamRows {
    <#
        BAM/DAM UserSettings: value *name* is the executable path; data starts with FILETIME.
        Live registry only (Collect). Empty if the key is missing - not proof the host never had BAM.
    #>
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][string]$Root
    )
    $rows = @()
    if (-not (Test-Path -LiteralPath $Root)) { return $rows }
    try {
        foreach ($sidKey in (Get-ChildItem -LiteralPath $Root -ErrorAction Stop)) {
            $sid = [string]$sidKey.PSChildName
            if (-not $sid) { continue }
            $rk = $null
            try { $rk = Get-Item -LiteralPath $sidKey.PSPath -ErrorAction Stop } catch { continue }
            foreach ($name in @($rk.GetValueNames())) {
                if (-not $name -or $name -eq '(default)') { continue }
                $raw = $null
                try { $raw = $rk.GetValue($name) } catch { continue }
                $len = 0
                if ($raw -is [byte[]]) { $len = $raw.Length }
                $rows += [PSCustomObject]@{
                    Kind           = $Kind
                    SID            = $sid
                    Path           = $name
                    LastExecuteUtc = (ConvertFrom-FotonFileTimeUtc -Bytes $raw -Offset 0)
                    DataBytes      = $len
                }
            }
        }
    }
    catch { }
    $rows | Sort-Object Kind, SID, Path
}

function Get-FotonRegValue {
    <# Best-effort registry value. Missing key/name returns $null — collectors must not throw. #>
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

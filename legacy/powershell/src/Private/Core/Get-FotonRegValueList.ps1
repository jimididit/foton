function Get-FotonRegValueList {
    <# Every value under a key as name/data pairs, skipping PowerShell provider metadata properties. #>
    param([string]$Path)
    $out = @()
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $out }
        $key = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        foreach ($prop in $key.PSObject.Properties) {
            if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $out += [PSCustomObject]@{
                Key   = $Path
                Name  = $prop.Name
                Value = ($prop.Value -join ' ')
            }
        }
    }
    catch { }
    return $out
}

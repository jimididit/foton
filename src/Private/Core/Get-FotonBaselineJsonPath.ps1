function Get-FotonBaselineJsonPath {
    <#
        Folder packages store the snapshot as baseline.json. A bare .json path
        is returned unchanged. Compare and the snapshot report both use this.
    #>
    param(
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Baseline not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        $json = Join-Path $item.FullName 'baseline.json'
        if (-not (Test-Path -LiteralPath $json)) {
            throw "No baseline.json in package folder: $Path"
        }
        return $json
    }
    return $item.FullName
}

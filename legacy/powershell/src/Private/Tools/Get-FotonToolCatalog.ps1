function Get-FotonToolCatalogPath {
    <#
        .SYNOPSIS
        Returns the path to the pinned external-tool catalog JSON.
    #>
    param([string]$CatalogPath)

    if ($CatalogPath) {
        if (-not (Test-Path -LiteralPath $CatalogPath)) {
            throw ("Catalog not found: {0}" -f $CatalogPath)
        }
        return (Get-Item -LiteralPath $CatalogPath).FullName
    }

    $candidates = @(
        (Join-Path $script:FotonSrcRoot 'Private\Tools\FotonToolCatalog.json')
        (Join-Path $script:FotonModuleRoot 'src\Private\Tools\FotonToolCatalog.json')
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) {
            return (Get-Item -LiteralPath $c).FullName
        }
    }
    throw 'FotonToolCatalog.json not found under the module tree.'
}

function Get-FotonToolCatalog {
    <#
        .SYNOPSIS
        Loads the pinned external-tool catalog (Hayabusa first cut).

        .PARAMETER CatalogPath
        Optional override for tests. Production uses the module catalog.
    #>
    param([string]$CatalogPath)

    $path = Get-FotonToolCatalogPath -CatalogPath $CatalogPath
    $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
    $data = $raw | ConvertFrom-Json
    if (-not $data -or -not $data.Tools) {
        throw ("Catalog has no Tools array: {0}" -f $path)
    }
    return @($data.Tools)
}

function Get-FotonToolCatalogEntry {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$CatalogPath
    )

    $want = $Name.Trim()
    foreach ($t in @(Get-FotonToolCatalog -CatalogPath $CatalogPath)) {
        if ([string]$t.Name -eq $want) { return $t }
    }
    throw ("Tool '{0}' is not in the Foton catalog. Supported: {1}" -f $Name, (
            (@(Get-FotonToolCatalog -CatalogPath $CatalogPath) | ForEach-Object { $_.Name }) -join ', '))
}

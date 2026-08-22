function Invoke-FotonParse {
    <#
    .SYNOPSIS
        Run available parsers over files in a loaded package or an explicit path.

    .DESCRIPTION
        Offline only. Currently Prefetch (.pf). Other formats emit nothing until
        their ConvertFrom-Foton* parsers exist.

    .PARAMETER PackagePath
        Optional case folder. If omitted, uses session CaseRoot.

    .PARAMETER Path
        Parse a single file.

    .EXAMPLE
        Invoke-FotonParse -Path C:\lab\NOTEPAD.EXE-D41D8CD9.pf
    #>
    [CmdletBinding()]
    param(
        [string]$PackagePath,
        [string]$Path
    )
    if ($PackagePath) {
        Get-FotonPackage -Path $PackagePath | Out-Null
    }
    $files = @()
    if ($Path) {
        $files = @(Get-Item -LiteralPath $Path)
    }
    elseif ($script:FotonSession.CaseRoot) {
        $files = @(Get-ChildItem -LiteralPath $script:FotonSession.CaseRoot -Recurse -Filter '*.pf' -File -ErrorAction SilentlyContinue)
    }
    else {
        throw 'Pass -Path or load a package that contains Prefetch files.'
    }
    $out = @()
    foreach ($f in $files) {
        $out += ConvertFrom-FotonPrefetch -Path $f.FullName
    }
    return $out
}

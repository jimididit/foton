function Invoke-FotonParse {
    <#
    .SYNOPSIS
        Run available parsers over files in a loaded package or an explicit path.

    .DESCRIPTION
        Offline only. Prefetch (.pf) already in the package (typically
        08_Filesystem/prefetch) and shortcuts (.lnk). Does not read %SystemRoot%.

    .PARAMETER PackagePath
        Optional case folder. If omitted, uses session CaseRoot.

    .PARAMETER Path
        Parse a single file.

    .EXAMPLE
        Invoke-FotonParse -Path C:\lab\note.lnk
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
        $files = @(Get-ChildItem -LiteralPath $script:FotonSession.CaseRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Extension -match '\.(pf|lnk)$' -and
                    $_.DirectoryName -notmatch '[\\/](evtx|analysis)([\\/]|$)'
                })
    }
    else {
        throw 'Pass -Path or load a package that contains Prefetch or LNK files.'
    }
    $out = @()
    foreach ($f in $files) {
        $ext = $f.Extension.ToLower()
        if ($ext -eq '.pf') { $out += ConvertFrom-FotonPrefetch -Path $f.FullName }
        elseif ($ext -eq '.lnk') { $out += ConvertFrom-FotonLnk -Path $f.FullName }
    }
    return $out
}

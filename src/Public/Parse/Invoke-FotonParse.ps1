function Invoke-FotonParse {
    <#
    .SYNOPSIS
        Run available parsers over files in a loaded package or an explicit path.

    .DESCRIPTION
        Offline only. Prefetch (.pf) already in the package (typically
        08_Filesystem/prefetch) and shortcuts (.lnk). Does not read %SystemRoot%.

        A case folder or ZIP is a package: every .pf/.lnk under it is parsed.
        A single .pf or .lnk is parsed in isolation. Windows 10+ Prefetch is often
        MAM-compressed; those rows are recorded as Format MAM-compressed, not as
        executable names.

        Writes analysis/parsed_records.csv and analysis/Foton_Parse.html.
        ZIP runs also write those next to the zip. Does not write findings.csv
        (that is Invoke-FotonAnalysis) and does not rewrite collect hashes.csv.

    .PARAMETER PackagePath
        Case folder or ZIP. If omitted, uses a Path that looks like a package, or
        the session CaseRoot from Get-FotonPackage.

    .PARAMETER Path
        One .pf/.lnk, or a case folder/ZIP (same as PackagePath).

    .EXAMPLE
        Invoke-FotonParse -Path D:\Cases\Foton_HOSTNAME_20260823-011150Z

        Parses copied Prefetch and LNK files in that package.

    .EXAMPLE
        Invoke-FotonParse -Path C:\lab\note.lnk

    .OUTPUTS
        Parser records. Also writes CSV when a case root is known.
    #>
    [CmdletBinding()]
    param(
        [string]$PackagePath,
        [string]$Path
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }

    $single = $null
    $pkg = $PackagePath
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Parse path not found: $Path"
        }
        $item = Get-Item -LiteralPath $Path
        $isZip = ($item.Extension -eq '.zip')
        $isDir = [bool]$item.PSIsContainer
        if ($isZip -or $isDir) {
            $pkg = $item.FullName
        }
        else {
            $single = $item
        }
    }

    if ($pkg) {
        Get-FotonPackage -Path $pkg | Out-Null
    }

    $files = @()
    if ($single) {
        $files = @($single)
    }
    elseif ($script:FotonSession.CaseRoot) {
        $files = @(Get-ChildItem -LiteralPath $script:FotonSession.CaseRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Extension -match '\.(pf|lnk)$' -and
                    $_.DirectoryName -notmatch '[\\/](evtx|analysis)([\\/]|$)'
                })
    }
    else {
        throw 'Pass a .pf/.lnk file, a case folder, or a case ZIP.'
    }

    Write-FotonStatus ("Parsing {0} Prefetch/LNK file(s) (offline)" -f $files.Count) 'Step'

    $out = @()
    foreach ($f in $files) {
        $ext = $f.Extension.ToLower()
        if ($ext -eq '.pf') { $out += ConvertFrom-FotonPrefetch -Path $f.FullName }
        elseif ($ext -eq '.lnk') { $out += ConvertFrom-FotonLnk -Path $f.FullName }
        else {
            Write-FotonStatus ("Skipped (not .pf/.lnk): {0}" -f $f.Name) 'Info'
        }
    }

    $why = $null
    if ($out.Count -eq 0) {
        $why = 'No .pf or .lnk files were in that path. Parse does not read %SystemRoot%\Prefetch live.'
        $pfTask = @($script:FotonSession.Manifest | Where-Object { $_.Task -eq 'prefetch_files' }) | Select-Object -First 1
        if ($pfTask -and $pfTask.Status -eq 'SkippedNotElevated') {
            $why = 'prefetch_files was skipped (not elevated). This package has no copied .pf files. Re-collect elevated with Foton-Collect.ps1 that includes Collect schema 1.2.0.'
        }
        elseif ($pfTask -and $pfTask.Status -eq 'NoData') {
            $why = 'prefetch_files ran but copied nothing. Prefetch may be disabled or empty; see 08_Filesystem/prefetch_files.csv.'
        }
        elseif (-not $pfTask -and $script:FotonSession.CaseRoot) {
            $why = 'This package has no prefetch_files task (older collect). Listing CSV is not parseable. Re-collect with module 1.9+ / schema 1.2.0.'
        }
        Write-FotonStatus $why 'Info'
    }
    else {
        $supported = @($out | Where-Object { $_.Supported -eq $true }).Count
        $mam = @($out | Where-Object { $_.Format -eq 'MAM-compressed' }).Count
        Write-FotonStatus ("Parsed {0} file(s): {1} supported name(s), {2} MAM-compressed (name not inflated)" -f $out.Count, $supported, $mam) 'Good'
    }

    $csvRows = @()
    $caseRoot = $script:FotonSession.CaseRoot
    $rootNorm = ''
    if ($caseRoot) { $rootNorm = ($caseRoot.TrimEnd('\', '/') + '\').ToLowerInvariant() }
    foreach ($r in $out) {
        $identity = ''
        if ($r.PSObject.Properties['ExecutableName']) { $identity = [string]$r.ExecutableName }
        if (-not $identity -and $r.PSObject.Properties['LocalBasePath']) { $identity = [string]$r.LocalBasePath }
        $srcShow = [string]$r.SourcePath
        $srcNorm = $srcShow.ToLowerInvariant()
        if ($rootNorm -and $srcNorm.StartsWith($rootNorm)) {
            $srcShow = $srcShow.Substring($caseRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')
        }
        $csvRows += [PSCustomObject]@{
            SourcePath = $srcShow
            Format     = [string]$r.Format
            Supported  = [bool]$r.Supported
            Identity   = $identity
            SizeBytes  = $r.SizeBytes
            SHA256     = [string]$r.SHA256
            Note       = [string]$r.Note
        }
    }

    if (-not $single) {
        $htmlPath = $null
        if ($caseRoot -and (Test-Path -LiteralPath $caseRoot)) {
            $analysisDir = Join-Path $caseRoot 'analysis'
            New-Item -Path $analysisDir -ItemType Directory -Force | Out-Null
            $csvPath = Join-Path $analysisDir 'parsed_records.csv'
            $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-FotonStatus "Wrote $csvPath" 'Good'
            $htmlPath = Join-Path $analysisDir 'Foton_Parse.html'
            New-FotonParseReport -Records $csvRows -OutputPath $htmlPath -EmptyReason $why | Out-Null
        }
        $pkgMeta = $script:FotonSession.Package
        if ($pkgMeta -and $pkgMeta.Kind -eq 'Zip' -and $pkgMeta.SourcePath) {
            $stem = [IO.Path]::GetFileNameWithoutExtension($pkgMeta.SourcePath)
            $parent = Split-Path -Parent $pkgMeta.SourcePath
            $csvRows | Export-Csv -Path (Join-Path $parent ($stem + '_parse.csv')) -NoTypeInformation -Encoding UTF8
            $htmlPath = Join-Path $parent ($stem + '_Parse.html')
            New-FotonParseReport -Records $csvRows -OutputPath $htmlPath -EmptyReason $why | Out-Null
        }
        if ($htmlPath) {
            Write-FotonStatus "Open $htmlPath (this is not findings.csv; that file is triage Analyze)" 'Good'
        }
    }

    return $out
}

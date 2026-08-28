function Invoke-FotonParse {
    <#
    .SYNOPSIS
        Run available parsers over files in a loaded package or an explicit path.

    .DESCRIPTION
        Offline only. Prefetch (.pf) already in the package (typically
        08_Filesystem/prefetch), shortcuts (.lnk), jumplists
        (.automaticDestinations-ms / .customDestinations-ms), exported EVTX
        under 07_Event_Logs/evtx, and copied Amcache.hve under 08_Filesystem/amcache.
        Does not read %SystemRoot% or live event logs.

        A case folder or ZIP is a package: every .pf/.lnk/.evtx/jumplist/Amcache.hve
        under it is parsed except analysis/. A single .pf, .lnk, .evtx, jumplist,
        or .hve is parsed in isolation.
        Windows 10+ Prefetch is often MAM-compressed; those rows are Format
        MAM-compressed, not executable names. EVTX rows are selected Event IDs only.

        Writes analysis/parsed_records.csv and analysis/Foton_Parse.html.
        ZIP runs also write those next to the zip. Does not write findings.csv
        (that is Invoke-FotonAnalysis) and does not rewrite collect hashes.csv.

    .PARAMETER PackagePath
        Case folder or ZIP. If omitted, uses a Path that looks like a package, or
        the session CaseRoot from Get-FotonPackage.

    .PARAMETER Path
        One .pf/.lnk/.evtx/jumplist, or a case folder/ZIP (same as PackagePath).

    .EXAMPLE
        Invoke-FotonParse -Path D:\Cases\Foton_HOSTNAME_20260823-011150Z

        Parses copied Prefetch, LNK, jumplist, EVTX, and Amcache.hve in that package.

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
        # A package that contains a copy of itself would otherwise parse every
        # artifact twice and report double the rows for the same evidence.
        $skip = $null
        if ($script:FotonSession.Package) { $skip = [string]$script:FotonSession.Package['NestedDuplicate'] }
        $files = @(Get-ChildItem -LiteralPath $script:FotonSession.CaseRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    ($_.Extension -match '\.(pf|lnk|evtx)$' -or
                     $_.Name -like '*.automaticDestinations-ms' -or
                     $_.Name -like '*.customDestinations-ms' -or
                     $_.Name -ieq 'Amcache.hve' -or
                     ($_.Extension -ieq '.hve' -and $_.Directory.Name -ieq 'amcache')) -and
                    $_.DirectoryName -notmatch '[\\/]analysis([\\/]|$)' -and
                    (-not $skip -or -not $_.FullName.StartsWith($skip, [StringComparison]::OrdinalIgnoreCase))
                })
    }
    else {
        throw 'Pass a .pf/.lnk/.evtx/jumplist/Amcache.hve file, a case folder, or a case ZIP.'
    }

    Write-FotonStatus ("Parsing {0} Prefetch/LNK/jumplist/EVTX/Amcache file(s) (offline)" -f $files.Count) 'Step'

    $out = @()
    foreach ($f in $files) {
        $ext = $f.Extension.ToLower()
        $n = $f.Name.ToLowerInvariant()
        if ($ext -eq '.pf') { $out += ConvertFrom-FotonPrefetch -Path $f.FullName }
        elseif ($ext -eq '.lnk') { $out += ConvertFrom-FotonLnk -Path $f.FullName }
        elseif ($ext -eq '.evtx') { $out += ConvertFrom-FotonEvtx -Path $f.FullName }
        elseif ($n -like '*.automaticdestinations-ms' -or $n -like '*.customdestinations-ms') {
            $out += ConvertFrom-FotonJumplist -Path $f.FullName
        }
        elseif ($ext -eq '.hve') {
            $out += ConvertFrom-FotonAmcache -Path $f.FullName
        }
        else {
            Write-FotonStatus ("Skipped (not .pf/.lnk/.evtx): {0}" -f $f.Name) 'Info'
        }
    }

    $why = $null
    if ($out.Count -eq 0) {
        $why = 'No .pf, .lnk, jumplist, .evtx, or Amcache.hve files were in that path. Parse does not read live Prefetch, event logs, or Amcache.'
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
        $ev = @($out | Where-Object { $_.Format -eq 'EVTX' -and $_.Supported -eq $true }).Count
        Write-FotonStatus ("Parsed {0} row(s): {1} supported name(s), {2} MAM-compressed, {3} EVTX row(s)" -f $out.Count, $supported, $mam, $ev) 'Good'
    }

    $csvRows = @()
    $caseRoot = $script:FotonSession.CaseRoot
    $rootNorm = ''
    if ($caseRoot) { $rootNorm = ($caseRoot.TrimEnd('\', '/') + '\').ToLowerInvariant() }
    foreach ($r in $out) {
        $identity = ''
        if ($r.PSObject.Properties['Identity'] -and [string]$r.Identity) { $identity = [string]$r.Identity }
        if (-not $identity -and $r.PSObject.Properties['ExecutableName']) { $identity = [string]$r.ExecutableName }
        if (-not $identity -and $r.PSObject.Properties['LocalBasePath']) { $identity = [string]$r.LocalBasePath }
        if (-not $identity -and $r.PSObject.Properties['Path']) { $identity = [string]$r.Path }
        if (-not $identity -and $r.PSObject.Properties['LowerCaseLongPath']) { $identity = [string]$r.LowerCaseLongPath }
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

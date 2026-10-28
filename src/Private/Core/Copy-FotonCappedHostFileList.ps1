function Copy-FotonCappedHostFileList {
    <#
        Copy an explicit list of live files (newest first) with count and byte
        caps. DestRelative may include subfolders so user hives and LNKs do not
        collide on leaf name. Status is Copied / Missing / CopyError / CappedSkip.
    #>
    param(
        [Parameter(Mandatory)]$Items,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [string]$PackageRelativeDirectory,
        [int]$MaxFiles = 400,
        [long]$MaxTotalBytes = 83886080
    )

    $rows = New-Object System.Collections.ArrayList
    $list = @($Items | Where-Object { $_ })
    if ($list.Count -eq 0) {
        $null = $rows.Add([PSCustomObject]@{
                SourcePath   = ''
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'NoData'
                Note         = 'No source paths were queued. Visibility gap, not proof the artifact class was empty.'
            })
        return @($rows)
    }

    $sorted = @($list | Sort-Object {
            $p = [string]$_.SourcePath
            # Do not Test-Path UNC during sort (would auth to remote).
            if ($p -and ($p.StartsWith('\\') -or $p.StartsWith('//'))) {
                [datetime]::MinValue
            }
            elseif ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
                try { (Get-Item -LiteralPath $p -Force).LastWriteTimeUtc } catch { [datetime]::MinValue }
            }
            else { [datetime]::MinValue }
        } -Descending)

    $copied = 0
    $used = [int64]0
    $destRootFull = $null
    try { $destRootFull = [IO.Path]::GetFullPath($DestinationDirectory) } catch { $destRootFull = $DestinationDirectory }

    foreach ($it in $sorted) {
        $src = [string]$it.SourcePath
        $relLeaf = [string]$it.DestRelative
        if (-not $relLeaf) { $relLeaf = [string]$it.DestRelative }
        if (-not $relLeaf) { $relLeaf = [IO.Path]::GetFileName($src) }

        # Never probe UNC: Test-Path / open would auth to remote shares (NTLM leak).
        if ($src -and ($src.StartsWith('\\') -or $src.StartsWith('//'))) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $src
                    DestRelative = $relLeaf
                    SizeBytes    = 0
                    SHA256       = ''
                    Status       = 'SkippedUnc'
                    Note         = 'UNC source refused. Deep Collect does not follow remote paths (NTLM / network footprint).'
                })
            continue
        }

        # DestRelative must stay under DestinationDirectory (no .. escape).
        if ($relLeaf -match '(^|[\\/])\.\.([\\/]|$)') {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $src
                    DestRelative = $relLeaf
                    SizeBytes    = 0
                    SHA256       = ''
                    Status       = 'CopyError'
                    Note         = 'DestRelative contained .. segments; refused to prevent package-directory escape.'
                })
            continue
        }

        if (-not $src -or -not (Test-Path -LiteralPath $src -PathType Leaf)) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $src
                    DestRelative = $relLeaf
                    SizeBytes    = 0
                    SHA256       = ''
                    Status       = 'Missing'
                    Note         = 'Source leaf not found. Visibility gap, not proof it never existed on the host.'
                })
            continue
        }
        $len = [int64]0
        try { $len = (Get-Item -LiteralPath $src -Force).Length } catch { }
        $skipNote = $null
        if ($copied -ge $MaxFiles) {
            $skipNote = "Capped at MaxFiles=$MaxFiles. Inventory CSVs still list names that were not copied."
        }
        elseif (($used + $len) -gt [int64]$MaxTotalBytes) {
            $skipNote = "Capped at MaxTotalBytes=$MaxTotalBytes. Inventory CSVs still list names that were not copied."
        }
        if ($skipNote) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $src
                    DestRelative = $relLeaf
                    SizeBytes    = $len
                    SHA256       = ''
                    Status       = 'CappedSkip'
                    Note         = $skipNote
                })
            continue
        }

        $dest = Join-Path $DestinationDirectory $relLeaf
        $destFull = $null
        try { $destFull = [IO.Path]::GetFullPath($dest) } catch { $destFull = $dest }
        $rootPrefix = $destRootFull.TrimEnd('\') + '\'
        if ($destRootFull -and $destFull -and
            -not ($destFull.Equals($destRootFull, [StringComparison]::OrdinalIgnoreCase)) -and
            -not $destFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $src
                    DestRelative = $relLeaf
                    SizeBytes    = $len
                    SHA256       = ''
                    Status       = 'CopyError'
                    Note         = 'Resolved destination left DestinationDirectory; copy refused.'
                })
            continue
        }

        $copy = Copy-FotonHostFile -SourcePath $src -DestinationPath $dest
        $rel = $relLeaf
        if ($PackageRelativeDirectory) {
            $rel = Join-Path $PackageRelativeDirectory $relLeaf
        }
        $null = $rows.Add([PSCustomObject]@{
                SourcePath   = $copy.SourcePath
                DestRelative = $rel
                SizeBytes    = $copy.SizeBytes
                SHA256       = $copy.SHA256
                Status       = $copy.Status
                Note         = $copy.Note
            })
        if ($copy.Status -eq 'Copied') {
            $copied++
            $used = $used + [int64]$copy.SizeBytes
        }
    }

    return @($rows)
}

function Get-FotonSafePathSegment {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'unknown' }
    $s = [regex]::Replace($Name, '[\\/:*?"<>|]', '_')
    $s = $s.Trim()
    if (-not $s) { return 'unknown' }
    return $s
}

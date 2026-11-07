function Copy-FotonCappedHostFiles {
    <#
        Copy newest-first files from a live directory (Prefetch). Cap count and
        total bytes so a busy host cannot fill the case USB. Listing CSV stays
        the inventory of names that existed; this is the parseable payload.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceDirectory,
        [Parameter(Mandatory)][string]$Filter,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [string]$PackageRelativeDirectory,
        # 1024 is the Windows 10/11 Prefetch ceiling. A lower count cap dropped the
        # very executions under review once later activity rewrote 200+ .pf files.
        [int]$MaxFiles = 1024,
        [long]$MaxTotalBytes = 83886080
    )

    $rows = New-Object System.Collections.ArrayList
    if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
        $null = $rows.Add([PSCustomObject]@{
                SourcePath   = $SourceDirectory
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'Missing'
                Note         = 'Source directory not found. Prefetch is often disabled or the token cannot see it.'
            })
        return @($rows)
    }

    $files = @(Get-ChildItem -LiteralPath $SourceDirectory -Filter $Filter -File -Force -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending)

    if ($files.Count -eq 0) {
        $null = $rows.Add([PSCustomObject]@{
                SourcePath   = $SourceDirectory
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'NoData'
                Note         = 'Directory existed but no files matched the filter.'
            })
        return @($rows)
    }

    $copied = 0
    $used = [int64]0
    foreach ($f in $files) {
        $skipNote = $null
        if ($copied -ge $MaxFiles) {
            $skipNote = "Capped at MaxFiles=$MaxFiles. Prefer the listing CSV for names not copied."
        }
        elseif (($used + [int64]$f.Length) -gt [int64]$MaxTotalBytes) {
            $skipNote = "Capped at MaxTotalBytes=$MaxTotalBytes. Prefer the listing CSV for names not copied."
        }
        if ($skipNote) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $f.FullName
                    DestRelative = ''
                    SizeBytes    = $f.Length
                    SHA256       = ''
                    Status       = 'CappedSkip'
                    Note         = $skipNote
                })
            continue
        }

        $dest = Join-Path $DestinationDirectory $f.Name
        $copy = Copy-FotonHostFile -SourcePath $f.FullName -DestinationPath $dest
        $rel = $f.Name
        if ($PackageRelativeDirectory) {
            $rel = Join-Path $PackageRelativeDirectory $f.Name
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

function Copy-FotonHostFileFamily {
    <#
        Copy a primary artifact plus same-directory sidecars (ESE WAL/SHM, hive .LOG*).
        Identity of the family is the primary leaf; extra files whose names start
        with that leaf are journals, not separate evidence types.
    #>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [string]$PackageRelativeDirectory,
        [long]$MaxTotalBytes = 104857600
    )

    $rows = New-Object System.Collections.ArrayList
    $primaryLeaf = [IO.Path]::GetFileName($SourcePath)
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        $null = $rows.Add([PSCustomObject]@{
                SourcePath   = $SourcePath
                DestRelative = ''
                SizeBytes    = 0
                SHA256       = ''
                Status       = 'Missing'
                Note         = 'Primary file not found. Visibility gap, not proof it was never present.'
            })
        return @($rows)
    }

    $srcDir = Split-Path -Parent $SourcePath
    $leafNorm = $primaryLeaf.ToLowerInvariant()
    $family = @(Get-ChildItem -LiteralPath $srcDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $n = $_.Name.ToLowerInvariant()
                $n -eq $leafNorm -or $n.StartsWith($leafNorm)
            } |
            Sort-Object { if ($_.Name.ToLowerInvariant() -eq $leafNorm) { 0 } else { 1 } }, Name)

    $budget = [int64]$MaxTotalBytes
    foreach ($f in $family) {
        if ($f.Length -gt $budget) {
            $null = $rows.Add([PSCustomObject]@{
                    SourcePath   = $f.FullName
                    DestRelative = ''
                    SizeBytes    = $f.Length
                    SHA256       = ''
                    Status       = 'CappedSkip'
                    Note         = 'File exceeds remaining copy budget. Full file remains on the host; this package is a capped copy.'
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
            $budget = $budget - [int64]$copy.SizeBytes
        }
    }

    return @($rows)
}

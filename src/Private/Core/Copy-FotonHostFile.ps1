function Copy-FotonHostFile {
    <#
        Copy a live host file into the case package. Opens the source with
        FileShare.ReadWrite so Superfetch / Amcache / SRUM locks do not force an
        in-place read. Parse must use the copy, never the live path.

        Status is a fact about the attempt (Copied / Missing / CopyError).
    #>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    $row = [PSCustomObject]@{
        SourcePath = $SourcePath
        DestName   = [IO.Path]::GetFileName($DestinationPath)
        SizeBytes  = 0
        SHA256     = ''
        Status     = 'CopyError'
        Note       = ''
    }

    if ([string]::IsNullOrWhiteSpace($SourcePath) -or -not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        $row.Status = 'Missing'
        $row.Note = 'Source leaf not found. Visibility gap, not proof the artifact never existed on the host.'
        return $row
    }

    $src = $null
    $dst = $null
    try {
        $destDir = Split-Path -Parent $DestinationPath
        if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }

        $share = [System.IO.FileShare]::ReadWrite
        $src = [System.IO.File]::Open($SourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $dst = [System.IO.File]::Create($DestinationPath)
        $src.CopyTo($dst)
        $dst.Flush()
        $dst.Dispose()
        $dst = $null
        $src.Dispose()
        $src = $null

        $item = Get-Item -LiteralPath $DestinationPath -Force -ErrorAction Stop
        $row.SizeBytes = $item.Length
        $row.SHA256 = Get-FotonSafeHash -Path $DestinationPath
        $row.Status = 'Copied'
        $row.Note = 'Copied with FileShare.ReadWrite. Do not parse the live path.'
    }
    catch {
        $row.Status = 'CopyError'
        $row.Note = $_.Exception.Message
        try {
            if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch { }
    }
    finally {
        if ($null -ne $dst) { try { $dst.Dispose() } catch { } }
        if ($null -ne $src) { try { $src.Dispose() } catch { } }
    }

    return $row
}

function Save-FotonRegistryHive {
    <#
        Export a loaded registry hive into the case package with reg.exe save.
        Loaded hives are opened exclusively by the kernel, so the FileShare copy in
        Copy-FotonHostFile fails on them with "being used by another process".
        reg save asks the configuration manager for a consistent image instead; the
        result is a clean hive with no .LOG sidecars to replay.

        The only write is the destination file inside the package. Requires an
        Administrator token (SeBackupPrivilege); callers gate on -RequiresElevation.
        Row shape matches Copy-FotonHostFile so hive manifests stay one format.
    #>
    param(
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$DestinationPath,
        [string]$PackageRelativePath
    )

    $rel = $PackageRelativePath
    if (-not $rel) { $rel = [IO.Path]::GetFileName($DestinationPath) }
    $row = [PSCustomObject]@{
        SourcePath   = $RegistryPath
        DestRelative = $rel
        SizeBytes    = 0
        SHA256       = ''
        Status       = 'SaveError'
        Note         = ''
    }

    try {
        $destDir = Split-Path -Parent $DestinationPath
        if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        $out = & reg.exe save $RegistryPath $DestinationPath /y 2>&1
        $code = $LASTEXITCODE
        if ($code -ne 0 -or -not (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
            $row.DestRelative = ''
            $row.Note = ('reg save exit {0}: {1}' -f $code, (($out | Out-String).Trim()))
            if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
                Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction SilentlyContinue
            }
            return $row
        }
        $item = Get-Item -LiteralPath $DestinationPath -Force -ErrorAction Stop
        $row.SizeBytes = $item.Length
        $row.SHA256 = Get-FotonSafeHash -Path $DestinationPath
        $row.Status = 'Saved'
        $row.Note = 'Exported with reg save (consistent image of the loaded hive; no transaction logs needed).'
    }
    catch {
        $row.DestRelative = ''
        $row.Note = $_.Exception.Message
    }
    return $row
}

function Write-FotonManifestFiles {
    $manifestCsv = Join-Path $script:FotonSession.Dirs['Collection'] 'collection_manifest.csv'
    $script:FotonSession.Manifest | Export-Csv -Path $manifestCsv -NoTypeInformation -Encoding UTF8

    $findingsCsv = Join-Path $script:FotonSession.Dirs['Collection'] 'findings.csv'
    if ($script:FotonSession.Findings.Count -gt 0) {
        $script:FotonSession.Findings | Export-Csv -Path $findingsCsv -NoTypeInformation -Encoding UTF8
    }

    if ($script:FotonSession.Errors.Count -gt 0) {
        $script:FotonSession.Errors | Export-Csv -Path (Join-Path $script:FotonSession.Dirs['Collection'] 'collection_errors.csv') -NoTypeInformation -Encoding UTF8
    }
}

function Write-FotonArtifactHashes {
    Write-FotonStatus 'Hashing collected artifacts (SHA-256)' 'Step'
    $rows = @()
    $root = $script:FotonSession.CaseRoot
    foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'hashes.csv' -or $f.Name -eq 'hashes.txt') { continue }
        $hash = ''
        try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $hash = 'HASH_ERROR' }
        $rel = $f.FullName.Substring($root.Length).TrimStart('\')
        $rows += [PSCustomObject]@{
            RelativePath = $rel
            SizeBytes    = $f.Length
            SHA256       = $hash
            ModifiedUtc  = $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
    $rows | Export-Csv -Path (Join-Path $script:FotonSession.Dirs['Collection'] 'hashes.csv') -NoTypeInformation -Encoding UTF8
    $txt = @()
    $txt += "Foton artifact hashes (SHA-256) - generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    $txt += ''
    foreach ($r in $rows) { $txt += ("{0}  {1}" -f $r.SHA256, $r.RelativePath) }
    $txt | Out-File -FilePath (Join-Path $script:FotonSession.Dirs['Collection'] 'hashes.txt') -Encoding UTF8
    Write-FotonStatus ("Hashed {0} artifacts" -f $rows.Count) 'Good'
    return $rows.Count
}

function Compress-FotonCasePackage {
    Write-FotonStatus 'Compressing case package' 'Step'
    $zipPath = "$($script:FotonSession.CaseRoot).zip"
    try {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [System.IO.Compression.ZipFile]::CreateFromDirectory($script:FotonSession.CaseRoot, $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal, $true)
        return $zipPath
    }
    catch {
        try {
            Compress-Archive -Path (Join-Path $script:FotonSession.CaseRoot '*') -DestinationPath $zipPath -Force -ErrorAction Stop
            return $zipPath
        }
        catch {
            Write-FotonStatus "Compression failed: $($_.Exception.Message). The uncompressed case folder is still available." 'Warn'
            return $null
        }
    }
}

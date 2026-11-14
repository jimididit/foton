<#
.SYNOPSIS
    Signs a published Foton release's foton-release.json with an offline release key and uploads the signature.
.DESCRIPTION
    Run after the release workflow has published vX.Y.Z, on the machine holding the key. It downloads the release's
    foton-release.json, checks it (product, version, and that every hash it lists matches the release's own
    SHA256SUMS.txt), checks the ZIP's GitHub build provenance, signs the file's exact bytes (ECDSA P-256 over SHA-256),
    verifies the new signature with the key's public half, and uploads foton-release.json.sig. The console's updater
    installs nothing from a release until that signature exists.
.EXAMPLE
    .\packaging\sign-release.ps1 -Version 3.3.0 -KeyPath E:\FotonKeys\foton-release-key-primary.pfx
#>
param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$KeyPath,
    # Sign this local statement instead of downloading it, and do not upload (tests, dry runs).
    [string]$StatementPath,
    [switch]$NoUpload,
    [System.Security.SecureString]$Password
)
$ErrorActionPreference = 'Stop'
$repo = 'jimididit/foton'
$tag = "v$Version"
$work = Join-Path ([IO.Path]::GetTempPath()) ("foton-sign-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    if ($StatementPath) { $statement = (Resolve-Path -LiteralPath $StatementPath).Path }
    else {
        gh release download $tag --repo $repo -p 'foton-release.json' -p 'SHA256SUMS.txt' -D $work
        if ($LASTEXITCODE -ne 0) { throw "Could not download foton-release.json and SHA256SUMS.txt of $tag." }
        $statement = Join-Path $work 'foton-release.json'
    }
    $bytes = [IO.File]::ReadAllBytes($statement)
    $json = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ($json.product -ne 'Foton' -or $json.version -ne $Version) { throw "foton-release.json says $($json.product) $($json.version), not Foton $Version." }

    if (-not $StatementPath) {
        # Every hash in the statement must be the release's own: what is signed is what was published.
        $sums = @{}
        foreach ($line in Get-Content (Join-Path $work 'SHA256SUMS.txt')) { $h, $n = $line -split '\s+', 2; $sums[$n] = $h }
        $listed = @{ $json.zip.name = $json.zip.sha256 }
        foreach ($p in $json.files.PSObject.Properties) { $listed[$p.Name] = $p.Value }
        foreach ($n in $listed.Keys) { if ($sums[$n] -ne $listed[$n]) { throw "$n in foton-release.json does not match the release's SHA256SUMS.txt." } }
        gh release download $tag --repo $repo -p $json.zip.name -D $work
        gh attestation verify (Join-Path $work $json.zip.name) --repo $repo | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "$($json.zip.name) has no valid GitHub build provenance; not signing." }
        $actual = (Get-FileHash (Join-Path $work $json.zip.name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $json.zip.sha256) { throw "The downloaded $($json.zip.name) does not match foton-release.json." }
    }

    if (-not $Password) { $Password = Read-Host -AsSecureString "Password for $KeyPath" }
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path -LiteralPath $KeyPath).Path, $Password, $flags)
    try {
        $private = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
        $public = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
        if (-not $private) { throw "$KeyPath holds no ECDSA private key." }
        $signature = $private.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        if (-not $public.VerifyData($bytes, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) { throw 'The new signature does not verify; nothing written.' }
        $q = $public.ExportParameters($false).Q
        $blob = [byte[]](0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00) + $q.X + $q.Y
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fingerprint = ([BitConverter]::ToString($sha.ComputeHash([byte[]]$blob)) -replace '-', '').ToLowerInvariant()
        $sha.Dispose()
    }
    finally { $cert.Dispose() }

    $sigPath = Join-Path (Split-Path $statement) 'foton-release.json.sig'
    [IO.File]::WriteAllText($sigPath, [Convert]::ToBase64String($signature) + "`n", (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Signed Foton $Version with key $fingerprint"
    if (-not $NoUpload -and -not $StatementPath) {
        gh release upload $tag $sigPath --repo $repo --clobber
        if ($LASTEXITCODE -ne 0) { throw "Upload of foton-release.json.sig to $tag failed." }
        Write-Host "Uploaded foton-release.json.sig to $tag."
    }
    else { Write-Host "Wrote $sigPath (not uploaded)." }
}
finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }

<#
.SYNOPSIS
    Makes the two Foton release signing keys (primary and backup), each in its own password-protected .pfx.
.DESCRIPTION
    Run once, on the offline machine or media that will hold the keys. The keys are ECDSA P-256, made in memory and
    written only to the .pfx files: nothing goes into the Windows certificate store. Keep the two .pfx files apart
    (two offline media), each with its own strong password. public-keys.txt holds what the console pins: give that to
    the developer, never the .pfx files or their passwords.
.EXAMPLE
    .\packaging\new-release-key.ps1 -OutputFolder E:\FotonKeys
#>
param(
    [Parameter(Mandatory)][string]$OutputFolder,
    # For automated tests only; interactive use prompts (twice) for each key's password.
    [System.Security.SecureString]$PrimaryPassword,
    [System.Security.SecureString]$BackupPassword
)
$ErrorActionPreference = 'Stop'

function Read-NewPassword([string]$Role) {
    while ($true) {
        $a = Read-Host -AsSecureString "Password for the $Role key (at least 16 characters)"
        $b = Read-Host -AsSecureString "Repeat it"
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -ne $pb) { Write-Host 'The two entries differ; try again.'; continue }
        if ($pa.Length -lt 16) { Write-Host 'Too short; use at least 16 characters.'; continue }
        return $a
    }
}

# The public key as a CNG ECCPUBLICBLOB (magic "ECS1", key length 32, X, Y): what the console imports with CngKey.Import.
function Get-PublicBlob([System.Security.Cryptography.ECDsa]$Key) {
    $q = $Key.ExportParameters($false).Q
    $blob = New-Object byte[] 72
    [byte[]](0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00) | ForEach-Object -Begin { $i = 0 } -Process { $blob[$i++] = $_ }
    [Array]::Copy($q.X, 0, $blob, 8, 32)
    [Array]::Copy($q.Y, 0, $blob, 40, 32)
    return $blob
}

$folder = [IO.Path]::GetFullPath($OutputFolder)
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$lines = @('Foton release signing keys: public halves (safe to share; the console pins these).', '')
foreach ($role in 'primary', 'backup') {
    $pfx = Join-Path $folder "foton-release-key-$role.pfx"
    if (Test-Path -LiteralPath $pfx) { throw "$pfx already exists; refusing to overwrite a key." }
    $password = if ($role -eq 'primary' -and $PrimaryPassword) { $PrimaryPassword } elseif ($role -eq 'backup' -and $BackupPassword) { $BackupPassword } else { Read-NewPassword $role }
    $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    try {
        $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Foton release key ($role)", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $now = [DateTimeOffset]::UtcNow
        $cert = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddYears(20))
        [IO.File]::WriteAllBytes($pfx, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))
        $cert.Dispose()
        $blob = Get-PublicBlob $key
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fingerprint = ([BitConverter]::ToString($sha.ComputeHash($blob)) -replace '-', '').ToLowerInvariant()
        $sha.Dispose()
        $lines += "$role key"
        $lines += "  public key (ECCPUBLICBLOB, base64): $([Convert]::ToBase64String($blob))"
        $lines += "  fingerprint (SHA-256 of the blob):  $fingerprint"
        $lines += ''
        Write-Host "Wrote $pfx (fingerprint $fingerprint)"
    }
    finally { $key.Dispose() }
}
$public = Join-Path $folder 'public-keys.txt'
[IO.File]::WriteAllLines($public, [string[]]$lines)
Write-Host "Wrote $public. Give the developer that file; keep the two .pfx files offline and apart, with their passwords."

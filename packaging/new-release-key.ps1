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

$MinimumPassword = 16

# Compares two SecureStrings in their unmanaged copies, zeroed afterwards, so no plaintext string is left on the heap.
function Test-SamePassword([System.Security.SecureString]$A, [System.Security.SecureString]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    $marshal = [Runtime.InteropServices.Marshal]
    $pa = $marshal::SecureStringToBSTR($A); $pb = $marshal::SecureStringToBSTR($B)
    try {
        $same = $true
        for ($i = 0; $i -lt $A.Length * 2; $i += 2) { if ($marshal::ReadInt16($pa, $i) -ne $marshal::ReadInt16($pb, $i)) { $same = $false } }
        return $same
    }
    finally { $marshal::ZeroFreeBSTR($pa); $marshal::ZeroFreeBSTR($pb) }
}

function Read-NewPassword([string]$Role) {
    while ($true) {
        $a = Read-Host -AsSecureString "Password for the $Role key (at least $MinimumPassword characters)"
        $b = Read-Host -AsSecureString "Repeat it"
        if (-not (Test-SamePassword $a $b)) { Write-Host 'The two entries differ; try again.'; continue }
        if ($a.Length -lt $MinimumPassword) { Write-Host "Too short; use at least $MinimumPassword characters."; continue }
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
$roles = 'primary', 'backup'
$public = Join-Path $folder 'public-keys.txt'
# Check everything before writing anything, so a refusal or a bad password never leaves half a key set behind.
foreach ($path in @($roles | ForEach-Object { Join-Path $folder "foton-release-key-$_.pfx" }) + $public) {
    if (Test-Path -LiteralPath $path) { throw "$path already exists; refusing to overwrite a key." }
}
$passwords = @{}
foreach ($role in $roles) {
    $given = if ($role -eq 'primary') { $PrimaryPassword } else { $BackupPassword }
    if ($given -and $given.Length -lt $MinimumPassword) { throw "The $role password is shorter than $MinimumPassword characters." }
    $passwords[$role] = if ($given) { $given } else { Read-NewPassword $role }
}

New-Item -ItemType Directory -Force -Path $folder | Out-Null
$written = @()
$done = $false
try {
    $lines = @('Foton release signing keys: public halves (safe to share; the console pins these).', '')
    foreach ($role in $roles) {
        $pfx = Join-Path $folder "foton-release-key-$role.pfx"
        $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        try {
            $request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Foton release key ($role)", $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            $now = [DateTimeOffset]::UtcNow
            $cert = $request.CreateSelfSigned($now.AddMinutes(-5), $now.AddYears(20))
            try { $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $passwords[$role]) }
            finally { $cert.Dispose() }
            $written += $pfx
            [IO.File]::WriteAllBytes($pfx, $bytes)
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
    $written += $public
    [IO.File]::WriteAllLines($public, [string[]]$lines)
    $done = $true
}
finally {
    # A key without its recorded public half (or the reverse) is useless and confusing: remove this run's files.
    if (-not $done) { foreach ($path in $written) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue } }
}
Write-Host "Wrote $public. Give the developer that file; keep the two .pfx files offline and apart, with their passwords."
